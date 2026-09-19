"""Memory-safe attachment streaming to ephemeral temp files.

Downloads Gmail attachments in fixed-size chunks straight to an encrypted-
permission temp file while hashing and enforcing resource limits, so a
25 MB attachment never materializes as a single in-memory bytes object.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from typing import Any, Optional

import psutil

from app.core.attachment_limits import (
    MAX_ATTACHMENT_SIZE_BYTES,
    MEMORY_CRITICAL_THRESHOLD_MB,
    STREAM_CHUNK_SIZE,
)
from app.core.errors import AttachmentTooLargeError, MemoryLimitExceededError

logger = logging.getLogger("cyberguard.attachment.streamer")


class AttachmentStreamer:
    """Streams attachments to 0600 temp files with sha256 + limit enforcement."""

    async def stream_to_temp_file(
        self,
        gmail_client: Any,
        message_id: str,
        attachment_id: str,
        expected_size: int,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> tuple[str, str, int]:
        """Stream an attachment to a private temp file.

        Returns (temp_path, sha256_hex, actual_size). The temp file is created
        with 0600 permissions, written in STREAM_CHUNK_SIZE chunks, and deleted
        by this method if any limit is violated or any error occurs — callers
        only own the file when (path, hash, size) is returned successfully.
        """
        if expected_size > MAX_ATTACHMENT_SIZE_BYTES:
            raise AttachmentTooLargeError(
                f"Attachment size {expected_size} bytes exceeds limit "
                f"{MAX_ATTACHMENT_SIZE_BYTES} bytes"
            )

        fd, temp_path = tempfile.mkstemp(prefix="cyberguard_", suffix=".scan")
        os.chmod(temp_path, 0o600)

        hasher = hashlib.sha256()
        total_size = 0
        process = psutil.Process()
        # Track scan-attributable growth, not absolute RSS: production
        # analysis workers legitimately hold ~1 GB of ML models, so an
        # absolute threshold would abort every scan in a healthy process.
        baseline_mb = process.memory_info().rss / (1024 * 1024)
        try:
            with os.fdopen(fd, "wb") as temp_file:
                async for chunk in gmail_client.stream_attachment(
                    message_id,
                    attachment_id,
                    chunk_size=STREAM_CHUNK_SIZE,
                    access_token=access_token,
                    refresh_token=refresh_token,
                ):
                    temp_file.write(chunk)
                    hasher.update(chunk)
                    total_size += len(chunk)

                    if total_size > MAX_ATTACHMENT_SIZE_BYTES:
                        raise AttachmentTooLargeError(
                            f"Attachment streamed {total_size} bytes, exceeding limit "
                            f"{MAX_ATTACHMENT_SIZE_BYTES} bytes (declared {expected_size})"
                        )

                    memory_mb = process.memory_info().rss / (1024 * 1024)
                    if memory_mb - baseline_mb > MEMORY_CRITICAL_THRESHOLD_MB:
                        raise MemoryLimitExceededError(
                            f"Scan memory growth {memory_mb - baseline_mb:.0f} MB exceeds critical threshold "
                            f"{MEMORY_CRITICAL_THRESHOLD_MB} MB"
                        )
            return temp_path, hasher.hexdigest(), total_size
        except Exception:
            self.cleanup_temp_file(temp_path)
            raise

    @staticmethod
    def cleanup_temp_file(temp_path: Optional[str]) -> None:
        """Delete a scan temp file if it still exists; never raise."""
        if not temp_path:
            return
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError as exc:
            logger.warning("Failed to clean up scan temp file %s: %s", temp_path, exc)
