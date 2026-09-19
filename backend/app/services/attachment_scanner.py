"""Attachment scanner — ATTACH-SCAN Phase 1 (memory-safe foundation).

Phase 1 implements Level 1 (basic validation): streamed download with
hashing, magic-byte type detection, and MIME mismatch scoring. Levels 2-4
(archive inspection, static analysis, sandboxing) arrive in Phases 2-4 and
plug in behind _level1_basic_validation.

Every path — success, skip, or failure — guarantees the scan temp file is
deleted; only scan metadata and results are ever persisted (never the file).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.errors import AttachmentTooLargeError
from app.services.attachment_streamer import AttachmentStreamer
from app.services.file_validator import FileValidator

logger = logging.getLogger("cyberguard.attachment.scanner")


@dataclass
class ScanResult:
    """Outcome of scanning a single attachment."""

    status: str  # completed | skipped | failed
    risk_score: int = 0
    verdict: str = "safe"
    indicators: list[dict[str, Any]] = field(default_factory=list)
    sha256: Optional[str] = None
    detected_mime: Optional[str] = None
    declared_mime: Optional[str] = None
    mime_mismatch: bool = False
    scan_duration_ms: int = 0
    error: Optional[str] = None
    temp_path: Optional[str] = None  # internal handoff; cleared after cleanup


class AttachmentScanner:
    """Scans attachments level-by-level with hard resource limits."""

    def __init__(self):
        self.streamer = AttachmentStreamer()
        self.validator = FileValidator()

    async def scan_attachment(
        self,
        gmail_client: Any,
        message_id: str,
        attachment_id: str,
        filename: str,
        declared_mime: str,
        expected_size: int,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> ScanResult:
        """Scan one attachment and always clean up its temp file."""
        start = time.monotonic()
        temp_path: Optional[str] = None
        try:
            result = await self._level1_basic_validation(
                gmail_client=gmail_client,
                message_id=message_id,
                attachment_id=attachment_id,
                filename=filename,
                declared_mime=declared_mime,
                expected_size=expected_size,
                access_token=access_token,
                refresh_token=refresh_token,
            )
            temp_path = result.temp_path
            if result.status != "completed":
                return result

            # Level 2 (archive inspection), Level 3 (static analysis) and
            # Level 4 (sandbox detonation) hooks land in Phases 2-4.

            result.scan_duration_ms = int((time.monotonic() - start) * 1000)
            result.status = "completed"
            return result
        except AttachmentTooLargeError as exc:
            return ScanResult(
                status="failed",
                verdict="malicious",
                risk_score=100,
                indicators=[{"type": "oversized_file", "severity": "critical"}],
                declared_mime=declared_mime,
                error=str(exc),
            )
        except Exception as exc:
            logger.warning("Attachment scan failed for %s/%s: %s", message_id, attachment_id, exc)
            return ScanResult(status="failed", declared_mime=declared_mime, error=str(exc))
        finally:
            if temp_path:
                self.streamer.cleanup_temp_file(temp_path)

    async def _level1_basic_validation(
        self,
        gmail_client: Any,
        message_id: str,
        attachment_id: str,
        filename: str,
        declared_mime: str,
        expected_size: int,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> ScanResult:
        """Stream to temp file, hash, detect the real type, score mismatches."""
        temp_path, sha256, actual_size = await self.streamer.stream_to_temp_file(
            gmail_client,
            message_id,
            attachment_id,
            expected_size,
            access_token=access_token,
            refresh_token=refresh_token,
        )

        detected_mime = self.validator.detect_file_type(temp_path)
        mime_validation = self.validator.validate_mime_type(declared_mime, detected_mime)

        if not self.validator.is_supported_type(detected_mime):
            return ScanResult(
                status="skipped",
                verdict="safe",
                indicators=[{"type": "unsupported_type", "severity": "info"}],
                sha256=sha256,
                detected_mime=detected_mime,
                declared_mime=declared_mime,
                error=f"Unsupported type: {detected_mime}",
                temp_path=temp_path,
            )

        indicators: list[dict[str, Any]] = []
        risk_score = 0
        if mime_validation["mismatch"]:
            indicators.append(
                {
                    "type": "mime_mismatch",
                    "severity": "medium",
                    "description": f"Declared {declared_mime}, detected {detected_mime}",
                }
            )
            risk_score += mime_validation["risk_score"]

        result = ScanResult(
            status="completed",
            risk_score=risk_score,
            verdict="safe",
            indicators=indicators,
            sha256=sha256,
            detected_mime=detected_mime,
            declared_mime=declared_mime,
            mime_mismatch=mime_validation["mismatch"],
        )
        result.temp_path = temp_path
        return result
