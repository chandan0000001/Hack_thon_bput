"""Archive inspection with memory-safe one-at-a-time extraction.

Extracts exactly one member to a 0600 temp file, inspects it, deletes it,
then moves to the next — an archive never materializes fully on disk or in
memory. Nested archives recurse with a depth budget, and every extraction is
bounded by member counts, byte budgets, and a compression-ratio (zip bomb)
check computed BEFORE any bytes are written.

Supported containers use the stdlib only: ZIP, TAR, GZIP. RAR/7Z are
detected and reported as uninspectable rather than pulled in via extra
native dependencies (graceful degradation, Phase 3+ can add engines).
"""

from __future__ import annotations

import gzip
import logging
import os
import tarfile
import tempfile
import zipfile
from typing import Optional

from app.core.attachment_limits import (
    MAX_ARCHIVE_COMPRESSION_RATIO,
    MAX_ARCHIVE_DEPTH,
    MAX_EXTRACTED_FILES,
    MAX_EXTRACTED_TOTAL_SIZE,
    STREAM_CHUNK_SIZE,
)
from app.services.attachment_streamer import AttachmentStreamer
from app.services.file_validator import FileValidator

logger = logging.getLogger("cyberguard.attachment.archive")

_TEMP_PREFIX = "cyberguard_member_"


class ArchiveInspector:
    """Bounded, recursive archive inspection."""

    def __init__(self, limits=None):
        # limits: module or namespace exposing the attachment_limits names;
        # injectable for tests/custom policies.
        if limits is None:
            from app.core import attachment_limits as limits_module

            limits = limits_module
        self._max_depth = getattr(limits, "MAX_ARCHIVE_DEPTH", MAX_ARCHIVE_DEPTH)
        self._max_files = getattr(limits, "MAX_EXTRACTED_FILES", MAX_EXTRACTED_FILES)
        self._max_total = getattr(limits, "MAX_EXTRACTED_TOTAL_SIZE", MAX_EXTRACTED_TOTAL_SIZE)
        self._max_ratio = getattr(limits, "MAX_ARCHIVE_COMPRESSION_RATIO", MAX_ARCHIVE_COMPRESSION_RATIO)
        self._chunk = getattr(limits, "STREAM_CHUNK_SIZE", STREAM_CHUNK_SIZE)
        self.validator = FileValidator()
        self.streamer = AttachmentStreamer()

    async def inspect(self, file_path: str, current_depth: int = 0) -> dict:
        """Inspect an archive (recursively) without ever extracting everything at once."""
        result: dict = {
            "engine": "archive",
            "is_archive": False,
            "extracted_count": 0,
            "extracted_files": [],
            "depth_reached": current_depth,
            "risk_score": 0,
            "indicators": [],
            "_bytes_used": 0,  # internal running extraction budget
        }

        archive_type = self._detect_archive_type(file_path)
        if archive_type is None:
            return result
        result["is_archive"] = True

        if current_depth >= self._max_depth:
            result["indicators"].append({"type": "archive_depth_exceeded", "severity": "high"})
            result["depth_reached"] = current_depth
            result["risk_score"] += 40
            return result

        if archive_type in ("rar", "7z"):
            # Detected but not extractable with the stdlib engine set.
            result["indicators"].append(
                {"type": "archive_format_unsupported", "severity": "info",
                 "description": f"{archive_type.upper()} archive detected but not inspectable"}
            )
            result["risk_score"] += 5
            return result

        try:
            if archive_type == "zip":
                await self._inspect_zip(file_path, current_depth, result)
            elif archive_type == "tar":
                await self._inspect_tar(file_path, current_depth, result)
            elif archive_type == "gzip":
                await self._inspect_gzip(file_path, current_depth, result)
        except Exception as exc:
            logger.warning("Archive inspection failed for %s: %s", file_path, exc)
            result["indicators"].append(
                {"type": "archive_inspection_error", "severity": "info", "description": str(exc)}
            )
        finally:
            result["depth_reached"] = max(result["depth_reached"], current_depth)
            result.pop("_bytes_used", None)  # internal extraction budget counter
        return result

    # ------------------------------------------------------------------
    # ZIP
    # ------------------------------------------------------------------

    async def _inspect_zip(self, file_path: str, depth: int, result: dict) -> None:
        with zipfile.ZipFile(file_path) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]

            encrypted = any(i.flag_bits & 0x1 for i in infos)
            if encrypted:
                result["indicators"].append(
                    {"type": "encrypted_archive", "severity": "medium",
                     "description": "Password-protected archive contents cannot be inspected"}
                )
                result["risk_score"] += 20

            uncompressed_total = sum(i.file_size for i in infos)
            compressed_total = sum(i.compress_size for i in infos) or 1
            if uncompressed_total / compressed_total > self._max_ratio:
                result["indicators"].append(
                    {"type": "zip_bomb_suspected", "severity": "high",
                     "description": f"Compression ratio {uncompressed_total / compressed_total:.0f} "
                     f"exceeds {self._max_ratio}"}
                )
                result["risk_score"] += 50
                return  # refuse extraction entirely

            for info in infos:
                if result["extracted_count"] >= self._max_files:
                    result["indicators"].append(
                        {"type": "extraction_limit_exceeded", "severity": "medium",
                         "description": f"More than {self._max_files} members; remaining members not extracted"}
                    )
                    result["risk_score"] += 15
                    return
                if info.flag_bits & 0x1:
                    continue  # encrypted member: already flagged, cannot extract
                if result["_bytes_used"] + info.file_size > self._max_total:
                    result["indicators"].append(
                        {"type": "extraction_size_limit_exceeded", "severity": "medium",
                         "description": f"Uncompressed budget {self._max_total} bytes reached"}
                    )
                    result["risk_score"] += 15
                    return
                if self._is_unsafe_member(info.filename):
                    result["indicators"].append(
                        {"type": "unsafe_member_path", "severity": "medium",
                         "description": f"Unsafe member path skipped: {info.filename}"}
                    )
                    result["risk_score"] += 15
                    continue

                member = self._extract_zip_member(archive, info)
                try:
                    result["_bytes_used"] += info.file_size
                    await self._process_member(info.filename, member, depth, result)
                finally:
                    self.streamer.cleanup_temp_file(member)
        return

    def _extract_zip_member(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
        fd, member_path = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".member")
        try:
            with os.fdopen(fd, "wb") as out, archive.open(info) as src:
                while chunk := src.read(self._chunk):
                    out.write(chunk)
            os.chmod(member_path, 0o600)
            return member_path
        except Exception:
            self.streamer.cleanup_temp_file(member_path)
            raise

    # ------------------------------------------------------------------
    # TAR
    # ------------------------------------------------------------------

    async def _inspect_tar(self, file_path: str, depth: int, result: dict) -> None:
        with tarfile.open(file_path, "r:*") as archive:
            members = [m for m in archive.getmembers() if m.isfile()]
            for member in members:
                if result["extracted_count"] >= self._max_files:
                    result["indicators"].append(
                        {"type": "extraction_limit_exceeded", "severity": "medium",
                         "description": f"More than {self._max_files} members; remaining members not extracted"}
                    )
                    result["risk_score"] += 15
                    return
                if result["_bytes_used"] + member.size > self._max_total:
                    result["indicators"].append(
                        {"type": "extraction_size_limit_exceeded", "severity": "medium",
                         "description": f"Uncompressed budget {self._max_total} bytes reached"}
                    )
                    result["risk_score"] += 15
                    return
                if self._is_unsafe_member(member.name):
                    result["indicators"].append(
                        {"type": "unsafe_member_path", "severity": "medium",
                         "description": f"Unsafe member path skipped: {member.name}"}
                    )
                    result["risk_score"] += 15
                    continue

                fd, member_path = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".member")
                try:
                    with os.fdopen(fd, "wb") as out:
                        src = archive.extractfile(member)
                        if src is None:
                            continue
                        while chunk := src.read(self._chunk):
                            out.write(chunk)
                    os.chmod(member_path, 0o600)
                    result["_bytes_used"] += member.size
                    await self._process_member(member.name, member_path, depth, result)
                finally:
                    self.streamer.cleanup_temp_file(member_path)
        return

    # ------------------------------------------------------------------
    # GZIP (single-member stream)
    # ------------------------------------------------------------------

    async def _inspect_gzip(self, file_path: str, depth: int, result: dict) -> None:
        fd, member_path = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".member")
        try:
            total = 0
            with os.fdopen(fd, "wb") as out, gzip.open(file_path, "rb") as src:
                while chunk := src.read(self._chunk):
                    total += len(chunk)
                    if total > self._max_total:
                        raise ValueError("gzip member exceeds extraction size budget")
                    out.write(chunk)
            os.chmod(member_path, 0o600)
            try:
                await self._process_member(os.path.basename(file_path), member_path, depth, result)
            finally:
                self.streamer.cleanup_temp_file(member_path)
        except Exception:
            self.streamer.cleanup_temp_file(member_path)
            raise

    # ------------------------------------------------------------------
    # Member handling
    # ------------------------------------------------------------------

    async def _process_member(self, name: str, member_path: str, depth: int, result: dict) -> None:
        """Record one extracted member; recurse when it is itself an archive."""
        detected = self.validator.detect_file_type(member_path)
        size = os.path.getsize(member_path)
        result["extracted_count"] += 1
        result["extracted_files"].append(
            {"name": name, "size_bytes": size, "detected_mime": detected}
        )

        if self._detect_archive_type(member_path) is not None:
            nested = await self.inspect(member_path, current_depth=depth + 1)
            result["depth_reached"] = max(result["depth_reached"], nested["depth_reached"])
            result["risk_score"] += nested["risk_score"]
            result["indicators"].extend(nested["indicators"])
            result["extracted_files"].extend(
                {**f, "name": f"{name}/{f['name']}"} for f in nested["extracted_files"]
            )
            result["extracted_count"] += nested["extracted_count"]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_archive_type(self, file_path: str) -> Optional[str]:
        """Return 'zip' | 'tar' | 'gzip' | 'rar' | '7z' when the file is an archive."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
        except OSError:
            return None

        if header[:4] == b"PK\x03\x04":
            return "zip"
        if header[:2] == b"\x1f\x8b":
            return "gzip"
        if header[:6] == b"Rar!\x1a\x07":
            return "rar"
        if header[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        # Plain (uncompressed) tar has no leading magic; ustar sits at offset 257.
        if header[257:262] == b"ustar":
            return "tar"
        # V7 tar without ustar magic: fall back to extension hint.
        if file_path.endswith(".tar"):
            return "tar"
        return None

    @staticmethod
    def _is_unsafe_member(name: str) -> bool:
        """Zip-slip guard: refuse absolute paths and traversal components."""
        if not name:
            return False
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("~"):
            return True
        return any(part == ".." for part in normalized.split("/"))
