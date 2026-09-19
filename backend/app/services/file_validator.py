"""Content-based file type detection and MIME validation for attachments.

Declared MIME types come from attacker-controlled email headers, so every
attachment's true type is derived from magic bytes read off disk, then
compared against the declaration to catch spoofing (e.g. an "invoice.pdf"
that is really an MZ executable).
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
from pathlib import Path

from app.core.attachment_limits import (
    SUPPORTED_MIME_TYPES,
    WEBP_FORMAT_MAGIC,
    WEBP_RIFF_MAGIC,
    _SORTED_MAGIC_SIGNATURES,
)

logger = logging.getLogger("cyberguard.attachment.validator")

STREAM_READ_CHUNK = 65_536

# Extension fallbacks mimetypes misses or gets wrong for our domain.
_EXTENSION_MIME_OVERRIDES = {
    ".7z": "application/x-7z-compressed",
    ".rar": "application/x-rar-compressed",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


class FileValidator:
    """Detects real file types from magic bytes and validates declarations."""

    def detect_file_type(self, file_path: str) -> str:
        """Return the detected MIME type for a file on disk.

        Reads the first 16 bytes and matches known magic signatures. Falls
        back to an extension-based guess when no signature matches; returns
        application/octet-stream when nothing is identifiable.
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
        except OSError as exc:
            logger.warning("Cannot read file header for %s: %s", file_path, exc)
            return "application/octet-stream"

        if header[:4] == WEBP_RIFF_MAGIC and header[8:12] == WEBP_FORMAT_MAGIC:
            return "image/webp"

        for magic, mime in _SORTED_MAGIC_SIGNATURES:
            if header.startswith(magic):
                return mime

        return self._guess_from_extension(file_path)

    def validate_mime_type(self, declared_mime: str, detected_mime: str) -> dict:
        """Compare the declared MIME type against content-based detection.

        Returns {declared_mime, detected_mime, mismatch, risk_score} where
        risk_score is 30 on mismatch and 0 otherwise.
        """
        declared = (declared_mime or "").lower().split(";")[0].strip()
        detected = (detected_mime or "").lower().strip()

        # OLE2 containers legitimately back doc/xls/ppt, so a declared Office
        # MIME with a generic ms-office detection is not a mismatch.
        if detected == "application/vnd.ms-office" and declared.startswith("application/vnd.ms-"):
            mismatch = False
        else:
            mismatch = bool(declared) and declared != detected

        return {
            "declared_mime": declared,
            "detected_mime": detected,
            "mismatch": mismatch,
            "risk_score": 30 if mismatch else 0,
        }

    def is_supported_type(self, mime_type: str) -> bool:
        """Return True if the MIME type is in the supported set."""
        return (mime_type or "").lower().strip() in SUPPORTED_MIME_TYPES

    def calculate_sha256_streaming(self, file_path: str) -> str:
        """Return the sha256 hex digest of a file, read in 64 KB chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(STREAM_READ_CHUNK), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _guess_from_extension(self, file_path: str) -> str:
        suffix = Path(file_path).suffix.lower()
        if suffix in _EXTENSION_MIME_OVERRIDES:
            return _EXTENSION_MIME_OVERRIDES[suffix]
        guessed, _ = mimetypes.guess_type(file_path)
        return guessed or "application/octet-stream"
