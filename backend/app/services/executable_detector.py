"""Executable detection and PE analysis for scanned attachments.

Identifies Windows PE executables from magic bytes (declared names are
attacker controlled), extracts light PE metadata via pefile when available,
and flags two high-value behaviours: packed/encrypted content (entropy) and
extension/content disguise (an "invoice.pdf" that is really an MZ binary, or
an .exe that arrived declared as a document).
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Optional

from app.core.attachment_limits import EXECUTABLE_EXTENSIONS

logger = logging.getLogger("cyberguard.attachment.executable")

ENTROPY_PACKED_THRESHOLD = 7.0
ENTROPY_CHUNK = 65_536

DOCUMENT_IMAGE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".txt", ".html",
}
DOCUMENT_IMAGE_MIMES = {
    "application/pdf", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "image/jpeg", "image/png", "image/webp", "image/gif", "text/plain", "text/html",
}

MZ_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"
PE_HEADER_OFFSET_LOCATION = 0x3C  # MZ header field holding the PE header offset


class ExecutableDetector:
    """Detects executables and their disguise/packing indicators."""

    def detect(
        self,
        file_path: str,
        declared_mime: Optional[str] = None,
        original_filename: Optional[str] = None,
    ) -> dict:
        """Analyze a file for executable content.

        Returns {engine, is_executable, pe_info, indicators, risk_score} where
        pe_info = {sections, imports_count, entropy} (sections/imports are None
        when pefile is unavailable or the PE header is malformed).
        """
        indicators: list[dict] = []
        risk_score = 0

        header = self._read_header(file_path)
        is_executable = header[:2] == MZ_MAGIC

        pe_info: dict = {"sections": None, "imports_count": None, "entropy": 0.0}
        if is_executable:
            pe_info["entropy"] = self._file_entropy(file_path)

            pe_data = self._parse_pe_header(file_path)
            if pe_data:
                pe_info.update(pe_data)

            if pe_info["entropy"] > ENTROPY_PACKED_THRESHOLD:
                indicators.append(
                    {
                        "type": "packed_or_encrypted",
                        "severity": "medium",
                        "description": f"Entropy {pe_info['entropy']:.2f} exceeds "
                        f"{ENTROPY_PACKED_THRESHOLD} (packed or encrypted content)",
                    }
                )
                risk_score += 25

            if self._is_disguise(file_path, declared_mime, original_filename):
                indicators.append(
                    {
                        "type": "executable_disguise",
                        "severity": "high",
                        "description": "Executable content presenting as a document/image "
                        f"(declared {declared_mime or 'unknown'}, filename {original_filename or Path(file_path).name})",
                    }
                )
                risk_score += 40

        return {
            "engine": "executable",
            "is_executable": is_executable,
            "pe_info": pe_info,
            "indicators": indicators,
            "risk_score": risk_score,
        }

    def _is_disguise(
        self, file_path: str, declared_mime: Optional[str], original_filename: Optional[str]
    ) -> bool:
        """An executable wearing a document/image identity is a disguise.

        Two directions both count: MZ content carrying a document/image
        extension or declared MIME, and an executable extension arriving
        declared as a document/image MIME.
        """
        declared = (declared_mime or "").lower().split(";")[0].strip()

        if declared and (declared in DOCUMENT_IMAGE_MIMES or declared.startswith("image/")):
            # Executable by extension, or executable by content, declared as a document.
            return True

        effective_name = original_filename or Path(file_path).name
        suffix = Path(effective_name).suffix.lower()
        if suffix in DOCUMENT_IMAGE_EXTENSIONS:
            return True  # MZ content behind a document extension
        return False

    def _parse_pe_header(self, file_path: str) -> Optional[dict]:
        """Parse sections/imports via pefile; None when unavailable or malformed."""
        try:
            import pefile
        except ImportError:
            return None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            sections = len(pe.sections or [])
            imports = sum(len(entry.imports) for entry in (pe.DIRECTORY_ENTRY_IMPORT or []))
            return {"sections": sections, "imports_count": imports}
        except Exception as exc:
            logger.debug("PE header parse failed for %s: %s", file_path, exc)
            return None

    def _read_header(self, file_path: str) -> bytes:
        try:
            with open(file_path, "rb") as f:
                return f.read(64)
        except OSError:
            return b""

    def _file_entropy(self, file_path: str) -> float:
        """Shannon entropy over the whole file, read in chunks (0.0–8.0)."""
        counts = [0] * 256
        total = 0
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(ENTROPY_CHUNK):
                    for byte in chunk:
                        counts[byte] += 1
                    total += len(chunk)
        except OSError:
            return 0.0
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counts:
            if count:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
