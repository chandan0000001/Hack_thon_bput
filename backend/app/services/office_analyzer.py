"""Office document content analysis — OOXML/OLE inspection without execution.

OOXML (docx/docm/xlsx/xlsm/pptx/pptm) is opened as a zip: VBA project
presence, macro-enabled extensions, external relationships (hyperlinks and
OLE objects) are read straight from the package parts. Legacy OLE
(doc/xls/ppt) is scanned for VBA streams via oletools when available,
falling back to a raw-stream heuristic. Nothing is ever executed and all
content is treated as untrusted.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cyberguard.attachment.office")

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"
URL_PATTERN_STR = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
ENCRYPTION_PART = "EncryptionInfo"

MACRO_ENABLED_SUFFIXES = {".docm", ".xlsm", ".pptm"}

OOXML_VBA_PART_SUFFIX = "vbaProject.bin"

# Relationship types that pull in external/OLE content.
_OLE_OBJECT_TYPE = re.compile(r"oleObject|package", re.IGNORECASE)
_EXTERNAL_TARGET = re.compile(r"https?://", re.IGNORECASE)


class OfficeAnalyzer:
    """Macro, external-object, and URL inspection for Office documents."""

    def __init__(self, limits=None):
        if limits is None:
            from app.core import attachment_limits as limits_module

            limits = limits_module
        self._max_urls = getattr(limits, "MAX_URLS_PER_ATTACHMENT", 50)

    def analyze(self, file_path: str, mime_type: Optional[str] = None,
                original_filename: Optional[str] = None) -> dict:
        """Dispatch OOXML vs legacy OLE by content magic; never raises."""
        result: dict = {
            "engine": "office",
            "indicators": [],
            "urls_found": [],
            "risk_score": 0,
            "has_macros": False,
        }

        try:
            header = self._read_header(file_path)
        except OSError as exc:
            logger.warning("Cannot read Office document %s: %s", file_path, exc)
            return result

        if header[:4] == ZIP_MAGIC:
            self._analyze_ooxml(file_path, original_filename, result)
        elif header[:8] == OLE2_MAGIC:
            self._analyze_ole(file_path, result)
        else:
            logger.info("Office analyzer: unrecognized container for %s", file_path)

        # Macro-enabled extension check applies to both containers and uses
        # the original filename (the temp scan file is named *.scan).
        suffix = Path(original_filename or file_path).suffix.lower()
        if suffix in MACRO_ENABLED_SUFFIXES:
            result["indicators"].append(
                {"type": "macro_enabled_extension", "severity": "medium",
                 "description": f"Macro-enabled Office format ({suffix})"}
            )
            result["risk_score"] += 15

        result["urls_found"] = sorted(set(result["urls_found"]))[: self._max_urls]
        return result

    # ------------------------------------------------------------------
    # OOXML (zip package)
    # ------------------------------------------------------------------

    def _analyze_ooxml(self, file_path: str, original_filename: Optional[str], result: dict) -> None:
        try:
            with zipfile.ZipFile(file_path) as package:
                names = package.namelist()

                vba_parts = [n for n in names if n.endswith(OOXML_VBA_PART_SUFFIX)]
                if vba_parts:
                    result["has_macros"] = True
                    result["indicators"].append(
                        {"type": "office_macro_present", "severity": "high",
                         "description": f"OOXML package embeds a VBA project ({', '.join(vba_parts)})"}
                    )
                    result["risk_score"] += 30

                for rels_name in (n for n in names if n.endswith(".rels")):
                    self._scan_relationships(package, rels_name, result)
        except zipfile.BadZipFile as exc:
            result["indicators"].append(
                {"type": "office_corrupt", "severity": "medium",
                 "description": f"OOXML package unreadable: {exc}"}
            )
            result["risk_score"] += 15

    def _scan_relationships(self, package: zipfile.ZipFile, rels_name: str, result: dict) -> None:
        """Read one .rels part: external hyperlink targets and OLE objects."""
        try:
            root = ET.fromstring(package.read(rels_name))
        except Exception as exc:
            logger.debug("Cannot parse %s: %s", rels_name, exc)
            return

        for rel in root.iter():
            tag = rel.tag.rsplit("}", 1)[-1]
            if tag != "Relationship":
                continue
            target = rel.get("Target", "")
            mode = (rel.get("TargetMode") or "Internal").lower()
            rel_type = rel.get("Type", "")

            if mode == "external" and _EXTERNAL_TARGET.search(target):
                result["urls_found"].append(target)
                if _OLE_OBJECT_TYPE.search(rel_type):
                    result["indicators"].append(
                        {"type": "office_external_object", "severity": "high",
                         "description": f"External OLE/package object referenced: {target}"}
                    )
                    result["risk_score"] += 20

    # ------------------------------------------------------------------
    # Legacy OLE (doc/xls/ppt)
    # ------------------------------------------------------------------

    def _analyze_ole(self, file_path: str, result: dict) -> None:
        if self._is_encrypted_ole(file_path):
            result["indicators"].append(
                {"type": "office_encrypted", "severity": "medium",
                 "description": "Password-protected/encrypted Office document cannot be inspected"}
            )
            result["risk_score"] += 20
            return  # encrypted streams yield neither macros nor URLs

        has_macros = self._ole_has_vba(file_path)
        if has_macros:
            result["has_macros"] = True
            result["indicators"].append(
                {"type": "office_macro_present", "severity": "high",
                 "description": "Legacy OLE document contains VBA macro streams"}
            )
            result["risk_score"] += 30

        urls = self._ole_urls(file_path)
        result["urls_found"].extend(urls)

    def _is_encrypted_ole(self, file_path: str) -> bool:
        """OOXML-in-OLE encryption carries an EncryptionInfo stream."""
        try:
            with open(file_path, "rb") as f:
                haystack = f.read(65_536)
            return ENCRYPTION_PART.encode() in haystack
        except OSError:
            return False

    def _ole_has_vba(self, file_path: str) -> bool:
        """oletools when available; raw VBA-stream heuristic otherwise."""
        try:
            from oletools.olevba import VBA_Parser

            parser = VBA_Parser(file_path)
            try:
                return bool(parser.detect_vba_macros())
            finally:
                close = getattr(parser, "close", None)
                if callable(close):
                    close()
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("oletools VBA detection failed for %s: %s", file_path, exc)

        # Heuristic fallback: VBA project/storage stream name fragments.
        try:
            with open(file_path, "rb") as f:
                haystack = f.read(2_000_000)
            return b"_VBA_PROJECT" in haystack or b"\x05VBA" in haystack or b"Macros" in haystack
        except OSError:
            return False

    def _ole_urls(self, file_path: str) -> list[str]:
        try:
            with open(file_path, "rb") as f:
                haystack = f.read(2_000_000)
            return URL_PATTERN_STR.findall(haystack.decode("latin-1"))
        except OSError:
            return []

    @staticmethod
    def _read_header(file_path: str) -> bytes:
        with open(file_path, "rb") as f:
            return f.read(16)
