"""PDF content analysis — structural inspection without execution.

Read-only: pypdf parses the document; raw keyword scans cover the byte
stream so nothing hides from a parser quirk, and URLs are harvested from
annotations, URI actions, and visible text. No JavaScript is ever
evaluated, no embedded files are ever opened.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from app.core.attachment_limits import MAX_PAGES_IN_PDF, MAX_URLS_PER_ATTACHMENT

logger = logging.getLogger("cyberguard.attachment.pdf")

PDF_MAGIC = b"%PDF-"
RAW_SCAN_CHUNK = 65_536
RAW_SCAN_OVERLAP = 64  # keywords can straddle chunk boundaries

_RAW_JS = re.compile(rb"/JavaScript|/JS[\s\(<]")
_RAW_EMBEDDED = re.compile(rb"/EmbeddedFile")
_RAW_AUTO_ACTION = re.compile(rb"/OpenAction|/Launch|/AA[\s\(<]")
_URL_PATTERN = re.compile(rb"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_URL_PATTERN_STR = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


class PdfAnalyzer:
    """Structural PDF analysis (JavaScript/embeds/auto-actions/URLs)."""

    def __init__(self, limits=None):
        if limits is None:
            from app.core import attachment_limits as limits_module

            limits = limits_module
        self._max_pages = getattr(limits, "MAX_PAGES_IN_PDF", MAX_PAGES_IN_PDF)
        self._max_urls = getattr(limits, "MAX_URLS_PER_ATTACHMENT", MAX_URLS_PER_ATTACHMENT)

    def analyze(self, file_path: str, mime_type: Optional[str] = None) -> dict:
        """Analyze a PDF; never raises (corrupt docs become an indicator)."""
        result: dict = {
            "engine": "pdf",
            "indicators": [],
            "urls_found": [],
            "risk_score": 0,
            "page_count": 0,
        }

        effective_mime = mime_type or self._detect_mime(file_path)
        if effective_mime != "application/pdf":
            return result

        raw = self._raw_scan(file_path)
        if raw is None:
            return result

        # --- Raw structural keyword scan (parser-independent) -----------
        if raw["javascript"]:
            result["indicators"].append(
                {"type": "pdf_javascript", "severity": "high",
                 "description": "PDF contains JavaScript (/JavaScript or /JS)"}
            )
            result["risk_score"] += 25
        if raw["embedded"]:
            result["indicators"].append(
                {"type": "pdf_embedded_file", "severity": "medium",
                 "description": "PDF embeds file objects (/EmbeddedFile)"}
            )
            result["risk_score"] += 20
        if raw["auto_action"]:
            result["indicators"].append(
                {"type": "pdf_auto_action", "severity": "high",
                 "description": "PDF triggers automatic actions (/OpenAction, /AA or /Launch)"}
            )
            result["risk_score"] += 25

        urls = {u.decode("latin-1") for u in raw["urls"]}

        # --- Structured parse via pypdf (read-only) ----------------------
        page_count, text_urls, annot_urls = self._structured_scan(file_path, result)
        result["page_count"] = page_count
        if page_count > self._max_pages:
            result["indicators"].append(
                {"type": "pdf_excessive_pages", "severity": "low",
                 "description": f"PDF has {page_count} pages (processing capped at {self._max_pages})"}
            )
            result["risk_score"] += 10

        urls.update(text_urls)
        urls.update(annot_urls)
        result["urls_found"] = sorted(urls)[: self._max_urls]
        return result

    def _detect_mime(self, file_path: str) -> Optional[str]:
        try:
            with open(file_path, "rb") as f:
                return "application/pdf" if f.read(5) == PDF_MAGIC else None
        except OSError:
            return None

    def _raw_scan(self, file_path: str) -> Optional[dict]:
        """Chunk-wise scan of the raw byte stream for keywords and URLs."""
        try:
            javascript = embedded = auto_action = False
            urls: set[bytes] = set()
            tail = b""
            with open(file_path, "rb") as f:
                while chunk := f.read(RAW_SCAN_CHUNK):
                    window = tail + chunk
                    javascript = javascript or bool(_RAW_JS.search(window))
                    embedded = embedded or bool(_RAW_EMBEDDED.search(window))
                    auto_action = auto_action or bool(_RAW_AUTO_ACTION.search(window))
                    urls.update(_URL_PATTERN.findall(window))
                    tail = window[-RAW_SCAN_OVERLAP:]
            return {"javascript": javascript, "embedded": embedded, "auto_action": auto_action, "urls": urls}
        except OSError as exc:
            logger.warning("Cannot read PDF for raw scan %s: %s", file_path, exc)
            return None

    def _structured_scan(self, file_path: str, result: dict) -> tuple[int, set, set]:
        """pypdf pass: page count, visible-text URLs, annotation URI URLs.

        Returns (page_count, text_urls, annot_urls). A corrupt/unparseable
        document adds the pdf_corrupt indicator instead of raising.
        """
        text_urls: set[str] = set()
        annot_urls: set[str] = set()
        try:
            try:
                from pypdf import PdfReader
            except ImportError:  # pragma: no cover - pypdf is a declared dep
                from PyPDF2 import PdfReader

            reader = PdfReader(file_path, strict=False)
            page_count = len(reader.pages)

            for page in reader.pages[: self._max_pages]:
                try:
                    text = page.extract_text() or ""
                    text_urls.update(_URL_PATTERN_STR.findall(text))
                except Exception:
                    continue  # one bad page must not sink the analysis
                try:
                    for annot_ref in page.get("/Annots") or []:
                        annot = annot_ref.get_object()
                        action = annot.get("/A")
                        if action is not None:
                            action = action.get_object()
                            if str(action.get("/S")) == "/URI" and action.get("/URI"):
                                annot_urls.add(str(action["/URI"]))
                        elif annot.get("/URI"):
                            annot_urls.add(str(annot["/URI"]))
                except Exception:
                    continue
            return page_count, text_urls, annot_urls
        except Exception as exc:
            logger.info("PDF structured parse failed for %s: %s", file_path, exc)
            result["indicators"].append(
                {"type": "pdf_corrupt", "severity": "medium",
                 "description": f"PDF structure unparseable (possible obfuscation): {exc}"}
            )
            result["risk_score"] += 15
            return 0, text_urls, annot_urls
