"""Text extraction and phishing analysis for scanned attachments.

Extracts visible text from pdf/office/html/txt attachments (capped) and runs
the EXISTING phishing vocabulary from `app.services.phishing_detector`
(urgency keywords, credential-request phrases, threat language, financial
vocabulary) — no duplicated keyword lists. The text channel's total risk
contribution is capped so a page-long rant cannot dominate the verdict.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Optional

from app.core.attachment_limits import MAX_PAGES_IN_PDF, MAX_TEXT_EXTRACT_CHARS
from app.services.phishing_detector import (
    CREDENTIAL_REQUEST_PHRASES,
    FINANCIAL_VOCABULARY,
    THREAT_LANGUAGE_PHRASES,
    URGENCY_KEYWORDS,
)

logger = logging.getLogger("cyberguard.attachment.text")

HTML_READ_CAP_BYTES = 2_000_000

_TAG_STRIP = re.compile(r"<[^>]+>")
_XML_TEXT_NODE = re.compile(r">([^<>]+)<")
_WHITESPACE = re.compile(r"\s+")

TEXT_RISK_CAP = 30
CREDENTIAL_WEIGHT = 10
KEYWORD_WEIGHT = 5

_HTML_TAG_STRIP_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)


class AttachmentTextAnalyzer:
    """Extracts attachment text and scores it with shared phishing vocabulary."""

    def __init__(self, limits=None):
        if limits is None:
            from app.core import attachment_limits as limits_module

            limits = limits_module
        self._max_chars = getattr(limits, "MAX_TEXT_EXTRACT_CHARS", MAX_TEXT_EXTRACT_CHARS)
        self._max_pdf_pages = getattr(limits, "MAX_PAGES_IN_PDF", MAX_PAGES_IN_PDF)

    def extract_text(self, file_path: str, mime: str) -> str:
        """Extract visible text capped at MAX_TEXT_EXTRACT_CHARS."""
        mime = (mime or "").lower().split(";")[0].strip()
        try:
            if mime == "application/pdf":
                return self._extract_pdf_text(file_path)
            if mime == "text/html":
                return self._extract_html_text(file_path)
            if mime == "text/plain":
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(self._max_chars)
            if self._is_office_mime(mime):
                return self._extract_office_text(file_path)
        except Exception as exc:
            logger.info("Text extraction failed for %s (%s): %s", file_path, mime, exc)
        return ""

    def analyze(self, text: str) -> dict:
        """Run shared phishing vocabulary over extracted text."""
        indicators: list[dict] = []
        risk_score = 0

        if text:
            lowered = text.lower()

            for phrase in CREDENTIAL_REQUEST_PHRASES:
                if phrase in lowered:
                    indicators.append(
                        {"type": "attachment_credential_request", "severity": "medium",
                         "description": f"Credential-request phrase in attachment text: '{phrase}'"}
                    )
                    risk_score += CREDENTIAL_WEIGHT

            for keyword in URGENCY_KEYWORDS:
                if keyword in lowered:
                    indicators.append(
                        {"type": "attachment_urgency", "severity": "low",
                         "description": f"Urgency keyword in attachment text: '{keyword}'"}
                    )
                    risk_score += KEYWORD_WEIGHT

            for phrase in THREAT_LANGUAGE_PHRASES:
                if phrase in lowered:
                    indicators.append(
                        {"type": "attachment_threat_language", "severity": "medium",
                         "description": f"Threat language in attachment text: '{phrase}'"}
                    )
                    risk_score += KEYWORD_WEIGHT

            for phrase in FINANCIAL_VOCABULARY:
                if phrase in lowered:
                    indicators.append(
                        {"type": "attachment_financial", "severity": "low",
                         "description": f"Financial keyword in attachment text: '{phrase}'"}
                    )
                    risk_score += KEYWORD_WEIGHT

        risk_score = min(risk_score, TEXT_RISK_CAP)
        return {
            "engine": "text",
            "indicators": indicators,
            "risk_score": risk_score,
            "char_count": len(text),
        }

    # ------------------------------------------------------------------
    # Extraction backends
    # ------------------------------------------------------------------

    def _extract_pdf_text(self, file_path: str) -> str:
        try:
            from pypdf import PdfReader
        except ImportError:  # pragma: no cover - pypdf is a declared dep
            from PyPDF2 import PdfReader

        reader = PdfReader(file_path, strict=False)
        chunks = []
        total = 0
        for page in reader.pages[: self._max_pdf_pages]:
            if total >= self._max_chars:
                break
            try:
                chunk = page.extract_text() or ""
            except Exception:
                continue
            chunks.append(chunk)
            total += len(chunk)
        return ("".join(chunks))[: self._max_chars]

    def _extract_html_text(self, file_path: str) -> str:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read(HTML_READ_CAP_BYTES)
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(raw, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            text = soup.get_text(separator=" ")
        except ImportError:
            raw = _HTML_TAG_STRIP_RE.sub(" ", raw)
            text = _TAG_STRIP.sub(" ", raw)
        return _WHITESPACE.sub(" ", text).strip()[: self._max_chars]

    def _extract_office_text(self, file_path: str) -> str:
        """Concatenate text from the main XML parts of an OOXML package."""
        chunks = []
        total = 0
        with zipfile.ZipFile(file_path) as package:
            for name in package.namelist():
                if total >= self._max_chars:
                    break
                if not name.endswith(".xml"):
                    continue
                if not any(part in name for part in ("word/", "xl/", "ppt/", "sharedStrings")):
                    continue
                try:
                    root = ET.fromstring(package.read(name))
                except Exception:
                    continue
                text = " ".join(node.text or "" for node in root.iter() if node.text)
                chunks.append(text)
                total += len(text)
        return _WHITESPACE.sub(" ", " ".join(chunks)).strip()[: self._max_chars]

    @staticmethod
    def _is_office_mime(mime: str) -> bool:
        return mime in {
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-office",
        }
