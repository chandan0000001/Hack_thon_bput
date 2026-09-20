"""URL extraction from attachments and hand-off to the EXISTING url engine.

This module deliberately does NOT re-implement URL scoring: every URL found
in an attachment is handed to `app.services.url_detector.analyze_url_heuristics`
(the same engine that scores URLs in email bodies), and its indicators are
weighted with `scoring_service.calculate_score`. One URL code path, one
verdict vocabulary.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Optional

from app.core.attachment_limits import MAX_URLS_PER_ATTACHMENT
from app.services import url_detector as url_engine
from app.services.pdf_analyzer import PdfAnalyzer
from app.services.office_analyzer import OfficeAnalyzer
from app.services.scoring_service import calculate_score

logger = logging.getLogger("cyberguard.attachment.urls")

URL_PATTERN_STR = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)

TEXT_READ_CAP = 2_000_000


class AttachmentUrlExtractor:
    """Extracts URLs from attachments; scoring stays in the url engine."""

    def __init__(self, limits=None):
        if limits is None:
            from app.core import attachment_limits as limits_module

            limits = limits_module
        self._max_urls = getattr(limits, "MAX_URLS_PER_ATTACHMENT", MAX_URLS_PER_ATTACHMENT)

    def extract_from_text(self, text: str) -> list[str]:
        """Pull URLs from text after deobfuscating common lure encodings."""
        if not text:
            return []
        deobfuscated = self._deobfuscate(text)
        urls = URL_PATTERN_STR.findall(deobfuscated)
        normalized = []
        for url in urls:
            # One decode pass catches %2F-style obfuscation of the path.
            candidate = url.rstrip(".,;:!?")
            try:
                candidate = urllib.parse.unquote(candidate)
            except Exception:
                pass
            if candidate not in normalized:
                normalized.append(candidate)
        return normalized[: self._max_urls]

    def extract_from_file(self, file_path: str, mime: str,
                          original_filename: Optional[str] = None) -> list[str]:
        """Extract URLs by container type: raw text/html, analyzers for pdf/office."""
        mime = (mime or "").lower().split(";")[0].strip()
        if mime in ("text/plain", "text/html"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(TEXT_READ_CAP)
            except OSError as exc:
                logger.warning("Cannot read %s for URL extraction: %s", file_path, exc)
                return []
            return self.extract_from_text(text)
        if mime == "application/pdf":
            return PdfAnalyzer().analyze(file_path, mime_type=mime)["urls_found"]
        if self._is_office_mime(mime):
            return OfficeAnalyzer().analyze(file_path, mime_type=mime,
                                            original_filename=original_filename)["urls_found"]
        return []

    def hand_off(self, urls: list[str]) -> list[dict]:
        """Score each URL with the EXISTING url heuristics engine.

        Returns one {url, existing_risk, flagged, indicator_count} entry per
        URL. Engine failure on a single URL never aborts the batch.
        """
        results: list[dict] = []
        for url in urls[: self._max_urls]:
            try:
                indicators = url_engine.analyze_url_heuristics(url)
                risk = calculate_score(indicators)
                results.append(
                    {
                        "url": url,
                        "existing_risk": risk,
                        "flagged": risk > 0,
                        "indicator_count": len(indicators),
                    }
                )
            except Exception as exc:
                logger.warning("URL engine failed for %s: %s", url, exc)
                results.append({"url": url, "existing_risk": 0, "flagged": False, "error": str(exc)})
        return results

    @staticmethod
    def _deobfuscate(text: str) -> str:
        """Undo common lure encodings: hxxp, [.], (.) — one pass, conservatively."""
        text = re.sub(r"h(?:tt)?xxps?", lambda m: m.group(0).lower().replace("xx", "tt"), text,
                      flags=re.IGNORECASE)
        text = text.replace("[.]", ".").replace("(.)", ".")
        return text

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
