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
from app.services.archive_inspector import ArchiveInspector
from app.services.attachment_risk_scorer import AttachmentRiskScorer
from app.services.attachment_streamer import AttachmentStreamer
from app.services.attachment_text_analyzer import AttachmentTextAnalyzer
from app.services.attachment_url_extractor import AttachmentUrlExtractor
from app.services.clamav_scanner import ClamAVScanner
from app.services.executable_detector import ExecutableDetector
from app.services.file_validator import FileValidator
from app.services.office_analyzer import OfficeAnalyzer
from app.services.pdf_analyzer import PdfAnalyzer
from app.services.yara_scanner import YaraScanner

logger = logging.getLogger("cyberguard.attachment.scanner")

MALICIOUS_RISK_THRESHOLD = 80
SUSPICIOUS_RISK_THRESHOLD = 40

_VERDICT_SEVERITY = {"safe": 0, "suspicious": 1, "malicious": 2}

# URL/text channels each cap their contribution so one chatty channel
# cannot dominate the verdict (see docs/attachment_content_analysis.md).
URL_RISK_CAP = 30
URL_FLAG_WEIGHT = {"high": 10, "medium": 5}

OFFICE_MIME_TYPES = {
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-office",
}

TEXT_MIME_TYPES = {"text/plain", "text/html"}


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
    severity: str = "low"  # Phase 4: final severity band from the risk scorer
    explanation: str = ""  # Phase 4: human-readable verdict explanation


class AttachmentScanner:
    """Scans attachments level-by-level with hard resource limits."""

    def __init__(self):
        self.streamer = AttachmentStreamer()
        self.validator = FileValidator()
        # Phase 2 malware-detection engines — all optional/graceful:
        # ClamAV reports unavailable without a clamd daemon, YARA without a
        # ruleset; the archive and executable engines are stdlib/pefile-based.
        self.clamav = ClamAVScanner()
        self.yara = YaraScanner()
        self.executable = ExecutableDetector()
        self.archive = ArchiveInspector()
        self.pdf = PdfAnalyzer()
        self.office = OfficeAnalyzer()
        self.url_extractor = AttachmentUrlExtractor()
        self.text = AttachmentTextAnalyzer()
        self.risk_scorer = AttachmentRiskScorer()

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

            if temp_path:
                result = await self._level2_malware_detection(
                    temp_path=temp_path,
                    detected_mime=result.detected_mime or "",
                    declared_mime=declared_mime,
                    filename=filename,
                    result=result,
                )
                result = await self._level3_content_analysis(
                    temp_path=temp_path,
                    detected_mime=result.detected_mime or "",
                    filename=filename,
                    result=result,
                )

            # Level 4 (sandbox detonation) lands in Phase 5.

            # Phase 4: final verdict/severity/explanation from the risk scorer
            # (the scorer's forced-malicious checks subsume the Level-2
            # overrides; a result's verdict never gets downgraded here).
            scored = self.risk_scorer.score(result.indicators, total_risk=result.risk_score)
            result.risk_score = scored["risk_score"]
            if _VERDICT_SEVERITY.get(scored["verdict"], 0) >= _VERDICT_SEVERITY.get(result.verdict, 0):
                result.verdict = scored["verdict"]
            result.severity = scored["severity"]
            result.explanation = scored["explanation"]

            result.scan_duration_ms = int((time.monotonic() - start) * 1000)
            result.status = "completed"
            return result
        except AttachmentTooLargeError as exc:
            return ScanResult(
                status="failed",
                verdict="malicious",
                risk_score=100,
                severity="critical",
                indicators=[{"type": "oversized_file", "severity": "critical"}],
                declared_mime=declared_mime,
                error=str(exc),
                explanation="Attachment rejected: exceeds the 25 MB size limit (treated as malicious).",
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

    async def _level2_malware_detection(
        self,
        temp_path: str,
        detected_mime: str,
        declared_mime: str,
        filename: str,
        result: ScanResult,
    ) -> ScanResult:
        """Run the malware engines over the temp file and merge their signals.

        Every engine is individually try/except guarded: one engine failing
        (missing daemon, bad rule, parse crash) records an info indicator and
        never aborts the scan.
        """
        clamav_infected = False
        executable_disguised = False

        # --- ClamAV -----------------------------------------------------
        try:
            clamav = self.clamav.scan_file(temp_path)
            if clamav["status"] == "infected":
                clamav_infected = True
                result.indicators.append(
                    {
                        "type": "clamav_signature",
                        "severity": "critical",
                        "description": f"ClamAV signature hit: {clamav['signature']}",
                    }
                )
                result.risk_score += clamav["risk_score"]
            elif clamav["status"] in ("error", "unavailable"):
                result.indicators.append(
                    {
                        "type": "engine_unavailable" if clamav["status"] == "unavailable" else "engine_error",
                        "engine": "clamav",
                        "severity": "info",
                        "description": f"ClamAV {clamav['status']}; scan continued without AV verdict",
                    }
                )
        except Exception as exc:
            self._record_engine_failure(result, "clamav", exc)

        # --- YARA -------------------------------------------------------
        try:
            yara = self.yara.scan_file(temp_path)
            if yara["available"] and yara["matches"]:
                for match in yara["matches"]:
                    result.indicators.append(
                        {
                            "type": "yara_match",
                            "severity": "medium",
                            "rule": match["rule"],
                            "description": f"YARA rule {match['rule']} matched: {match['description']}",
                        }
                    )
                result.risk_score += yara["risk_score"]
            elif not yara["available"]:
                result.indicators.append(
                    {"type": "engine_unavailable", "engine": "yara", "severity": "info"}
                )
        except Exception as exc:
            self._record_engine_failure(result, "yara", exc)

        # --- Executable detection ----------------------------------------
        try:
            executable = self.executable.detect(temp_path, declared_mime=declared_mime, original_filename=filename)
            if executable["is_executable"]:
                result.indicators.extend(executable["indicators"])
                result.risk_score += executable["risk_score"]
                executable_disguised = any(
                    i.get("type") == "executable_disguise" for i in executable["indicators"]
                )
        except Exception as exc:
            self._record_engine_failure(result, "executable", exc)

        # --- Archive inspection -------------------------------------------
        try:
            archive = await self.archive.inspect(temp_path)
            if archive["is_archive"]:
                result.indicators.extend(archive["indicators"])
                result.risk_score += archive["risk_score"]
        except Exception as exc:
            self._record_engine_failure(result, "archive", exc)

        # --- Verdict ------------------------------------------------------
        if clamav_infected or executable_disguised:
            result.verdict = "malicious"
        else:
            result.verdict = self._verdict_for_risk(result.risk_score)
        return result

    @staticmethod
    def _verdict_for_risk(risk_score: int) -> str:
        if risk_score >= MALICIOUS_RISK_THRESHOLD:
            return "malicious"
        if risk_score >= SUSPICIOUS_RISK_THRESHOLD:
            return "suspicious"
        return "safe"

    async def _level3_content_analysis(
        self,
        temp_path: str,
        detected_mime: str,
        filename: str,
        result: ScanResult,
    ) -> ScanResult:
        """Content analysis: PDF/Office structure, URL hand-off, text phishing.

        Like Level 2, every sub-engine is individually try/except guarded —
        a failure records an info indicator and the scan continues.
        """
        # --- Document structure analysis (PDF / Office) -------------------
        urls_found: list[str] = []
        structure_engine = "pdf" if detected_mime == "application/pdf" else "office"
        structure_analysis: Optional[dict] = None
        try:
            if detected_mime == "application/pdf":
                structure_analysis = self.pdf.analyze(temp_path, mime_type=detected_mime)
            elif detected_mime in OFFICE_MIME_TYPES:
                structure_analysis = self.office.analyze(
                    temp_path, mime_type=detected_mime, original_filename=filename
                )
            if structure_analysis:
                result.indicators.extend(structure_analysis["indicators"])
                result.risk_score += structure_analysis["risk_score"]
                urls_found.extend(structure_analysis.get("urls_found", []))
        except Exception as exc:
            self._record_engine_failure(result, structure_engine, exc)

        # --- Raw text for text/html attachments (structure engines above
        # already harvested their URLs) ------------------------------------
        text_analysis: Optional[dict] = None
        try:
            if detected_mime in TEXT_MIME_TYPES:
                text = self.text.extract_text(temp_path, detected_mime)
                text_analysis = self.text.analyze(text)
                result.indicators.extend(text_analysis["indicators"])
                result.risk_score += text_analysis["risk_score"]
                urls_found.extend(self.url_extractor.extract_from_text(text))
        except Exception as exc:
            self._record_engine_failure(result, "text", exc)

        # --- URL hand-off to the existing url engine -----------------------
        try:
            if urls_found:
                handoff = self.url_extractor.hand_off(urls_found)
                url_risk = 0
                for entry in handoff:
                    if not entry.get("flagged"):
                        continue
                    weight = URL_FLAG_WEIGHT["high"] if entry["existing_risk"] >= 25 else URL_FLAG_WEIGHT["medium"]
                    if url_risk + weight > URL_RISK_CAP:
                        weight = max(0, URL_RISK_CAP - url_risk)
                    url_risk += weight
                    result.indicators.append(
                        {
                            "type": "attachment_url_flagged",
                            "severity": "high" if entry["existing_risk"] >= 25 else "medium",
                            "url": entry["url"],
                            "existing_risk": entry["existing_risk"],
                            "description": f"URL flagged by the shared url engine "
                            f"(risk {entry['existing_risk']}): {entry['url']}",
                        }
                    )
                    if url_risk >= URL_RISK_CAP:
                        break
                result.risk_score += url_risk
        except Exception as exc:
            self._record_engine_failure(result, "url", exc)

        # --- Verdict: never downgrade a forced Level-2 verdict -------------
        computed = self._verdict_for_risk(result.risk_score)
        if _VERDICT_SEVERITY[computed] > _VERDICT_SEVERITY[result.verdict]:
            result.verdict = computed
        return result

    @staticmethod
    def _record_engine_failure(result: ScanResult, engine: str, exc: Exception) -> None:
        logger.warning("Malware engine '%s' failed during scan: %s", engine, exc)
        result.indicators.append(
            {
                "type": "engine_error",
                "engine": engine,
                "severity": "info",
                "description": f"Engine '{engine}' failed: {exc}",
            }
        )
