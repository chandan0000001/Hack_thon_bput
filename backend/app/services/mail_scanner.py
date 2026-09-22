"""Mail scanning pipeline (Phase 3 — analysis only).

Routes a provider-neutral NormalizedMessage through the existing detection
engines (phishing, URL, impersonation), aggregates scores with the shared
scoring service, and produces a verbose, structured ScanResult.

Phase boundary: this service NEVER performs provider write operations. Any
recommended enforcement action is reported honestly as
``provider_operation_status = "deferred_to_phase_4"``.
"""

import inspect
import logging
import re
from collections.abc import Iterable

from app.schemas.email import NormalizedMessage
from app.schemas.scan_results import (
    OPERATION_DEFERRED,
    OPERATION_NONE_REQUIRED,
    FeatureAnalysis,
    Indicator,
    ScanResult,
)
from app.services.domain_intelligence import live_enrich_url
from app.services.impersonation_detector import analyze_impersonation_heuristics
from app.services.ml_inference import blend_scores, split_ml_indicator
from app.services.phishing_detector import analyze_email_heuristics
from app.services.scoring_service import SEVERITY_WEIGHTS, calculate_score, get_severity
from app.services.url_detector import analyze_url_heuristics

logger = logging.getLogger("cyberguard.mail_scanner")

_URL_PATTERN = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
_HTML_HREF_PATTERN = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)

_MAX_URLS_PER_MESSAGE = 10
_MAX_BODY_CHARS = 20000

_ENGINES_RUN = "Engines run"


def _indicator_weight(indicator: dict) -> float:
    return float(SEVERITY_WEIGHTS.get(str(indicator.get("severity", "")).lower(), 0))


def _map_indicators(indicators: Iterable[dict]) -> list[Indicator]:
    return [
        Indicator(
            name=str(i.get("type") or "indicator"),
            value=str(i.get("value") or i.get("description") or ""),
            weight=_indicator_weight(i),
        )
        for i in indicators
    ]


def _engine_score(indicators: list[dict]) -> int:
    """Engine verdict score: heuristic weight-sum blended with the engine's
    ML probability via the monotonic blend (identical to the shipped
    routes_analysis path: ML may raise, never lower the heuristic verdict)."""
    heuristic_indicators, ml_probability = split_ml_indicator(indicators)
    heuristic_score = calculate_score(heuristic_indicators)
    if ml_probability is not None:
        return blend_scores(heuristic_score, ml_probability)
    return heuristic_score


def _feature_analysis(engine: str, indicators: list[dict], explanation: str) -> tuple[FeatureAnalysis, list[dict]]:
    score = _engine_score(indicators)
    return (
        FeatureAnalysis(
            engine=engine,
            severity=get_severity(score),
            score=round(score / 100, 2),
            explanation=explanation,
            indicators=_map_indicators(indicators),
        ),
        indicators,
    )


def _verbose_indicator_summary(indicators: list[dict], limit: int = 6) -> str:
    if not indicators:
        return "No suspicious indicators were found by this engine."
    lines = [
        f"- {i.get('description', i.get('type', 'indicator'))}"
        + (f" (matched: '{i['value']}')" if i.get("value") else "")
        for i in indicators[:limit]
    ]
    if len(indicators) > limit:
        lines.append(f"- … and {len(indicators) - limit} more indicator(s).")
    return "\n".join(lines)


def _extract_urls(message: NormalizedMessage) -> list[str]:
    """Collect unique URLs from body text, HTML hrefs, and plain body text."""
    candidates: list[str] = []
    for source in (message.body_text or "", message.body_html or ""):
        candidates.extend(_HTML_HREF_PATTERN.findall(source))
        candidates.extend(_URL_PATTERN.findall(source))
    seen: set[str] = set()
    urls: list[str] = []
    for url in candidates:
        url = url.rstrip(").,;:'\"!?")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:_MAX_URLS_PER_MESSAGE]


def _strip_quoted_email(body: str) -> str:
    """Trim long quoted reply chains so quoted noise doesn't dominate."""
    if not body:
        return ""
    quoted = body.find("\n>")
    if quoted > 0 and quoted < len(body) // 2:
        return body[:quoted]
    return body


def _phishing_analysis(message: NormalizedMessage) -> tuple[FeatureAnalysis, list[dict]]:
    body = _strip_quoted_email((message.body_text or "")[:_MAX_BODY_CHARS])
    indicators = analyze_email_heuristics(message.sender, message.subject, body)
    explanation = (
        f"The phishing engine inspected the sender '{message.sender}', the subject "
        f"'{message.subject}', and the message body.\n"
        + _verbose_indicator_summary(indicators)
    )
    return _feature_analysis("phishing_detector", indicators, explanation)


async def _url_analysis(message: NormalizedMessage) -> tuple[FeatureAnalysis, list[dict]]:
    urls = _extract_urls(message)
    if not urls:
        return (
            FeatureAnalysis(
                engine="url_detector",
                severity="safe",
                score=0.0,
                explanation="No URLs were found in the message body, so URL forensics had nothing to analyze.",
                indicators=[],
            ),
            [],
        )

    all_indicators: list[dict] = []
    per_url_notes: list[str] = []
    for url in urls:
        indicators = analyze_url_heuristics(url)
        # Firecrawl live enrichment (optional; additive heuristics-side indicators).
        indicators = await live_enrich_url(url, indicators)
        all_indicators.extend(indicators)
        if indicators:
            per_url_notes.append(f"URL '{url}' raised {len(indicators)} indicator(s):\n" + _verbose_indicator_summary(indicators, limit=4))
        else:
            per_url_notes.append(f"URL '{url}' looked structurally normal to the URL forensics engine.")

    score = calculate_score(all_indicators)
    explanation = (
        f"{len(urls)} URL(s) were extracted from the message and analyzed.\n"
        + "\n".join(per_url_notes)
    )
    return _feature_analysis("url_detector", all_indicators, explanation)


def _impersonation_analysis(message: NormalizedMessage) -> tuple[FeatureAnalysis, list[dict]]:
    body = _strip_quoted_email((message.body_text or "")[:_MAX_BODY_CHARS])
    # Claimed identity: display-name portion of the From header if present
    # (e.g. "PayPal Support <billing@evil.test>" → "PayPal Support").
    claimed_identity = message.sender
    if "<" in message.sender and ">" in message.sender:
        claimed_identity = message.sender.split("<", 1)[0].strip().strip('"')
    indicators = analyze_impersonation_heuristics(
        f"{message.subject}\n{body}", claimed_identity
    )
    explanation = (
        f"The impersonation engine checked whether '{claimed_identity or message.sender}' "
        "shows authority claims, pressure tactics, unusual requests, or secrecy demands.\n"
        + _verbose_indicator_summary(indicators)
    )
    return _feature_analysis("impersonation_detector", indicators, explanation)


def _attachment_analysis(message: NormalizedMessage) -> FeatureAnalysis | None:
    media = [a for a in message.attachments_meta if a.get("is_media")]
    if not media:
        return None
    names = ", ".join(a.get("filename", "unnamed") for a in media)
    return FeatureAnalysis(
        engine="deepfake_media",
        severity="safe",
        score=0.0,
        explanation=(
            f"{len(media)} media attachment(s) present ({names}). Media forensics "
            "requires downloading the binary attachment content, which is out of "
            "scope for this scan — no deepfake verdict is issued (honest skip, "
            "not a clean bill of health)."
        ),
        indicators=[],
    )


def _recommendation(overall_severity: str) -> str:
    if overall_severity in ("critical", "high"):
        return "quarantine"
    if overall_severity == "medium":
        return "flag_for_review"
    return "none"


def _overall_explanation(message: NormalizedMessage, analyses: list[FeatureAnalysis], score: int, severity: str) -> str:
    verdicts = "; ".join(f"{a.engine}={a.severity} ({a.score:.2f})" for a in analyses)
    top = sorted(
        (i for a in analyses for i in a.indicators), key=lambda i: i.weight, reverse=True
    )[:4]
    evidence = "; ".join(f"'{i.value or i.name}'" for i in top if i.value or i.name)
    return (
        f"Message '{message.subject or '(no subject)'}' from '{message.sender}' was analyzed by "
        f"{len(analyses)} engine(s): {verdicts}. The combined risk score is {score}/100 "
        f"({severity}), derived from the weighted severity of every indicator "
        "(critical 25 / high 15 / medium 5, capped at 100)."
        + (f" Strongest evidence: {evidence}." if evidence else " No strong evidence was found.")
    )


async def scan_message(message: NormalizedMessage) -> ScanResult:
    """Run the detection pipeline over one normalized message.

    Deterministic and analysis-only: the same message always yields the same
    verdict, and no provider write operation is ever attempted here.
    """
    analyses: list[FeatureAnalysis] = []
    raw_indicators: list[dict] = []
    for build in (_phishing_analysis, _url_analysis, _impersonation_analysis):
        result = build(message)
        # _url_analysis is async (Firecrawl live enrichment); the rest are sync.
        analysis, indicators = await result if inspect.isawaitable(result) else result
        analyses.append(analysis)
        raw_indicators.extend(indicators)
    attachment_analysis = _attachment_analysis(message)
    if attachment_analysis is not None:
        analyses.append(attachment_analysis)

    overall_score = calculate_score(raw_indicators)
    overall_severity = get_severity(overall_score)
    recommended_action = _recommendation(overall_severity)

    if recommended_action == "none":
        provider_operation_status = OPERATION_NONE_REQUIRED
        provider_operation_detail = "No provider action required for this verdict."
    else:
        provider_operation_status = OPERATION_DEFERRED
        provider_operation_detail = (
            f"Analysis succeeded; '{recommended_action}' requires Gmail write access "
            "and is implemented in Phase 4 (quarantine & sender rules). "
            "No action was performed on the mailbox yet."
        )

    return ScanResult(
        message_id=message.provider_message_id,
        provider=message.provider,
        sender=message.sender,
        subject=message.subject,
        received_at=message.received_at.isoformat() if message.received_at else None,
        overall_severity=overall_severity,
        overall_score=round(overall_score / 100, 2),
        overall_explanation=_overall_explanation(
            message, analyses, overall_score, overall_severity
        ),
        feature_analyses=analyses,
        recommended_action=recommended_action,
        provider_operation_status=provider_operation_status,
        provider_operation_detail=provider_operation_detail,
    )
