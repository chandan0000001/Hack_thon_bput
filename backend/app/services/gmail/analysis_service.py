"""Email analysis service for threat detection, ML inference, and result persistence."""

from __future__ import annotations

import asyncio
import copy
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.metrics import (
    email_analysis_jobs_total,
    job_processing_duration_seconds,
    processed_emails_total,
)
from app.db.models import GmailAccount, ProcessedEmail, ScanResult
from app.services.attachment_scanner import AttachmentScanner
from app.services.auth_verifier import verify_or_parse
from app.services.impersonation_detector import analyze_impersonation_heuristics
from app.services.ml_inference import (
    ml_indicator,
    predict_email,
    predict_url,
    split_ml_indicator,
)
from app.services.phishing_detector import analyze_email_heuristics
from app.services.realtime_notifier import notify_email_processed
from app.services.scoring_service import (
    SEVERITY_WEIGHTS,
    calculate_score,
    get_severity,
)
from app.services.se_pattern_engine import (
    SEPatternEngine,
    assess_confidence,
    blend_se,
)
from app.services.url_detector import analyze_url_heuristics
from app.services.verdict_builder import VerdictBuilder

logger = logging.getLogger("cyberguard.gmail.analysis")

# Attachment risk lives on the 0-100 scale; the email pipeline scores 0-1.
ATTACHMENT_RISK_SCALE = 100


async def scan_email_attachments(
    gmail_client: Any,
    access_token: Optional[str],
    refresh_token: Optional[str],
    message_id: str,
    attachments_meta: list[dict[str, Any]],
    scanner: Optional[AttachmentScanner] = None,
) -> list[dict[str, Any]]:
    """Stream-scan every pending attachment and fill scan_results in place.

    One attachment failing (network, engine crash) records scan_status
    "failed" with the error and the loop continues — an AV outage on one
    attachment must not blind the rest of the email.
    """
    scanner = scanner or AttachmentScanner()
    for attachment in attachments_meta:
        if attachment.get("scan_status") not in (None, "pending"):
            continue  # already scanned (re-analysis of a fetched email)
        if not attachment.get("attachment_id"):
            attachment["scan_status"] = "skipped"
            attachment["scan_results"] = {
                "status": "skipped",
                "risk_score": 0,
                "verdict": "safe",
                "error": "no attachment_id on the Gmail part",
            }
            continue
        try:
            scan_result = await scanner.scan_attachment(
                gmail_client,
                message_id,
                attachment["attachment_id"],
                attachment.get("filename") or "",
                attachment.get("mime_type") or "application/octet-stream",
                int(attachment.get("size_bytes") or 0),
                access_token=access_token,
                refresh_token=refresh_token,
            )
            attachment["scan_status"] = scan_result.status
            attachment["scan_results"] = {
                "status": scan_result.status,
                "risk_score": scan_result.risk_score,
                "verdict": scan_result.verdict,
                "severity": scan_result.severity,
                "indicators": scan_result.indicators,
                "sha256": scan_result.sha256,
                "detected_mime": scan_result.detected_mime,
                "scan_duration_ms": scan_result.scan_duration_ms,
                "explanation": scan_result.explanation,
            }
            if scan_result.error:
                attachment["scan_results"]["error"] = scan_result.error
        except Exception as exc:
            logger.warning(
                "Attachment scan crashed for %s/%s: %s", message_id, attachment.get("filename"), exc
            )
            attachment["scan_status"] = "failed"
            attachment["scan_results"] = {
                "status": "failed",
                "risk_score": 0,
                "verdict": "unknown",
                "error": str(exc),
            }
    return attachments_meta


def aggregate_attachment_risk(
    email_risk_100: int,
    attachments_meta: list[dict[str, Any]],
) -> tuple[int, str | None, list[dict[str, Any]]]:
    """Fold attachment risk into the email's 0-100 risk (monotonic raise-only).

    Returns (final_risk_100, override_verdict_or_None, attachment_indicators).
    The attachment channel can elevate the email's risk/verdict but never
    lower it; failed scans contribute risk 0 rather than blocking the email.
    """
    indicators: list[dict[str, Any]] = []
    final_risk = email_risk_100
    override_verdict: str | None = None

    scan_results = [
        (a.get("scan_results") or {})
        for a in (attachments_meta or [])
        if isinstance(a, dict)
    ]
    risks = [int(r.get("risk_score") or 0) for r in scan_results]
    max_attachment_risk = max(risks) if risks else 0

    if max_attachment_risk > final_risk:
        final_risk = max_attachment_risk
        override_verdict = "malicious" if max_attachment_risk >= 80 else "suspicious"

    for r in scan_results:
        for ind in r.get("indicators") or []:
            if isinstance(ind, dict) and ind.get("severity") != "info":
                indicators.append({**ind, "source": "attachment"})

    return final_risk, override_verdict, indicators


async def _load_gmail_context(
    db: AsyncSession, processed_email: ProcessedEmail
) -> tuple[Any, Optional[str], Optional[str]] | None:
    """Load the Gmail client + decrypted tokens for attachment streaming."""
    stmt = select(GmailAccount).where(GmailAccount.id == processed_email.gmail_account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()
    if account is None:
        return None
    try:
        access_token = account.get_access_token()
        refresh_token = account.get_refresh_token()
    except Exception as exc:
        logger.warning("Cannot decrypt Gmail tokens for attachment scanning: %s", exc)
        return None
    if not access_token:
        return None
    from app.services.gmail.client import GmailClient

    return GmailClient(), access_token, refresh_token


def monotonic_blend(heuristic: float, ml: Optional[float]) -> float:
    """Monotonic blend formula: final_score = max(heuristic, 0.45*heuristic + 0.55*ml).

    Ensures ML probability may elevate a heuristic verdict, but never lower it.
    """
    if ml is None:
        return round(heuristic, 3)
    blended = 0.45 * heuristic + 0.55 * ml
    return round(max(heuristic, blended), 3)


def _indicator_weight(indicator: dict[str, Any]) -> float:
    sev = str(indicator.get("severity", "")).lower()
    return float(SEVERITY_WEIGHTS.get(sev, indicator.get("weight", 0)))


def _build_explanation(
    sender: str,
    subject: str,
    risk_score: float,
    severity: str,
    text_score: float,
    url_score: float,
    impers_score: float,
    top_indicators: list[dict[str, Any]],
) -> str:
    verdicts = [
        f"phishing={text_score:.2f}",
        f"url={url_score:.2f}",
        f"impersonation={impers_score:.2f}",
    ]
    evidence = [
        f"'{i.get('description') or i.get('type')}'"
        for i in top_indicators[:4]
        if i.get("description") or i.get("type")
    ]
    evidence_str = "; ".join(evidence) if evidence else "No suspicious indicators were found."
    return (
        f"Message '{subject or '(no subject)'}' from '{sender}' was evaluated by CyberGuard threat analysis engines: "
        f"{', '.join(verdicts)}. The combined threat score is {round(risk_score * 100)}/100 ({severity}). "
        f"Strongest evidence: {evidence_str}"
    )


async def process_email_analysis(
    db: AsyncSession,
    processed_email_id: str,
    supabase_client: Optional[Any] = None,
) -> dict[str, Any]:
    """Execute threat detection pipeline, ML inference, and result persistence."""
    start_time = time.perf_counter()

    # 1. Load processed_email with row lock; verify status == 'fetched'
    stmt = (
        select(ProcessedEmail)
        .where(ProcessedEmail.id == processed_email_id)
        .with_for_update()
    )
    processed_email = (await db.execute(stmt)).scalar_one_or_none()
    if processed_email is None:
        raise ValueError(f"ProcessedEmail not found: {processed_email_id}")

    if processed_email.processing_status != "fetched":
        logger.info(
            "ProcessedEmail %s already in status '%s'; skipping analysis",
            processed_email_id,
            processed_email.processing_status,
        )
        return {
            "processed_email_id": processed_email_id,
            "status": "skipped",
            "reason": f"already_{processed_email.processing_status}",
            "risk_score": processed_email.risk_score or 0.0,
            "classification": processed_email.classification or "unknown",
            "scan_result_id": processed_email.scan_result_id,
        }

    # 2. Transition status -> 'analyzing'
    processed_email.processing_status = "analyzing"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # 3. Extract normalized email data, urls, body, headers, signals
    signals = dict(processed_email.signals or {})
    norm_email = signals.get("normalized_email") or {}
    subject = norm_email.get("subject") or processed_email.subject or ""
    sender = norm_email.get("sender") or processed_email.sender or ""
    body_text = norm_email.get("body_text") or ""
    urls: list[str] = signals.get("urls") or []
    headers: dict[str, str] = signals.get("headers") or {}
    spf = str(signals.get("spf") or "none")
    dkim = str(signals.get("dkim") or "none")
    dmarc = str(signals.get("dmarc") or "none")

    # 4. Detection Engines & 5. ML Inference
    # --- A. Phishing Analysis ---
    text_indicators = analyze_email_heuristics(sender, subject, body_text)
    heuristic_text_inds, ml_email_prob = split_ml_indicator(text_indicators)
    if ml_email_prob is None:
        ml_email_prob = predict_email("\n".join([sender, subject, body_text]))

    text_heur_score = calculate_score(heuristic_text_inds) / 100.0
    ml_email_score = ml_email_prob if ml_email_prob is not None else 0.0
    text_score = monotonic_blend(text_heur_score, ml_email_prob)

    # --- B. URL Analysis ---
    url_indicators: list[dict[str, Any]] = []
    ml_url_scores: list[float] = []
    url_scores: list[float] = []

    for url in urls:
        u_inds = analyze_url_heuristics(url)
        u_heur, u_ml = split_ml_indicator(u_inds)
        if u_ml is None:
            u_ml = predict_url(url)
        u_heur_score = calculate_score(u_heur) / 100.0
        u_ml_score = u_ml if u_ml is not None else 0.0
        u_final = monotonic_blend(u_heur_score, u_ml)

        url_indicators.extend(u_inds)
        ml_url_scores.append(u_ml_score)
        url_scores.append(u_final)

    url_score = max(url_scores) if url_scores else 0.0
    url_model = max(ml_url_scores) if ml_url_scores else 0.0

    # --- C. Impersonation Analysis ---
    claimed_identity = sender
    if "<" in sender and ">" in sender:
        claimed_identity = sender.split("<", 1)[0].strip().strip('"')
    impers_indicators = analyze_impersonation_heuristics(
        f"{subject}\n{body_text}", claimed_identity
    )
    impers_score = calculate_score(impers_indicators) / 100.0

    # --- D. Authentication Signals (SPF/DKIM/DMARC) ---
    # AUTH-VERIFY: run INDEPENDENT verification (DNS SPF, DKIM crypto, DMARC
    # policy+alignment). When verification is unavailable (offline mode, DNS
    # down, missing deps), verify_or_parse falls back to the MX-parsed
    # Authentication-Results from fetch time (source="mx_parsed") — parse-only
    # results are never presented as independently verified.
    auth_verification: Optional[dict[str, Any]] = None
    if get_settings().AUTH_VERIFY_ENABLED:
        try:
            auth_verification = await asyncio.to_thread(
                verify_or_parse,
                dict(signals),
                {"sender": sender, "headers": headers, "body_text": body_text},
            )
        except Exception as exc:
            logger.warning(
                "Auth verification crashed for processed_email %s: %s", processed_email_id, exc
            )

    auth_indicators: list[dict[str, Any]] = []
    auth_source = "parse_only"
    if auth_verification is not None:
        auth_source = str(auth_verification.get("source") or "unavailable")
        auth_indicators = list(auth_verification.get("indicators") or [])
        if auth_verification.get("explanation"):
            auth_indicators.append({
                "type": "auth_verification_note",
                "severity": "info",
                "weight": 0,
                "description": str(auth_verification["explanation"]),
            })
    else:
        # Verification disabled or crashed: keep the legacy parse-only rules.
        spf_lower = spf.lower()
        dmarc_lower = dmarc.lower()
        dkim_lower = dkim.lower()

        if "fail" in spf_lower:
            auth_indicators.append({
                "type": "spf_fail",
                "severity": "high",
                "description": f"Sender Policy Framework (SPF) check failed ({spf})",
                "weight": 15,
            })
        if "fail" in dmarc_lower:
            auth_indicators.append({
                "type": "dmarc_fail",
                "severity": "high",
                "description": f"DMARC authentication failed ({dmarc})",
                "weight": 15,
            })
        if "fail" in dkim_lower:
            auth_indicators.append({
                "type": "dkim_fail",
                "severity": "medium",
                "description": f"DKIM digital signature failed ({dkim})",
                "weight": 10,
            })

    # 6. Risk Score Aggregation & Classification
    all_heuristics = (
        heuristic_text_inds
        + [i for i in url_indicators if i.get("type") != "ml_model"]
        + impers_indicators
        + auth_indicators
    )
    combined_heur_score = calculate_score(all_heuristics) / 100.0

    # AUTH-VERIFY: the independent verification score can RAISE the heuristic
    # stage but never lower it (monotonic merge).
    if auth_verification is not None and auth_source == "independent":
        auth_risk = int(auth_verification.get("risk_score") or 0)
        if auth_risk > 0:
            combined_heur_score = max(combined_heur_score, min(1.0, auth_risk / 100.0))

    # --- E. Social-engineering pattern analysis (SE-HARDENING) --------------
    # Narrative-level detection (security-alert framing + attachment lure).
    # Merged monotonically AFTER the auth section: SE can raise the heuristic
    # stage, never lower it. SE indicators join the display summary but their
    # score contribution flows exclusively through the blend below.
    se_result: Optional[dict[str, Any]] = None
    if get_settings().SE_PATTERN_ENABLED:
        try:
            se_result = await asyncio.to_thread(SEPatternEngine().analyze, body_text, subject)
        except Exception as exc:
            logger.warning(
                "SE pattern analysis crashed for processed_email %s: %s", processed_email_id, exc
            )
    se_indicators: list[dict[str, Any]] = []
    if se_result is not None:
        se_indicators = list(se_result.get("indicators") or [])
        if int(se_result.get("risk_score") or 0) > 0:
            combined_heur_score = blend_se(
                combined_heur_score, int(se_result["risk_score"]) / 100.0
            )

    all_ml_probs: list[float] = []
    if ml_email_prob is not None:
        all_ml_probs.append(ml_email_prob)
    all_ml_probs.extend([p for p in ml_url_scores if p > 0.0])
    max_ml = max(all_ml_probs) if all_ml_probs else None

    blended_risk = monotonic_blend(combined_heur_score, max_ml)
    # Ensure individual critical engine verdicts are preserved
    risk_score = round(min(1.0, max(blended_risk, text_score, url_score, impers_score)), 3)

    # --- E. Attachment scanning (ATTACH-SCAN Phase 4) --------------------
    # Metadata was captured at fetch time (scan_status "pending"); here the
    # bytes are streamed and scanned, then folded into the email risk
    # monotonically (attachments can raise it, never lower it).
    # Deep copy is REQUIRED: the scanner mutates entries in place, and a
    # shallow copy shares dicts with the loaded attribute — SQLAlchemy would
    # then see old == new at flush and skip the UPDATE entirely.
    attachments_meta = copy.deepcopy(
        [a for a in (processed_email.attachments_meta or []) if isinstance(a, dict)]
    )
    email_risk_100 = round(risk_score * 100)
    attachment_indicators: list[dict[str, Any]] = []
    if any(a.get("scan_status") in (None, "pending") for a in attachments_meta):
        gmail_context = None
        try:
            gmail_context = await _load_gmail_context(db, processed_email)
        except Exception as exc:
            logger.warning("Gmail context unavailable for attachment scanning: %s", exc)
        if gmail_context:
            gmail_client, access_token, refresh_token = gmail_context
            try:
                attachments_meta = await scan_email_attachments(
                    gmail_client,
                    access_token,
                    refresh_token,
                    processed_email.gmail_message_id,
                    attachments_meta,
                )
                processed_email.attachments_meta = attachments_meta
            except Exception as exc:
                logger.warning("Attachment scanning failed for email %s: %s", processed_email.id, exc)

    final_risk_100, override_verdict, attachment_indicators = aggregate_attachment_risk(
        email_risk_100, attachments_meta
    )
    if final_risk_100 > email_risk_100:
        risk_score = round(min(1.0, final_risk_100 / 100.0), 3)

    if risk_score >= 0.7:
        classification = "phishing"
    elif risk_score >= 0.35:
        classification = "suspicious"
    else:
        classification = "safe"

    severity = get_severity(round(risk_score * 100))

    # 7. Build Signals Dictionary & Indicators Summary
    all_raw_indicators = (
        text_indicators + url_indicators + impers_indicators + auth_indicators + se_indicators
    )
    sorted_inds = sorted(all_raw_indicators, key=_indicator_weight, reverse=True)
    seen_keys: set[tuple[str, str]] = set()
    indicators_summary: list[dict[str, Any]] = []
    for ind in sorted_inds:
        k = (str(ind.get("type")), str(ind.get("description")))
        if k not in seen_keys:
            seen_keys.add(k)
            indicators_summary.append(ind)

    if attachment_indicators:
        indicators_summary.extend(attachment_indicators)

    top_indicators = indicators_summary[:10]

    auth_verification_summary: Optional[dict[str, Any]] = None
    if auth_verification is not None:
        auth_verification_summary = {
            "source": auth_source,
            "risk_score": int(auth_verification.get("risk_score") or 0),
            "spf": (auth_verification.get("spf") or {}).get("status"),
            "dkim": (auth_verification.get("dkim") or {}).get("status"),
            "dmarc": (auth_verification.get("dmarc") or {}).get("status"),
        }

    # SE-HARDENING D3: low-confidence labelling. Weak heuristic AND weak ML
    # downgrade confidence; a weak heuristic with no URL evidence but an
    # attachment reference is flagged for separate attachment verification.
    confidence_info = assess_confidence(
        combined_heur_score, max_ml, len(url_indicators), body_text
    )

    signals_dict = dict(signals)
    signals_dict.update({
        "text_model": round(ml_email_score, 4),
        "url_model": round(url_model, 4),
        "ml_url_scores": [round(s, 4) for s in ml_url_scores],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "auth_verification": auth_verification_summary,
        "se_patterns": {
            "engine": (se_result or {}).get("engine", "se_patterns"),
            "risk_score": int((se_result or {}).get("risk_score") or 0),
            "match_counts": (se_result or {}).get("match_counts", {}),
        },
        "confidence": confidence_info.get("confidence") or "normal",
        "impersonation": round(impers_score, 4),
        "indicators_summary": indicators_summary,
    })

    # 8. Update processed_emails record with state -> 'analyzed'
    processed_email.risk_score = risk_score
    processed_email.classification = classification
    processed_email.signals = signals_dict
    processed_email.processing_status = "analyzed"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # 9. Create scan_results row
    explanation_text = _build_explanation(
        sender=sender,
        subject=subject,
        risk_score=risk_score,
        severity=severity,
        text_score=text_score,
        url_score=url_score,
        impers_score=impers_score,
        top_indicators=top_indicators,
    )
    if confidence_info.get("notes"):
        explanation_text = (explanation_text + " " + " ".join(confidence_info["notes"])).strip()
    engine_results = {
        "phishing": {"score": text_score, "indicators": text_indicators},
        "url": {"score": url_score, "indicators": url_indicators, "urls_analyzed": len(urls)},
        "impersonation": {"score": impers_score, "indicators": impers_indicators},
        "auth": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "indicators": auth_indicators,
            "verification": auth_verification_summary,
        },
        "attachments": {
            "scanned": len(attachments_meta),
            "results": [
                {
                    "filename": a.get("filename"),
                    "scan_status": a.get("scan_status"),
                    "scan_results": a.get("scan_results"),
                }
                for a in attachments_meta
            ],
        },
    }

    scan_result = ScanResult(
        id=str(uuid.uuid4()),
        owner_user_id=processed_email.owner_user_id,
        provider_message_id=processed_email.gmail_message_id,
        verdict=classification,
        risk_score=risk_score,
        scan_details={
            "severity": severity,
            "risk_score": risk_score,
            "indicators": top_indicators,
            "explanation": explanation_text,
            "engine_results": engine_results,
        },
    )
    db.add(scan_result)
    await db.flush()

    # 10. Update processed_emails.scan_result_id and 11. transition status -> 'completed'
    # Phase 4: final explainable verdict folds in attachment signals; body
    # risk passed on the 0-100 scale; attachment scan results included.
    verdict_info = VerdictBuilder().build_explainable_verdict(
        final_risk_100, indicators_summary, attachments_meta
    )
    if override_verdict and override_verdict == "malicious":
        verdict_info["verdict"] = "malicious"
        verdict_info["severity"] = "critical"
    processed_email.verdict = verdict_info["verdict"]
    processed_email.severity = verdict_info["severity"]
    processed_email.explanation = verdict_info["explanation"]

    processed_email.scan_result_id = scan_result.id
    processed_email.processing_status = "completed"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(processed_email)

    # Trigger Realtime Notification Hook (D3)
    try:
        await notify_email_processed(db, str(processed_email.id), supabase_client=supabase_client)
    except Exception as exc:
        logger.warning("Failed triggering realtime notification for %s: %s", processed_email_id, exc)

    logger.info(
        "Email analysis completed: processed_email_id=%s, risk_score=%.3f, classification=%s, scan_result_id=%s",
        processed_email_id,
        risk_score,
        classification,
        scan_result.id,
    )

    duration = time.perf_counter() - start_time
    try:
        job_processing_duration_seconds.labels(job_type="email_analysis").observe(duration)
        email_analysis_jobs_total.labels(status="success", classification=classification).inc()
        processed_emails_total.labels(classification=classification).inc()
    except Exception:
        pass

    # 12. Return summary
    return {
        "processed_email_id": str(processed_email.id),
        "risk_score": risk_score,
        "classification": classification,
        "scan_result_id": str(scan_result.id),
        "status": "completed",
    }
