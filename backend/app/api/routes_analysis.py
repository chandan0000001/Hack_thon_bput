"""Analysis pipeline endpoints using Async SQLAlchemy and OpenRouter XAI."""

import asyncio
import difflib
import hashlib
import uuid
from typing import Any, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Header, Query, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from app.ai.openrouter_client import (
    call_openrouter,
    generate_heuristic_explanation,
    generate_heuristic_fallback_explanation,
)
from app.ai.prompt_templates import (
    ACCOUNT_TAKEOVER_SYSTEM_PROMPT,
    DEEPFAKE_SYSTEM_PROMPT,
    IMPERSONATION_SYSTEM_PROMPT,
    NETWORK_THREAT_SYSTEM_PROMPT,
    PHISHING_SYSTEM_PROMPT,
    URL_SYSTEM_PROMPT,
    format_account_takeover_user_prompt,
    format_deepfake_user_prompt,
    format_impersonation_user_prompt,
    format_network_user_prompt,
    format_phishing_user_prompt,
    format_url_user_prompt,
)
from app.core.errors import NotFoundError, PermissionDeniedError, UnauthorizedError, ValidationError
from app.core.security import (
    TenantContext,
    get_current_user,
    get_tenant_context,
    require_role,
    tenant_criteria,
)
from app.core.storage import (
    MAX_MEDIA_SIZE_BYTES,
    download_media,
    upload_media_to_supabase,
)
from app.db.models import Alert, Event, MediaFile, OrgOrganization, OrgProject, VerifiedIdentity
from app.db.session import async_session_maker, get_db, set_session_user
from app.schemas.alerts import AlertResponse
from app.services.account_takeover_detector import analyze_auth_log_heuristics
from app.services.ato_detector import AccountTakeoverDetector, classify_enforcement
from app.services.alert_service import create_alert
from app.core.config import get_settings
from app.services import auth_verifier
from app.services.deepfake_detector import analyze_media
from app.services.impersonation_detector import analyze_impersonation_heuristics
from app.services.domain_intelligence import live_enrich_url
from app.services.ml_inference import score_with_ml, url_model_artifact
from app.queue.client import get_queue
from app.services.network_threat_detector import analyze_network_heuristics
from app.services.phishing_detector import analyze_email_heuristics
from app.services.scoring_service import calculate_score, get_severity, get_url_decision
from app.services.attachment_scanner import AttachmentScanner
from app.services.se_pattern_engine import (
    ATTACHMENT_REFERENCE_WARNING,
    SEPatternEngine,
    assess_confidence,
    blend_se,
    references_attachment,
)
from app.services.url_detector import analyze_url_heuristics

logger = logging.getLogger("cyberguard.security")

router = APIRouter(prefix="/analysis", tags=["Analysis"])

ANALYSIS_MEDIA_CONTENT_TYPE_PREFIXES = ("image/", "video/", "audio/")
ANALYSIS_MEDIA_SOURCE = "media_upload"


class EmailAnalysisRequest(BaseModel):
    source: str = Field(default="api", min_length=1)
    sender: str = Field(min_length=1)
    subject: str
    body: str
    # AUTH-VERIFY: optional raw SMTP header block. Manual/paste scans carry no
    # SMTP headers, so SPF/DKIM/DMARC can only be verified when the caller
    # supplies them; absence yields an info indicator + response warning,
    # never an auth pass.
    raw_headers: Optional[str] = None
    target_user: Optional[str] = None


class UrlAnalysisRequest(BaseModel):
    source: str = Field(default="api", min_length=1)
    url: str = Field(min_length=1)
    target_user: Optional[str] = None


class UrlVisualAnalysisRequest(BaseModel):
    """Cascaded Stage-1 + Stage-2 request (visual brand verification)."""

    url: str = Field(min_length=1)
    screenshot: str = Field(min_length=1, description="base64 PNG/JPEG (data: URL prefix tolerated)")
    source: str = Field(default="extension", min_length=1)


class ImpersonationAnalysisRequest(BaseModel):
    source: str = Field(default="api", min_length=1)
    message: str
    claimed_identity: str = Field(min_length=1)


class AccountTakeoverAnalysisRequest(BaseModel):
    source: str = Field(default="api", min_length=1)
    # Legacy personal-workspace flow: authentication-log records run through
    # analyze_auth_log_heuristics + the shared analysis pipeline.
    events: list[dict[str, Any]] = []
    # SCENARIO-3 org-scoped fusion flow: baseline vs abnormal activity
    # timeline. Its presence selects the org flow; organization scope is
    # resolved server-side from the credential, never from this body.
    account_id: Optional[str] = Field(default=None, max_length=255)
    baseline_profile: Optional[dict[str, Any]] = None
    suspicious_events: Optional[list[dict[str, Any]]] = None


class NetworkAnalysisRequest(BaseModel):
    source: str = Field(default="api", min_length=1)
    flows: list[dict[str, Any]] = []
    api_logs: list[dict[str, Any]] = []


async def _create_analysis_event(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    created_by: str,
    event_type: str,
    source: str,
    raw_data: dict[str, Any],
) -> str:
    """Insert a new event with status 'analyzing' and return its id."""
    event_id = str(uuid.uuid4())
    event = Event(
        id=event_id,
        organization_id=tenant.organization_id,
        project_id=tenant.project_id,
        owner_user_id=tenant.owner_user_id,
        event_type=str(event_type)[:64],
        source=str(source)[:64],
        raw_data=raw_data,
        status="analyzing",
        created_by=str(created_by)[:64] if created_by else None,
    )
    db.add(event)
    await db.commit()
    return event_id


async def _bg_generate_explanation(
    alert_id: str,
    system_prompt: str,
    user_prompt: str,
    module: str,
    indicators: list[dict],
    raw_data: dict[str, Any],
    risk_score: int,
    auth_warnings: Optional[list[str]] = None,
    extra_notes: Optional[list[str]] = None,
    timeout: float = 15.0,
    *,
    user_id: Optional[str] = None,
) -> None:
    """Asynchronously generate LLM explanation and attach it to the persisted Alert.

    Wraps OpenRouter/LLM in asyncio.wait_for(timeout=15.0). On timeout or failure, invokes
    generate_heuristic_fallback_explanation and persists the fallback explanation to DB.
    """
    print(f"[bg_explanation] Task started for alert_id={alert_id}, module={module}")
    logger.info("Background explanation task started for alert %s", alert_id)
    explanation: Optional[str] = None
    mitre_techniques: Optional[list[Any]] = None
    try:
        try:
            llm_output = await asyncio.wait_for(
                call_openrouter(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    module=module,
                    indicators=indicators,
                    raw_data=raw_data,
                    risk_score=risk_score,
                ),
                timeout=timeout,
            )
            if llm_output and isinstance(llm_output, dict):
                explanation = llm_output.get("explanation")
                mitre_techniques = llm_output.get("mitre_techniques")
                if explanation:
                    print(f"[bg_explanation] LLM success for alert_id={alert_id}")
                    logger.info("LLM explanation succeeded for alert %s", alert_id)
        except (asyncio.TimeoutError, TimeoutError):
            print(f"[bg_explanation] LLM timed out after {timeout:.1f}s for alert_id={alert_id}; using heuristic fallback")
            logger.warning(
                "LLM explanation timed out after %.1fs for alert %s; using heuristic fallback",
                timeout,
                alert_id,
            )
        except Exception as llm_err:
            print(f"[bg_explanation] LLM call failed for alert_id={alert_id}: {llm_err}; using heuristic fallback")
            logger.warning(
                "LLM explanation failed for alert %s: %s; using heuristic fallback",
                alert_id,
                llm_err,
            )

        if not explanation:
            print(f"[bg_explanation] Generating heuristic fallback explanation for alert_id={alert_id}")
            fast_meta = generate_heuristic_explanation(
                module=module,
                indicators=indicators,
                raw_data=raw_data,
                risk_score=risk_score,
            )
            mitre_techniques = mitre_techniques or fast_meta.get("mitre_techniques", [])
            recommended_actions = fast_meta.get("recommended_actions", [])
            explanation = generate_heuristic_fallback_explanation(
                score=risk_score,
                indicators=indicators,
                mitre_tags=mitre_techniques,
                recommended_actions=recommended_actions,
                module=module,
            )
            print(f"[bg_explanation] Heuristic fallback generated for alert_id={alert_id}")

        if explanation:
            if auth_warnings:
                explanation = (explanation + " " + " ".join(auth_warnings)).strip()
            if extra_notes:
                explanation = (explanation + " " + " ".join(extra_notes)).strip()

            print(f"[bg_explanation] Opening DB session to save explanation for alert_id={alert_id}")
            async with async_session_maker() as session:
                if user_id:
                    await set_session_user(session, user_id)
                res = await session.execute(select(Alert).where(Alert.id == alert_id))
                db_alert = res.scalar_one_or_none()
                if db_alert:
                    db_alert.explanation = explanation
                    if mitre_techniques:
                        db_alert.mitre = mitre_techniques
                    await session.commit()
                    print(f"[bg_explanation] Successfully saved explanation to DB for alert_id={alert_id}")
                    logger.info("Saved explanation to DB for alert %s", alert_id)
                else:
                    print(f"[bg_explanation] ERROR: Alert {alert_id} not found in DB!")
                    logger.error("Alert %s not found in DB during background explanation update", alert_id)
    except (asyncio.CancelledError, RuntimeError):
        pass
    except Exception as exc:
        print(f"[bg_explanation] Fatal error for alert_id={alert_id}: {exc}")
        logger.error("Background LLM explanation failed for alert %s: %s", alert_id, exc)


async def _run_analysis_pipeline(
    db: AsyncSession,
    tenant: TenantContext,
    *,
    event_type: str,
    module: str,
    source: str,
    raw_data: dict[str, Any],
    indicators: list[dict],
    system_prompt: str,
    user_prompt_builder: Any,
    min_score: int = 0,
    auth_warnings: Optional[list[str]] = None,
    extra_notes: Optional[list[str]] = None,
) -> Any:
    """Shared async detection pipeline: persist event, score, alert immediately with explanation=None, explain in bg."""
    event_id = await _create_analysis_event(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_type=event_type,
        source=source,
        raw_data=raw_data,
    )

    # Hybrid engine: heuristic + ML blend. The URL module applies the
    # confidence-floor policy (blend_scores_url) so a high model probability
    # cannot be masked by lexically clean URLs.
    _heuristic_score, hybrid_score, _ml_probability = score_with_ml(indicators, policy=module)
    hybrid_score = max(int(hybrid_score), int(min_score))
    severity = get_severity(hybrid_score)

    calculated_confidence: Optional[float] = None
    if _ml_probability is not None and 0.0 <= _ml_probability <= 1.0:
        # Distance from 0.5 decision boundary: model confidence in its classification
        calculated_confidence = round(max(_ml_probability, 1.0 - _ml_probability), 2)
    elif hybrid_score is not None:
        # Baseline confidence from distance to ambiguity midpoint 50
        calculated_confidence = round(0.50 + abs(hybrid_score - 50) / 100.0, 2)

    fast_meta = generate_heuristic_explanation(
        module=module,
        indicators=indicators,
        raw_data=raw_data,
        risk_score=hybrid_score,
    )

    llm_output = {
        "explanation": None,
        "mitre_techniques": fast_meta.get("mitre_techniques", []),
        "recommended_actions": fast_meta.get("recommended_actions", []),
    }

    alert = await create_alert(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_id=event_id,
        module=module,
        raw_data=raw_data,
        indicators=indicators,
        score=hybrid_score,
        severity=severity,
        llm_output=llm_output,
        confidence=calculated_confidence,
    )

    if callable(user_prompt_builder):
        user_prompt = user_prompt_builder(raw_data, indicators, hybrid_score, severity)
    else:
        user_prompt = str(user_prompt_builder)

    asyncio.create_task(
        _bg_generate_explanation(
            alert_id=alert.id,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            module=module,
            indicators=indicators,
            raw_data=raw_data,
            risk_score=hybrid_score,
            auth_warnings=auth_warnings,
            extra_notes=extra_notes,
            user_id=tenant.user_id,
        )
    )

    return alert


@router.post("/email", response_model=AlertResponse)
async def analyze_email(
    payload: EmailAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full phishing analysis pipeline for an email."""
    raw_data = payload.model_dump(mode="json")
    indicators = await asyncio.to_thread(
        analyze_email_heuristics,
        sender=payload.sender,
        subject=payload.subject,
        body=payload.body,
    )

    # AUTH-VERIFY (manual path): verify SPF/DKIM/DMARC only when raw_headers
    # were supplied; absence is flagged, never treated as pass.
    auth_warnings: list[str] = []
    min_score = 0
    if get_settings().AUTH_VERIFY_ENABLED:
        try:
            auth_section = await asyncio.to_thread(
                auth_verifier.manual_auth_section,
                payload.sender,
                payload.body,
                payload.raw_headers,
            )
            indicators.extend(auth_section["indicators"])
            auth_warnings = auth_section["warnings"]
            verification = auth_section["verification"]
            raw_data["auth_verification"] = {
                "source": verification.get("source"),
                "risk_score": int(verification.get("risk_score") or 0),
                "spf": (verification.get("spf") or {}).get("status"),
                "dkim": (verification.get("dkim") or {}).get("status"),
                "dmarc": (verification.get("dmarc") or {}).get("status"),
            }
            if verification.get("source") == "independent":
                min_score = int(verification.get("risk_score") or 0)
        except Exception as exc:
            logger.warning("Manual-path auth verification failed: %s", exc)

    # SE-HARDENING (manual path): social-engineering narrative patterns. The
    # SE blend is applied to the pre-SE heuristic so SE contributes through
    # the formula exactly once; indicators join the list for display.
    se_result: Optional[dict[str, Any]] = None
    if get_settings().SE_PATTERN_ENABLED:
        try:
            se_result = await asyncio.to_thread(
                SEPatternEngine().analyze, payload.body, payload.subject
            )
            if int(se_result.get("risk_score") or 0) > 0:
                h100 = calculate_score(indicators)
                min_score = max(
                    min_score,
                    int(round(blend_se(h100 / 100.0, int(se_result["risk_score"]) / 100.0) * 100)),
                )
            indicators.extend(
                {**i, "source": "se_patterns"} for i in se_result.get("indicators") or []
            )
            raw_data["se_patterns"] = {
                "engine": se_result.get("engine"),
                "risk_score": int(se_result.get("risk_score") or 0),
            }
        except Exception as exc:
            logger.warning("Manual-path SE pattern analysis failed: %s", exc)

    # SE-HARDENING D4: the manual path can see that the message references
    # attachments but never scans attachment content — warn in the SAME
    # warnings array as the auth warnings, without duplicates.
    if references_attachment(payload.body) and ATTACHMENT_REFERENCE_WARNING not in auth_warnings:
        auth_warnings.append(ATTACHMENT_REFERENCE_WARNING)

    extra_notes: list[str] = []
    try:
        h100, _hybrid, ml_prob = score_with_ml(indicators)
        url_indicator_count = sum(
            1 for i in indicators if "url" in str(i.get("type", "")).lower()
        )
        conf = assess_confidence(h100 / 100.0, ml_prob, url_indicator_count, payload.body)
        if conf.get("notes"):
            extra_notes = conf["notes"]
    except Exception as exc:
        logger.warning("Manual-path confidence assessment failed: %s", exc)

    alert = await _run_analysis_pipeline(
        db,
        tenant,
        event_type="phishing_email",
        module="phishing",
        source=payload.source,
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=PHISHING_SYSTEM_PROMPT,
        user_prompt_builder=format_phishing_user_prompt,
        min_score=min_score,
        auth_warnings=auth_warnings,
        extra_notes=extra_notes,
    )

    if auth_warnings:
        alert.summary = ((alert.summary or "") + " " + auth_warnings[0]).strip()[:250]
        await db.commit()

    response = AlertResponse.model_validate(alert)
    # AUTH-VERIFY: raw_data is not part of AlertResponse, so surface the
    # compact per-protocol statuses explicitly for the frontend Auth panel.
    response.auth_verification = raw_data.get("auth_verification")
    if auth_warnings:
        response.warnings = auth_warnings
    return response


@router.post("/email-attachment", response_model=AlertResponse)
async def analyze_email_with_attachment(
    sender: str = Form(...),
    subject: str = Form(default=""),
    body: str = Form(...),
    file: Optional[UploadFile] = File(default=None),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Phishing pipeline for an email with an optional uploaded attachment.

    Runs the standard email heuristics, scans the attachment through the
    ATTACH-SCAN Level 1-3 pipeline, and merges the attachment's indicators
    into the email verdict. Only scan metadata is ever persisted.
    """
    indicators = await asyncio.to_thread(
        analyze_email_heuristics,
        sender=sender,
        subject=subject,
        body=body,
    )

    attachment_summary: Optional[dict[str, Any]] = None
    if file is not None and file.filename:
        scanner = AttachmentScanner()
        scan_result = await scanner.scan_uploaded_file(
            file,
            file.filename,
            file.content_type or "application/octet-stream",
        )
        for ind in scan_result.indicators:
            if isinstance(ind, dict) and ind.get("severity") != "info":
                indicators.append({**ind, "source": "attachment"})
        if scan_result.verdict == "malicious":
            indicators.append(
                {
                    "type": "attachment_malicious_verdict",
                    "severity": "critical",
                    "description": scan_result.explanation
                    or f"Attachment '{file.filename}' scanned as malicious",
                    "source": "attachment",
                }
            )
        attachment_summary = {
            "filename": file.filename,
            "size_bytes": file.size,
            "scan_status": scan_result.status,
            "verdict": scan_result.verdict,
            "risk_score": scan_result.risk_score,
            "severity": scan_result.severity,
            "sha256": scan_result.sha256,
            "detected_mime": scan_result.detected_mime,
            "declared_mime": scan_result.declared_mime,
            "mime_mismatch": scan_result.mime_mismatch,
            "scan_duration_ms": scan_result.scan_duration_ms,
            "explanation": scan_result.explanation,
            "error": scan_result.error,
        }

    raw_data = {
        "source": "api",
        "sender": sender,
        "subject": subject,
        "body": body,
        "attachment": attachment_summary,
    }
    return await _run_analysis_pipeline(
        db,
        tenant,
        event_type="phishing_email",
        module="phishing",
        source="api",
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=PHISHING_SYSTEM_PROMPT,
        user_prompt_builder=format_phishing_user_prompt,
    )


@router.post("/url", response_model=AlertResponse)
async def analyze_url(
    payload: UrlAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full malicious URL analysis pipeline for a single URL.

    Both entry points (web dashboard manual input and browser extension) hit
    this one endpoint and therefore the same engine. The raw and normalized
    URL pair is stored as evidence; detection runs on the normalized form.
    """
    from app.core.rate_limit import get_url_analysis_limiter
    from app.core.url_normalization import normalization_pair

    if not get_url_analysis_limiter().allow(tenant.user_id):
        raise HTTPException(status_code=429, detail="URL analysis rate limit exceeded; slow down")

    normalized = normalization_pair(payload.url)
    if not normalized["normalized_url"] and not normalized["url"]:
        raise HTTPException(status_code=422, detail="unparseable url")
    analysis_url = normalized["normalized_url"] or normalized["url"]

    raw_data = payload.model_dump(mode="json")
    raw_data.update(normalized)
    indicators = await asyncio.to_thread(analyze_url_heuristics, analysis_url)
    # Firecrawl live enrichment (optional; additive heuristics-side indicators).
    indicators = await live_enrich_url(analysis_url, indicators)
    return await _run_analysis_pipeline(
        db,
        tenant,
        event_type="malicious_url",
        module="url",
        source=payload.source,
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=URL_SYSTEM_PROMPT,
        user_prompt_builder=lambda data, ind, score, sev: format_url_user_prompt(payload.url, ind, score, sev),
    )


@router.post("/url/visual")
async def analyze_url_visual(
    payload: UrlVisualAnalysisRequest,
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Cascaded URL analysis — Stage 1 inline, Stage 2 (Phishpedia) on the worker.

    Stage 1 (lexical XGBoost + heuristics) runs inline and is returned
    immediately. When Stage 1 is suspicious, the screenshot is handed to the
    visual worker (heavy CV stays off the API process); the fused
    SAFE/WARN/REVIEW/BLOCK verdict is polled via GET /analysis/url/visual/{job_id}.
    Verdicts are cached in Redis with a TTL keyed on the registrable domain so
    repeated navigation to the same attacker domain never re-runs vision.
    """
    from app.core.url_reputation import get_registrable_domain
    from app.services.evidence_fusion import stage2_required
    from app.workers.visual_worker import visual_verdict_cache_key

    from app.core.rate_limit import get_url_analysis_limiter

    if not get_url_analysis_limiter().allow(tenant.user_id):
        raise HTTPException(status_code=429, detail="URL analysis rate limit exceeded; slow down")

    url = payload.url.strip()
    # Stage 1 inline (fast path — heuristics + XGBoost, URL confidence floor).
    indicators = await asyncio.to_thread(analyze_url_heuristics, url)
    heuristic_score, _hybrid, ml_probability = score_with_ml(indicators, policy="url")
    stage1_summary = {
        "heuristic_score": heuristic_score,
        "hybrid_score": _hybrid,
        "ml_probability": ml_probability,
        "severity": get_severity(_hybrid),
        "model_version": url_model_artifact(),
        **get_url_decision(get_severity(_hybrid), ml_probability),
    }

    # Domain-TTL cache: a verdict for this registrable domain already exists.
    try:
        queue = await get_queue()
        import json as _json

        cached_raw = await queue.pool.get(visual_verdict_cache_key(url))
        if cached_raw:
            cached = _json.loads(cached_raw)
            cached["stage1"] = stage1_summary
            cached["cache"] = "domain_ttl_hit"
            return cached
    except Exception:
        queue = None  # redis unavailable: proceed uncached

    if not stage2_required(ml_probability):
        return {
            "url": url,
            "stage1": stage1_summary,
            "stage2": None,
            "fusion": {
                "decision": "safe" if ml_probability is not None and ml_probability < 0.5 else "warn",
                "reasons": [f"Stage-1 probability {ml_probability} below visual-verification threshold"],
            },
            "cache": None,
        }

    if queue is None:
        queue = await get_queue()
    screenshot_hash = hashlib.sha1(payload.screenshot[:4096].encode("utf-8", "ignore")).hexdigest()[:16]
    job_id = f"visual_phish:{get_registrable_domain(url)}:{screenshot_hash}"
    job = await queue.enqueue_job(
        "visual_phish_check",
        url,
        payload.screenshot,
        _job_id=job_id,
    )
    return {
        "url": url,
        "stage1": stage1_summary,
        "stage2": "queued",
        "job_id": job_id,
        "poll": f"/analysis/url/visual/{job_id}",
        "queued": job is not None,
    }


@router.get("/url/visual/{job_id}")
async def get_url_visual_result(
    job_id: str,
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Poll a queued Stage-2 visual verification job."""
    from arq.jobs import Job as ArqJob

    queue = await get_queue()
    job = ArqJob(job_id, redis=queue.pool)
    try:
        result = await job.result(timeout=0.5)
    except Exception:
        info = await queue.job_info(job_id)
        return {"job_id": job_id, "status": "running" if info else "unknown", "result": None}
    return {"job_id": job_id, "status": "done", "result": result}


@router.post("/impersonation", response_model=AlertResponse)
async def analyze_impersonation(
    payload: ImpersonationAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full digital impersonation analysis pipeline for a message."""
    raw_data = payload.model_dump(mode="json")
    indicators = await asyncio.to_thread(
        analyze_impersonation_heuristics,
        message=payload.message,
        claimed_identity=payload.claimed_identity,
    )
    return await _run_analysis_pipeline(
        db,
        tenant,
        event_type="impersonation_message",
        module="impersonation",
        source=payload.source,
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=IMPERSONATION_SYSTEM_PROMPT,
        user_prompt_builder=format_impersonation_user_prompt,
    )


@router.post("/identity-fraud", response_model=AlertResponse)
async def analyze_identity_fraud(
    payload: ImpersonationAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full digital identity fraud / impersonation analysis pipeline."""
    return await analyze_impersonation(payload, db=db, tenant=tenant)


# SCENARIO-3: The /account-takeover path serves two flows behind one auth
# dependency. An org API key (cg_org_...) or a JWT selects the tenant
# SERVER-SIDE (key row / membership check) — the request body never carries
# an organization_id. A payload with baseline_profile/suspicious_events runs
# the strictly org-scoped ATO fusion engine; legacy {events} payloads keep
# the personal auth-log pipeline unchanged.
async def require_account_takeover_auth(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_organization_id: Optional[str] = Header(None, alias="X-Organization-Id"),
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """Resolve the tenant from a Supabase JWT or an org API key."""
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("Missing bearer credentials")

    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("Empty bearer token")

    # Path A: organization API key (cg_org_...), same validation path as the
    # project gateway / Scenario 2 (cyberguard.validate_org_api_key).
    if token.startswith("cg_org_"):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        res = await db.execute(
            text(
                "SELECT key_id, project_id, organization_id, role, owner_user_id, status "
                "FROM cyberguard.validate_org_api_key(:h)"
            ),
            {"h": token_hash},
        )
        key_row = res.mappings().first()
        if not key_row or key_row["status"] != "active":
            raise UnauthorizedError("Invalid or inactive API key")
        if key_row["role"] == "viewer":
            raise PermissionDeniedError("Viewer keys cannot perform account-takeover analysis")

        # Stamp the RLS identity before any tenant-scoped query runs.
        await set_session_user(db, str(key_row["owner_user_id"]))
        try:
            await db.execute(
                text("UPDATE cyberguard.org_api_keys SET last_used_at = now() WHERE id = :kid"),
                {"kid": str(key_row["key_id"])},
            )
            await db.commit()
        except Exception:  # noqa: BLE001 - usage stamping must never fail auth
            await db.rollback()

        organization = (
            await db.execute(
                select(OrgOrganization).where(OrgOrganization.id == str(key_row["organization_id"]))
            )
        ).scalar_one_or_none()
        project = (
            await db.execute(select(OrgProject).where(OrgProject.id == str(key_row["project_id"])))
        ).scalar_one_or_none()

        return TenantContext(
            user_id=str(key_row["owner_user_id"]),
            owner_user_id=str(key_row["owner_user_id"]),
            organization_id=str(key_row["organization_id"]),
            organization_name=organization.name if organization else "Organization",
            role="admin" if key_row["role"] == "master" else str(key_row["role"]),
            is_single_user=False,
            project_id=str(key_row["project_id"]) if key_row["project_id"] else None,
        )

    # Path B: Supabase JWT through the standard tenant resolution. The
    # X-Organization-Id header is forwarded explicitly (membership-validated
    # inside get_tenant_context); defaults must never be passed implicitly —
    # direct calls would leak FastAPI's Header marker objects into queries.
    user = await get_current_user(
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
        db=db,
    )
    tenant = await get_tenant_context(
        user=user, db=db, x_organization_id=x_organization_id, org_id=None
    )
    if tenant.role == "viewer":
        raise PermissionDeniedError("Role does not have permission for account-takeover analysis")
    return tenant


@router.post("/account-takeover")
async def analyze_account_takeover(
    payload: AccountTakeoverAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_account_takeover_auth),
) -> Any:
    """Account-takeover analysis.

    - Org flow (baseline_profile/suspicious_events present): strictly
      organization-scoped 3-signal fusion (rules + anomaly + threat intel).
      Fails closed when the credential carries no organization context.
    - Legacy flow ({events}): authentication-log heuristics pipeline.
    """
    if payload.suspicious_events is not None or payload.baseline_profile is not None:
        if not tenant.organization_id:
            # Fail closed: the ATO fusion flow is org-only by design and must
            # never fall back to a personal workspace.
            raise PermissionDeniedError(
                "Account-takeover analysis requires an organization context"
            )

        # JWT path: stamp the user's active project when it belongs to the
        # resolved organization (org API keys already carry project_id from
        # the key row).
        if tenant.project_id is None:
            from app.db.models import User

            user_row = (
                await db.execute(select(User).where(User.id == tenant.user_id))
            ).scalar_one_or_none()
            active_project_id = getattr(user_row, "active_project_id", None)
            if active_project_id:
                belongs = (
                    await db.execute(
                        select(OrgProject.id).where(
                            OrgProject.id == active_project_id,
                            OrgProject.organization_id == tenant.organization_id,
                        )
                    )
                ).scalar_one_or_none()
                if belongs:
                    tenant.project_id = str(belongs)

        result = AccountTakeoverDetector().analyze(
            payload.baseline_profile, payload.suspicious_events or []
        )
        score = int(result["risk_score"])
        indicators = [
            {**i, "source": "ato_detector"} for i in result["indicators"]
        ]
        account = (payload.account_id or "unknown account").strip()

        # ATO-UI-OVERHAUL: strict 3-tier enforcement decided by the fused
        # score (SAFE<30 ALLOWED / MEDIUM USER_NOTIFIED / CRITICAL
        # ACCOUNT_RESTRICTED+USER_NOTIFIED). The account "lock" and the
        # notification are mocks recorded in the persisted metadata — no
        # real mailbox/session side effects leave this service.
        enforcement = classify_enforcement(score)
        if enforcement["notified"]:
            logger.info(
                "[mock] ATO USER_NOTIFIED: account=%s org=%s score=%d",
                account,
                tenant.organization_id,
                score,
            )
        if enforcement["account_restricted"]:
            logger.info(
                "[mock] ATO ACCOUNT_RESTRICTED: account=%s org=%s score=%d",
                account,
                tenant.organization_id,
                score,
            )

        event_id = await _create_analysis_event(
            db,
            tenant=tenant,
            created_by=tenant.user_id,
            event_type="account_takeover",
            source="ato_org_api",
            raw_data={
                "account_id": payload.account_id,
                "baseline_profile": payload.baseline_profile,
                "suspicious_events": payload.suspicious_events,
                "source": payload.source,
                "enforcement": enforcement,
            },
        )

        explanation = (
            f"Account-takeover analysis for '{account}': {result['risk_level'].upper()} "
            f"risk ({score}/100) from {len(result['indicators'])} fused indicators "
            f"(rules, anomaly vs baseline, threat intel). Verdict "
            f"{result['verdict']}."
        )
        alert = await create_alert(
            db,
            tenant=tenant,
            created_by=tenant.user_id,
            event_id=event_id,
            module="account_takeover",
            raw_data={
                "subject": f"Account takeover risk: {account}",
                "account_id": payload.account_id,
                "target_user": payload.account_id,
                "enforcement": enforcement,
            },
            indicators=indicators,
            score=score,
            severity=get_severity(score),
            llm_output={
                "explanation": explanation,
                "summary": explanation[:250],
                "recommended_actions": [
                    {"action": action} for action in result["recommended_actions"]
                ],
            },
        )

        return {
            "verdict": result["verdict"],
            "risk_level": result["risk_level"],
            "risk_score": score,
            "account_id": payload.account_id,
            "enforcement": enforcement,
            "action_taken": enforcement["action_taken"],
            "indicators": indicators,
            "suspicious_events": result["timeline"],
            "recommended_actions": result["recommended_actions"],
            "threat_intel": result["threat_intel"],
            "explanation": explanation,
            "organization": {
                "id": tenant.organization_id,
                "name": tenant.organization_name,
            },
            "project": {"id": tenant.project_id} if tenant.project_id else None,
            "event_id": event_id,
            "alert_id": alert.id,
        }

    # Legacy personal/org auth-log pipeline (unchanged contract). The shared
    # pipeline returns the raw Alert ORM row — the route previously converted
    # it via response_model=AlertResponse, so validate explicitly here.
    indicators = await asyncio.to_thread(analyze_auth_log_heuristics, payload.events)
    alert = await _run_analysis_pipeline(
        db,
        tenant,
        event_type="account_takeover",
        module="account_takeover",
        source=payload.source,
        raw_data=payload.model_dump(mode="json", exclude={"baseline_profile", "suspicious_events"}),
        indicators=indicators,
        system_prompt=ACCOUNT_TAKEOVER_SYSTEM_PROMPT,
        user_prompt_builder=lambda data, ind, score, sev: format_account_takeover_user_prompt(payload.events, ind, score, sev),
    )
    return AlertResponse.model_validate(alert)


def _require_org_tenant(tenant: TenantContext) -> None:
    """The ATO event list/detail views are org-scoped by design."""
    if not tenant.organization_id:
        raise PermissionDeniedError(
            "Account-takeover analysis requires an organization context"
        )


@router.get("/account-takeover/events")
async def list_account_takeover_events(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_account_takeover_auth),
) -> dict:
    """Recent org-flow ATO events for the authenticated org/project.

    Summaries only (id, timestamp, user_email, risk_score, action_taken);
    the organization/project scope comes from the credential, never a query
    parameter, so one tenant cannot list another's events.
    """
    _require_org_tenant(tenant)
    conditions = [
        tenant_criteria(Event, tenant),
        Event.event_type == "account_takeover",
        Event.source == "ato_org_api",
    ]
    if tenant.project_id:
        conditions.append(Event.project_id == tenant.project_id)
    rows = (
        await db.execute(
            select(Event, Alert)
            .join(Alert, Alert.event_id == Event.id)
            .where(*conditions)
            .order_by(Event.created_at.desc())
            .limit(limit)
        )
    ).all()

    events = []
    for event, alert in rows:
        raw = event.raw_data or {}
        score = int(alert.risk_score or 0)
        stored = raw.get("enforcement") or {}
        # Rows written before enforcement metadata existed are classified on
        # read from the score — single source of truth either way.
        enforcement = stored if stored.get("action_taken") else classify_enforcement(score)
        events.append(
            {
                "id": str(event.id),
                "timestamp": event.created_at,
                "user_email": raw.get("account_id") or alert.target_user or "unknown",
                "risk_score": score,
                "action_taken": enforcement.get("action_taken"),
                "tier": enforcement.get("tier"),
                "severity": alert.severity,
                "account_restricted": bool(enforcement.get("account_restricted")),
            }
        )
    return {"events": events, "count": len(events)}


@router.get("/account-takeover/events/{event_id}")
async def get_account_takeover_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_account_takeover_auth),
) -> dict:
    """Read-only detail view payload for one org-flow ATO event.

    The annotated timeline is recomputed deterministically from the stored
    baseline + suspicious events; the persisted Alert remains the authority
    for risk score and explanation. Cross-tenant ids 404, never leak.
    """
    _require_org_tenant(tenant)
    event = (
        await db.execute(
            select(Event).where(tenant_criteria(Event, tenant), Event.id == event_id)
        )
    ).scalar_one_or_none()
    if event is None or event.event_type != "account_takeover" or event.source != "ato_org_api":
        raise NotFoundError("Event", event_id)

    alert = (
        await db.execute(
            select(Alert).where(tenant_criteria(Alert, tenant), Alert.event_id == event_id)
        )
    ).scalar_one_or_none()

    raw = event.raw_data or {}
    result = AccountTakeoverDetector().analyze(
        raw.get("baseline_profile"), raw.get("suspicious_events") or []
    )
    score = int(alert.risk_score) if alert is not None else int(result["risk_score"])
    stored = raw.get("enforcement") or {}
    enforcement = stored if stored.get("action_taken") else classify_enforcement(score)

    return {
        "event_id": str(event.id),
        "alert_id": str(alert.id) if alert is not None else None,
        "account_id": raw.get("account_id"),
        "created_at": event.created_at,
        "risk_score": score,
        "risk_level": result["risk_level"],
        "enforcement": enforcement,
        "action_taken": enforcement.get("action_taken"),
        "baseline_profile": raw.get("baseline_profile") or {},
        "suspicious_events": result["timeline"],
        "indicators": (alert.indicators if alert is not None else None)
        or [{**i, "source": "ato_detector"} for i in result["indicators"]],
        "recommended_actions": result["recommended_actions"],
        "explanation": alert.explanation if alert is not None else None,
        "organization": {
            "id": tenant.organization_id,
            "name": tenant.organization_name,
        },
        "project": {"id": tenant.project_id} if tenant.project_id else None,
    }


@router.post("/network", response_model=AlertResponse)
async def analyze_network(
    payload: NetworkAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full network/API abuse analysis pipeline for flows and API logs."""
    raw_data = payload.model_dump(mode="json")
    indicators = await asyncio.to_thread(
        analyze_network_heuristics,
        flows=payload.flows,
        api_logs=payload.api_logs,
    )
    module = "network" if payload.flows else "api_abuse"
    return await _run_analysis_pipeline(
        db,
        tenant,
        event_type=module,
        module=module,
        source=payload.source,
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=NETWORK_THREAT_SYSTEM_PROMPT,
        user_prompt_builder=lambda data, ind, score, sev: format_network_user_prompt(payload.flows, payload.api_logs, ind, score, sev),
    )


@router.post("/media")
async def analyze_media_upload(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Full deepfake/media-forensics pipeline for an uploaded media file."""
    content_type = file.content_type or ""
    if not content_type.startswith(ANALYSIS_MEDIA_CONTENT_TYPE_PREFIXES):
        raise ValidationError("File must be an image, video, or audio upload")

    file.file.seek(0, 2)
    size_bytes = file.file.tell()
    file.file.seek(0)
    if size_bytes > MAX_MEDIA_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds maximum allowed size of 25 MB",
        )
    file_bytes = file.file.read()
    file_name = file.filename or "upload.bin"
    file.file.seek(0)

    event_id = str(uuid.uuid4())
    event = Event(
        id=event_id,
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        event_type="deepfake_media",
        source=ANALYSIS_MEDIA_SOURCE,
        raw_data={
            "file_name": file_name,
            "content_type": content_type,
            "size_bytes": size_bytes,
        },
        status="analyzing",
        created_by=tenant.user_id,
    )
    db.add(event)
    await db.flush()

    try:
        media_record = upload_media_to_supabase(file, event_id, content_bytes=file_bytes)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Media storage upload failed (%s); proceeding with forensic analysis", exc)
        media_record = {
            "file_name": file_name,
            "storage_path": f"media/{event_id}/{file_name}",
            "file_type": content_type,
            "size_bytes": size_bytes,
        }
    
    db.add(
        MediaFile(
            id=str(uuid.uuid4()),
            event_id=event_id,
            owner_user_id=tenant.owner_user_id,
            file_name=media_record["file_name"],
            storage_path=media_record["storage_path"],
            file_type=media_record["file_type"],
            size_bytes=media_record["size_bytes"],
        )
    )
    await db.commit()

    # Forensics analysis in worker thread
    result = await asyncio.to_thread(analyze_media, file_bytes, file_name, content_type)

    fast_meta = generate_heuristic_explanation(
        module="deepfake",
        indicators=result.get("indicators", []),
        raw_data={"file_name": file_name, "media_type": result.get("media_type")},
        risk_score=result.get("risk_score", 0),
    )
    llm_output = {
        "explanation": None,
        "mitre_techniques": fast_meta.get("mitre_techniques", []),
        "recommended_actions": fast_meta.get("recommended_actions", []),
    }

    alert = await create_alert(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_id=event_id,
        module="deepfake",
        raw_data={
            "file_name": file_name,
            "content_type": content_type,
            "storage_path": media_record["storage_path"],
            "media_type": result["media_type"],
            "method": result["method"],
            "simulated": result["simulated"],
            # Deterministic evidence trail (image pipeline): Model A / Model B
            # probabilities, fusion method and disagreement flag.
            **({
                "model_evidence": result["model_evidence"],
                "fusion": result["fusion"],
                "disagreement": result.get("disagreement"),
            } if "model_evidence" in result else {}),
        },
        indicators=result["indicators"],
        score=result["risk_score"],
        severity=result["severity"],
        llm_output=llm_output,
    )

    user_prompt = format_deepfake_user_prompt(
        result,
        risk_score=result.get("risk_score", 0),
        severity=result.get("severity", "safe"),
    )
    asyncio.create_task(
        _bg_generate_explanation(
            alert_id=alert.id,
            system_prompt=DEEPFAKE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            module="deepfake",
            indicators=result["indicators"],
            raw_data={"file_name": file_name, "media_type": result["media_type"]},
            risk_score=result["risk_score"],
            user_id=tenant.user_id,
        )
    )

    return {
        **result,
        "event_id": event_id,
        "alert_id": alert.id,
        "storage_path": media_record["storage_path"],
        "explanation": None,
        "mitre_techniques": alert.mitre,
        "recommended_actions": [
            {
                "action": action.action,
                "automation_level": action.automation_level,
                "requires_approval": action.requires_approval,
            }
            for action in alert.recommended_actions
        ],
    }


@router.post("/media/event/{event_id}")
async def analyze_media_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Re-run the deepfake pipeline for an already-ingested media event."""
    query = (
        select(MediaFile)
        .join(Event, Event.id == MediaFile.event_id)
        .where(MediaFile.event_id == event_id, tenant_criteria(MediaFile, tenant))
    )
    result = await db.execute(query)
    media = result.scalar_one_or_none()
    if media is None:
        raise NotFoundError("Media file for event", event_id)

    file_bytes = download_media(media.storage_path)
    file_name = media.file_name or "media"
    content_type = media.file_type or ""

    analysis_res = await asyncio.to_thread(analyze_media, file_bytes, file_name, content_type)

    media_score = analysis_res.get("risk_score", 0)
    media_severity = analysis_res.get("severity", get_severity(media_score))

    fast_meta = generate_heuristic_explanation(
        module="deepfake",
        indicators=analysis_res.get("indicators", []),
        raw_data={"file_name": file_name, "media_type": analysis_res.get("media_type")},
        risk_score=media_score,
    )
    llm_output = {
        "explanation": None,
        "mitre_techniques": fast_meta.get("mitre_techniques", []),
        "recommended_actions": fast_meta.get("recommended_actions", []),
    }

    alert = await create_alert(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_id=event_id,
        module="deepfake",
        raw_data={
            "file_name": file_name,
            "content_type": content_type,
            "storage_path": media.storage_path,
            "media_type": analysis_res["media_type"],
            "method": analysis_res["method"],
            "simulated": analysis_res["simulated"],
            # Deterministic evidence trail (image pipeline).
            **({
                "model_evidence": analysis_res["model_evidence"],
                "fusion": analysis_res["fusion"],
                "disagreement": analysis_res.get("disagreement"),
            } if "model_evidence" in analysis_res else {}),
        },
        indicators=analysis_res["indicators"],
        score=analysis_res["risk_score"],
        severity=analysis_res["severity"],
        llm_output=llm_output,
    )

    user_prompt = format_deepfake_user_prompt(
        analysis_res,
        risk_score=media_score,
        severity=media_severity,
    )
    asyncio.create_task(
        _bg_generate_explanation(
            alert_id=alert.id,
            system_prompt=DEEPFAKE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            module="deepfake",
            indicators=analysis_res["indicators"],
            raw_data={"file_name": file_name, "media_type": analysis_res["media_type"]},
            risk_score=media_score,
            user_id=tenant.user_id,
        )
    )

    return {
        **analysis_res,
        "event_id": event_id,
        "alert_id": alert.id,
        "storage_path": media.storage_path,
        "explanation": None,
        "mitre_techniques": alert.mitre,
        "recommended_actions": [
            {
                "action": action.action,
                "automation_level": action.automation_level,
                "requires_approval": action.requires_approval,
            }
            for action in alert.recommended_actions
        ],
    }


# ---------------------------------------------------------------------------
# SCENARIO-2: Organization-scoped identity-fraud analysis
#
# Authentication accepts a Supabase JWT *or* an organization API key
# (cg_org_...). In both cases the organization/project scope is resolved
# SERVER-SIDE from the credential (tenant context / org_api_keys row) — the
# endpoints never accept an organization_id from the client, so one tenant
# cannot read, seed, or analyze against another tenant's verified identities.
# ---------------------------------------------------------------------------


class VerifiedIdentityCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role_title: Optional[str] = Field(default=None, max_length=120)
    email: Optional[str] = Field(default=None, max_length=255)
    username: Optional[str] = Field(default=None, max_length=64)


def _identity_risk_tier(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _text_similarity(a: Optional[str], b: Optional[str]) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a.strip().lower(), b.strip().lower()).ratio()


def _email_domain(email: Optional[str]) -> str:
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


async def require_identity_fraud_auth(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """Resolve the tenant from a Supabase JWT or an org API key.

    Org API keys are validated through the same security-definer function the
    public project gateway uses (cyberguard.validate_org_api_key); the
    resulting organization_id / project_id come from the key row itself.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("Missing bearer credentials")

    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("Empty bearer token")

    # Path A: organization API key (cg_org_...).
    if token.startswith("cg_org_"):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        res = await db.execute(
            text(
                "SELECT key_id, project_id, organization_id, role, owner_user_id, status "
                "FROM cyberguard.validate_org_api_key(:h)"
            ),
            {"h": token_hash},
        )
        key_row = res.mappings().first()
        if not key_row or key_row["status"] != "active":
            raise UnauthorizedError("Invalid or inactive API key")
        if key_row["role"] == "viewer":
            raise PermissionDeniedError("Viewer keys cannot perform identity-fraud actions")

        # Stamp the RLS identity before any tenant-scoped query runs.
        await set_session_user(db, str(key_row["owner_user_id"]))
        try:
            await db.execute(
                text("UPDATE cyberguard.org_api_keys SET last_used_at = now() WHERE id = :kid"),
                {"kid": str(key_row["key_id"])},
            )
            await db.commit()
        except Exception:  # noqa: BLE001 - usage stamping must never fail auth
            await db.rollback()

        organization = (
            await db.execute(
                select(OrgOrganization).where(OrgOrganization.id == str(key_row["organization_id"]))
            )
        ).scalar_one_or_none()
        project = (
            await db.execute(select(OrgProject).where(OrgProject.id == str(key_row["project_id"])))
        ).scalar_one_or_none()

        return TenantContext(
            user_id=str(key_row["owner_user_id"]),
            owner_user_id=str(key_row["owner_user_id"]),
            organization_id=str(key_row["organization_id"]),
            organization_name=organization.name if organization else "Organization",
            role="admin" if key_row["role"] == "master" else str(key_row["role"]),
            is_single_user=False,
            project_id=str(key_row["project_id"]) if key_row["project_id"] else None,
        )

    # Path B: Supabase JWT through the standard tenant resolution.
    try:
        user = await get_current_user(
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
            db=db,
        )
    except UnauthorizedError:
        raise
    tenant = await get_tenant_context(user=user, db=db)
    if tenant.role not in ("admin", "analyst"):
        raise PermissionDeniedError("Role does not have permission for identity-fraud analysis")
    if tenant.organization_id is None:
        # The feature is org-scoped by design: verified identities and fraud
        # analysis must never fall back to a personal workspace.
        raise PermissionDeniedError("Identity-fraud analysis requires an organization context")
    return tenant


def _verified_identity_payload(row: VerifiedIdentity) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "role_title": row.role_title,
        "email": row.email,
        "username": row.username,
    }


@router.post("/identity-fraud/verified", status_code=status.HTTP_201_CREATED)
async def create_verified_identity(
    payload: VerifiedIdentityCreate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_identity_fraud_auth),
) -> dict:
    """Seed a trusted identity scoped to the authenticated organization."""
    row = VerifiedIdentity(
        id=str(uuid.uuid4()),
        organization_id=tenant.organization_id or "",
        project_id=tenant.project_id,        owner_user_id=tenant.owner_user_id or None,
        name=payload.name.strip(),
        role_title=(payload.role_title or "").strip() or None,
        email=(payload.email or "").strip().lower() or None,
        username=(payload.username or "").strip().lower() or None,
        created_by=tenant.user_id,
    )
    db.add(row)
    await db.commit()
    result = _verified_identity_payload(row)
    result["organization_id"] = str(row.organization_id)
    return result


@router.get("/identity-fraud/verified")
async def list_verified_identities(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_identity_fraud_auth),
) -> dict:
    """List the authenticated organization's verified identities."""
    query = select(VerifiedIdentity).where(tenant_criteria(VerifiedIdentity, tenant))
    rows = (await db.execute(query)).scalars().all()
    return {"identities": [_verified_identity_payload(r) for r in rows], "count": len(rows)}


@router.post("/identity-fraud")
async def analyze_identity_fraud(
    claimed_name: str = Form(...),
    claimed_email: str = Form(...),
    claimed_username: str = Form(default=""),
    message: str = Form(default=""),
    media: Optional[UploadFile] = File(default=None),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_identity_fraud_auth),
) -> dict:
    """Identity-fraud analysis for a claimed contact/profile.

    Compares the claimed attributes against the organization's verified
    identities (server-side tenant scope), runs deepfake forensics on the
    optional profile media, and persists an Event + Alert under the tenant.
    """
    # 1. Tenant-scoped verified-identity roster.
    roster_query = select(VerifiedIdentity).where(tenant_criteria(VerifiedIdentity, tenant))
    roster = (await db.execute(roster_query)).scalars().all()

    best: Optional[VerifiedIdentity] = None
    best_score = 0.0
    for row in roster:
        candidate = max(
            _text_similarity(claimed_name, row.name),
            _text_similarity(claimed_email, row.email),
            _text_similarity(claimed_username, row.username),
        )
        if candidate > best_score:
            best, best_score = row, candidate

    evidence: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    imp_score = 0

    # 2. Impersonation evidence.
    if best is not None and best_score > 0.4:
        domain_ok = bool(_email_domain(claimed_email)) and (
            _email_domain(claimed_email) == _email_domain(best.email)
        )
        if not domain_ok:
            imp_score += 45
            evidence.append({
                "status": "danger",
                "text": (
                    "Profile identity does not match the verified identity "
                    f"(Domain Mismatch: {_email_domain(claimed_email) or 'unknown'} "
                    f"vs {_email_domain(best.email) or 'unknown'})"
                ),
            })
            indicators.append({
                "type": "identity_domain_mismatch",
                "severity": "high",
                "description": (
                    f"Claimed email domain {_email_domain(claimed_email)!r} does not match "
                    f"verified domain {_email_domain(best.email)!r}"
                ),
                "source": "identity_fraud",
            })
        else:
            evidence.append({"status": "pass", "text": "Email domain matches the verified identity"})

        name_sim = _text_similarity(claimed_name, best.name)
        if name_sim > 0.8 and claimed_name.strip().lower() != (best.name or "").strip().lower():
            imp_score += 20
            evidence.append({
                "status": "danger",
                "text": (
                    f"Claimed name '{claimed_name}' closely mimics the verified "
                    f"identity '{best.name}'"
                ),
            })
            indicators.append({
                "type": "identity_name_mimicry",
                "severity": "medium",
                "description": f"Claimed name similarity {name_sim:.2f} vs verified '{best.name}'",
                "source": "identity_fraud",
            })
        elif name_sim > 0.8:
            evidence.append({"status": "pass", "text": "Name matches the verified identity"})

        username_sim = _text_similarity(claimed_username, best.username)
        if best.username and claimed_username and username_sim > 0.75:
            imp_score += 15
            evidence.append({
                "status": "danger",
                "text": (
                    "Username shows strong similarity to the genuine account "
                    f"({best.username})"
                ),
            })
            indicators.append({
                "type": "identity_username_mimicry",
                "severity": "medium",
                "description": f"Claimed username similarity {username_sim:.2f} vs '{best.username}'",
                "source": "identity_fraud",
            })
    else:
        imp_score += 25
        evidence.append({
            "status": "warn",
            "text": (
                "No verified identity baseline matches this claim in the organization; "
                "authenticity could not be corroborated"
            ),
        })

    # 3. Message content: impersonation heuristics + social-engineering patterns.
    message_score = 0
    if message:
        message_indicators = await asyncio.to_thread(
            analyze_impersonation_heuristics, message=message, claimed_identity=claimed_name
        )
        try:
            se_result = await asyncio.to_thread(SEPatternEngine().analyze, message, "")
            message_indicators.extend(
                {**i, "source": "se_patterns"} for i in se_result.get("indicators") or []
            )
        except Exception as exc:  # noqa: BLE001 - SE engine is additive
            logger.warning("Identity-fraud SE analysis failed: %s", exc)
        message_score = min(100, calculate_score(message_indicators))
        imp_score = min(100, imp_score + round(message_score * 0.4))
        indicators.extend(message_indicators)
        if message_score >= 40:
            evidence.append({
                "status": "danger",
                "text": "Message contains urgency and financial-request indicators",
            })
        elif message_score > 0:
            evidence.append({
                "status": "warn",
                "text": "Message contains weak social-engineering patterns",
            })

    imp_score = min(100, imp_score)

    # 4. Media forensics (deepfake pipeline).
    media_analysis: Optional[dict[str, Any]] = None
    df_score = 0
    if media is not None and media.filename:
        content_type = media.content_type or ""
        if not content_type.startswith(ANALYSIS_MEDIA_CONTENT_TYPE_PREFIXES):
            raise ValidationError("Profile media must be an image, video, or audio upload")
        file_bytes = await media.read()
        media_analysis = await asyncio.to_thread(
            analyze_media, file_bytes, media.filename, content_type
        )
        df_score = int(media_analysis.get("risk_score") or 0)
        if df_score >= 40:
            evidence.append({
                "status": "danger",
                "text": "Profile image similarity/manipulation detected",
            })
        else:
            evidence.append({
                "status": "pass",
                "text": "Profile media forensics found no manipulation signals",
            })
        indicators.extend(media_analysis.get("indicators") or [])

    overall = max(imp_score, df_score)
    overall_tier = _identity_risk_tier(overall)
    severity = get_severity(overall)

    verdict = (
        "identity_fraud_detected"
        if overall_tier == "high" and (imp_score >= 70 or df_score >= 70)
        else ("suspicious" if overall_tier != "low" else "no_fraud_detected")
    )

    if overall_tier == "high":
        recommended = [
            "Do not trust the request.",
            "Verify the person's identity through an independent channel.",
            "Report/escalate the suspicious account.",
        ]
    elif overall_tier == "medium":
        recommended = [
            "Treat the request as unverified.",
            "Confirm the sender's identity through a known contact channel before acting.",
            "Report the attempt to the security team.",
        ]
    else:
        recommended = ["No immediate action required; continue to monitor for follow-up attempts."]

    # 5. Persist event + alert under the authenticated tenant (never raw media).
    event_id = await _create_analysis_event(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_type="identity_fraud",
        source="identity_fraud_api",
        raw_data={
            "claimed_name": claimed_name,
            "claimed_username": claimed_username,
            "claimed_email": claimed_email,
            "message": message,
            "media_file": media.filename if media else None,
            "verified_identity_id": str(best.id) if best else None,
        },
    )

    explanation = (
        f"Identity-fraud analysis for '{claimed_name}' <{claimed_email}>: "
        f"impersonation score {imp_score}/100, deepfake score {df_score}/100, "
        f"verdict {verdict}."
    )
    alert = await create_alert(
        db,
        tenant=tenant,
        created_by=tenant.user_id,
        event_id=event_id,
        module="identity_fraud",
        raw_data={
            "subject": f"Identity fraud attempt: {claimed_name}",
            "claimed_name": claimed_name,
            "claimed_email": claimed_email,
            "claimed_username": claimed_username,
            "message": message,
        },
        indicators=indicators,
        score=overall,
        severity=severity,
        llm_output={"explanation": explanation, "summary": explanation[:250]},
    )

    return {
        "verdict": verdict,
        "overall_risk": overall_tier,
        "risk_score": overall,
        "impersonation_risk": _identity_risk_tier(imp_score),
        "impersonation_score": imp_score,
        "deepfake_risk": _identity_risk_tier(df_score),
        "deepfake_score": df_score,
        "verified_identity": _verified_identity_payload(best) if best else None,
        "organization": {
            "id": tenant.organization_id,
            "name": tenant.organization_name,
        },
        "project": {"id": tenant.project_id} if tenant.project_id else None,
        "evidence": evidence,
        "recommended_action": recommended,
        "indicators": indicators,
        "media_analysis": {
            "file_name": media.filename,
            "method": media_analysis.get("method"),
            "risk_score": df_score,
            "severity": media_analysis.get("severity"),
            "simulated": media_analysis.get("simulated"),
        }
        if media_analysis
        else None,
        "event_id": event_id,
        "alert_id": alert.id,
    }
