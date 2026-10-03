"""Analysis pipeline endpoints using Async SQLAlchemy and OpenRouter XAI."""

import asyncio
import hashlib
import uuid
from typing import Any, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from app.ai.openrouter_client import call_openrouter
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
from app.core.errors import NotFoundError, ValidationError
from app.core.security import TenantContext, require_role, tenant_criteria
from app.core.storage import (
    MAX_MEDIA_SIZE_BYTES,
    download_media,
    upload_media_to_supabase,
)
from app.db.models import Event, MediaFile
from app.db.session import get_db
from app.schemas.alerts import AlertResponse
from app.services.account_takeover_detector import analyze_auth_log_heuristics
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
    events: list[dict[str, Any]]


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
) -> Any:
    """Shared async detection pipeline: persist event, score, explain, alert.

    min_score (AUTH-VERIFY): floor for the hybrid score so independent
    verification can raise, never lower, the final risk."""
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

    if callable(user_prompt_builder):
        user_prompt = user_prompt_builder(raw_data, indicators, hybrid_score, severity)
    else:
        user_prompt = str(user_prompt_builder)

    llm_output = await call_openrouter(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        module=module,
        indicators=indicators,
        raw_data=raw_data,
        risk_score=hybrid_score,
    )

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
    )

    if auth_warnings:
        suffix = " " + " ".join(auth_warnings)
        alert.explanation = ((alert.explanation or "") + suffix).strip()
        alert.summary = ((alert.summary or "") + " " + auth_warnings[0]).strip()[:250]
        await db.commit()

    # SE-HARDENING D3: low-confidence labelling on the manual path — weak
    # heuristic + weak ML appends the manual-review note; a weak heuristic
    # with no URL evidence but an attachment reference appends the separate-
    # verification note.
    try:
        h100, _hybrid, ml_prob = score_with_ml(indicators)
        url_indicator_count = sum(
            1 for i in indicators if "url" in str(i.get("type", "")).lower()
        )
        conf = assess_confidence(h100 / 100.0, ml_prob, url_indicator_count, payload.body)
        if conf.get("notes"):
            alert.explanation = (
                (alert.explanation or "") + " " + " ".join(conf["notes"])
            ).strip()
            await db.commit()
    except Exception as exc:
        logger.warning("Manual-path confidence assessment failed: %s", exc)

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


@router.post("/account-takeover", response_model=AlertResponse)
async def analyze_account_takeover(
    payload: AccountTakeoverAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(require_role(["admin", "analyst"])),
) -> Any:
    """Full account takeover analysis pipeline for authentication logs."""
    raw_data = payload.model_dump(mode="json")
    indicators = await asyncio.to_thread(analyze_auth_log_heuristics, payload.events)
    return await _run_analysis_pipeline(
        db,
        tenant,
        event_type="account_takeover",
        module="account_takeover",
        source=payload.source,
        raw_data=raw_data,
        indicators=indicators,
        system_prompt=ACCOUNT_TAKEOVER_SYSTEM_PROMPT,
        user_prompt_builder=lambda data, ind, score, sev: format_account_takeover_user_prompt(payload.events, ind, score, sev),
    )


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

    llm_output = await call_openrouter(
        DEEPFAKE_SYSTEM_PROMPT,
        format_deepfake_user_prompt(
            result,
            risk_score=result.get("risk_score", 0),
            severity=result.get("severity", "safe"),
        ),
        module="deepfake",
        indicators=result["indicators"],
        raw_data={"file_name": file_name, "media_type": result["media_type"]},
        risk_score=result["risk_score"],
    )

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
        },
        indicators=result["indicators"],
        score=result["risk_score"],
        severity=result["severity"],
        llm_output=llm_output,
    )

    return {
        **result,
        "event_id": event_id,
        "alert_id": alert.id,
        "storage_path": media_record["storage_path"],
        "explanation": alert.explanation,
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
    llm_output = await call_openrouter(
        DEEPFAKE_SYSTEM_PROMPT,
        format_deepfake_user_prompt(
            analysis_res,
            risk_score=media_score,
            severity=media_severity,
        ),
        module="deepfake",
        indicators=analysis_res["indicators"],
        raw_data={"file_name": file_name, "media_type": analysis_res["media_type"]},
        risk_score=media_score,
    )

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
        },
        indicators=analysis_res["indicators"],
        score=analysis_res["risk_score"],
        severity=analysis_res["severity"],
        llm_output=llm_output,
    )

    return {
        **analysis_res,
        "event_id": event_id,
        "alert_id": alert.id,
        "storage_path": media.storage_path,
        "explanation": alert.explanation,
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
