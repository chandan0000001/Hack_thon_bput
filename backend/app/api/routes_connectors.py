"""Email connector endpoints (Phase 1-2: Gmail only).

All endpoints require the authenticated user except the OAuth callback,
which validates a single-use, high-entropy state row instead. Connector
responses never contain token material.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, NotFoundError, PermissionDeniedError
from app.core.security import CurrentUser, get_current_user
from app.db.models import GmailAccount, JobQueue, ProcessedEmail, ScanResult as DBScanResult
from app.db.session import get_db
from app.schemas.connectors import (
    ConnectorAccountRead,
    ConnectorAuthorizeRequest,
    ConnectorAuthorizeResponse,
    ConnectorCapabilitiesResponse,
    ConnectorDisconnectResponse,
    ConnectorListResponse,
    ConnectorOperationListResponse,
    ConnectorOperationRead,
    ConnectorTestResponse,
    GmailAccountItem,
    GmailAccountsListResponse,
)
from app.schemas.email import MessageSummary, NormalizedMessage
from app.services.action_engine import enforce_scan_results
from app.schemas.scan_results import ScanResult
from app.services.connectors import connector_service
from app.services.connectors.oauth_service import OAuthFlowError, create_gmail_authorization_url, handle_gmail_callback
from app.services.connectors.token_manager import TokenRefreshError, get_valid_access_token
from app.services.email_providers.base import EmailProviderError
from app.services.email_providers.gmail import gmail_provider
from app.services.email_providers.registry import get_registry
from app.services.mail_scanner import scan_message
from app.services.scoring_service import get_recommended_action
from app.services.trusted_senders import annotate_scan_with_trust, is_sender_trusted
from app.services.security_history_service import record_event

logger = logging.getLogger("cyberguard.connectors.api")

router = APIRouter(prefix="/connectors", tags=["Email Connectors"])

_MAX_SCAN_MESSAGES = 25
_BODY_PREVIEW_CHARS = 300


class ScanRequest(BaseModel):
    message_ids: Optional[list[str]] = None
    scan_recent: Optional[int] = Field(default=None, ge=1, le=25)


def _provider_error(exc: Exception) -> AppError:
    """Map provider/token failures to honest, safe API errors."""
    error_class = getattr(exc, "error_class", None) or "failed"
    if error_class == "reauth_required":
        return PermissionDeniedError("Mailbox authorization expired — reconnect this connector.")
    if error_class == "insufficient_scope":
        return AppError(
            "Gmail access was denied — the granted scopes are insufficient for this operation.",
            code="insufficient_scope",
            status_code=403,
        )
    return AppError(
        f"Email provider error: {exc}",
        code="provider_error",
        status_code=502,
    )


async def _require_owned_connector(connector_id: str, user: CurrentUser, db: AsyncSession):
    """Ownership gate: users can only touch their own connectors (RLS + filter)."""
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    if connector.status == "revoked":
        raise PermissionDeniedError("This connector is disconnected — reconnect it first.")
    return connector


def _to_summary(message: NormalizedMessage) -> MessageSummary:
    text = message.body_text or ""
    return MessageSummary(
        provider_message_id=message.provider_message_id,
        provider=message.provider,
        sender=message.sender,
        recipients=message.recipients,
        subject=message.subject,
        received_at=message.received_at,
        is_read=message.is_read,
        has_attachments=bool(message.attachments_meta),
        body_preview=text[:_BODY_PREVIEW_CHARS],
    )

logger = logging.getLogger("cyberguard.connectors.api")

router = APIRouter(prefix="/connectors", tags=["Email Connectors"])


def _safe_reason(exc: OAuthFlowError) -> str:
    """Map flow failures to a safe redirect reason (no provider payloads)."""
    allowed = {
        "invalid_state": "invalid_state",
        "token_exchange_failed": "token_exchange_failed",
        "missing_refresh_token": "missing_refresh_token",
        "profile_failed": "profile_failed",
        "not_configured": "not_configured",
    }
    return allowed.get(exc.reason, "failed")


@router.get("/capabilities", response_model=ConnectorCapabilitiesResponse)
async def connector_capabilities() -> ConnectorCapabilitiesResponse:
    """Honest provider registry: Gmail only, others declared coming soon/unsupported."""
    items = [
        {
            "provider": entry.provider,
            "display_name": entry.display_name,
            "status": entry.status,
            "capabilities": entry.capabilities.to_dict() if entry.capabilities else None,
            "detail": entry.detail,
        }
        for entry in get_registry()
    ]
    return ConnectorCapabilitiesResponse(items=items)


@router.get("/operations", response_model=ConnectorOperationListResponse)
async def connector_operations(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
) -> ConnectorOperationListResponse:
    logs = await connector_service.list_operations(db, user.id, limit=min(limit, 200))
    return ConnectorOperationListResponse(items=[ConnectorOperationRead(**connector_service.serialize_operation(l)) for l in logs])


@router.get("", response_model=ConnectorListResponse)
async def list_connectors(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorListResponse:
    connectors = await connector_service.list_connectors(db, user.id)
    return ConnectorListResponse(
        items=[ConnectorAccountRead(**connector_service.serialize_connector(c)) for c in connectors]
    )


@router.post("/gmail/authorize", response_model=ConnectorAuthorizeResponse)
async def gmail_authorize(
    payload: ConnectorAuthorizeRequest | None = None,
    reconnect: Optional[str] = Query(default=None),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorAuthorizeResponse:
    """Create a single-use OAuth state and return the Google consent URL."""
    redirect_after = payload.redirect_after if payload else None
    rec = (payload.reconnect if payload else None) or reconnect
    if not get_settings().GMAIL_CONNECTOR_ENABLED:
        raise PermissionDeniedError("Gmail connector is disabled")
    try:
        url = await create_gmail_authorization_url(db, user.id, redirect_after, reconnect=rec)
    except OAuthFlowError as exc:
        raise PermissionDeniedError(exc.message)
    return ConnectorAuthorizeResponse(authorization_url=url)


@router.get("/gmail/accounts", response_model=GmailAccountsListResponse)
async def list_gmail_accounts(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    now: Optional[str] = Query(default=None),
    x_test_now: Optional[str] = Header(default=None, alias="X-Test-Now"),
) -> GmailAccountsListResponse:
    """List Gmail accounts separated into active connected and recently disconnected (3-day TTL).

    - connected: status == 'connected'
    - recent: status == 'disconnected' AND disconnected_at > now - 3 days
    - each recent item includes removes_at = disconnected_at + 3 days
    - purged rows are omitted entirely
    - zero tokens exposed in response
    """
    ref_time = None
    time_source = now or x_test_now
    if time_source:
        try:
            ref_time = datetime.fromisoformat(time_source.replace(" ", "+").replace("Z", "+00:00"))
        except Exception:
            ref_time = None
    if ref_time is None:
        ref_time = datetime.now(timezone.utc)

    cutoff = ref_time - timedelta(days=3)

    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == user.id)
        .order_by(GmailAccount.created_at.desc())
    )
    accounts = (await db.execute(stmt)).scalars().all()

    connected_list: list[GmailAccountItem] = []
    recent_list: list[GmailAccountItem] = []

    for acc in accounts:
        if acc.status in ("connected", "paused"):
            connected_list.append(
                GmailAccountItem(
                    id=acc.id,
                    email=acc.email,
                    status=acc.status,
                    paused_at=acc.paused_at.isoformat() if acc.paused_at else None,
                    last_push_at=acc.last_push_at.isoformat() if acc.last_push_at else None,
                    created_at=acc.created_at.isoformat() if acc.created_at else None,
                    last_sync_at=acc.last_sync_at.isoformat() if acc.last_sync_at else None,
                    sync_status=acc.sync_status,
                    last_error=acc.last_error,
                )
            )
        elif acc.status == "disconnected" and acc.disconnected_at is not None:
            disc_at = acc.disconnected_at
            if disc_at.tzinfo is None:
                disc_at = disc_at.replace(tzinfo=timezone.utc)
            removes_at = disc_at + timedelta(days=3)
            if disc_at > cutoff:
                recent_list.append(
                    GmailAccountItem(
                        id=acc.id,
                        email=acc.email,
                        status="disconnected",
                        disconnected_at=disc_at.isoformat(),
                        paused_at=None,
                        last_push_at=acc.last_push_at.isoformat() if acc.last_push_at else None,
                        removes_at=removes_at.isoformat(),
                        created_at=acc.created_at.isoformat() if acc.created_at else None,
                        last_sync_at=acc.last_sync_at.isoformat() if acc.last_sync_at else None,
                        sync_status=acc.sync_status,
                        last_error=acc.last_error,
                    )
                )

    return GmailAccountsListResponse(
        connected=connected_list,
        recent=recent_list,
    )


@router.delete("/gmail/accounts/{account_id}")
async def early_remove_gmail_account(
    account_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Early remove a disconnected Gmail account (owner-scoped).

    - Allowed ONLY for status='disconnected' rows -> sets status='purged'.
    - If status='connected' or status='paused' -> 409 Conflict.
    - If account not found or wrong owner -> 404 Not Found.
    """
    stmt = select(GmailAccount).where(GmailAccount.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is None or account.owner_user_id != user.id:
        raise NotFoundError("Gmail account", account_id)

    if account.status in ("connected", "paused"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot early-remove an active connected or paused account. Disconnect first.",
        )

    account.status = "purged"
    account.updated_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("Early-removed Gmail account %s for user %s -> status=purged", account_id, user.id)
    return {"success": True, "id": account.id, "status": "purged"}


@router.post("/gmail/accounts/{account_id}/disconnect")
async def disconnect_gmail_account_by_id(
    account_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Disconnect a specific Gmail account by ID."""
    stmt = select(GmailAccount).where(GmailAccount.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is None or account.owner_user_id != user.id:
        raise NotFoundError("Gmail account", account_id)

    from app.services.gmail_account_service import perform_gmail_disconnect
    return await perform_gmail_disconnect(db, account)


@router.post("/gmail/disconnect")
async def disconnect_gmail_account_default(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Disconnect the default Gmail account for the authenticated user."""
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == user.id)
        .order_by(GmailAccount.created_at.desc())
    )
    account = (await db.execute(stmt)).scalars().first()

    if account is None:
        raise NotFoundError("Gmail account not found")

    from app.services.gmail_account_service import perform_gmail_disconnect
    return await perform_gmail_disconnect(db, account)


@router.post("/gmail/accounts/{account_id}/pause")
async def pause_gmail_account_by_id(
    account_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Pause live sync for a specific Gmail account."""
    stmt = select(GmailAccount).where(GmailAccount.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is None or account.owner_user_id != user.id:
        raise NotFoundError("Gmail account", account_id)

    from app.services.gmail_account_service import perform_gmail_pause
    return await perform_gmail_pause(db, account)


@router.post("/gmail/pause")
async def pause_gmail_account_default(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Pause live sync for the default Gmail account for the authenticated user."""
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == user.id, GmailAccount.status.in_(["connected", "paused"]))
        .order_by(GmailAccount.created_at.desc())
    )
    account = (await db.execute(stmt)).scalars().first()

    if account is None:
        raise NotFoundError("Gmail account not found")

    from app.services.gmail_account_service import perform_gmail_pause
    return await perform_gmail_pause(db, account)


@router.post("/gmail/accounts/{account_id}/resume")
async def resume_gmail_account_by_id(
    account_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Resume live sync for a specific Gmail account."""
    stmt = select(GmailAccount).where(GmailAccount.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is None or account.owner_user_id != user.id:
        raise NotFoundError("Gmail account", account_id)

    from app.services.gmail_account_service import perform_gmail_resume
    return await perform_gmail_resume(db, account)


@router.post("/gmail/resume")
async def resume_gmail_account_default(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Resume live sync for the default Gmail account for the authenticated user."""
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == user.id, GmailAccount.status.in_(["connected", "paused"]))
        .order_by(GmailAccount.created_at.desc())
    )
    account = (await db.execute(stmt)).scalars().first()

    if account is None:
        raise NotFoundError("Gmail account not found")

    from app.services.gmail_account_service import perform_gmail_resume
    return await perform_gmail_resume(db, account)



@router.get("/gmail/callback", include_in_schema=False)
async def gmail_callback(code: str | None = None, state: str | None = None) -> RedirectResponse:
    """OAuth callback: no bearer token here — the single-use state row carries
    the owner. Redirects to the frontend with a safe status; never tokens."""
    settings = get_settings()
    frontend = settings.FRONTEND_CONNECTORS_URL

    if not code or not state:
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=missing_parameters")

    try:
        connector = await handle_gmail_callback(code, state)
        logger.info("Gmail connector connected for owner=%s (%s)", connector.owner_user_id, connector.provider_email)
        return RedirectResponse(f"{frontend}?connected=gmail&status=success")
    except OAuthFlowError as exc:
        logger.warning("Gmail callback failed: %s (%s)", exc.reason, exc.message)
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason={_safe_reason(exc)}")
    except RuntimeError as exc:
        # e.g. missing CONNECTOR_TOKEN_KEY — loud, honest failure
        logger.error("Gmail callback configuration error: %s", exc)
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=server_configuration")
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected Gmail callback failure")
        return RedirectResponse(f"{frontend}?connected=gmail&status=error&reason=failed")


@router.post("/{connector_id}/test", response_model=ConnectorTestResponse)
async def test_connector(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorTestResponse:
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    result = await connector_service.test_connector(db, connector)
    return ConnectorTestResponse(**result)


@router.delete("/{connector_id}", response_model=ConnectorDisconnectResponse)
async def disconnect_connector(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConnectorDisconnectResponse:
    connector = await connector_service.get_connector(db, connector_id, user.id)
    if connector is None:
        raise NotFoundError("Email connector", connector_id)
    await connector_service.disconnect_connector(db, connector)
    return ConnectorDisconnectResponse(id=connector.id, status=connector.status)


# ---------------------------------------------------------------------------
# Mailbox scanning (Phase 3 — analysis only, no provider write operations)
# ---------------------------------------------------------------------------


@router.get("/{connector_id}/messages", response_model=list[MessageSummary])
async def list_connector_messages(
    connector_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=50),
) -> list[MessageSummary]:
    """List recent mailbox messages as normalized metadata (no heavy bodies)."""
    connector = await _require_owned_connector(connector_id, user, db)
    try:
        access_token = await get_valid_access_token(connector, db)
        message_ids = await gmail_provider.list_messages(access_token, max_results=limit)
        messages = []
        for entry in message_ids:
            messages.append(await gmail_provider.get_message(access_token, entry["id"]))
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc
    return [_to_summary(m) for m in messages]


@router.post("/{connector_id}/scan", response_model=list[ScanResult])
async def scan_connector_messages(
    connector_id: str,
    payload: ScanRequest | None = None,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScanResult]:
    """Fetch messages via the token manager and run the detection pipeline.

    Ownership is enforced by the connector lookup (owner filter + RLS);
    analysis only — enforcement actions are reported as deferred_to_phase_4.
    """
    connector = await _require_owned_connector(connector_id, user, db)
    payload = payload or ScanRequest()

    try:
        access_token = await get_valid_access_token(connector, db)
        if payload.message_ids:
            message_ids = payload.message_ids[:_MAX_SCAN_MESSAGES]
        else:
            recent = min(payload.scan_recent or 10, _MAX_SCAN_MESSAGES)
            entries = await gmail_provider.list_messages(access_token, max_results=recent)
            message_ids = [entry["id"] for entry in entries]

        pairs: list[tuple[NormalizedMessage, ScanResult]] = []
        for message_id in message_ids:
            message = await gmail_provider.get_message(access_token, message_id)
            scan = await scan_message(message)
            # Trust list (FP-hardening D1): annotate trusted senders in the
            # scan itself — verdict still shown, enforcement becomes
            # recommend-only in the action engine.
            if await is_sender_trusted(db, user.id, message.sender):
                scan = annotate_scan_with_trust(scan)
            pairs.append((message, scan))
            # Security history: one scan_verdict per analyzed message (Phase 5).
            await record_event(
                db,
                tenant=None,
                owner_user_id=user.id,
                event_type="scan_verdict",
                actor_type="system",
                connector=connector,
                provider_message_id=message.provider_message_id,
                sender_email=message.sender,
                subject=message.subject,
                severity=scan.overall_severity,
                score=scan.overall_score,
                explanation=scan.overall_explanation,
                indicators=[
                    {"name": ind.name, "value": ind.value, "weight": ind.weight}
                    for analysis in scan.feature_analyses
                    for ind in analysis.indicators
                ],
                action_requested=scan.recommended_action,
                operation_status="success",
                operation_detail=f"{len(scan.feature_analyses)} engine(s) analyzed the message",
            )
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc

    # Phase 4: run the action engine on the fresh scan results. Provider
    # failures are recorded per-message in the ScanResult (honest reporting),
    # they do not fail the whole scan.
    results = await enforce_scan_results(db, connector, pairs)

    connector.last_sync_at = datetime.now(timezone.utc)
    await db.commit()
    return results


@router.get("/{connector_id}/messages/{message_id}/analysis")
async def get_message_analysis(
    connector_id: str,
    message_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Full ScanResult plus the full normalized message for the review view."""
    connector = await _require_owned_connector(connector_id, user, db)
    try:
        access_token = await get_valid_access_token(connector, db)
        message = await gmail_provider.get_message(access_token, message_id)
    except (EmailProviderError, TokenRefreshError) as exc:
        raise _provider_error(exc) from exc
    scan_result = await scan_message(message)
    return {"scan": scan_result, "message": message}


class ProcessedEmailItem(BaseModel):
    id: str
    gmail_message_id: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    received_at: Optional[datetime] = None
    processing_status: str
    risk_score: Optional[float] = None
    classification: Optional[str] = None
    enforcement_status: Optional[str] = None
    enforcement_detail: Optional[str] = None
    severity: Optional[str] = None
    recommended_action: Optional[str] = None
    provider_operation_status: Optional[str] = None
    engines: list[dict] = []
    created_at: datetime
    updated_at: datetime


class IngestionActivityResponse(BaseModel):
    connected_mailboxes: list[dict]
    recent_emails: list[ProcessedEmailItem]
    recent_jobs: list[dict]
    summary: dict


@router.get("/activity", response_model=IngestionActivityResponse)
async def get_ingestion_activity(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> IngestionActivityResponse:
    """Fetch live mailbox ingestion, threat analysis, and enforcement activity."""
    # 1. Connected mailboxes
    connectors = await connector_service.list_connectors(db, user.id)
    connected_mailboxes = [
        {
            "id": c.id,
            "email": c.provider_email,
            "provider": c.provider,
            "status": c.status,
            "last_sync_at": c.last_sync_at,
            "last_error": c.last_error,
        }
        for c in connectors
    ]

    # 2. Recent ProcessedEmails
    pe_query = (
        select(ProcessedEmail)
        .where(ProcessedEmail.owner_user_id == user.id)
        .order_by(ProcessedEmail.created_at.desc())
        .limit(limit)
    )
    pe_rows = (await db.execute(pe_query)).scalars().all()

    recent_emails = []
    total_phishing = 0
    total_quarantined = 0

    # Batch-load stored scan details so live rows carry the same verdict
    # metadata (severity, engine breakdown, action) as the manual scan
    # results preview. Scores stored in scan_details are 0.0-1.0.
    scan_ids = [pe.scan_result_id for pe in pe_rows if pe.scan_result_id]
    scan_details_by_id: dict[str, dict] = {}
    if scan_ids:
        sr_rows = (
            await db.execute(select(DBScanResult).where(DBScanResult.id.in_(scan_ids)))
        ).scalars().all()
        for sr in sr_rows:
            if isinstance(sr.scan_details, dict):
                scan_details_by_id[sr.id] = sr.scan_details

    for pe in pe_rows:
        signals = pe.signals or {}
        enf_status = signals.get("enforcement_status")
        enf_detail = signals.get("enforcement_detail")
        if not enf_status and pe.classification == "phishing":
            enf_status = "quarantined"
        elif not enf_status and pe.processing_status == "completed":
            enf_status = "clean"

        if pe.classification == "phishing" or (pe.risk_score or 0) >= 0.7:
            total_phishing += 1
        if enf_status in ("quarantined", "success"):
            total_quarantined += 1

        details = scan_details_by_id.get(pe.scan_result_id) if pe.scan_result_id else None
        engines = []
        severity = None
        if details:
            severity = details.get("severity")
            for name, er in (details.get("engine_results") or {}).items():
                if isinstance(er, dict) and er.get("score") is not None:
                    engines.append({"engine": name, "score": er.get("score")})
        # EMAIL-ACTION-MATRIX: derive the 4-tier action from the stored score
        recommended_action = get_recommended_action(pe.risk_score or 0.0)

        recent_emails.append(
            ProcessedEmailItem(
                id=pe.id,
                gmail_message_id=pe.gmail_message_id,
                sender=pe.sender,
                subject=pe.subject,
                received_at=pe.received_at,
                processing_status=pe.processing_status,
                risk_score=pe.risk_score,
                classification=pe.classification,
                enforcement_status=enf_status,
                enforcement_detail=enf_detail,
                severity=severity,
                recommended_action=recommended_action,
                provider_operation_status=enf_status,
                engines=engines,
                created_at=pe.created_at,
                updated_at=pe.updated_at,
            )
        )

    # 3. Recent JobQueue items
    jq_query = (
        select(JobQueue)
        .where(JobQueue.owner_user_id == user.id)
        .order_by(JobQueue.created_at.desc())
        .limit(limit)
    )
    jq_rows = (await db.execute(jq_query)).scalars().all()
    recent_jobs = [
        {
            "id": j.id,
            "job_id": j.job_id,
            "job_type": j.job_type,
            "status": j.status,
            "error": j.error,
            "created_at": j.created_at,
            "updated_at": j.updated_at,
        }
        for j in jq_rows
    ]

    return IngestionActivityResponse(
        connected_mailboxes=connected_mailboxes,
        recent_emails=recent_emails,
        recent_jobs=recent_jobs,
        summary={
            "total_processed": len(pe_rows),
            "threats_detected": total_phishing,
            "quarantined": total_quarantined,
        },
    )
