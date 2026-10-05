"""Alert persistence and query service using Async SQLAlchemy."""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import NotFoundError
from app.core.security import TenantContext, tenant_criteria
from app.db.models import Alert, Event, RecommendedAction, ResponseCatalog

logger = logging.getLogger("cyberguard.alerts")

MODULE_DEFAULT_THREAT_TYPES = {
    "phishing": "phishing_email",
    "url": "malicious_url",
    "impersonation": "impersonation_message",
    "account_takeover": "account_takeover",
    "network": "network_anomaly",
    "api_abuse": "api_rate_abuse",
    "deepfake": "deepfake_media",
}

VALID_AUTOMATION_LEVELS = {"automatic", "semi-automatic", "manual"}
VALID_PRIORITIES = {"safe", "low", "medium", "high", "critical"}


def _clean_automation_level(value: Any) -> str:
    level = str(value or "").strip().lower()
    return level if level in VALID_AUTOMATION_LEVELS else "manual"


def _clean_priority(value: Any, fallback: str = "low") -> str:
    priority = str(value or "").strip().lower()
    if priority in VALID_PRIORITIES:
        return priority
    return fallback if fallback in VALID_PRIORITIES else "low"


async def create_alert(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    event_id: Optional[str],
    module: str,
    raw_data: dict[str, Any],
    indicators: list[dict[str, Any]],
    score: int,
    severity: str,
    llm_output: dict[str, Any],
    created_by: Optional[str] = None,
    confidence: Optional[float] = None,
) -> Alert:
    """Persist an alert and its recommended actions, and update the associated event."""
    alert_id = str(uuid.uuid4())
    raw_title = raw_data.get("subject") or raw_data.get("url") or f"{module.replace('_', ' ').title()} threat detected"
    raw_title = str(raw_title).strip()
    title = (raw_title[:251] + "...") if len(raw_title) > 255 else raw_title
    threat_type = raw_data.get("threat_type") or MODULE_DEFAULT_THREAT_TYPES.get(module, module)
    if threat_type:
        threat_type = str(threat_type)[:64]
    raw_exp = llm_output.get("explanation")
    explanation = str(raw_exp) if raw_exp else None
    mitre = llm_output.get("mitre_techniques") or []

    # ORG-WIRE: fall back to the owner's active/personal org when the tenant
    # carries none (worker/service paths) so the org-branch RLS policies
    # (migration 0018) can expose the alert to org members.
    organization_id = tenant.organization_id
    if organization_id is None:
        try:
            from app.services.org_context import resolve_org_id

            organization_id = await resolve_org_id(db, tenant.owner_user_id or tenant.user_id)
        except Exception:  # noqa: BLE001 - stamping is best-effort
            organization_id = None

    target_user = str(raw_data["target_user"])[:255] if raw_data.get("target_user") else None
    target_service = str(raw_data["target_service"])[:255] if raw_data.get("target_service") else None
    source_ip = str(raw_data["source_ip"])[:64] if raw_data.get("source_ip") else None

    # ORG-REDESIGN: carry the tenant's project scope onto the alert so
    # project dashboards aggregate the right rows.
    alert = Alert(
        id=alert_id,
        organization_id=organization_id,
        project_id=getattr(tenant, "project_id", None),
        owner_user_id=tenant.owner_user_id,
        event_id=event_id,
        title=title,
        module=str(module)[:64],
        threat_type=threat_type,
        severity=str(severity)[:32],
        risk_score=score,
        confidence=confidence,
        status="new",
        summary=explanation[:250] if explanation else title[:250],
        indicators=indicators,
        explanation=explanation,
        mitre=mitre,
        target_user=target_user,
        target_service=target_service,
        source_ip=source_ip,
        created_by=str(created_by)[:64] if created_by else None,
    )
    db.add(alert)
    await db.flush()

    # Match and attach recommended actions
    raw_actions = llm_output.get("recommended_actions") or []
    catalog_result = await db.execute(select(ResponseCatalog))
    catalog_rows = catalog_result.scalars().all()

    for raw_act in raw_actions:
        action_text = raw_act.get("action") if isinstance(raw_act, dict) else str(raw_act)
        action_text = action_text.strip()
        if not action_text:
            continue

        # Look for catalog match
        normalized = action_text.lower()
        matched_cat = next(
            (c for c in catalog_rows if c.action.lower() == normalized or c.action.lower() in normalized),
            None,
        )

        rec = RecommendedAction(
            id=str(uuid.uuid4()),
            alert_id=alert.id,
            action=matched_cat.action if matched_cat else action_text,
            description=matched_cat.description if matched_cat else action_text,
            automation_level=_clean_automation_level(matched_cat.automation_level if matched_cat else "manual"),
            requires_approval=matched_cat.requires_approval if matched_cat else False,
            priority=_clean_priority(severity, fallback="low"),
            executed=False,
        )
        db.add(rec)

    # Mark event completed if event_id is given
    if event_id:
        event_query = await db.execute(select(Event).where(Event.id == event_id))
        event = event_query.scalar_one_or_none()
        if event:
            event.status = "completed"

    await db.commit()

    # Re-fetch alert with loaded actions
    result = await db.execute(
        select(Alert)
        .options(selectinload(Alert.recommended_actions))
        .where(Alert.id == alert.id)
    )
    return result.scalar_one()


async def get_alert(db: AsyncSession, alert_id: str, tenant: TenantContext) -> Alert:
    """Fetch an alert by ID scoped to the active tenant."""
    query = (
        select(Alert)
        .options(selectinload(Alert.recommended_actions))
        .where(Alert.id == alert_id, tenant_criteria(Alert, tenant))
    )
    result = await db.execute(query)
    alert = result.scalar_one_or_none()
    if alert is None:
        raise NotFoundError("Alert", alert_id)
    return alert


async def list_alerts(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    severity: Optional[str] = None,
    module: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> list[Alert]:
    """List alerts scoped to the active tenant with filters and search."""
    query = (
        select(Alert)
        .options(selectinload(Alert.recommended_actions))
        .where(tenant_criteria(Alert, tenant))
    )

    if severity:
        query = query.where(Alert.severity == severity)
    if module:
        query = query.where(Alert.module == module)
    if status:
        query = query.where(Alert.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                Alert.title.ilike(pattern),
                Alert.summary.ilike(pattern),
                Alert.explanation.ilike(pattern),
            )
        )

    query = query.order_by(desc(Alert.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_alert_status(
    db: AsyncSession,
    alert_id: str,
    tenant: TenantContext,
    new_status: str,
    actor: str = "analyst",
) -> Alert:
    """Update status of an alert with audit logging."""
    from app.services import audit_service

    alert = await get_alert(db, alert_id, tenant)
    old_status = alert.status
    alert.status = new_status
    await db.commit()
    await db.refresh(alert)

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=actor,
        user_name=actor,
        action="Alert status updated",
        resource=f"alert:{alert_id}",
        details=f"Status changed from {old_status} to {new_status}",
    )
    return alert
