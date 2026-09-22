"""Incident management service using Async SQLAlchemy."""

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import NotFoundError, ValidationError
from app.core.security import TenantContext, tenant_criteria
from app.db.models import Incident, IncidentAlert, IncidentEvent
from app.services import audit_service

logger = logging.getLogger("cyberguard.incidents")

VALID_STATUSES = {"open", "investigating", "contained", "closed"}


async def create_incident(
    db: AsyncSession,
    *,
    tenant: TenantContext,
    title: str,
    severity: str,
    linked_alert_ids: list[str],
    created_by: str,
) -> Incident:
    """Create an incident, link alerts, add a timeline entry, and audit it."""
    clean_title = str(title).strip()
    if len(clean_title) > 255:
        clean_title = clean_title[:251] + "..."
    incident = Incident(
        id=str(uuid.uuid4()),
        organization_id=tenant.organization_id,
        owner_user_id=tenant.owner_user_id,
        title=clean_title,
        severity=str(severity)[:32],
        status="open",
        created_by=str(created_by)[:64] if created_by else None,
    )
    db.add(incident)
    await db.flush()

    for alert_id in linked_alert_ids:
        link = IncidentAlert(incident_id=incident.id, alert_id=alert_id)
        db.add(link)

    timeline_event = IncidentEvent(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action="Incident Created",
        actor=created_by,
        details=f"Linked {len(linked_alert_ids)} alert(s)",
    )
    db.add(timeline_event)
    await db.commit()

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=created_by,
        user_name=created_by,
        action="Incident created",
        resource=f"incident:{incident.id}",
        details=f"Incident '{title}' created with severity '{severity}'",
    )

    return await get_incident(db, incident.id, tenant)


async def get_incident(db: AsyncSession, incident_id: str, tenant: TenantContext) -> Incident:
    """Fetch an incident with its timeline and linked alerts."""
    query = (
        select(Incident)
        .options(selectinload(Incident.timeline), selectinload(Incident.alert_links))
        .where(Incident.id == incident_id, tenant_criteria(Incident, tenant))
    )
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    if incident is None:
        raise NotFoundError("Incident", incident_id)
    return incident


async def list_incidents(
    db: AsyncSession,
    tenant: TenantContext,
    status_filter: Optional[str] = None,
) -> list[Incident]:
    """List incidents scoped to the active tenant, newest activity first."""
    if status_filter and status_filter not in VALID_STATUSES:
        raise ValidationError(f"Invalid status filter; must be one of {sorted(VALID_STATUSES)}")

    query = (
        select(Incident)
        .options(selectinload(Incident.timeline), selectinload(Incident.alert_links))
        .where(tenant_criteria(Incident, tenant))
    )
    if status_filter:
        query = query.where(Incident.status == status_filter)

    query = query.order_by(desc(Incident.updated_at))
    result = await db.execute(query)
    return list(result.scalars().all())


async def update_incident_status(
    db: AsyncSession,
    incident_id: str,
    tenant: TenantContext,
    new_status: str,
    actor: str,
) -> Incident:
    """Change an incident's status, record timeline entry, and audit it."""
    if new_status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'; must be one of {sorted(VALID_STATUSES)}")

    incident = await get_incident(db, incident_id, tenant)
    incident.status = new_status

    timeline_event = IncidentEvent(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action=f"Status changed to {new_status}",
        actor=actor,
    )
    db.add(timeline_event)
    await db.commit()

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=actor,
        user_name=actor,
        action=f"Incident status changed to {new_status}",
        resource=f"incident:{incident_id}",
    )
    return await get_incident(db, incident_id, tenant)


async def assign_incident(
    db: AsyncSession,
    incident_id: str,
    tenant: TenantContext,
    assigned_to: str,
    actor: str,
) -> Incident:
    """Assign an incident to an analyst, record timeline entry, and audit it."""
    incident = await get_incident(db, incident_id, tenant)
    incident.assigned_to = assigned_to

    timeline_event = IncidentEvent(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action=f"Assigned to {assigned_to}",
        actor=actor,
    )
    db.add(timeline_event)
    await db.commit()

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=actor,
        user_name=actor,
        action="Incident assigned",
        resource=f"incident:{incident_id}",
        details=f"Assigned to {assigned_to}",
    )
    return await get_incident(db, incident_id, tenant)


async def escalate_incident(
    db: AsyncSession,
    incident_id: str,
    tenant: TenantContext,
    reason: str,
    actor: str,
) -> Incident:
    """Escalate an incident to critical severity and audit the action."""
    incident = await get_incident(db, incident_id, tenant)
    incident.severity = "critical"

    timeline_event = IncidentEvent(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action="Incident Escalated",
        actor=actor,
        details=reason,
    )
    db.add(timeline_event)
    await db.commit()

    await audit_service.log_action(
        db,
        tenant=tenant,
        user_id=actor,
        user_name=actor,
        action="Incident escalated",
        resource=f"incident:{incident_id}",
        details=reason,
    )
    return await get_incident(db, incident_id, tenant)
