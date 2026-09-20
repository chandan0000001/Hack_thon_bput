"""Security history writer (Phase 5).

One record_event call per real security event / provider operation. Writers
must pass the REAL provider operation status/detail — never default to
success. AI chat content is never written here.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

import uuid

from app.db.models import AuditLog, SecurityEvent

logger = logging.getLogger("cyberguard.security_history")


async def record_event(
    db: AsyncSession,
    *,
    tenant=None,
    owner_user_id: str | None = None,
    event_type: str,
    actor_type: str,
    connector=None,
    connector_id: str | None = None,
    provider: str | None = None,
    provider_message_id: str | None = None,
    sender_email: str | None = None,
    subject: str | None = None,
    severity: str | None = None,
    score: float | None = None,
    explanation: str | None = None,
    indicators: list[dict] | None = None,
    action_requested: str | None = None,
    action_performed: str | None = None,
    operation_status: str | None = None,
    operation_detail: str | None = None,
    quarantined_item_id: str | None = None,
    blocked_sender_id: str | None = None,
) -> SecurityEvent:
    """Append one security-history row. History recording is best-effort: a
    failure to record must never break the operation it describes."""
    if tenant is not None:
        owner = tenant.owner_user_id or tenant.user_id
    else:
        owner = owner_user_id
    if not owner:
        raise ValueError("record_event requires a tenant or owner_user_id")

    # ORG-WIRE: stamp the org (explicit tenant org, else the owner's active /
    # personal org) so org-branch RLS (migration 0018) makes the event visible
    # to org members. Best-effort — a failed stamp must not fail the event.
    organization_id = tenant.organization_id if tenant is not None else None
    if organization_id is None:
        try:
            from app.services.org_context import resolve_org_id

            organization_id = await resolve_org_id(db, owner)
        except Exception:  # noqa: BLE001 - stamping is best-effort
            organization_id = None

    event = SecurityEvent(
        owner_user_id=owner,
        organization_id=organization_id,
        event_type=event_type,
        actor_type=actor_type,
        connector_id=connector_id or (connector.id if connector is not None else None),
        provider=provider or (connector.provider if connector is not None else None),
        provider_message_id=provider_message_id,
        sender_email=sender_email,
        subject=subject,
        severity=severity,
        score=score,
        explanation=explanation,
        indicators=indicators,
        action_requested=action_requested,
        action_performed=action_performed,
        operation_status=operation_status,
        operation_detail=operation_detail,
        quarantined_item_id=quarantined_item_id,
        blocked_sender_id=blocked_sender_id,
    )
    db.add(event)
    # Matching audit row (Phase 5 req 5): audit records distinguish the actor.
    db.add(
        AuditLog(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            owner_user_id=owner,
            user_id=owner,
            user_name=f"actor:{actor_type}",
            action=f"security_event:{event_type}",
            resource=event.provider_message_id or event.sender_email or "security_event",
            details=operation_detail,
            actor_type=actor_type,
        )
    )
    try:
        await db.commit()
    except Exception:  # noqa: BLE001 - history must not break operations
        await db.rollback()
        logger.exception("Failed to record security event %s", event_type)
        return event
    await db.refresh(event)

    # Phase 7: high-severity events trigger an email notification to the
    # user's registered notification_email (never a connected mailbox).
    try:
        from app.services.notification_service import maybe_notify

        await maybe_notify(
            db,
            owner_user_id=owner,
            event_type=event_type,
            severity=severity,
            sender_email=sender_email,
            subject=subject,
            operation_status=operation_status,
            operation_detail=operation_detail,
        )
    except Exception:  # noqa: BLE001 - notifications must not break operations
        logger.exception("Notification hook failed for %s", event_type)
    return event


def serialize_event(event: SecurityEvent, include_indicators: bool = True) -> dict:
    """Metadata-only serialization (no tokens, no plaintext secrets)."""
    data = {
        "id": event.id,
        "event_type": event.event_type,
        "connector_id": event.connector_id,
        "provider": event.provider,
        "provider_message_id": event.provider_message_id,
        "sender_email": event.sender_email,
        "subject": event.subject,
        "severity": event.severity,
        "score": event.score,
        "explanation": event.explanation,
        "action_requested": event.action_requested,
        "action_performed": event.action_performed,
        "actor_type": event.actor_type,
        "operation_status": event.operation_status,
        "operation_detail": event.operation_detail,
        "quarantined_item_id": event.quarantined_item_id,
        "blocked_sender_id": event.blocked_sender_id,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }
    if include_indicators:
        data["indicators"] = event.indicators or []
    return data
