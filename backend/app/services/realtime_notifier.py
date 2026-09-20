"""Realtime notification service for real-time pipeline event broadcasts."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ProcessedEmail, ScanResult, SecurityEvent

logger = logging.getLogger("cyberguard.realtime_notifier")


async def notify_email_processed(
    db: AsyncSession,
    processed_email_id: str,
    supabase_client: Optional[Any] = None,
) -> dict[str, Any]:
    """Emit a real-time event when an email finishes threat analysis.

    Dispatches an event to Supabase Realtime channel if configured/provided,
    and persists an auditable SecurityEvent row in the database.
    """
    # 1. Load processed email and associated scan result
    stmt = (
        select(ProcessedEmail)
        .where(ProcessedEmail.id == processed_email_id)
    )
    processed_email = (await db.execute(stmt)).scalar_one_or_none()
    if processed_email is None:
        logger.warning("ProcessedEmail %s not found for realtime notification", processed_email_id)
        return {"emitted": False, "reason": "not_found"}

    scan_result: Optional[ScanResult] = None
    if processed_email.scan_result_id:
        sr_stmt = select(ScanResult).where(ScanResult.id == processed_email.scan_result_id)
        scan_result = (await db.execute(sr_stmt)).scalar_one_or_none()

    # 2. Build standard notification payload
    payload = {
        "processed_email_id": str(processed_email.id),
        "risk_score": processed_email.risk_score or 0.0,
        "classification": processed_email.classification or "safe",
        "scan_result_id": processed_email.scan_result_id,
        "owner_user_id": processed_email.owner_user_id,
    }
    event_type = "email_analyzed"

    # 3. Emit to Supabase Realtime if client provided / available
    channel_emitted = False
    if supabase_client is not None:
        try:
            if hasattr(supabase_client, "channel"):
                ch = supabase_client.channel("realtime:emails")
                if hasattr(ch, "send"):
                    ch.send({"type": "broadcast", "event": event_type, "payload": payload})
                channel_emitted = True
            elif hasattr(supabase_client, "emit"):
                supabase_client.emit(event_type, payload)
                channel_emitted = True
        except Exception as exc:
            logger.warning("Failed emitting broadcast to Supabase Realtime: %s", exc)

    # 4. Record event in security_events table for audit & persistence
    # ORG-WIRE: stamp the owner's active org (personal-org fallback) so the
    # org-branch RLS policies (migration 0018) make pipeline events visible
    # to org members. Never fails the notification path.
    organization_id: Optional[str] = None
    try:
        from app.services.org_context import resolve_org_id

        organization_id = await resolve_org_id(db, processed_email.owner_user_id)
    except Exception:  # noqa: BLE001 - stamping is best-effort
        logger.debug("org stamp lookup failed for %s", processed_email.owner_user_id)
    sec_event = SecurityEvent(
        owner_user_id=processed_email.owner_user_id,
        organization_id=organization_id,
        event_type=event_type,
        provider="gmail",
        provider_message_id=processed_email.gmail_message_id,
        sender_email=processed_email.sender,
        subject=processed_email.subject,
        severity=scan_result.verdict if scan_result else (processed_email.classification or "safe"),
        score=processed_email.risk_score,
        explanation=(scan_result.scan_details or {}).get("explanation") if scan_result else None,
        indicators=(scan_result.scan_details or {}).get("indicators") if scan_result else None,
        actor_type="system",
        operation_status="success",
        operation_detail=json.dumps(payload),
    )
    db.add(sec_event)
    await db.commit()

    logger.info(
        "Realtime event '%s' emitted for processed_email_id=%s, owner=%s",
        event_type,
        processed_email_id,
        processed_email.owner_user_id,
    )

    return {
        "event_type": event_type,
        "payload": payload,
        "emitted": True,
        "channel_emitted": channel_emitted,
        "security_event_id": sec_event.id,
    }
