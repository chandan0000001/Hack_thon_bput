"""Gmail Pub/Sub webhook endpoint with validation and thin enqueue."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.core.rate_limit import get_rate_limiter
from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue
from app.queue.client import enqueue, make_gmail_sync_job_id
from app.services.gmail.pubsub_validator import validate_pubsub_message
from app.services.idempotency_service import ensure_job

logger = logging.getLogger("cyberguard.gmail_webhook")

router = APIRouter(tags=["Gmail Webhook"])


@router.post("/webhooks/gmail")
async def gmail_pubsub_webhook(request: Request) -> dict[str, Any]:
    """Receive Google Pub/Sub push notification for Gmail mailbox changes.

    Thin webhook guarantees:
    - Never fetches emails or calls Gmail API
    - Never runs ML inference or scoring
    - Never writes to processed_emails (only job_queue)
    - Response time <50ms
    """
    # 1. Validate Pub/Sub push message structure, base64 data, and auth token
    parsed = await validate_pubsub_message(request)
    email_address = parsed["email_address"]
    history_id = str(parsed["history_id"])

    # 2. Lookup connected Gmail account (use admin session to query across tenants)
    from sqlalchemy import func
    admin_session_maker = _get_admin_session_maker()
    async with admin_session_maker() as db:
        stmt = select(GmailAccount).where(func.lower(GmailAccount.email) == email_address.lower())
        account = (await db.execute(stmt)).scalar_one_or_none()

        if account is None:
            # Fallback: auto-register from connected EmailConnectorAccount if available
            from app.db.models import EmailConnectorAccount
            from app.core.crypto import decrypt_secret
            from app.services.gmail_account_service import get_or_create_gmail_account

            conn_stmt = select(EmailConnectorAccount).where(
                EmailConnectorAccount.provider == "gmail",
                func.lower(EmailConnectorAccount.provider_email) == email_address.lower(),
                EmailConnectorAccount.status == "connected",
            )
            connector = (await db.execute(conn_stmt)).scalar_one_or_none()
            if connector and connector.refresh_token_enc:
                try:
                    access_token = decrypt_secret(connector.access_token_enc) if connector.access_token_enc else None
                    refresh_token = decrypt_secret(connector.refresh_token_enc)
                    account = await get_or_create_gmail_account(
                        db,
                        owner_user_id=connector.owner_user_id,
                        email=email_address,
                        access_token=access_token,
                        refresh_token=refresh_token,
                    )
                    logger.info("Auto-registered GmailAccount from connector for %s", email_address)
                except Exception:
                    logger.exception("Failed to auto-register GmailAccount from connector")

        if account is None:
            logger.warning("Pub/Sub notification received for unknown email: %s", email_address)
            return {"status": "ignored", "reason": "unknown_email"}

        # Diagnostic plateau check: record last_push_at on every push (accepted or dropped)
        now_push = datetime.now(timezone.utc)
        account.last_push_at = now_push

        # WORKER GUARD: drop + ACK for disconnected, purged, missing token, or paused
        if account.status in ("disconnected", "purged"):
            logger.info(
                "Dropping push for disconnected account %s (%s, status=%s)",
                account.id,
                email_address,
                account.status,
            )
            await db.commit()
            return {"status": "ignored", "reason": "account_disconnected"}

        if not account.get_refresh_token():
            logger.info(
                "Dropping push for account %s (%s) due to missing refresh token",
                account.id,
                email_address,
            )
            await db.commit()
            return {"status": "ignored", "reason": "no_refresh_token"}

        if account.status == "paused" or account.sync_status == "paused":
            logger.info("Dropping push for paused account %s (%s)", account.id, email_address)
            await db.commit()
            return {"status": "ignored", "reason": "account_paused"}

        if account.status != "connected":
            logger.info(
                "Dropping push for account %s (%s) with status=%s",
                account.id,
                email_address,
                account.status,
            )
            await db.commit()
            return {"status": "ignored", "reason": f"account_{account.status}"}

        # Increment Prometheus metric for received Gmail webhook events
        try:
            from app.core.metrics import gmail_events_received_total
            gmail_events_received_total.labels(owner_user_id=account.owner_user_id).inc()
        except Exception:
            pass

        # 4. Generate deterministic job ID
        job_id = make_gmail_sync_job_id(account.owner_user_id, history_id)
        payload = {
            "account_id": account.id,
            "history_id": history_id,
        }

        # 5. Check if job already exists in DB (idempotency check)
        existing_stmt = select(JobQueue).where(JobQueue.job_id == job_id)
        existing_job = (await db.execute(existing_stmt)).scalar_one_or_none()
        if existing_job is not None:
            logger.info("Duplicate notification for job %s; returning existing job", job_id)
            return {"status": "accepted", "job_id": job_id, "duplicate": True}

        # 6. Apply rate limiting (defer by 5s if bucket exhausted)
        limiter = get_rate_limiter()
        defer_by = limiter.acquire(account.owner_user_id, "gmail_sync")
        defer_seconds = defer_by if defer_by > 0 else None

        # 7. Insert job into job_queue table
        await ensure_job(
            db,
            owner_user_id=account.owner_user_id,
            job_type="gmail_sync",
            job_id=job_id,
            payload=payload,
        )

    # 8. Enqueue to Redis/Arq worker
    await enqueue(
        "gmail_sync",
        kwargs=payload,
        job_id=job_id,
        defer_by=defer_seconds,
    )

    return {"status": "accepted", "job_id": job_id}
