"""Watch renewal service for automated Gmail Pub/Sub push notification maintenance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import GmailAccount
from app.services.gmail.client import (
    GmailAuthError,
    GmailClient,
    GmailRateLimitError,
    GmailScopeError,
    GmailServerError,
)
from app.services.gmail_account_service import is_greater_history_id
from app.workers.base import get_db_session

logger = logging.getLogger("cyberguard.gmail.watch")


def epoch_ms_to_datetime(epoch_ms: int | str) -> datetime:
    """Convert epoch timestamp in milliseconds to timezone-aware UTC datetime."""
    return datetime.fromtimestamp(int(epoch_ms) / 1000.0, tz=timezone.utc)


async def _run_renew_watches(
    db: AsyncSession,
    client: Optional[Any] = None,
    account_ids: Optional[list[str]] = None,
    owner_user_id: Optional[str] = None,
) -> dict[str, Any]:
    """Internal implementation of watch renewal on an open database session."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    threshold = now + timedelta(hours=24)

    # 1. Query accounts expiring within 24h (or uninitialized) and not paused
    stmt = (
        select(GmailAccount)
        .where(
            (
                (GmailAccount.watch_expiration < threshold)
                | (GmailAccount.watch_expiration.is_(None))
            )
            & (GmailAccount.status == "connected")
            & (GmailAccount.sync_status != "paused")
        )
    )
    if account_ids is not None:
        stmt = stmt.where(GmailAccount.id.in_(account_ids))
    if owner_user_id is not None:
        stmt = stmt.where(GmailAccount.owner_user_id == owner_user_id)
    accounts = (await db.execute(stmt)).scalars().all()

    gmail_client = client or GmailClient()
    renewed_count = 0
    error_count = 0
    skipped_count = 0
    renewed_ids: list[str] = []

    for account in accounts:
        try:
            access_token = account.get_access_token()
            refresh_token = account.get_refresh_token()
        except Exception as exc:
            logger.warning("Failed to decrypt tokens for account %s: %s", account.id, exc)
            account.sync_status = "error"
            account.last_error = "reauth_required"
            account.updated_at = now
            error_count += 1
            continue

        try:
            watch_resp = await gmail_client.watch(
                access_token=access_token or "",
                topic=settings.GMAIL_PUBSUB_TOPIC,
                labels=["INBOX"],
                refresh_token=refresh_token,
            )

            # Extract expiration epoch ms
            exp_raw = watch_resp.get("expiration")
            if exp_raw is not None:
                account.watch_expiration = epoch_ms_to_datetime(exp_raw)

            # Optionally update historyId if returned
            resp_hist = watch_resp.get("historyId")
            if resp_hist and is_greater_history_id(resp_hist, account.last_history_id):
                account.last_history_id = str(resp_hist)

            account.sync_status = "active"
            account.last_error = None
            account.updated_at = datetime.now(timezone.utc)
            renewed_count += 1
            renewed_ids.append(str(account.id))

        except (GmailAuthError, GmailScopeError) as exc:
            logger.warning("Auth/scope error renewing watch for account %s: %s", account.id, exc)
            account.sync_status = "error"
            account.last_error = "reauth_required"
            account.updated_at = datetime.now(timezone.utc)
            error_count += 1

        except (GmailRateLimitError, GmailServerError) as exc:
            logger.warning("Transient error renewing watch for account %s: %s", account.id, exc)
            skipped_count += 1

        except Exception as exc:
            logger.warning("Unexpected error renewing watch for account %s: %s", account.id, exc)
            skipped_count += 1

    await db.commit()

    logger.info(
        "Watch renewal completed: %d evaluated, %d renewed, %d errors, %d skipped",
        len(accounts),
        renewed_count,
        error_count,
        skipped_count,
    )
    return {
        "total_evaluated": len(accounts),
        "renewed": renewed_count,
        "errors": error_count,
        "skipped": skipped_count,
        "renewed_account_ids": renewed_ids,
    }


async def renew_watches(
    db_or_ctx: Any = None,
    client: Optional[Any] = None,
    account_ids: Optional[list[str]] = None,
    owner_user_id: Optional[str] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Renew Gmail Pub/Sub push notification watches for expiring accounts.

    Accepts either an AsyncSession (direct invocation/testing), an Arq worker ctx dict,
    or None (opens session via async_session_maker).
    """
    if hasattr(db_or_ctx, "execute"):
        return await _run_renew_watches(
            db_or_ctx, client=client, account_ids=account_ids, owner_user_id=owner_user_id
        )

    if isinstance(db_or_ctx, dict):
        cli = client or db_or_ctx.get("gmail_client")
        async with get_db_session(db_or_ctx) as db:
            return await _run_renew_watches(
                db, client=cli, account_ids=account_ids, owner_user_id=owner_user_id
            )

    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        return await _run_renew_watches(
            db, client=client, account_ids=account_ids, owner_user_id=owner_user_id
        )
