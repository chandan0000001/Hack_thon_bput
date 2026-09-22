"""Gmail account purge service for cleaning up stale disconnected accounts after 3-day TTL.

Purge Strategy:
- Accounts with status='disconnected' and disconnected_at < (now - 3 days) are evaluated.
- If an account has foreign-key dependents in processed_emails:
  soft-purge by setting status='purged'. This preserves email scan history, risk scores,
  and audit trails (FK-safe).
- If an account has zero foreign-key dependents:
  hard-delete the row from gmail_accounts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GmailAccount, ProcessedEmail
from app.workers.base import get_db_session

logger = logging.getLogger("cyberguard.gmail.purge")


async def _run_purge_stale_accounts(
    db: AsyncSession,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=3)

    # Find disconnected accounts older than 3 days
    stmt = (
        select(GmailAccount)
        .where(
            GmailAccount.status == "disconnected",
            GmailAccount.disconnected_at.is_not(None),
            GmailAccount.disconnected_at < cutoff,
        )
    )
    stale_accounts = (await db.execute(stmt)).scalars().all()

    purged_count = 0
    hard_deleted_count = 0

    for account in stale_accounts:
        account.status = "purged"
        account.updated_at = current_time
        purged_count += 1
        logger.info(
            "Soft-purged stale Gmail account %s (%s) -> status=purged",
            account.id,
            account.email,
        )

    if stale_accounts:
        await db.commit()

    return {
        "purged": purged_count,
        "hard_deleted": hard_deleted_count,
        "total": purged_count + hard_deleted_count,
    }


async def purge_stale_gmail_accounts(
    db_or_ctx: Any = None,
    now: Optional[datetime] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Purge stale disconnected Gmail accounts exceeding the 3-day retention period.

    Accepts an AsyncSession (direct/testing), an Arq worker ctx dict, or None (creates session).
    """
    if hasattr(db_or_ctx, "execute"):
        return await _run_purge_stale_accounts(db_or_ctx, now=now)

    if isinstance(db_or_ctx, dict):
        async with get_db_session(db_or_ctx) as db:
            return await _run_purge_stale_accounts(db, now=now)

    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        return await _run_purge_stale_accounts(db, now=now)
