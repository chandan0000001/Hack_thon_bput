"""Gmail account service for managing connected accounts, tokens, lifecycle, and history checkpoints."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Optional

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EmailConnectorAccount, GmailAccount
from app.services.email_providers.gmail import GOOGLE_REVOKE_URL
from app.services.gmail.client import GmailClient

logger = logging.getLogger("cyberguard.gmail_account_service")


async def revoke_google_token(token: str, timeout: float = 10.0) -> bool:
    """Best-effort Google OAuth token revocation."""
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(GOOGLE_REVOKE_URL, data={"token": token})
            if resp.status_code == 200:
                logger.info("Successfully revoked Google token")
                return True
            logger.warning("Google token revoke returned HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        logger.warning("Could not reach Google revoke endpoint: %s", exc)
        return False


async def perform_gmail_disconnect(
    db: AsyncSession,
    account: GmailAccount,
    gmail_client: Optional[GmailClient] = None,
) -> dict[str, Any]:
    """Execute graceful, resilient, idempotent Gmail disconnect for a GmailAccount.

    Idempotent:
    - If status is already 'disconnected', returns success immediately without Google API calls.
    - If active/connected: calls gmail.users.stop, revokes Google OAuth token, marks 'disconnected',
      clears stored credentials, and updates matching EmailConnectorAccount.
    - NEVER touches shared Pub/Sub topics or subscriptions.
    """
    if account.status == "disconnected":
        return {"success": True, "message": "Gmail disconnected", "status": "disconnected"}

    refresh_token = account.get_refresh_token()
    access_token = account.get_access_token()

    client = gmail_client or GmailClient()

    # 1. Stop watch push notifications (resilient to already expired/stopped)
    if access_token or refresh_token:
        try:
            await client.stop(
                access_token=access_token or "",
                refresh_token=refresh_token,
            )
        except Exception as exc:
            logger.warning("Error stopping Gmail watch during disconnect: %s", exc)

    # 2. Revoke OAuth token at Google (resilient to network/invalid)
    token_to_revoke = refresh_token or access_token
    if token_to_revoke:
        try:
            await revoke_google_token(token_to_revoke)
        except Exception as exc:
            logger.warning("Error revoking Google token during disconnect: %s", exc)

    # 3. Clear credentials & set status
    now = datetime.now(timezone.utc)
    account.set_refresh_token(None)
    account.set_access_token(None)
    account.last_history_id = None
    account.watch_expiration = None
    account.status = "disconnected"
    account.disconnected_at = now
    account.sync_status = "paused"

    # Also synchronize corresponding EmailConnectorAccount if present
    stmt = select(EmailConnectorAccount).where(
        EmailConnectorAccount.owner_user_id == account.owner_user_id,
        EmailConnectorAccount.provider == "gmail",
        func.lower(EmailConnectorAccount.provider_email) == func.lower(account.email),
    )
    connector = (await db.execute(stmt)).scalar_one_or_none()
    if connector is not None:
        connector.status = "revoked"
        connector.access_token_enc = None
        connector.refresh_token_enc = None
        connector.access_token_expires_at = None

    await db.commit()
    await db.refresh(account)
    logger.info("Successfully disconnected Gmail account %s (%s)", account.id, account.email)
    return {"success": True, "message": "Gmail disconnected", "status": "disconnected"}


async def get_or_create_gmail_account(
    db: AsyncSession,
    owner_user_id: str,
    email: str,
    access_token: Optional[str],
    refresh_token: Optional[str],
    reconnect_account_id: Optional[str] = None,
) -> GmailAccount:
    """Lookup, revive, or create a GmailAccount with encrypted tokens.

    1. If reconnect_account_id is provided:
       - Lookup by (id, owner_user_id).
       - If found with status='disconnected', revive it (status='connected', disconnected_at=None).
       - If missing or status='purged', falls through to normal fresh connect path.
    2. Lookup by (owner_user_id, email).
       - If exists: revive/update with status='connected', disconnected_at=None, fresh tokens.
       - If not exists: create with status='connected', disconnected_at=None.
    """
    now = datetime.now(timezone.utc)

    # Reconnect path: revive specific existing account if provided and disconnected
    if reconnect_account_id:
        stmt = select(GmailAccount).where(
            GmailAccount.id == reconnect_account_id,
            GmailAccount.owner_user_id == owner_user_id,
        )
        rec_acc = (await db.execute(stmt)).scalar_one_or_none()
        if rec_acc is not None and rec_acc.status == "disconnected":
            rec_acc.status = "connected"
            rec_acc.disconnected_at = None
            rec_acc.sync_status = "active"
            rec_acc.last_error = None
            rec_acc.email = email
            rec_acc.set_access_token(access_token)
            rec_acc.set_refresh_token(refresh_token)
            rec_acc.updated_at = now
            await db.commit()
            await db.refresh(rec_acc)
            logger.info("Revived disconnected Gmail account %s (%s)", rec_acc.id, email)
            return rec_acc
        # If missing or purged, fall through to normal fresh connect path

    stmt = select(GmailAccount).where(
        GmailAccount.owner_user_id == owner_user_id,
        func.lower(GmailAccount.email) == func.lower(email),
    )
    account = (await db.execute(stmt)).scalar_one_or_none()

    if account is not None:
        account.status = "connected"
        account.disconnected_at = None
        account.sync_status = "active"
        account.last_error = None
        account.set_access_token(access_token)
        account.set_refresh_token(refresh_token)
        account.updated_at = now
        await db.commit()
        await db.refresh(account)
        return account

    account = GmailAccount(
        owner_user_id=owner_user_id,
        email=email,
        status="connected",
        disconnected_at=None,
        sync_status="active",
        last_history_id=None,
        watch_expiration=None,
        created_at=now,
        updated_at=now,
    )
    account.set_access_token(access_token)
    account.set_refresh_token(refresh_token)
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


def is_greater_history_id(new_id: Optional[str], old_id: Optional[str]) -> bool:
    """Compare two history IDs, treating them as integers when numeric."""
    if new_id is None:
        return False
    if old_id is None:
        return True
    try:
        return int(new_id) > int(old_id)
    except (ValueError, TypeError):
        return str(new_id) > str(old_id)


async def update_history_id(
    db: AsyncSession,
    gmail_account_id: str,
    new_history_id: str,
) -> GmailAccount:
    """Update last_history_id using a SELECT ... FOR UPDATE row lock to serialize concurrent updates.

    Only updates last_history_id if new_history_id > current last_history_id.
    """
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.id == gmail_account_id)
        .with_for_update()
    )
    account = (await db.execute(stmt)).scalar_one()
    now = datetime.now(timezone.utc)
    if is_greater_history_id(new_history_id, account.last_history_id):
        account.last_history_id = str(new_history_id)
    account.last_sync_at = now
    account.updated_at = now
    await db.commit()
    await db.refresh(account)
    return account


async def update_watch_expiration(
    db: AsyncSession,
    gmail_account_id: str,
    expiration: datetime,
) -> GmailAccount:
    """Update watch_expiration timestamp for Pub/Sub push subscription."""
    stmt = select(GmailAccount).where(GmailAccount.id == gmail_account_id)
    account = (await db.execute(stmt)).scalar_one()
    account.watch_expiration = expiration
    account.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(account)
    return account
