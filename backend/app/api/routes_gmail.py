"""Gmail lifecycle and status API routes.

Provides endpoints for:
- POST /gmail/disconnect: stop watch, revoke tokens, clear credentials, mark disconnected.
- GET /gmail/status: return current connection status without exposing sensitive credentials.
- GET /gmail/accounts: return connected and recent accounts split with 3-day TTL.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.security import CurrentUser, get_current_user
from app.db.models import GmailAccount
from app.db.session import get_db
from app.schemas.connectors import GmailAccountItem, GmailAccountsListResponse
from app.services.gmail.client import GmailClient
from app.services.gmail_account_service import perform_gmail_disconnect

logger = logging.getLogger("cyberguard.routes_gmail")

router = APIRouter(tags=["Gmail Lifecycle"])


class GmailDisconnectResponse(BaseModel):
    success: bool
    message: str
    status: str = "disconnected"


class GmailStatusResponse(BaseModel):
    connected: bool
    email: Optional[str] = None
    status: str = Field(description="connected or disconnected")


def get_gmail_client() -> GmailClient:
    """Dependency provider for GmailClient to allow overriding in tests."""
    return GmailClient()


@router.get("/gmail/status", response_model=GmailStatusResponse)
async def get_gmail_status(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> GmailStatusResponse:
    """Return current Gmail connection status without exposing sensitive credentials."""
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == current_user.id)
        .order_by(GmailAccount.created_at.desc())
    )
    account = (await db.execute(stmt)).scalars().first()

    if account is None or account.status != "connected":
        return GmailStatusResponse(
            connected=False,
            email=account.email if account and account.status != "purged" else None,
            status="disconnected",
        )

    return GmailStatusResponse(
        connected=True,
        email=account.email,
        status="connected",
    )


@router.post("/gmail/disconnect", response_model=GmailDisconnectResponse)
async def disconnect_gmail(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    gmail_client: GmailClient = Depends(get_gmail_client),
) -> GmailDisconnectResponse:
    """Disconnect Gmail integration for the current authenticated user.

    Idempotent operation:
    - 404 if no Gmail account exists for this user.
    - If status is already 'disconnected', returns success immediately without Google API calls.
    - If connected: calls gmail.users.stop, revokes Google OAuth token, marks disconnected,
      and cleans up stored credentials.
    """
    stmt = (
        select(GmailAccount)
        .where(GmailAccount.owner_user_id == current_user.id)
        .order_by(GmailAccount.created_at.desc())
    )
    account = (await db.execute(stmt)).scalars().first()

    if account is None:
        raise NotFoundError("Gmail account not found")

    res = await perform_gmail_disconnect(db, account, gmail_client=gmail_client)
    return GmailDisconnectResponse(**res)


@router.get("/gmail/accounts", response_model=GmailAccountsListResponse)
async def list_gmail_accounts_route(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    now: Optional[str] = Query(default=None),
    x_test_now: Optional[str] = Header(default=None, alias="X-Test-Now"),
) -> GmailAccountsListResponse:
    """List Gmail accounts separated into active connected and recently disconnected (3-day TTL)."""
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
        if acc.status == "connected":
            connected_list.append(
                GmailAccountItem(
                    id=acc.id,
                    email=acc.email,
                    status="connected",
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
