"""Service-role database access for pre-authentication lookups.

Row-level security on ``cyberguard.users`` denies anonymous reads, so the two
lookup operations that must happen *before* a request is authenticated
(username availability, username → email resolution at sign-in) run on a
separate engine built from ``MIGRATION_DATABASE_URL`` (the service/postgres
role, which bypasses RLS). On SQLite (tests/local dev) there is no RLS and the
main database is used directly.
"""

import logging
from functools import lru_cache
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.db.admin")


def _to_async_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@lru_cache(maxsize=1)
def _get_admin_session_maker() -> async_sessionmaker:
    settings = get_settings()
    if "sqlite" in settings.async_database_url:
        # No RLS on SQLite (tests/local): admin lookups share the app database
        # so test runs stay deterministic regardless of MIGRATION_DATABASE_URL.
        # The schema-translate map resolves the "cyberguard" prefix.
        url = settings.async_database_url
        options = {
            "connect_args": {"check_same_thread": False},
            "execution_options": {"schema_translate_map": {"cyberguard": None}},
        }
    else:
        url = _to_async_url(settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL)
        options = {}
    engine = create_async_engine(url, echo=False, future=True, **options)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def is_username_taken(username: str) -> bool:
    """Return True when the username already exists (service-role lookup)."""
    from app.db.models import User

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(User.id).where(User.username == username).limit(1)
        )
        return result.scalar_one_or_none() is not None


async def resolve_email_for_identifier(identifier: str) -> Optional[str]:
    """Resolve a username (or bare email) to its account email (service-role lookup)."""
    from app.db.models import User

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(User.email).where(User.username == identifier).limit(1)
        )
        return result.scalar_one_or_none()


async def find_user_by_email(email: str) -> Optional[dict]:
    """Resolve an account by email (service-role lookup).

    RLS on ``users`` hides other accounts from the app role, so org admin
    member-invites resolve invitees through the service role. Returns
    {id, email, full_name, status, username} or None.
    """
    from app.db.models import User

    clean_email = (email or "").strip().lower()
    async with _get_admin_session_maker()() as session:
        result = await session.execute(select(User).where(User.email == clean_email).limit(1))
        user = result.scalar_one_or_none()
        if user is None:
            return None
        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "status": getattr(user, "status", "active") or "active",
            "username": user.username,
        }


async def precreate_user_for_invite(email: str) -> dict:
    """Pre-create a stub user row with status='invited' for a member invite so
    they can join and claim the account on first login (service-role write).
    Handles race conditions gracefully."""
    import uuid as _uuid
    from sqlalchemy.exc import IntegrityError
    from app.db.models import User

    clean_email = (email or "").strip().lower()
    async with _get_admin_session_maker()() as session:
        result = await session.execute(select(User).where(User.email == clean_email).limit(1))
        user = result.scalar_one_or_none()
        if user is not None:
            return {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "status": getattr(user, "status", "active") or "active",
                "username": user.username,
            }

        user = User(
            id=str(_uuid.uuid4()),
            email=clean_email,
            full_name=clean_email.split("@")[0],
            status="invited",
            is_single_user=False,
        )
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            result = await session.execute(select(User).where(User.email == clean_email).limit(1))
            user = result.scalar_one()

        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "status": getattr(user, "status", "active") or "active",
            "username": user.username,
        }


async def claim_invited_stub(old_user_id: str, new_user_id: str) -> None:
    """Migrate an invited stub user row and its memberships to the authenticated user ID."""
    from sqlalchemy import update
    from app.db.models import OrgMember, User

    async with _get_admin_session_maker()() as session:
        await session.execute(
            update(OrgMember).where(OrgMember.user_id == old_user_id).values(user_id=new_user_id)
        )
        await session.execute(
            update(User).where(User.id == old_user_id).values(id=new_user_id, status="active")
        )
        await session.commit()


# --- Connector OAuth state (service-role; the Gmail callback carries no
# bearer token, so it cannot pass RLS. Acceptable because state is
# high-entropy, expires after CONNECTOR_OAUTH_STATE_TTL_SECONDS, is
# single-use, and no token is ever exposed to the frontend). ---


async def consume_connector_oauth_state(state: str) -> Optional[dict]:
    """Atomically read-and-delete a single-use OAuth state row.

    Returns {owner_user_id, provider, redirect_after} or None when unknown,
    already consumed, or expired.
    """
    from datetime import datetime, timezone

    from sqlalchemy import delete

    from app.db.models import ConnectorOAuthState

    async with _get_admin_session_maker()() as session:
        result = await session.execute(
            select(ConnectorOAuthState).where(ConnectorOAuthState.state == state)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        # Delete first (single-use), then validate expiry.
        await session.execute(
            delete(ConnectorOAuthState).where(ConnectorOAuthState.state == state)
        )
        await session.commit()
        expires_at = row.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            # SQLite returns naive datetimes; treat as UTC.
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at is not None and expires_at < datetime.now(timezone.utc):
            return None
        return {
            "owner_user_id": row.owner_user_id,
            "provider": row.provider,
            "redirect_after": row.redirect_after,
        }


async def log_connector_operation_admin(
    *,
    owner_user_id: str,
    provider: str,
    operation: str,
    status: str,
    connector_id: Optional[str] = None,
    message: Optional[str] = None,
    provider_error_code: Optional[str] = None,
    provider_error_detail: Optional[str] = None,
) -> None:
    """Write a connector operation log via the service role (pre-auth paths)."""
    import logging
    import uuid

    from app.db.models import ConnectorOperationLog

    logger_ = logging.getLogger("cyberguard.connectors")
    try:
        async with _get_admin_session_maker()() as session:
            session.add(
                ConnectorOperationLog(
                    id=str(uuid.uuid4()),
                    owner_user_id=owner_user_id,
                    connector_id=connector_id,
                    provider=provider,
                    operation=operation,
                    status=status,
                    message=message,
                    provider_error_code=provider_error_code,
                    provider_error_detail=provider_error_detail,
                )
            )
            await session.commit()
    except Exception:  # noqa: BLE001 - logging must never break the flow
        logger_.exception("Failed to write connector operation log (admin)")
