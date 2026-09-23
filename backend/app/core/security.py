"""Authentication and Role-Based Access Control (RBAC) with Multi-Tenancy.

Phase -1 (user-only foundation):
1. Personal (single-user) mode is the active path: every row is owner-scoped
   via ``owner_user_id`` and PostgreSQL row-level security keyed on the
   ``app.user_id`` GUC.
2. Organization mode is frozen behind ``ORG_ENABLED`` (default False); the
   org tables and code paths below are kept intact for the later Orgs Phase.
"""

import logging
import re
import uuid
from typing import Callable, Optional

from fastapi import Depends, Header, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from supabase import Client, create_client

from app.core.config import get_settings
from app.core.errors import ComingSoonError, NotFoundError, PermissionDeniedError
from app.db.models import OrgMember, OrgOrganization, User
from app.db.session import current_user_id, get_db, set_session_user

logger = logging.getLogger("cyberguard.security")

bearer_scheme = HTTPBearer(auto_error=False)

USERNAME_PATTERN = re.compile(r"^[a-z0-9_.]{3,32}$")

ORG_COMING_SOON = "Organization accounts are coming soon."


class CurrentUser(BaseModel):
    """Identity of the authenticated user."""

    id: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    username: Optional[str] = None
    account_type: str = "personal"
    role: Optional[str] = None
    notification_email: Optional[str] = None


class TenantContext(BaseModel):
    """Context defining the active user, active organization, and user's role.

    Personal workspaces carry ``organization_id = None`` and scope all data by
    ``owner_user_id`` instead.
    """

    user_id: str
    user_email: Optional[str] = None
    # Owner scope for personal workspaces; defaults keep hand-built contexts
    # (tests, scripts) valid. _personal_tenant always sets it to user_id.
    owner_user_id: str = ""
    organization_id: Optional[str] = None
    organization_name: str = "Personal Workspace"
    role: str  # 'admin' | 'analyst' | 'viewer'
    is_single_user: bool  # True when accessing personal workspace
    # ORG-REDESIGN: project scope when the request carries one (project
    # gateway calls, or JWT paths resolved against the active project).
    project_id: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}


def tenant_criteria(model, tenant: TenantContext):
    """SQLAlchemy filter scoping ``model`` rows to the active tenant.

    Personal tenants filter by ``owner_user_id``; organization tenants (frozen
    until the Orgs Phase) filter by ``organization_id``.
    """
    if tenant.organization_id is None:
        return model.owner_user_id == tenant.owner_user_id
    return model.organization_id == tenant.organization_id


def require_org_enabled() -> Callable:
    """Dependency freezing organization endpoints until the Orgs Phase."""

    async def _check() -> None:
        if not get_settings().ORG_ENABLED:
            raise ComingSoonError(ORG_COMING_SOON)

    return _check


def _get_anon_client() -> Client:
    """Create a Supabase client with the anon key for token verification."""
    settings = get_settings()
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)


def _sanitize_username_prefix(raw: str) -> str:
    prefix = re.sub(r"[^a-z0-9_.]", "", (raw or "").lower())
    return prefix[:32]


async def _generate_unique_username(db: AsyncSession, email: Optional[str], user_id: str) -> str:
    """Generate a unique username from the email prefix (clash → '-2', '-3', ...).

    Uniqueness is checked via the service-role lookup because RLS on ``users``
    hides other accounts from the app-role session; the DB unique constraint
    remains the final enforcement.
    """
    from app.db.admin import is_username_taken

    base = _sanitize_username_prefix((email or "").split("@")[0]) or "user"
    for suffix in ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"]:
        candidate = f"{base}{suffix}"
        if not await is_username_taken(candidate):
            return candidate
    return f"user-{uuid.uuid4().hex[:8]}"


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    x_auth_mode: Optional[str] = Header(None),
) -> CurrentUser:
    """Verify Supabase bearer token and ensure the user exists in the local database."""
    if credentials is None or not credentials.credentials:
        raise PermissionDeniedError("Missing authentication token")

    token = credentials.credentials
    user_id: str
    email: Optional[str] = None
    full_name: Optional[str] = None

    # Verify via Supabase Auth
    try:
        response = _get_anon_client().auth.get_user(token)
        sb_user = getattr(response, "user", None)
        if sb_user is None:
            raise PermissionDeniedError("Invalid or expired authentication token")
        user_id = str(sb_user.id)
        email = getattr(sb_user, "email", None)
        user_meta = getattr(sb_user, "user_metadata", {}) or {}
        full_name = user_meta.get("full_name") or user_meta.get("name")
    except PermissionDeniedError:
        raise
    except Exception as exc:
        # Fallback for mock/test tokens in demo or local scripts
        if len(token) > 4 and ("demo" in token or "test" in token):
            clean_token = token.replace("demo-", "").replace("test-", "")
            if "@" in clean_token:
                email = clean_token
                user_id = f"user-{clean_token.split('@')[0]}"
            else:
                user_id = f"user-{clean_token[:12]}"
                email = f"{clean_token[:10]}@cyberguard.local"
            full_name = "Analyst"
        else:
            logger.warning("Token verification failed: %s", exc)
            raise PermissionDeniedError("Invalid or expired authentication token")

    # Publish the verified identity for the row-level-security GUC. This must
    # happen before any SQL runs on the request's session (the session was
    # acquired before this dependency executed).
    current_user_id.set(user_id)
    await set_session_user(db, user_id)

    # Upsert user in database: check by ID or email
    user_query = await db.execute(select(User).where(User.id == user_id))
    user = user_query.scalar_one_or_none()
    if user is None and email:
        from app.db.admin import claim_invited_stub, find_user_by_email

        admin_info = await find_user_by_email(email)
        if admin_info:
            stub_id = admin_info["id"]
            if stub_id != user_id:
                await claim_invited_stub(old_user_id=stub_id, new_user_id=user_id)
            user_query = await db.execute(select(User).where(User.id == user_id))
            user = user_query.scalar_one_or_none()
        else:
            email_query = await db.execute(select(User).where(User.email == email))
            user = email_query.scalar_one_or_none()

    if user is None:
        # OAuth / first-login JIT row: auto-generate a unique username.
        username = await _generate_unique_username(db, email, user_id)
        jit_account_type = "org" if (isinstance(x_auth_mode, str) and x_auth_mode.lower() == "org") else "personal"
        user = User(
            id=user_id,
            email=email,
            username=username,
            account_type=jit_account_type,
            full_name=full_name,
            status="active",
            is_single_user=(jit_account_type == "personal"),
        )
        db.add(user)
        try:
            await db.commit()
            await db.refresh(user)
        except IntegrityError:
            await db.rollback()
            user_query = await db.execute(select(User).where(User.id == user_id))
            user = user_query.scalar_one_or_none()
            if user is None and email:
                user_query = await db.execute(select(User).where(User.email == email))
                user = user_query.scalar_one_or_none()
    else:
        if not user.email and email:
            user.email = email
        if not user.full_name and full_name:
            user.full_name = full_name
        if not user.username and email:
            # Pre-phase rows created before usernames existed.
            user.username = await _generate_unique_username(db, email, user.id)
        if getattr(user, "status", None) == "invited":
            user.status = "active"
        if user.account_type == "personal":
            user.is_single_user = True
        await db.commit()

    current_user_id.set(user.id)
    await set_session_user(db, user.id)

    return CurrentUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        username=user.username,
        account_type=user.account_type or "personal",
        notification_email=user.notification_email,
    )


async def _personal_tenant(user: CurrentUser) -> TenantContext:
    return TenantContext(
        user_id=user.id,
        user_email=user.email,
        owner_user_id=user.id,
        organization_id=None,
        organization_name="Personal Workspace",
        role="admin",
        is_single_user=True,
    )


async def get_tenant_context(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    x_organization_id: Optional[str] = Header(None),
    org_id: Optional[str] = Query(None),
) -> TenantContext:
    """Resolve the active tenant for the request.

    With ``ORG_ENABLED=False`` (default) every request resolves to the user's
    personal workspace; organization resolution is frozen until the Orgs Phase.
    """
    await set_session_user(db, user.id)

    if not get_settings().ORG_ENABLED:
        return await _personal_tenant(user)

    target_org_id = x_organization_id or org_id

    # 1. If a specific organization was requested
    if target_org_id:
        # Check membership directly via OrgMember
        mem_query = await db.execute(
            select(OrgMember, OrgOrganization)
            .join(OrgOrganization, OrgMember.organization_id == OrgOrganization.id)
            .where(
                OrgMember.organization_id == target_org_id,
                OrgMember.user_id == user.id,
            )
        )
        row = mem_query.first()
        if row is not None:
            member, organization = row
            return TenantContext(
                user_id=user.id,
                user_email=user.email,
                owner_user_id=organization.owner_id,
                organization_id=organization.id,
                organization_name=organization.name,
                role=member.role,
                is_single_user=False,
            )

        # Check if owner
        org_query = await db.execute(select(OrgOrganization).where(OrgOrganization.id == target_org_id))
        organization = org_query.scalar_one_or_none()
        if organization is None:
            raise NotFoundError("Organization", target_org_id)
        if organization.owner_id != user.id:
            raise PermissionDeniedError("You are not a member of this organization")

        return TenantContext(
            user_id=user.id,
            user_email=user.email,
            owner_user_id=organization.owner_id,
            organization_id=organization.id,
            organization_name=organization.name,
            role="admin",
            is_single_user=False,
        )

    # 2. Look for user's active organization
    user_db_query = await db.execute(select(User.active_organization_id).where(User.id == user.id))
    active_org_id = user_db_query.scalar_one_or_none()

    if active_org_id:
        mem_query = await db.execute(
            select(OrgMember, OrgOrganization)
            .join(OrgOrganization, OrgMember.organization_id == OrgOrganization.id)
            .where(
                OrgMember.organization_id == active_org_id,
                OrgMember.user_id == user.id,
            )
        )
        row = mem_query.first()
        if row is not None:
            member, organization = row
            return TenantContext(
                user_id=user.id,
                user_email=user.email,
                owner_user_id=organization.owner_id,
                organization_id=organization.id,
                organization_name=organization.name,
                role=member.role,
                is_single_user=False,
            )

    # 3. Fallback to personal workspace (no organization row is created; org
    # tables stay frozen until the Orgs Phase).
    return await _personal_tenant(user)


def require_role(allowed_roles: list[str]) -> Callable:
    """Dependency enforcing that the user has one of the allowed roles in the active organization.

    In single-user mode (personal workspace), the owner has full admin access to all features.
    """

    async def _role_checker(tenant: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        # Personal workspace owners always have full access
        if tenant.is_single_user:
            return tenant

        if tenant.role not in allowed_roles:
            raise PermissionDeniedError(
                f"Role '{tenant.role}' does not have permission. Required role: {', '.join(allowed_roles)}"
            )
        return tenant

    return _role_checker
