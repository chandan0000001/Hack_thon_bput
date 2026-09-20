"""Authentication context, signup/sign-in, and current user endpoints.

Phase -1: signup/sign-in are mediated by the backend so usernames can be
enforced and resolved server-side. Organization endpoints are frozen behind
``require_org_enabled`` until the Orgs Phase.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.errors import ConflictError, PermissionDeniedError, ValidationError
from app.core.security import (
    USERNAME_PATTERN,
    CurrentUser,
    TenantContext,
    get_current_user,
    get_tenant_context,
    require_org_enabled,
)
from app.db.admin import is_username_taken, resolve_email_for_identifier
from app.db.models import Organization, OrganizationMember, User
from app.db.session import current_user_id, get_db

logger = logging.getLogger("cyberguard.auth")

router = APIRouter(prefix="/auth", tags=["Auth"])

ORG_COMING_SOON = "Organization accounts are coming soon."


class SwitchOrgRequest(BaseModel):
    organization_id: str


class SignupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    username: str = Field(min_length=3, max_length=32)
    full_name: Optional[str] = Field(default=None, max_length=255)


class SigninRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)  # email or username
    password: str = Field(min_length=1, max_length=128)


class NotificationEmailUpdate(BaseModel):
    notification_email: Optional[str] = Field(default=None, max_length=255)


@router.get("/config")
async def auth_config() -> dict[str, Any]:
    """Public bootstrap config for pre-auth pages (no token required)."""
    return {"org_enabled": get_settings().ORG_ENABLED}


@router.get("/username-available")
async def username_available(username: str) -> dict[str, Any]:
    """Check username availability (validated against the signup pattern)."""
    if not USERNAME_PATTERN.match(username or ""):
        return {"available": False, "reason": "invalid"}
    taken = await is_username_taken(username)
    return {"available": not taken, "reason": "taken" if taken else None}


@router.post("/signup")
async def signup(
    payload: SignupRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Create a Supabase auth user and the project user row with a unique username."""
    username = payload.username.strip().lower()
    if not USERNAME_PATTERN.match(username):
        raise ValidationError("Username must be 3-32 chars: lowercase letters, digits, '_' or '.'")

    if await is_username_taken(username):
        raise ConflictError("Username is already taken")

    # Create the Supabase auth identity first (project row needs its id).
    from app.core.security import _get_anon_client

    try:
        result = _get_anon_client().auth.sign_up(
            {
                "email": payload.email.strip().lower(),
                "password": payload.password,
                "options": {"data": {"full_name": payload.full_name, "username": username}},
            }
        )
    except Exception as exc:
        message = str(exc)
        if "already" in message.lower() and ("registered" in message.lower() or "exists" in message.lower()):
            raise ConflictError("An account with this email already exists")
        logger.warning("Supabase signup failed: %s", message)
        raise PermissionDeniedError("Signup failed: " + message)

    sb_user = getattr(result, "user", None)
    if sb_user is None:
        raise PermissionDeniedError("Signup failed: no user returned")
    if getattr(result, "session", None) is None and getattr(sb_user, "email_confirmed_at", None) is not None:
        # Email already confirmed by a prior identity; treat as duplicate email.
        raise ConflictError("An account with this email already exists")

    auth_id = str(sb_user.id)
    email = getattr(sb_user, "email", None) or payload.email.strip().lower()
    full_name = payload.full_name

    # Publish identity for the RLS GUC so the insert satisfies users policies
    # (id = current_setting('app.user_id')).
    current_user_id.set(auth_id)

    user = User(
        id=auth_id,
        email=email,
        username=username,
        account_type="user",
        full_name=full_name,
        is_single_user=True,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise ConflictError("Username is already taken")
    await db.refresh(user)

    session = getattr(result, "session", None)
    return {
        "confirmation_pending": session is None,
        "user": {"id": user.id, "email": user.email, "username": user.username},
        "session": None
        if session is None
        else {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        },
    }


@router.post("/signin")
async def signin(payload: SigninRequest) -> dict[str, Any]:
    """Sign in with email or username; usernames are resolved server-side."""
    identifier = payload.identifier.strip()
    email = identifier.lower() if "@" in identifier else None
    if email is None:
        email = await resolve_email_for_identifier(identifier.lower())
        if not email:
            raise PermissionDeniedError("Invalid email/username or password")

    from app.core.security import _get_anon_client

    try:
        result = _get_anon_client().auth.sign_in_with_password(
            {"email": email, "password": payload.password}
        )
    except Exception:
        raise PermissionDeniedError("Invalid email/username or password")

    session = getattr(result, "session", None)
    sb_user = getattr(result, "user", None)
    if session is None or sb_user is None:
        raise PermissionDeniedError("Invalid email/username or password")

    return {
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
        "expires_in": session.expires_in,
        "token_type": session.token_type,
        "user": {
            "id": str(sb_user.id),
            "email": getattr(sb_user, "email", None),
        },
    }


@router.get("/me")
async def read_current_user(
    user: CurrentUser = Depends(get_current_user),
    tenant: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return profile details, active workspace, and organization memberships."""
    orgs_list = []
    personal_org_id = None

    if get_settings().ORG_ENABLED:
        # Organization features are frozen by default; membership queries only
        # run in org mode so personal requests never depend on org rows.
        query = (
            select(User)
            .options(selectinload(User.memberships).selectinload(OrganizationMember.organization))
            .where(User.id == user.id)
        )
        res = await db.execute(query)
        user_db = res.scalar_one()
        for m in user_db.memberships:
            org = m.organization
            if org.is_personal:
                personal_org_id = org.id
            orgs_list.append(
                {
                    "id": org.id,
                    "name": org.name,
                    "slug": org.slug,
                    "is_personal": org.is_personal,
                    "role": m.role,
                }
            )

    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "username": user.username,
        "account_type": user.account_type,
        "notification_email": user.notification_email,
        "org_enabled": get_settings().ORG_ENABLED,
        "is_single_user": tenant.is_single_user,
        "active_role": tenant.role,
        "active_organization": None
        if tenant.organization_id is None
        else {
            "id": tenant.organization_id,
            "name": tenant.organization_name,
            "is_personal": tenant.is_single_user,
            "role": tenant.role,
        },
        "personal_organization_id": personal_org_id,
        "organizations": orgs_list,
    }


@router.put("/notification-email")
async def update_notification_email(
    payload: NotificationEmailUpdate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Register the address that receives system notifications.

    Strictly separate from any connected mailbox: system notifications NEVER
    go to connected mailboxes (privacy boundary)."""
    from app.core.errors import ValidationError

    email = (payload.notification_email or "").strip().lower() or None
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        raise ValidationError("notification_email must be a valid email address")

    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one()
    user_db.notification_email = email
    await db.commit()
    return {
        "notification_email": email,
        "message": "Notification email updated." if email else "Notification email cleared.",
    }


@router.post("/switch-org", dependencies=[Depends(require_org_enabled())])
async def switch_organization(
    payload: SwitchOrgRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Switch user's default active organization."""
    # Verify user is a member of the target organization
    member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == payload.organization_id,
            OrganizationMember.user_id == user.id,
        )
    )
    membership = member_query.scalar_one_or_none()
    if membership is None:
        # Check if owner
        org_query = await db.execute(select(Organization).where(Organization.id == payload.organization_id))
        org = org_query.scalar_one_or_none()
        if org is None or org.owner_id != user.id:
            raise PermissionDeniedError("You are not a member of this organization")

    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one()
    user_db.active_organization_id = payload.organization_id
    await db.commit()

    # ORG-WIRE: pipeline stamping caches this resolution per owner.
    from app.services.org_context import invalidate as invalidate_org_cache

    invalidate_org_cache(user.id)

    return {"message": "Active organization updated", "active_organization_id": payload.organization_id}
