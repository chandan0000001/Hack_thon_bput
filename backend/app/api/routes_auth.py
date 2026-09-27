"""Authentication context, signup/sign-in, and current user endpoints.

Phase -1: signup/sign-in are mediated by the backend so usernames can be
enforced and resolved server-side. Organization endpoints are frozen behind
``require_org_enabled`` until the Orgs Phase.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.errors import (
    AccountTypeMismatchError,
    ConflictError,
    EmailExistsError,
    InvalidCredentialsError,
    PermissionDeniedError,
    UnauthorizedError,
    ValidationError,
)
from app.core.security import (
    USERNAME_PATTERN,
    CurrentUser,
    TenantContext,
    _generate_unique_username,
    get_current_user,
    get_tenant_context,
    require_org_enabled,
)
from app.db.admin import find_user_by_email, is_username_taken, resolve_email_for_identifier
from app.db.models import (
    Organization,
    OrganizationMember,
    OrgMember,
    OrgOrganization,
    OrgProject,
    Project,
    User,
)
from app.db.session import current_user_id, get_db, set_session_user

logger = logging.getLogger("cyberguard.auth")

router = APIRouter(prefix="/auth", tags=["Auth"])

ORG_COMING_SOON = "Organization accounts are coming soon."


class SwitchOrgRequest(BaseModel):
    organization_id: str


class SignupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    username: Optional[str] = Field(default=None, max_length=32)
    name: Optional[str] = Field(default=None, max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=255)


class RegisterOrgRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    org_name: str = Field(min_length=2, max_length=120)
    name: Optional[str] = Field(default=None, max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=255)
    username: Optional[str] = Field(default=None, max_length=32)


class SigninRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)  # email or username
    password: str = Field(min_length=1, max_length=128)
    mode: Optional[str] = Field(default="personal", max_length=16)


class VerifyOtpRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    token: str = Field(min_length=1, max_length=128)
    type: Optional[str] = "email"
    mode: Optional[str] = "personal"


class OAuthCallbackRequest(BaseModel):
    code: Optional[str] = None
    mode: Optional[str] = "personal"
    email: Optional[str] = None
    state: Optional[str] = None


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


@router.post("/register", status_code=status.HTTP_201_CREATED)
@router.post("/signup", status_code=status.HTTP_200_OK)
async def signup(
    payload: SignupRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Create a Supabase auth user and the project user row with a unique username."""
    email_clean = payload.email.strip().lower()

    # Pre-check email existence in local DB
    target_user = await find_user_by_email(email_clean)
    if target_user:
        if target_user.get("status") == "invited":
            raise EmailExistsError(
                message="An account with this email already exists.",
                hint="check_invite",
            )
        raise EmailExistsError(
            message="An account with this email already exists.",
            hint="sign_in",
        )

    raw_user = (payload.username or "").strip().lower()
    if raw_user:
        if not USERNAME_PATTERN.match(raw_user):
            raise ValidationError("Username must be 3-32 chars: lowercase letters, digits, '_' or '.'")
        if await is_username_taken(raw_user):
            raise ConflictError("Username is already taken")
        username = raw_user
    else:
        username = await _generate_unique_username(db, email_clean, "usr")

    full_name = payload.name or payload.full_name

    # Create the Supabase auth identity first (project row needs its id).
    from app.core.security import _get_anon_client

    try:
        result = _get_anon_client().auth.sign_up(
            {
                "email": email_clean,
                "password": payload.password,
                "options": {"data": {"full_name": full_name, "username": username}},
            }
        )
    except Exception as exc:
        message = str(exc)
        if "already" in message.lower() and ("registered" in message.lower() or "exists" in message.lower()):
            target_user = await find_user_by_email(email_clean)
            hint = "check_invite" if (target_user and target_user.get("status") == "invited") else "sign_in"
            raise EmailExistsError(
                message="An account with this email already exists.",
                hint=hint,
            )
        logger.warning("Supabase signup failed: %s", message)
        raise PermissionDeniedError("Signup failed: " + message)

    sb_user = getattr(result, "user", None)
    if sb_user is None:
        raise PermissionDeniedError("Signup failed: no user returned")
    if getattr(result, "session", None) is None and getattr(sb_user, "email_confirmed_at", None) is not None:
        target_user = await find_user_by_email(email_clean)
        hint = "check_invite" if (target_user and target_user.get("status") == "invited") else "sign_in"
        raise EmailExistsError(
            message="An account with this email already exists.",
            hint=hint,
        )

    auth_id = str(sb_user.id)
    email = getattr(sb_user, "email", None) or email_clean

    # Publish identity for the RLS GUC so the insert satisfies users policies
    current_user_id.set(auth_id)
    await set_session_user(db, auth_id)

    user = User(
        id=auth_id,
        email=email,
        username=username,
        account_type="personal",
        full_name=full_name,
        status="active",
        is_single_user=True,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        err_msg = str(exc).lower()
        if "email" in err_msg or "ix_cyberguard_users_email" in err_msg:
            target_user = await find_user_by_email(email)
            hint = "check_invite" if (target_user and target_user.get("status") == "invited") else "sign_in"
            raise EmailExistsError(
                message="An account with this email already exists.",
                hint=hint,
            )
        raise ConflictError("Username is already taken")
    await db.refresh(user)

    session = getattr(result, "session", None)
    return {
        "confirmation_pending": session is None,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "status": getattr(user, "status", "active"),
        },
        "session": None
        if session is None
        else {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        },
        "access_token": session.access_token if session else None,
        "refresh_token": session.refresh_token if session else None,
    }


@router.post("/register-org", status_code=status.HTTP_201_CREATED)
async def register_org(
    payload: RegisterOrgRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Atomically create user, organization, admin membership, and default project."""
    email_clean = payload.email.strip().lower()

    # Pre-check email existence in local DB
    target_user = await find_user_by_email(email_clean)
    if target_user:
        raise EmailExistsError(
            message="An account with this email already exists.",
            hint="sign_in_then_create_org",
        )

    org_name = payload.org_name.strip()
    if len(org_name) < 2:
        raise ValidationError("Organization name must be at least 2 characters.")

    raw_user = (payload.username or "").strip().lower()
    if raw_user:
        if not USERNAME_PATTERN.match(raw_user):
            raise ValidationError("Username must be 3-32 chars: lowercase letters, digits, '_' or '.'")
        if await is_username_taken(raw_user):
            raise ConflictError("Username is already taken")
        username = raw_user
    else:
        username = await _generate_unique_username(db, email_clean, "org")

    full_name = payload.name or payload.full_name or org_name

    from app.core.security import _get_anon_client

    try:
        result = _get_anon_client().auth.sign_up(
            {
                "email": email_clean,
                "password": payload.password,
                "options": {"data": {"full_name": full_name, "username": username, "org_name": org_name}},
            }
        )
    except Exception as exc:
        message = str(exc)
        if "already" in message.lower() and ("registered" in message.lower() or "exists" in message.lower()):
            raise EmailExistsError(
                message="An account with this email already exists.",
                hint="sign_in_then_create_org",
            )
        logger.warning("Supabase signup failed in register-org: %s", message)
        raise PermissionDeniedError("Registration failed: " + message)

    sb_user = getattr(result, "user", None)
    if sb_user is None:
        raise PermissionDeniedError("Registration failed: no user returned")
    if getattr(result, "session", None) is None and getattr(sb_user, "email_confirmed_at", None) is not None:
        raise EmailExistsError(
            message="An account with this email already exists.",
            hint="sign_in_then_create_org",
        )

    auth_id = str(sb_user.id)
    email = getattr(sb_user, "email", None) or email_clean

    current_user_id.set(auth_id)
    await set_session_user(db, auth_id)

    org_id = str(uuid.uuid4())
    member_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    user = User(
        id=auth_id,
        email=email,
        username=username,
        account_type="org",
        full_name=full_name,
        status="active",
        is_single_user=False,
        active_organization_id=org_id,
        active_project_id=project_id,
        created_at=now,
    )
    db.add(user)

    org = OrgOrganization(
        id=org_id,
        name=org_name,
        owner_id=auth_id,
        status="active",
        created_at=now,
    )
    db.add(org)

    member = OrgMember(
        id=member_id,
        organization_id=org_id,
        user_id=auth_id,
        role="admin",
        joined_at=now,
    )
    db.add(member)

    project = OrgProject(
        id=project_id,
        organization_id=org_id,
        name="Default Project",
        slug="default",
        status="active",
        created_at=now,
    )
    db.add(project)

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        err_msg = str(exc).lower()
        if "email" in err_msg or "ix_cyberguard_users_email" in err_msg:
            raise EmailExistsError(
                message="An account with this email already exists.",
                hint="sign_in_then_create_org",
            )
        raise ConflictError("Username is already taken")

    session = getattr(result, "session", None)
    return {
        "confirmation_pending": session is None,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "status": user.status,
            "active_organization_id": user.active_organization_id,
            "active_project_id": user.active_project_id,
        },
        "organization": {
            "id": org.id,
            "name": org.name,
            "role": "admin",
        },
        "project": {
            "id": project.id,
            "name": project.name,
            "slug": project.slug,
        },
        "memberships": [
            {
                "id": org.id,
                "organization_id": org.id,
                "name": org.name,
                "role": "admin",
                "joined_at": member.joined_at.isoformat(),
            }
        ],
        "session": None
        if session is None
        else {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        },
        "access_token": session.access_token if session else None,
        "refresh_token": session.refresh_token if session else None,
    }


@router.post("/signin")
async def signin(payload: SigninRequest) -> dict[str, Any]:
    """Sign in with email or username; usernames are resolved server-side."""
    identifier = payload.identifier.strip()
    email = identifier.lower() if "@" in identifier else None
    if email is None:
        email = await resolve_email_for_identifier(identifier.lower())
        if not email:
            raise InvalidCredentialsError()

    mode = (payload.mode or "personal").strip().lower()

    # Realm check: only a COMMITTED row with account_type='org' rejects
    # personal-mode sign-in. A missing row (empty users table) never rejects —
    # unknown emails fail at the credential check below with 401. Sign-in is
    # read-only: no provisioning happens inside this verdict path.
    target_user = await find_user_by_email(email)
    if target_user and mode == "personal" and target_user.get("account_type") == "org":
        raise AccountTypeMismatchError()

    from app.core.security import _get_anon_client

    try:
        result = _get_anon_client().auth.sign_in_with_password(
            {"email": email, "password": payload.password}
        )
    except Exception:
        raise InvalidCredentialsError()

    session = getattr(result, "session", None)
    sb_user = getattr(result, "user", None)
    if session is None or sb_user is None:
        raise InvalidCredentialsError()

    # Post-check: catch rows committed between the pre-check and token issue.
    if not target_user:
        target_user = await find_user_by_email(email)
        if target_user and mode == "personal" and target_user.get("account_type") == "org":
            raise AccountTypeMismatchError()

    resolved_account_type = (target_user.get("account_type") if target_user else None) or "personal"

    return {
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
        "expires_in": session.expires_in,
        "token_type": session.token_type,
        "user": {
            "id": str(sb_user.id),
            "email": getattr(sb_user, "email", None),
            "account_type": resolved_account_type,
        },
    }


@router.get("/callback")
async def oauth_callback_get(
    code: Optional[str] = Query(None),
    mode: Optional[str] = Query("personal"),
    email: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """OAuth redirect callback handler."""
    resolved_mode = (mode or "personal").strip().lower()
    if state and "mode=org" in state.lower():
        resolved_mode = "org"
    elif state and "mode=personal" in state.lower():
        resolved_mode = "personal"

    resolved_email = email
    if not resolved_email and code:
        if "@" in code:
            resolved_email = code.strip().lower()
        else:
            try:
                from app.core.security import _get_anon_client
                res = _get_anon_client().auth.exchange_code_for_session({"auth_code": code})
                sb_user = getattr(res, "user", None)
                if sb_user:
                    resolved_email = getattr(sb_user, "email", None)
            except Exception:
                pass

    if resolved_email:
        target_user = await find_user_by_email(resolved_email.lower())
        if target_user:
            # Realm check: committed org accounts bounce back to the login
            # page with the mismatch banner instead of landing on /dashboard.
            if resolved_mode == "personal" and target_user.get("account_type") == "org":
                return RedirectResponse(
                    url="/login?mode=personal&error=account_type_mismatch",
                    status_code=status.HTTP_302_FOUND,
                )

    if resolved_mode == "org":
        return RedirectResponse(url="/org/select", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@router.post("/callback")
async def oauth_callback_post(
    payload: OAuthCallbackRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """OAuth token/code callback handler for API clients."""
    resolved_mode = (payload.mode or "personal").strip().lower()
    if payload.state and "mode=org" in payload.state.lower():
        resolved_mode = "org"

    resolved_email = payload.email
    if not resolved_email and payload.code:
        if "@" in payload.code:
            resolved_email = payload.code.strip().lower()
        else:
            try:
                from app.core.security import _get_anon_client
                res = _get_anon_client().auth.exchange_code_for_session({"auth_code": payload.code})
                sb_user = getattr(res, "user", None)
                if sb_user:
                    resolved_email = getattr(sb_user, "email", None)
            except Exception:
                pass

    if resolved_email:
        target_user = await find_user_by_email(resolved_email.lower())
        if target_user:
            # Realm check: committed org accounts reject personal-mode tokens.
            if resolved_mode == "personal" and target_user.get("account_type") == "org":
                raise AccountTypeMismatchError()
            return {
                "user": {
                    "id": target_user["id"],
                    "email": target_user["email"],
                    "account_type": target_user.get("account_type", "personal"),
                },
                "mode": resolved_mode,
            }
        else:
            from app.core.security import _generate_unique_username
            new_user_id = str(uuid.uuid4())
            username = await _generate_unique_username(db, resolved_email.lower(), new_user_id)
            user = User(
                id=new_user_id,
                email=resolved_email.lower(),
                username=username,
                account_type=resolved_mode,
                full_name=resolved_email.split("@")[0],
                status="active",
                is_single_user=(resolved_mode == "personal"),
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return {
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "account_type": user.account_type,
                },
                "mode": resolved_mode,
            }
    return {"status": "ok", "mode": resolved_mode}


@router.post("/verify-otp")
async def verify_otp(payload: VerifyOtpRequest) -> dict[str, Any]:
    """Verify one-time passcode with realm enforcement."""
    email = payload.email.strip().lower()
    mode = (payload.mode or "personal").strip().lower()

    target_user = await find_user_by_email(email)
    if target_user and mode == "personal" and target_user.get("account_type") == "org":
        raise AccountTypeMismatchError()

    from app.core.security import _get_anon_client
    try:
        res = _get_anon_client().auth.verify_otp({
            "email": email,
            "token": payload.token,
            "type": payload.type or "email",
        })
        session = getattr(res, "session", None)
        return {
            "session": None if not session else {
                "access_token": session.access_token,
                "refresh_token": session.refresh_token,
            }
        }
    except Exception as exc:
        raise PermissionDeniedError(str(exc))


@router.get("/me")
async def read_current_user(
    user: CurrentUser = Depends(get_current_user),
    tenant: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return profile details, active workspace, and organization memberships."""
    await set_session_user(db, user.id)
    memberships_list = []
    personal_org_id = None

    if get_settings().ORG_ENABLED:
        # Organization memberships derived directly from org_members + org_organizations
        query = (
            select(OrganizationMember, Organization)
            .join(Organization, OrganizationMember.organization_id == Organization.id)
            .where(OrganizationMember.user_id == user.id)
            .order_by(Organization.created_at.asc())
        )
        res = await db.execute(query)
        for member, org in res.all():
            if org.is_personal:
                personal_org_id = org.id
            memberships_list.append(
                {
                    "id": org.id,
                    "name": org.name,
                    "slug": org.slug,
                    "is_personal": org.is_personal,
                    "role": member.role,
                    "status": org.status,
                }
            )

    # ORG-REDESIGN: the persisted project selection (org scope only) so the
    # Topbar switcher hydrates without an extra request.
    active_project = None
    if get_settings().ORG_ENABLED and tenant.organization_id is not None:
        user_res = await db.execute(select(User.active_project_id).where(User.id == user.id))
        active_proj_id = user_res.scalar_one_or_none()
        if active_proj_id:
            res_proj = await db.execute(
                select(Project).where(
                    Project.id == active_proj_id,
                    Project.organization_id == tenant.organization_id,
                    Project.status == "active",
                )
            )
            proj = res_proj.scalar_one_or_none()
            if proj is not None:
                active_project = {"id": proj.id, "name": proj.name, "slug": proj.slug}

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
        "active_project": active_project,
        "personal_organization_id": personal_org_id,
        "memberships": memberships_list,
        "organizations": memberships_list,
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

    await set_session_user(db, user.id)
    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one_or_none()
    if user_db:
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
    await set_session_user(db, user.id)
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
    user_db = user_query.scalar_one_or_none()
    if user_db:
        user_db.active_organization_id = payload.organization_id
        await db.commit()

    # ORG-WIRE: pipeline stamping caches this resolution per owner.
    from app.services.org_context import invalidate as invalidate_org_cache

    invalidate_org_cache(user.id)

    return {"message": "Active organization updated", "active_organization_id": payload.organization_id}


class SwitchProjectRequest(BaseModel):
    project_id: Optional[str] = None  # None clears the selection


@router.post("/switch-project", dependencies=[Depends(require_org_enabled())])
async def switch_project(
    payload: SwitchProjectRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Persist the project switcher selection (org scope only).

    Validates that the project belongs to one of the user's orgs and is
    active; ``project_id: null`` clears the selection. The frontend also
    stores the value client-side and stamps ``X-Project-Id`` on requests —
    this endpoint makes the selection survive reloads and devices."""
    await set_session_user(db, user.id)
    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one_or_none()

    if payload.project_id is None:
        if user_db:
            user_db.active_project_id = None
            await db.commit()
        return {"message": "Active project cleared", "active_project_id": None}

    res = await db.execute(
        select(Project).where(
            Project.id == payload.project_id, Project.status == "active"
        )
    )
    project = res.scalar_one_or_none()
    if project is None:
        raise ValidationError("Project not found")

    # Membership of the project's org (member row or org ownership).
    member_query = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == project.organization_id,
            OrganizationMember.user_id == user.id,
        )
    )
    membership = member_query.scalar_one_or_none()
    if membership is None:
        org_query = await db.execute(
            select(Organization).where(Organization.id == project.organization_id)
        )
        org = org_query.scalar_one_or_none()
        if org is None or org.owner_id != user.id:
            raise PermissionDeniedError("You are not a member of this project's organization")

    if user_db:
        user_db.active_project_id = project.id
        await db.commit()
    return {
        "message": "Active project updated",
        "active_project_id": project.id,
        "project": {"id": project.id, "name": project.name, "slug": project.slug},
    }
