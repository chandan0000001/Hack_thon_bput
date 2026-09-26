"""Session-scoped Organization APIs (JWT only).

Implements 3-level architecture:
- Org level: Organization CRUD, membership & roles, aggregate dashboard
- Project level: Project lifecycle, API key management (plaintext-once, role-slot enforcement)
- Event level: Event review, verdict transitions, blocked indicators enforcement
"""

import hashlib
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
import inspect
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import delete, desc, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ComingSoonError, PermissionDeniedError, UnauthorizedError
from app.core.security import CurrentUser, ORG_COMING_SOON, bearer_scheme, get_current_user
from app.db.models import OrgApiKey, OrgBlockedIndicator, OrgEvent, OrgMember, OrgOrganization, OrgProject, User
from app.db.session import get_session, set_session_user

logger = logging.getLogger("cyberguard.orgs")

router = APIRouter(tags=["Organizations"])


async def get_org_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser:
    if get_org_current_user in request.app.dependency_overrides:
        override = request.app.dependency_overrides[get_org_current_user]
        res = override()
        if inspect.isawaitable(res):
            res = await res
        return res
    if get_current_user in request.app.dependency_overrides:
        override = request.app.dependency_overrides[get_current_user]
        res = override()
        if inspect.isawaitable(res):
            res = await res
        return res

    if credentials is None or not credentials.credentials:
        raise UnauthorizedError("Missing authentication token")
    try:
        return await get_current_user(credentials=credentials, db=session)
    except (PermissionDeniedError, UnauthorizedError) as exc:
        msg = str(exc)
        if "Missing" in msg or "Invalid" in msg or "expired" in msg or "Authentication required" in msg:
            raise UnauthorizedError(msg)
        raise


# ─────────────────────────────────────────────────────────────
# Request / Response Schemas
# ─────────────────────────────────────────────────────────────


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)


class UpdateOrgRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)


class InviteMemberRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    role: str = Field("viewer", pattern="^(admin|analyst|viewer)$")


class UpdateMemberRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|viewer)$")


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    slug: Optional[str] = Field(None, max_length=60)


class UpdateProjectRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    status: Optional[str] = Field(None, pattern="^(active|archived)$")


class DeleteProjectRequest(BaseModel):
    confirm_name: str = Field(..., min_length=1, max_length=120)


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    role: str = Field("master", pattern="^(master|viewer)$")


class EventVerdictActionRequest(BaseModel):
    action: str = Field(..., pattern="^(released|blocked_permanently|false_positive)$")
    reason: Optional[str] = None


class CreateBlockedIndicatorRequest(BaseModel):
    indicator_type: str = Field(..., pattern="^(ip|domain|email|hash|actor)$")
    indicator_value: str = Field(..., min_length=1, max_length=255)
    reason: Optional[str] = None
    project_id: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────


def _slugify(name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return cleaned[:60] if cleaned else "project"


async def _set_rls_context(session: AsyncSession, user_id: str) -> None:
    await set_session_user(session, user_id)


async def _get_org_and_role(
    org_id: str, user_id: str, session: AsyncSession, min_role: Optional[str] = None
) -> tuple[OrgOrganization, str]:
    await _set_rls_context(session, user_id)
    org = await session.get(OrgOrganization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if org.owner_id == user_id:
        user_role = "admin"
    else:
        m_stmt = select(OrgMember).where(
            OrgMember.organization_id == org_id,
            OrgMember.user_id == user_id,
        )
        member = (await session.execute(m_stmt)).scalar_one_or_none()
        if not member:
            raise HTTPException(status_code=403, detail="Not a member of this organization")
        user_role = member.role

    if min_role == "admin" and user_role != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")
    if min_role == "analyst" and user_role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or Admin permissions required")

    return org, user_role


def _extract_indicators_for_blocking(raw_data: Any, analysis_result: Any) -> list[tuple[str, str]]:
    """Extract candidate (indicator_type, indicator_value) pairs from event."""
    results: list[tuple[str, str]] = []
    seen = set()

    def add(itype: str, ival: str):
        val = str(ival).strip()
        if not val or len(val) < 2:
            return
        key = (itype, val.lower())
        if key not in seen:
            seen.add(key)
            results.append((itype, val))

    indicators = analysis_result.get("indicators", []) if isinstance(analysis_result, dict) else []
    for ind in indicators:
        if isinstance(ind, dict):
            itype = str(ind.get("type", "")).lower()
            val = ind.get("value") or ind.get("indicator")
            if val:
                t = "ip" if "ip" in itype else ("email" if "@" in str(val) else ("actor" if "user" in itype or "actor" in itype else "ip"))
                add(t, str(val))
            if "source_ip" in ind:
                add("ip", ind["source_ip"])
            if "ip" in ind:
                add("ip", ind["ip"])
            if "user" in ind:
                add("actor", ind["user"])
            if "email" in ind:
                add("email", ind["email"])
        elif isinstance(ind, str):
            s = ind.strip()
            if "@" in s:
                add("email", s)
            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
                add("ip", s)
            elif re.match(r"^[a-fA-F0-9]{32,64}$", s):
                add("hash", s)
            elif "." in s and " " not in s:
                add("domain", s)
            else:
                add("actor", s)

    if isinstance(raw_data, dict):
        for k in ["source_ip", "ip", "src_ip", "dest_ip", "dst_ip"]:
            if k in raw_data and raw_data[k]:
                add("ip", str(raw_data[k]))
        for k in ["email", "sender"]:
            if k in raw_data and raw_data[k]:
                add("email", str(raw_data[k]))
        for k in ["user", "username", "actor"]:
            if k in raw_data and raw_data[k]:
                add("actor", str(raw_data[k]))
        for k in ["domain", "host"]:
            if k in raw_data and raw_data[k]:
                add("domain", str(raw_data[k]))
        for k in ["hash", "md5", "sha256"]:
            if k in raw_data and raw_data[k]:
                add("hash", str(raw_data[k]))

    return results


def _has_blocked_indicator_match(blocked_rows: list[OrgBlockedIndicator], raw_data: Any, indicators: list[Any]) -> bool:
    """Check if any indicator in the event matches a blocked indicator."""
    import json
    data_str = json.dumps(raw_data).lower() if isinstance(raw_data, (dict, list)) else str(raw_data).lower()
    for b in blocked_rows:
        val = b.indicator_value.strip().lower()
        if not val:
            continue
        for ind in indicators:
            if isinstance(ind, str) and val in ind.lower():
                return True
            if isinstance(ind, dict):
                for v in ind.values():
                    if isinstance(v, str) and val in v.lower():
                        return True
        if val in data_str:
            return True
    return False


# ─────────────────────────────────────────────────────────────
# 1. Organization & Member Endpoints
# ─────────────────────────────────────────────────────────────


@router.post("/organizations", status_code=status.HTTP_201_CREATED)
@router.post("/orgs", status_code=status.HTTP_201_CREATED)
@router.post("/org/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    req: CreateOrgRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not get_settings().ORG_ENABLED:
        raise ComingSoonError(ORG_COMING_SOON)

    await _set_rls_context(session, user.id)
    org_id = str(uuid.uuid4())
    org = OrgOrganization(
        id=org_id,
        name=req.name.strip(),
        owner_id=user.id,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(org)

    # Owner is default admin member
    member = OrgMember(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        user_id=user.id,
        role="admin",
        joined_at=datetime.now(timezone.utc),
    )
    session.add(member)

    # Create default project
    default_proj = OrgProject(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        name="Default Project",
        slug="default",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(default_proj)

    # Sync active_organization_id if user exists
    user_row = await session.get(User, user.id)
    if user_row:
        user_row.active_organization_id = org_id

    await session.commit()

    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "owner_id": org.owner_id,
        "role": "admin",
        "status": org.status,
        "created_at": org.created_at.isoformat(),
        "default_project_id": default_proj.id,
    }


@router.get("/orgs")
@router.get("/org/organizations")
async def list_user_organizations(
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _set_rls_context(session, user.id)
    stmt = (
        select(OrgOrganization, OrgMember.role)
        .outerjoin(
            OrgMember,
            (OrgMember.organization_id == OrgOrganization.id) & (OrgMember.user_id == user.id),
        )
        .where(
            (OrgOrganization.owner_id == user.id)
            | (OrgMember.user_id == user.id)
        )
        .order_by(desc(OrgOrganization.created_at))
    )
    res = await session.execute(stmt)
    orgs = []
    for org, role in res.all():
        effective_role = "admin" if org.owner_id == user.id else (role or "viewer")
        orgs.append({
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "owner_id": org.owner_id,
            "status": org.status,
            "role": effective_role,
            "created_at": org.created_at.isoformat(),
        })
    return {"organizations": orgs}


@router.get("/organizations")
async def list_user_organizations_legacy(
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not get_settings().ORG_ENABLED:
        raise ComingSoonError(ORG_COMING_SOON)
    res = await list_user_organizations(user, session)
    return res["organizations"]


@router.get("/orgs/{org_id}")
@router.get("/org/{org_id}")
async def get_organization(
    org_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    org, role = await _get_org_and_role(org_id, user.id, session)

    proj_count = await session.scalar(
        select(func.count(OrgProject.id)).where(OrgProject.organization_id == org_id)
    )
    member_count = await session.scalar(
        select(func.count(OrgMember.id)).where(OrgMember.organization_id == org_id)
    )

    return {
        "id": org.id,
        "name": org.name,
        "owner_id": org.owner_id,
        "status": org.status,
        "role": role,
        "projects_count": proj_count or 0,
        "members_count": member_count or 0,
        "created_at": org.created_at.isoformat(),
    }


@router.patch("/orgs/{org_id}")
@router.patch("/org/{org_id}")
async def update_organization(
    org_id: str,
    req: UpdateOrgRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    org, _ = await _get_org_and_role(org_id, user.id, session, min_role="admin")
    org.name = req.name.strip()
    await session.commit()
    return {"id": org.id, "name": org.name, "status": org.status}


@router.get("/orgs/{org_id}/members")
@router.get("/org/{org_id}/members")
async def list_members(
    org_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    stmt = (
        select(OrgMember, User.email, User.full_name)
        .outerjoin(User, User.id == OrgMember.user_id)
        .where(OrgMember.organization_id == org_id)
        .order_by(OrgMember.joined_at)
    )
    res = await session.execute(stmt)
    members = []
    for m, email, full_name in res.all():
        members.append({
            "id": m.id,
            "organization_id": m.organization_id,
            "user_id": m.user_id,
            "email": email or "",
            "full_name": full_name or "",
            "role": m.role,
            "joined_at": m.joined_at.isoformat(),
        })
    return {"members": members}


@router.post("/orgs/{org_id}/members", status_code=status.HTTP_201_CREATED)
@router.post("/org/{org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_or_invite_member(
    org_id: str,
    req: InviteMemberRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    email = req.email.strip().lower()

    # Find or stub user via service-role (bypasses RLS on users table)
    from app.db.admin import find_user_by_email, precreate_user_for_invite

    target_user_info = await find_user_by_email(email)
    if not target_user_info:
        target_user_info = await precreate_user_for_invite(email)

    target_user_id = target_user_info["id"]
    target_user_email = target_user_info["email"]

    # Check if already member
    m_stmt = select(OrgMember).where(
        OrgMember.organization_id == org_id,
        OrgMember.user_id == target_user_id,
    )
    existing = (await session.execute(m_stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User is already a member of this organization")

    member = OrgMember(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        user_id=target_user_id,
        role=req.role,
        joined_at=datetime.now(timezone.utc),
    )
    session.add(member)
    await session.commit()

    return {
        "id": member.id,
        "organization_id": member.organization_id,
        "user_id": member.user_id,
        "email": target_user_email,
        "role": member.role,
        "joined_at": member.joined_at.isoformat(),
    }


@router.patch("/orgs/{org_id}/members/{member_id}")
@router.patch("/org/{org_id}/members/{member_id}")
async def update_member_role(
    org_id: str,
    member_id: str,
    req: UpdateMemberRoleRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    member = await session.get(OrgMember, member_id)
    if not member or member.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Member not found")

    member.role = req.role
    await session.commit()
    return {"id": member.id, "role": member.role}


@router.delete("/orgs/{org_id}/members/{member_id}")
@router.delete("/org/{org_id}/members/{member_id}")
async def remove_member(
    org_id: str,
    member_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    org, _ = await _get_org_and_role(org_id, user.id, session, min_role="admin")
    member = await session.get(OrgMember, member_id)
    if not member or member.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Member not found")

    if member.user_id == org.owner_id:
        raise HTTPException(status_code=400, detail="Cannot remove organization owner")

    await session.delete(member)
    await session.commit()
    return {"status": "deleted"}


# ─────────────────────────────────────────────────────────────
# 2. Project Endpoints
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/projects")
@router.get("/org/{org_id}/projects")
async def list_projects(
    org_id: str,
    status: Optional[str] = None,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    stmt = select(OrgProject).where(OrgProject.organization_id == org_id)
    if status:
        stmt = stmt.where(OrgProject.status == status)
    stmt = stmt.order_by(OrgProject.created_at)
    res = await session.execute(stmt)
    projects = res.scalars().all()
    return {
        "projects": [
            {
                "id": p.id,
                "organization_id": p.organization_id,
                "name": p.name,
                "slug": p.slug,
                "status": p.status,
                "created_at": p.created_at.isoformat(),
            }
            for p in projects
        ]
    }


@router.post("/orgs/{org_id}/projects", status_code=status.HTTP_201_CREATED)
@router.post("/org/{org_id}/projects", status_code=status.HTTP_201_CREATED)
async def create_project(
    org_id: str,
    req: CreateProjectRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    slug = _slugify(req.slug if req.slug else req.name)

    # Check slug uniqueness in org
    existing = await session.scalar(
        select(OrgProject).where(
            OrgProject.organization_id == org_id,
            OrgProject.slug == slug,
        )
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Project with slug '{slug}' already exists in this organization",
        )

    project = OrgProject(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        name=req.name.strip(),
        slug=slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(project)
    await session.commit()

    return {
        "id": project.id,
        "organization_id": project.organization_id,
        "name": project.name,
        "slug": project.slug,
        "status": project.status,
        "created_at": project.created_at.isoformat(),
    }


@router.get("/orgs/{org_id}/projects/{project_id}")
@router.get("/org/{org_id}/projects/{project_id}")
async def get_project(
    org_id: str,
    project_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    project = await session.get(OrgProject, project_id)
    if not project or project.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "id": project.id,
        "organization_id": project.organization_id,
        "name": project.name,
        "slug": project.slug,
        "status": project.status,
        "created_at": project.created_at.isoformat(),
    }


@router.patch("/orgs/{org_id}/projects/{project_id}")
@router.patch("/org/{org_id}/projects/{project_id}")
async def update_project(
    org_id: str,
    project_id: str,
    req: UpdateProjectRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    project = await session.get(OrgProject, project_id)
    if not project or project.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")

    if req.name:
        project.name = req.name.strip()
    if req.status:
        project.status = req.status

    await session.commit()
    return {
        "id": project.id,
        "name": project.name,
        "slug": project.slug,
        "status": project.status,
    }


@router.delete("/orgs/{org_id}/projects/{project_id}")
@router.delete("/org/{org_id}/projects/{project_id}")
async def delete_project(
    org_id: str,
    project_id: str,
    req: DeleteProjectRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Delete a project and its project-scoped rows (ORG-SETTINGS-P1).

    Admin-only. Requires an exact ``confirm_name`` match to the project name
    (409 otherwise). Cascades org_events / org_api_keys /
    org_blocked_indicators.project_id rows via the DB FKs; org-scoped rows
    (members, org-scoped indicators, the org itself) are untouched. Any
    user's ``active_project_id`` pointing at the deleted project is cleared
    in the same transaction — that write needs the service-role session
    because the users UPDATE policy is self-row-only under RLS.
    """
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    project = await session.get(OrgProject, project_id)
    if not project or project.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")

    if req.confirm_name != project.name:
        raise HTTPException(
            status_code=409,
            detail="confirm_name does not match the project name",
        )

    project_name = project.name
    project_slug = project.slug

    # Write phase on the service-role session (bypasses RLS for the
    # cross-user users.active_project_id clear) in a single transaction.
    from app.db.admin import _get_admin_session_maker

    admin_maker = _get_admin_session_maker()
    async with admin_maker() as admin_session:
        async with admin_session.begin():
            still_there = await admin_session.get(OrgProject, project_id)
            if not still_there or still_there.organization_id != org_id:
                raise HTTPException(status_code=404, detail="Project not found")
            if still_there.name != project_name:
                raise HTTPException(
                    status_code=409,
                    detail="confirm_name does not match the project name",
                )

            ev_count = await admin_session.scalar(
                select(func.count()).select_from(OrgEvent).where(OrgEvent.project_id == project_id)
            )
            key_count = await admin_session.scalar(
                select(func.count()).select_from(OrgApiKey).where(OrgApiKey.project_id == project_id)
            )
            ind_count = await admin_session.scalar(
                select(func.count())
                .select_from(OrgBlockedIndicator)
                .where(OrgBlockedIndicator.project_id == project_id)
            )
            ptr_count = await admin_session.execute(
                update(User)
                .where(User.active_project_id == project_id)
                .values(active_project_id=None)
            )
            await admin_session.execute(delete(OrgProject).where(OrgProject.id == project_id))

    return {
        "message": "Project deleted",
        "id": project_id,
        "name": project_name,
        "slug": project_slug,
        "deleted": {
            "events": int(ev_count or 0),
            "api_keys": int(key_count or 0),
            "blocked_indicators": int(ind_count or 0),
            "active_pointers_cleared": ptr_count.rowcount,
        },
    }


# ─────────────────────────────────────────────────────────────
# 3. API Key Management (Master & Viewer, Plaintext ONCE)
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/projects/{project_id}/keys")
@router.get("/org/{org_id}/projects/{project_id}/keys")
async def list_project_api_keys(
    org_id: str,
    project_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    stmt = (
        select(OrgApiKey)
        .where(
            OrgApiKey.organization_id == org_id,
            OrgApiKey.project_id == project_id,
        )
        .order_by(desc(OrgApiKey.created_at))
    )
    keys = (await session.execute(stmt)).scalars().all()

    # Plaintext and hash are NEVER returned
    return {
        "keys": [
            {
                "id": k.id,
                "project_id": k.project_id,
                "organization_id": k.organization_id,
                "name": k.name,
                "role": k.role,
                "key_prefix": k.key_prefix,
                "status": k.status,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "created_at": k.created_at.isoformat(),
            }
            for k in keys
        ]
    }


@router.post("/orgs/{org_id}/projects/{project_id}/keys", status_code=status.HTTP_201_CREATED)
@router.post("/org/{org_id}/projects/{project_id}/keys", status_code=status.HTTP_201_CREATED)
async def create_project_api_key(
    org_id: str,
    project_id: str,
    req: CreateApiKeyRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    project = await session.get(OrgProject, project_id)
    if not project or project.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")

    # Enforce slot: Only 1 active key per role per project
    existing_active = await session.scalar(
        select(OrgApiKey).where(
            OrgApiKey.project_id == project_id,
            OrgApiKey.role == req.role,
            OrgApiKey.status == "active",
        )
    )
    if existing_active:
        raise HTTPException(
            status_code=409,
            detail=f"An active {req.role} key already exists for this project. Revoke it before generating a new key.",
        )

    # Generate token
    raw_secret = f"cg_org_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
    key_prefix = raw_secret[:10] + "..."

    api_key_row = OrgApiKey(
        id=str(uuid.uuid4()),
        project_id=project_id,
        organization_id=org_id,
        name=req.name.strip(),
        role=req.role,
        key_hash=key_hash,
        key_prefix=key_prefix,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(api_key_row)
    await session.commit()

    # Return plaintext token ONCE
    return {
        "id": api_key_row.id,
        "project_id": api_key_row.project_id,
        "organization_id": api_key_row.organization_id,
        "name": api_key_row.name,
        "role": api_key_row.role,
        "key_prefix": api_key_row.key_prefix,
        "status": api_key_row.status,
        "created_at": api_key_row.created_at.isoformat(),
        "api_key": raw_secret,
    }


@router.post("/orgs/{org_id}/projects/{project_id}/keys/{key_id}/revoke")
@router.post("/org/{org_id}/projects/{project_id}/keys/{key_id}/revoke")
@router.delete("/orgs/{org_id}/projects/{project_id}/keys/{key_id}")
@router.delete("/org/{org_id}/projects/{project_id}/keys/{key_id}")
async def revoke_api_key(
    org_id: str,
    project_id: str,
    key_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="admin")
    key = await session.get(OrgApiKey, key_id)
    if not key or key.organization_id != org_id or key.project_id != project_id:
        raise HTTPException(status_code=404, detail="API key not found")

    key.status = "revoked"
    await session.commit()
    return {"status": "revoked", "id": key.id}


# ─────────────────────────────────────────────────────────────
# 4. Events & Review Endpoints
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/projects/{project_id}/events")
@router.get("/org/{org_id}/projects/{project_id}/events")
@router.get("/orgs/{org_id}/events")
@router.get("/org/{org_id}/events")
async def list_events(
    org_id: str,
    project_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    verdict: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    stmt = select(OrgEvent).where(OrgEvent.organization_id == org_id)

    if project_id:
        stmt = stmt.where(OrgEvent.project_id == project_id)
    if event_type:
        stmt = stmt.where(OrgEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(OrgEvent.severity == severity.lower())
    if verdict:
        stmt = stmt.where(OrgEvent.verdict == verdict)
    if q:
        search_pattern = f"%{q.lower()}%"
        stmt = stmt.where(
            func.cast(OrgEvent.raw_data, text("text")).ilike(search_pattern)
            | func.cast(OrgEvent.analysis_result, text("text")).ilike(search_pattern)
        )

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await session.scalar(count_stmt)) or 0

    stmt = stmt.order_by(desc(OrgEvent.created_at)).offset(offset).limit(limit)
    res = await session.execute(stmt)
    events = res.scalars().all()

    return {
        "total": total,
        "events": [
            {
                "id": e.id,
                "project_id": e.project_id,
                "organization_id": e.organization_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "source": e.source,
                "raw_data": e.raw_data,
                "analysis_result": e.analysis_result,
                "verdict": e.verdict,
                "user_action": e.user_action,
                "acted_by": e.acted_by,
                "acted_at": e.acted_at.isoformat() if e.acted_at else None,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/orgs/{org_id}/projects/{project_id}/events/{event_id}")
@router.get("/org/{org_id}/projects/{project_id}/events/{event_id}")
@router.get("/orgs/{org_id}/events/{event_id}")
@router.get("/org/{org_id}/events/{event_id}")
async def get_event_detail(
    org_id: str,
    event_id: str,
    project_id: Optional[str] = None,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    event = await session.get(OrgEvent, event_id)
    if not event or event.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Event not found")
    if project_id and event.project_id != project_id:
        raise HTTPException(status_code=404, detail="Event not found in this project")

    # Check if any indicator in this event is currently blocked
    blocked_stmt = select(OrgBlockedIndicator).where(OrgBlockedIndicator.organization_id == org_id)
    blocked_rows = (await session.execute(blocked_stmt)).scalars().all()
    has_blocked = _has_blocked_indicator_match(
        blocked_rows, event.raw_data, event.analysis_result.get("indicators", [])
    )

    return {
        "id": event.id,
        "project_id": event.project_id,
        "organization_id": event.organization_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "source": event.source,
        "raw_data": event.raw_data,
        "analysis_result": event.analysis_result,
        "verdict": event.verdict,
        "user_action": event.user_action,
        "acted_by": event.acted_by,
        "acted_at": event.acted_at.isoformat() if event.acted_at else None,
        "created_at": event.created_at.isoformat(),
        "indicator_blocked": has_blocked,
    }


@router.patch("/orgs/{org_id}/projects/{project_id}/events/{event_id}")
@router.patch("/org/{org_id}/projects/{project_id}/events/{event_id}")
@router.patch("/orgs/{org_id}/events/{event_id}")
@router.patch("/org/{org_id}/events/{event_id}")
async def update_event_verdict(
    org_id: str,
    event_id: str,
    req: EventVerdictActionRequest,
    project_id: Optional[str] = None,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="analyst")
    event = await session.get(OrgEvent, event_id)
    if not event or event.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Event not found")
    if project_id and event.project_id != project_id:
        raise HTTPException(status_code=404, detail="Event not found in this project")

    action = req.action
    now = datetime.now(timezone.utc)

    if action == "released":
        # Check if any indicator is in org_blocked_indicators
        blocked_stmt = select(OrgBlockedIndicator).where(
            OrgBlockedIndicator.organization_id == org_id
        )
        blocked_rows = (await session.execute(blocked_stmt)).scalars().all()
        if _has_blocked_indicator_match(blocked_rows, event.raw_data, event.analysis_result.get("indicators", [])):
            raise HTTPException(
                status_code=409,
                detail="Cannot release event: indicator is blocked permanently",
            )
        event.verdict = "released"
        event.user_action = "released"
        event.acted_by = user.id
        event.acted_at = now

    elif action == "blocked_permanently":
        event.verdict = "blocked_permanently"
        event.user_action = "blocked_permanently"
        event.acted_by = user.id
        event.acted_at = now

        # Auto-insert event indicators into org_blocked_indicators
        candidate_indicators = _extract_indicators_for_blocking(
            event.raw_data, event.analysis_result
        )
        for itype, ival in candidate_indicators:
            existing = await session.scalar(
                select(OrgBlockedIndicator).where(
                    OrgBlockedIndicator.organization_id == org_id,
                    OrgBlockedIndicator.indicator_type == itype,
                    OrgBlockedIndicator.indicator_value == ival,
                )
            )
            if not existing:
                new_b = OrgBlockedIndicator(
                    id=str(uuid.uuid4()),
                    organization_id=org_id,
                    project_id=event.project_id,
                    indicator_type=itype,
                    indicator_value=ival,
                    reason=f"Blocked via event {event.id}",
                    blocked_by=user.id,
                    blocked_at=now,
                )
                session.add(new_b)

    elif action == "false_positive":
        event.verdict = "false_positive"
        event.user_action = "false_positive"
        event.acted_by = user.id
        event.acted_at = now

    await session.commit()

    return {
        "id": event.id,
        "verdict": event.verdict,
        "user_action": event.user_action,
        "acted_by": event.acted_by,
        "acted_at": event.acted_at.isoformat() if event.acted_at else None,
    }


# ─────────────────────────────────────────────────────────────
# 5. Blocked Indicators Endpoints
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/blocked-indicators")
@router.get("/org/{org_id}/blocked-indicators")
async def list_blocked_indicators(
    org_id: str,
    indicator_type: Optional[str] = None,
    q: Optional[str] = None,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)
    stmt = select(OrgBlockedIndicator).where(OrgBlockedIndicator.organization_id == org_id)

    if indicator_type:
        stmt = stmt.where(OrgBlockedIndicator.indicator_type == indicator_type)
    if q:
        stmt = stmt.where(OrgBlockedIndicator.indicator_value.ilike(f"%{q}%"))

    stmt = stmt.order_by(desc(OrgBlockedIndicator.blocked_at))
    indicators = (await session.execute(stmt)).scalars().all()

    return {
        "indicators": [
            {
                "id": b.id,
                "organization_id": b.organization_id,
                "project_id": b.project_id,
                "indicator_type": b.indicator_type,
                "indicator_value": b.indicator_value,
                "reason": b.reason,
                "blocked_by": b.blocked_by,
                "blocked_at": b.blocked_at.isoformat(),
            }
            for b in indicators
        ]
    }


@router.post("/orgs/{org_id}/blocked-indicators", status_code=status.HTTP_201_CREATED)
@router.post("/org/{org_id}/blocked-indicators", status_code=status.HTTP_201_CREATED)
async def add_blocked_indicator(
    org_id: str,
    req: CreateBlockedIndicatorRequest,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="analyst")
    val = req.indicator_value.strip()

    # Check duplicate
    existing = await session.scalar(
        select(OrgBlockedIndicator).where(
            OrgBlockedIndicator.organization_id == org_id,
            OrgBlockedIndicator.indicator_type == req.indicator_type,
            OrgBlockedIndicator.indicator_value == val,
        )
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Indicator '{val}' of type '{req.indicator_type}' is already blocked",
        )

    blocked = OrgBlockedIndicator(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        project_id=req.project_id,
        indicator_type=req.indicator_type,
        indicator_value=val,
        reason=req.reason,
        blocked_by=user.id,
        blocked_at=datetime.now(timezone.utc),
    )
    session.add(blocked)
    await session.commit()

    return {
        "id": blocked.id,
        "organization_id": blocked.organization_id,
        "indicator_type": blocked.indicator_type,
        "indicator_value": blocked.indicator_value,
        "reason": blocked.reason,
        "blocked_by": blocked.blocked_by,
        "blocked_at": blocked.blocked_at.isoformat(),
    }


@router.delete("/orgs/{org_id}/blocked-indicators/{indicator_id}")
@router.delete("/org/{org_id}/blocked-indicators/{indicator_id}")
async def delete_blocked_indicator(
    org_id: str,
    indicator_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session, min_role="analyst")
    indicator = await session.get(OrgBlockedIndicator, indicator_id)
    if not indicator or indicator.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Blocked indicator not found")

    await session.delete(indicator)
    await session.commit()
    return {"status": "deleted", "id": indicator_id}


# ─────────────────────────────────────────────────────────────
# 6. Counters Initial Seed (Single aggregate SQL seed query)
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/projects/{project_id}/counters/initial")
@router.get("/org/{org_id}/projects/{project_id}/counters/initial")
async def get_initial_counters(
    org_id: str,
    project_id: str,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Seed fetch for live counters.

    Frontend calls this once on mount, then relies strictly on Supabase Realtime
    for incremental updates (zero polling).
    """
    await _get_org_and_role(org_id, user.id, session)

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    agg_sql = text("""
        SELECT
            count(*) FILTER (WHERE created_at >= :since) AS total_24h,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'critical') AS sev_critical,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'high') AS sev_high,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'medium') AS sev_medium,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'low') AS sev_low,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'log_event') AS type_log,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'ato_event') AS type_ato,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'network_event') AS type_network,
            count(*) FILTER (WHERE verdict = 'pending_review') AS pending_review
        FROM cyberguard.org_events
        WHERE organization_id = :org_id AND project_id = :project_id;
    """)
    res = await session.execute(agg_sql, {
        "org_id": org_id,
        "project_id": project_id,
        "since": since,
    })
    row = res.mappings().first() or {}

    blocked_count = await session.scalar(
        select(func.count(OrgBlockedIndicator.id)).where(
            OrgBlockedIndicator.organization_id == org_id
        )
    ) or 0

    return {
        "total_24h": int(row.get("total_24h") or 0),
        "by_severity": {
            "critical": int(row.get("sev_critical") or 0),
            "high": int(row.get("sev_high") or 0),
            "medium": int(row.get("sev_medium") or 0),
            "low": int(row.get("sev_low") or 0),
        },
        "by_type": {
            "log": int(row.get("type_log") or 0),
            "ato": int(row.get("type_ato") or 0),
            "network": int(row.get("type_network") or 0),
        },
        "pending_review": int(row.get("pending_review") or 0),
        "blocked_indicators_count": int(blocked_count),
    }


# ─────────────────────────────────────────────────────────────
# 7. Dashboard Overview Endpoint
# ─────────────────────────────────────────────────────────────


@router.get("/orgs/{org_id}/dashboard")
@router.get("/org/{org_id}/dashboard")
async def get_organization_dashboard(
    org_id: str,
    project_id: Optional[str] = None,
    user: CurrentUser = Depends(get_org_current_user),
    session: AsyncSession = Depends(get_session),
):
    await _get_org_and_role(org_id, user.id, session)

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    # Base query for events
    stmt_base = select(OrgEvent).where(OrgEvent.organization_id == org_id)
    if project_id:
        stmt_base = stmt_base.where(OrgEvent.project_id == project_id)

    # Aggregate counts
    agg_sql = text("""
        SELECT
            count(*) FILTER (WHERE created_at >= :since) AS total_24h,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'log_event') AS count_log,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'ato_event') AS count_ato,
            count(*) FILTER (WHERE created_at >= :since AND event_type = 'network_event') AS count_network,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'critical') AS sev_critical,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'high') AS sev_high,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'medium') AS sev_medium,
            count(*) FILTER (WHERE created_at >= :since AND severity = 'low') AS sev_low,
            count(*) FILTER (WHERE verdict = 'pending_review') AS pending_count,
            max(created_at) AS last_event_at
        FROM cyberguard.org_events
        WHERE organization_id = :org_id
        """ + (" AND project_id = :project_id" if project_id else "") + ";"
    )
    params: dict[str, Any] = {"org_id": org_id, "since": since}
    if project_id:
        params["project_id"] = project_id

    agg_res = await session.execute(agg_sql, params)
    row = agg_res.mappings().first() or {}

    # Blocked indicators count
    blocked_count = await session.scalar(
        select(func.count(OrgBlockedIndicator.id)).where(
            OrgBlockedIndicator.organization_id == org_id
        )
    ) or 0

    # Recent 10 events
    recent_stmt = (
        stmt_base.order_by(desc(OrgEvent.created_at))
        .limit(10)
    )
    recent_events = (await session.execute(recent_stmt)).scalars().all()

    last_event_at = row.get("last_event_at")

    return {
        "analyzers": {
            "log": {
                "name": "Log Analysis",
                "engine": "org_log_analyzer",
                "available": True,
                "count_24h": int(row.get("count_log") or 0),
            },
            "ato": {
                "name": "Account Takeover",
                "engine": "account_takeover_detector",
                "available": True,
                "count_24h": int(row.get("count_ato") or 0),
            },
            "network": {
                "name": "Network Threat",
                "engine": "network_threat_detector",
                "available": True,
                "count_24h": int(row.get("count_network") or 0),
            },
        },
        "total_24h": int(row.get("total_24h") or 0),
        "severity_mix": {
            "critical": int(row.get("sev_critical") or 0),
            "high": int(row.get("sev_high") or 0),
            "medium": int(row.get("sev_medium") or 0),
            "low": int(row.get("sev_low") or 0),
        },
        "pending_review": int(row.get("pending_count") or 0),
        "blocked_indicators_count": int(blocked_count),
        "last_event_at": last_event_at.isoformat() if last_event_at else None,
        "recent_events": [
            {
                "id": e.id,
                "project_id": e.project_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "verdict": e.verdict,
                "created_at": e.created_at.isoformat(),
            }
            for e in recent_events
        ],
    }
