"""ORG-1 foundation endpoints: org creation with name salting, API key
management, org settings, members (RBAC), and the org-scoped gateway.

User-mode code (Phases -1 through 7) is untouched: the frozen
``/organizations`` router stays exactly as it was; this router is the always-
on Orgs-Phase surface under ``/orgs``.

Gateway contract (server-to-server):

    POST /api/v1/org/{org_id}/gateway
    org_authorization: cg_live_...
    {"action": "scan_email" | "scan_url" | "ingest_log", "data": {...}}
"""

import asyncio
import logging
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    UnauthorizedError,
    ValidationError,
)
from fastapi import Request
from app.core.permissions import OrgRole, can_read_setting, require_org_role
from app.core.security import CurrentUser, TenantContext, get_current_user
from app.db.models import (
    EnforcementPolicy,
    Event,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OrganizationSetting,
    Project,
    ProjectAPIKey,
    User,
)
from app.db.session import get_db
from app.schemas.alerts import AlertResponse
from app.schemas.organizations import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    MemberAdd,
    MemberResponse,
    MemberRoleUpdate,
    OrganizationCreate,
    OrganizationResponse,
    SettingResponse,
    SettingUpsert,
)
from app.services import project_service
from app.services.api_key_service import (
    create_api_key,
    create_project_key,
    get_org_from_api_key,
    list_project_keys,
    revoke_project_key,
    validate_project_key,
)

logger = logging.getLogger("cyberguard.orgs")

router = APIRouter(prefix="/orgs", tags=["Org Foundation"])
gateway_router = APIRouter(prefix="/org", tags=["Org Gateway"])

MAX_SALT_ATTEMPTS = 8


class GatewayPayload(BaseModel):
    action: str
    data: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Projects + project-scoped API keys (ORG-REDESIGN)
# ---------------------------------------------------------------------------


class ProjectCreate(BaseModel):
    name: str


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    status: str
    created_at: Any = None


class ProjectKeyCreate(BaseModel):
    role: str  # master | viewer
    name: str = ""


class ProjectKeyResponse(BaseModel):
    id: str
    project_id: str
    name: str
    role: str
    key_prefix: str
    last_used_at: Any = None
    status: str
    created_at: Any = None


class ProjectKeyCreatedResponse(ProjectKeyResponse):
    """Plaintext ``key`` is returned EXACTLY ONCE by the create endpoint."""

    key: str


# ---------------------------------------------------------------------------
# Organization creation (name salting)
# ---------------------------------------------------------------------------


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name).strip().lower()
    return re.sub(r"[-\s]+", "-", slug)


async def _salt_organization_name(db: AsyncSession, name: str) -> str:
    """Return the first free ``name``: "Acme Corp" -> "Acme Corp-2" -> ...

    Uniqueness is enforced here rather than by a DB constraint because every
    user's personal workspace legitimately shares the literal name
    "Personal Workspace".
    """
    salted = name
    counter = 2
    for _ in range(MAX_SALT_ATTEMPTS):
        existing = await db.execute(
            select(Organization.id).where(Organization.name == salted).limit(1)
        )
        if existing.scalar_one_or_none() is None:
            return salted
        salted = f"{name}-{counter}"
        counter += 1
    raise ConflictError("Could not derive a unique organization name — try a different name")


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create an organization (creator becomes admin). Salts the name on
    conflict; applies to both email/password and OAuth flows (the frontend
    calls this after account creation when the user selects "Organization")."""
    display_name = payload.name.strip()
    salted_name = await _salt_organization_name(db, display_name)

    org = Organization(
        id=str(uuid.uuid4()),
        name=salted_name,
        display_name=display_name,
        slug=f"{_slugify(display_name) or 'org'}-{str(uuid.uuid4())[:6]}",
        is_personal=False,
        owner_id=user.id,  # creator (mission's created_by)
        status="active",
    )
    db.add(org)
    await db.flush()

    member = OrganizationMember(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        user_id=user.id,
        role=OrgRole.ADMIN.value,
    )
    db.add(member)

    user_query = await db.execute(select(User).where(User.id == user.id))
    user_db = user_query.scalar_one_or_none()
    if user_db is not None:
        user_db.active_organization_id = org.id

    # Default enforcement policy so server-mode integrations resolve a policy
    # for this org immediately (parity with the frozen /organizations route).
    db.add(EnforcementPolicy(
        organization_id=org.id,
        name="Balanced (default)",
        description="Auto-block critical/high, require approval for medium.",
        is_active=True,
    ))

    # ORG-REDESIGN: every new org starts with a 'General' project so the
    # project switcher and the project gateway are usable immediately.
    from app.services.project_service import ensure_default_project  # noqa: PLC0415

    await ensure_default_project(db, org_id=org.id, actor_user_id=user.id)

    await db.commit()

    return OrganizationResponse(
        id=org.id,
        name=org.name,
        display_name=org.display_name,
        slug=org.slug,
        is_personal=org.is_personal,
        owner_id=org.owner_id,
        created_at=org.created_at,
        role=OrgRole.ADMIN.value,
    )


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    org = await db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization", org_id)
    return OrganizationResponse(
        id=org.id,
        name=org.name,
        display_name=org.display_name,
        slug=org.slug,
        is_personal=org.is_personal,
        owner_id=org.owner_id,
        created_at=org.created_at,
        role=member.role,
    )


# ---------------------------------------------------------------------------
# API key management (admin only)
# ---------------------------------------------------------------------------


@router.post(
    "/{org_id}/api-keys",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_org_api_key(
    org_id: str,
    payload: ApiKeyCreate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create an API key. The plaintext is returned EXACTLY ONCE."""
    if await db.get(Organization, org_id) is None:
        raise NotFoundError("Organization", org_id)
    created = await create_api_key(
        db,
        organization_id=org_id,
        name=payload.name.strip(),
        expires_at=payload.expires_at,
        created_by=user.id,
    )
    stored = await db.get(OrganizationAPIKey, created["id"])
    return ApiKeyCreatedResponse(
        id=stored.id,
        name=stored.name,
        key_prefix=stored.key_prefix,
        key=created["key"],
        last_used_at=stored.last_used_at,
        expires_at=stored.expires_at,
        status=stored.status,
        created_at=stored.created_at,
    )


@router.get("/{org_id}/api-keys", response_model=list[ApiKeyResponse])
async def list_org_api_keys(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List API keys (prefix only — hashes and plaintext are never returned)."""
    result = await db.execute(
        select(OrganizationAPIKey)
        .where(OrganizationAPIKey.organization_id == org_id)
        .order_by(OrganizationAPIKey.created_at.desc())
    )
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            status=k.status,
            created_at=k.created_at,
        )
        for k in result.scalars().all()
    ]


@router.delete("/{org_id}/api-keys/{key_id}", response_model=ApiKeyResponse)
async def revoke_org_api_key(
    org_id: str,
    key_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    api_key = await db.get(OrganizationAPIKey, key_id)
    if api_key is None or api_key.organization_id != org_id:
        raise NotFoundError("API key", key_id)
    api_key.status = "revoked"
    await db.commit()
    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        status=api_key.status,
        created_at=api_key.created_at,
    )


# ---------------------------------------------------------------------------
# Organization settings
# ---------------------------------------------------------------------------


@router.get("/{org_id}/settings", response_model=list[SettingResponse])
async def list_org_settings(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List settings. Viewers are filtered out of sensitive keys (mirrors the
    organization_settings RLS policy)."""
    result = await db.execute(
        select(OrganizationSetting).where(OrganizationSetting.organization_id == org_id)
    )
    return [
        SettingResponse(key=s.key, value=s.value, updated_at=s.updated_at)
        for s in result.scalars().all()
        if can_read_setting(member.role, s.key)
    ]


@router.put("/{org_id}/settings/{key}", response_model=SettingResponse)
async def upsert_org_setting(
    org_id: str,
    key: str,
    payload: SettingUpsert,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    if len(key) > 64:
        raise ValidationError("Setting key must be at most 64 characters")
    result = await db.execute(
        select(OrganizationSetting).where(
            OrganizationSetting.organization_id == org_id,
            OrganizationSetting.key == key,
        )
    )
    setting = result.scalar_one_or_none()
    if setting is None:
        setting = OrganizationSetting(
            organization_id=org_id,
            key=key,
            value=payload.value,
            updated_by=user.id,
        )
        db.add(setting)
    else:
        setting.value = payload.value
        setting.updated_by = user.id
    await db.commit()
    return SettingResponse(key=setting.key, value=setting.value, updated_at=setting.updated_at)


# ---------------------------------------------------------------------------
# Members (admin-managed; roster readable by every member)
# ---------------------------------------------------------------------------


@router.get("/{org_id}/members", response_model=list[MemberResponse])
async def list_org_members(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(OrganizationMember.organization_id == org_id)
    )
    return [
        MemberResponse(
            id=m.id,
            organization_id=m.organization_id,
            user_id=m.user_id,
            email=m.user.email if m.user else None,
            full_name=m.user.full_name if m.user else None,
            role=m.role,
            joined_at=m.joined_at,
        )
        for m in result.scalars().all()
    ]


@router.post("/{org_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def add_org_member(
    org_id: str,
    payload: MemberAdd,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    org = await db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization", org_id)
    if org.is_personal:
        raise ValidationError("Personal workspaces cannot have additional members.")

    email = payload.email.strip().lower()
    # RLS on ``users`` hides other accounts from the app role — resolve (or
    # pre-create) the invitee through the service role, mirroring the frozen
    # /organizations invite behavior.
    from app.db.admin import find_user_by_email, precreate_user_for_invite

    invitee = await find_user_by_email(email)
    if invitee is None:
        invitee = await precreate_user_for_invite(email)

    existing = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == invitee["id"],
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"User '{email}' is already a member of this organization")

    new_member = OrganizationMember(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        user_id=invitee["id"],
        role=payload.role,
    )
    db.add(new_member)
    await db.commit()
    return MemberResponse(
        id=new_member.id,
        organization_id=new_member.organization_id,
        user_id=new_member.user_id,
        email=invitee["email"],
        full_name=invitee["full_name"],
        role=new_member.role,
        joined_at=new_member.joined_at,
    )


@router.patch("/{org_id}/members/{target_user_id}", response_model=MemberResponse)
async def update_org_member_role(
    org_id: str,
    target_user_id: str,
    payload: MemberRoleUpdate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    org = await db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization", org_id)
    if target_user_id == org.owner_id and payload.role != OrgRole.ADMIN.value:
        raise ValidationError("Cannot demote the organization owner")

    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise NotFoundError("Member in organization", target_user_id)

    target.role = payload.role
    await db.commit()
    return MemberResponse(
        id=target.id,
        organization_id=target.organization_id,
        user_id=target.user_id,
        email=target.user.email if target.user else None,
        full_name=target.user.full_name if target.user else None,
        role=target.role,
        joined_at=target.joined_at,
    )


@router.delete("/{org_id}/members/{target_user_id}")
async def remove_org_member(
    org_id: str,
    target_user_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    org = await db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization", org_id)
    if target_user_id == org.owner_id:
        raise ValidationError("Cannot remove the owner of the organization")
    if target_user_id == member.user_id:
        raise ValidationError("Admins cannot remove themselves — ask another admin")

    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise NotFoundError("Member in organization", target_user_id)

    await db.delete(target)
    await db.commit()
    return {"message": "Member removed"}


# ---------------------------------------------------------------------------
# Projects + project-scoped API keys (ORG-REDESIGN)
# ---------------------------------------------------------------------------


def _project_response(project: Project) -> dict[str, Any]:
    return {
        "id": project.id,
        "organization_id": project.organization_id,
        "name": project.name,
        "slug": project.slug,
        "status": project.status,
        "created_at": project.created_at,
    }


def _project_key_response(key: ProjectAPIKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "project_id": key.project_id,
        "name": key.name,
        "role": key.role,
        "key_prefix": key.key_prefix,
        "last_used_at": key.last_used_at,
        "status": key.status,
        "created_at": key.created_at,
    }


@router.get("/{org_id}/projects", response_model=list[ProjectResponse])
async def list_org_projects(
    org_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Active projects of the org (viewer+; feeds the project switcher)."""
    projects = await project_service.list_projects(db, org_id=org_id)
    return [_project_response(p) for p in projects]


@router.post("/{org_id}/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_org_project(
    org_id: str,
    payload: ProjectCreate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a project (admin). Slug auto-derived; duplicate name -> 409."""
    project = await project_service.create_project(
        db, org_id=org_id, name=payload.name, actor_user_id=member.user_id
    )
    return _project_response(project)


@router.delete("/{org_id}/projects/{project_id}")
async def archive_org_project(
    org_id: str,
    project_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Soft-archive a project (admin). Gateway 404s; history keeps stamps."""
    await project_service.archive_project(
        db, project_id=project_id, org_id=org_id, actor_user_id=member.user_id
    )
    return {"message": "Project archived", "status": "archived"}


@router.get("/{org_id}/projects/{project_id}/keys", response_model=list[ProjectKeyResponse])
async def list_org_project_keys(
    org_id: str,
    project_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Keys of one project (admin). No plaintext — ever."""
    keys = await list_project_keys(db, project_id=project_id, organization_id=org_id)
    return [_project_key_response(k) for k in keys]


@router.post(
    "/{org_id}/projects/{project_id}/keys",
    response_model=ProjectKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_org_project_key(
    org_id: str,
    project_id: str,
    payload: ProjectKeyCreate,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Generate the project's master or viewer key (admin). Plaintext is
    returned ONCE. One active key per (project, role): creating again is 409
    until the existing key is revoked."""
    project = await db.get(Project, project_id)
    if project is None or project.organization_id != org_id:
        raise NotFoundError("Project", project_id)
    created = await create_project_key(
        db,
        project_id=project_id,
        organization_id=org_id,
        role=payload.role,
        name=payload.name,
        actor_user_id=member.user_id,
    )
    key = await db.get(ProjectAPIKey, created["id"])
    resp = _project_key_response(key)
    resp["key"] = created["key"]
    return resp


@router.delete("/{org_id}/projects/{project_id}/keys/{key_id}")
async def revoke_org_project_key(
    org_id: str,
    project_id: str,
    key_id: str,
    member: OrganizationMember = Depends(require_org_role(OrgRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Revoke a project key (admin) — frees the (project, role) slot."""
    revoked = await revoke_project_key(
        db,
        key_id=key_id,
        project_id=project_id,
        organization_id=org_id,
        actor_user_id=member.user_id,
    )
    if revoked is None:
        raise NotFoundError("Project key", key_id)
    return {"message": f"{revoked.role} key revoked", "status": "revoked"}


# ---------------------------------------------------------------------------
# Org-scoped gateway (server-to-server, API-key auth)
# ---------------------------------------------------------------------------


def _org_tenant(org: Organization, project_id: str | None = None) -> TenantContext:
    """Tenant context for gateway requests: the org's service identity.

    Server-to-server calls have no user; the request runs under the org
    creator's RLS identity (stamped by validate_api_key) and rows are scoped
    to the organization.
    """
    return TenantContext(
        user_id=org.owner_id,
        owner_user_id=org.owner_id,
        organization_id=org.id,
        organization_name=org.name,
        role=OrgRole.ADMIN.value,
        is_single_user=False,
        project_id=project_id,
    )


async def _gateway_scan_email(
    db: AsyncSession, org: Organization, data: dict[str, Any], project_id: str | None = None
) -> Any:
    from app.ai.prompt_templates import (
        PHISHING_SYSTEM_PROMPT,
        format_phishing_user_prompt,
    )
    from app.api.routes_analysis import _run_analysis_pipeline
    from app.services.phishing_detector import analyze_email_heuristics

    sender = data.get("sender")
    if not sender:
        raise ValidationError("scan_email requires data.sender")
    tenant = _org_tenant(org, project_id)
    indicators = await asyncio.to_thread(
        analyze_email_heuristics,
        sender=sender,
        subject=data.get("subject", ""),
        body=data.get("body", ""),
    )
    alert = await _run_analysis_pipeline(
        db,
        tenant,
        event_type="phishing_email",
        module="phishing",
        source="gateway",
        raw_data=data,
        indicators=indicators,
        system_prompt=PHISHING_SYSTEM_PROMPT,
        user_prompt_builder=format_phishing_user_prompt,
    )
    # ORG-4 trigger: impersonation-type indicators page the impersonation group.
    from app.services.org_notification_service import (
        IMPERSONATION_INDICATOR_TYPES,
        impersonation_email,
        send_event,
    )
    impersonation_hits = [i for i in indicators if str(i.get("type")) in IMPERSONATION_INDICATOR_TYPES]
    if impersonation_hits:
        n_subject, n_body = impersonation_email(impersonation_hits, data.get("sender"))
        await send_event(
            db,
            organization_id=org.id,
            event_type="impersonation",
            subject=n_subject,
            body_html=n_body,
            event_metadata={"alert_id": alert.id, "sender": data.get("sender"),
                            "indicators": [i.get("type") for i in impersonation_hits]},
        )
    return AlertResponse.model_validate(alert).model_dump(mode="json")


async def _gateway_scan_url(
    db: AsyncSession, org: Organization, data: dict[str, Any], project_id: str | None = None
) -> Any:
    from app.ai.prompt_templates import URL_SYSTEM_PROMPT, format_url_user_prompt
    from app.api.routes_analysis import _run_analysis_pipeline
    from app.services.url_detector import analyze_url_heuristics

    url = data.get("url")
    if not url:
        raise ValidationError("scan_url requires data.url")
    tenant = _org_tenant(org, project_id)
    indicators = await asyncio.to_thread(analyze_url_heuristics, url)
    alert = await _run_analysis_pipeline(
        db,
        tenant,
        event_type="malicious_url",
        module="url",
        source="gateway",
        raw_data=data,
        indicators=indicators,
        system_prompt=URL_SYSTEM_PROMPT,
        user_prompt_builder=lambda d, ind, score, sev: format_url_user_prompt(url, ind, score, sev),
    )
    return AlertResponse.model_validate(alert).model_dump(mode="json")


async def _gateway_ingest_log(
    db: AsyncSession, org: Organization, data: dict[str, Any], project_id: str | None = None
) -> dict[str, Any]:
    """Splunk-style log ingestion: persist the raw log event AND the analyzed
    org log stream row (ORG-WIRE D4).

    Dual-write rationale: the generic ``Event`` row keeps the org dashboard
    aggregations working (summary/feature dashboards count ``events``), while
    the ``OrgLogEvent`` row (with the org_log_analyzer output) feeds
    ``/org/{id}/logs/stream`` and the log-analysis feature views, which
    previously only saw logs sent through ``POST /org/{id}/logs/ingest``.
    """
    from app.db.models import OrgLogEvent
    from app.services.org_log_analyzer import analyze_log

    event = Event(
        id=str(uuid.uuid4()),
        organization_id=org.id,
        project_id=project_id,
        owner_user_id=org.owner_id,
        event_type="log",
        source="gateway",
        raw_data=data,
        status="received",
        created_by=f"api_key:{org.id}",
    )
    db.add(event)

    analysis = analyze_log(data)
    log_event = OrgLogEvent(
        organization_id=org.id,
        project_id=project_id,
        log_type=analysis["log_type"],
        raw_data=data if isinstance(data, (dict, list)) else {"value": str(data)},
        analysis_result=analysis,
        severity=analysis["severity"],
        created_by=f"api_key:{org.id}",
    )
    db.add(log_event)
    await db.commit()
    return {
        "event_id": event.id,
        "log_id": log_event.id,
        "status": event.status,
        "stored": True,
    }


@gateway_router.post("/{org_id}/gateway")
async def org_gateway(
    org_id: str,
    payload: GatewayPayload,
    org: Organization = Depends(get_org_from_api_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """DEPRECATED (ORG-REDESIGN): org-flat gateway kept one version for
    compatibility. Use ``POST /org/{org_id}/projects/{project_slug}/gateway``
    with a project key instead. Removal tracked in DECISIONS.md."""
    logger.warning(
        "DEPRECATED org gateway used: POST /org/%s/gateway (org %s) — "
        "migrate to /org/{org_id}/projects/{project_slug}/gateway",
        org_id,
        org.id,
    )
    if org.id != org_id:
        raise PermissionDeniedError("API key does not belong to this organization")

    action = payload.action
    if action == "scan_email":
        result = await _gateway_scan_email(db, org, payload.data)
    elif action == "scan_url":
        result = await _gateway_scan_url(db, org, payload.data)
    elif action == "ingest_log":
        result = await _gateway_ingest_log(db, org, payload.data)
    else:
        raise ValidationError(f"Unknown action: {action}")

    return {"status": "success", "action": action, "result": result}


# ---------------------------------------------------------------------------
# Project-scoped gateway (ORG-REDESIGN)
# ---------------------------------------------------------------------------

# Viewer keys may call exactly these read-only actions; anything else is a
# 403 for viewers (master keys may attempt any action — unknown ones 404).
_PROJECT_VIEWER_ACTIONS = {"scan_email", "scan_url", "ingest_log"}


async def get_project_gateway_context(
    org_id: str,
    project_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> tuple[Organization, Project, str]:
    """Authenticate a project-gateway call: the ``org_authorization`` header
    must carry an ACTIVE key of THIS project in THIS org.

    Returns (org, project, role). 401 for missing/invalid/revoked keys and
    keys of another org/project; 404 for unknown or archived slugs."""
    raw_key = request.headers.get("org_authorization") or ""
    if not raw_key:
        raise UnauthorizedError("Missing org_authorization header")
    claims = await validate_project_key(db, raw_key)
    if claims is None:
        raise UnauthorizedError("Invalid or revoked project API key")
    if claims["organization_id"] != org_id:
        raise UnauthorizedError("Project API key does not belong to this organization")
    org = await db.get(Organization, org_id)
    if org is None or org.status != "active":
        raise UnauthorizedError("Organization is not active")
    project = await project_service.get_project_by_slug(db, org_id=org_id, slug=project_slug)
    if claims["project_id"] != project.id:
        raise UnauthorizedError("Project API key does not belong to this project")
    return org, project, claims["role"]


@gateway_router.post("/{org_id}/projects/{project_slug}/gateway")
async def org_project_gateway(
    payload: GatewayPayload,
    ctx: tuple[Organization, Project, str] = Depends(get_project_gateway_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Project-scoped gateway: the project key (master|viewer) authenticates
    the call; events/alerts/log rows are stamped with the project_id.

    master: all actions. viewer: read-only actions only (scan_email,
    scan_url, ingest_log); future write actions reject 403."""
    org, project, role = ctx

    action = payload.action
    if role == "viewer" and action not in _PROJECT_VIEWER_ACTIONS:
        raise PermissionDeniedError(
            f"Viewer keys cannot perform '{action}' — ask for a master key"
        )
    if action == "scan_email":
        result = await _gateway_scan_email(db, org, payload.data, project.id)
    elif action == "scan_url":
        result = await _gateway_scan_url(db, org, payload.data, project.id)
    elif action == "ingest_log":
        result = await _gateway_ingest_log(db, org, payload.data, project.id)
    else:
        raise ValidationError(f"Unknown action: {action}")

    return {"status": "success", "action": action, "project": project.slug, "result": result}
