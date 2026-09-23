"""Org-context resolution for pipeline stamping (ORG-WIRE).

Workers and service paths know only ``owner_user_id``; the org plane needs
the rows those paths create (security events, alerts, audit entries) stamped
with the owner's active organization so org-branch RLS (migration 0018) can
make them visible to org members.

``resolve_org_id`` is the single resolution rule:

1. the user's ``active_organization_id`` (set by ``POST /auth/switch-org``);
2. otherwise the user's PERSONAL org (``organizations.is_personal = true``
   and ``owner_id`` = user) — personal-mode rows still get a stable org
   stamp, which the fan-out rule uses to suppress duplicate notifications
   (Phase-7 already emails the owner) and dashboards treat as personal.

The result is cached per owner for ``_TTL_SECONDS``: a worker job processes
many emails for the same owner and the rule must not add a DB round-trip per
email — one cached lookup per job is the budget. Cache entries are
invalidated by ``invalidate`` (org switch, tests).
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("cyberguard.org_context")

_TTL_SECONDS = 60.0
# owner_user_id -> (monotonic deadline, (org_id, is_personal))
_cache: dict[str, tuple[float, tuple[Optional[str], bool]]] = {}


def invalidate(owner_user_id: Optional[str] = None) -> None:
    """Drop one owner's cached resolution (or the whole cache)."""
    if owner_user_id is None:
        _cache.clear()
    else:
        _cache.pop(owner_user_id, None)


async def resolve_org_context(db: AsyncSession, owner_user_id: str) -> tuple[Optional[str], bool]:
    """Return (org_id, is_personal) for the owner — cached, single-shot.

    ``org_id`` is None only when the user row itself is missing (or carries
    neither an active org nor a personal org): callers must tolerate None and
    write un-stamped rows, never fail the operation being stamped.
    """
    if not owner_user_id:
        return None, False
    now = time.monotonic()
    cached = _cache.get(owner_user_id)
    if cached and cached[0] > now:
        return cached[1]

    org_id: Optional[str] = None
    is_personal = False
    row = (
        await db.execute(
            text(
                "select active_organization_id from cyberguard.users where id = :uid"
            ),
            {"uid": owner_user_id},
        )
    ).first()
    if row is None:
        logger.debug("resolve_org_context: user %s not found", owner_user_id)
    else:
        active = row[0]
        if active:
            # Same membership semantics as get_tenant_context: the org_member_role
            # SECURITY DEFINER (members + owner fallback) must recognize the user,
            # otherwise a stale active_organization_id would stamp rows the user
            # can no longer see.
            role = (
                await db.execute(
                    text("select cyberguard.org_member_role(:org, :uid)"),
                    {"org": active, "uid": owner_user_id},
                )
            ).scalar()
            if role is not None:
                org_row = (
                    await db.execute(
                        text(
                            "select id from cyberguard.org_organizations where id = :org"
                        ),
                        {"org": active},
                    )
                ).first()
                if org_row is not None:
                    org_id = active
                    is_personal = False
        if org_id is None:
            first_org = (
                await db.execute(
                    text(
                        "select id from cyberguard.org_organizations "
                        "where owner_id = :uid "
                        "and status = 'active' order by created_at asc limit 1"
                    ),
                    {"uid": owner_user_id},
                )
            ).scalar()
            if first_org:
                org_id = first_org
                is_personal = False

    _cache[owner_user_id] = (now + _TTL_SECONDS, (org_id, is_personal))
    return org_id, is_personal


async def resolve_org_id(db: AsyncSession, owner_user_id: str) -> Optional[str]:
    """Org stamp for pipeline-created rows (see resolve_org_context)."""
    org_id, _ = await resolve_org_context(db, owner_user_id)
    return org_id


# ---------------------------------------------------------------------------
# Project resolution (ORG-REDESIGN)
# ---------------------------------------------------------------------------

_project_cache: dict[str, tuple[float, Optional[str]]] = {}


async def resolve_project_id(
    db: AsyncSession, owner_user_id: str, org_id: Optional[str]
) -> Optional[str]:
    """Project stamp for org-plane rows (best-effort, never fails the caller).

    Resolution rule (per D6 of ORG-REDESIGN):
    1. the user's persisted ``active_project_id`` — honored only when it
       belongs to ``org_id`` and is active;
    2. otherwise the org's oldest active project (the auto-provisioned
       'General' one for new orgs);
    3. otherwise None (row stays org-stamped only).

    Cached per (owner, org) for the same TTL budget as the org stamp.
    """
    if not owner_user_id or not org_id:
        return None
    key = f"{owner_user_id}:{org_id}"
    now = time.monotonic()
    cached = _project_cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    project_id: Optional[str] = None
    active = (
        await db.execute(
            text("select active_project_id from cyberguard.users where id = :uid"),
            {"uid": owner_user_id},
        )
    ).scalar()
    if active:
        valid = (
            await db.execute(
                text(
                    "select 1 from cyberguard.org_projects "
                    "where id = :pid and organization_id = :org and status = 'active'"
                ),
                {"pid": active, "org": org_id},
            )
        ).first()
        if valid is not None:
            project_id = active
    if project_id is None:
        project_id = (
            await db.execute(
                text(
                    "select id from cyberguard.org_projects "
                    "where organization_id = :org and status = 'active' "
                    "order by created_at asc limit 1"
                ),
                {"org": org_id},
            )
        ).scalar()

    _project_cache[key] = (now + _TTL_SECONDS, project_id)
    return project_id


def invalidate_projects(owner_user_id: Optional[str] = None) -> None:
    """Drop cached project resolutions (switch-project, tests)."""
    if owner_user_id is None:
        _project_cache.clear()
    else:
        for key in [k for k in _project_cache if k.startswith(f"{owner_user_id}:")]:
            _project_cache.pop(key, None)
