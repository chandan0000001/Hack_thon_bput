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
                personal_row = (
                    await db.execute(
                        text(
                            "select is_personal from cyberguard.organizations where id = :org"
                        ),
                        {"org": active},
                    )
                ).first()
                if personal_row is not None:
                    org_id = active
                    is_personal = bool(personal_row[0])
        if org_id is None:
            personal = (
                await db.execute(
                    text(
                        "select id from cyberguard.organizations "
                        "where is_personal = true and owner_id = :uid "
                        "and status = 'active' limit 1"
                    ),
                    {"uid": owner_user_id},
                )
            ).scalar()
            if personal:
                org_id = personal
                is_personal = True

    _cache[owner_user_id] = (now + _TTL_SECONDS, (org_id, is_personal))
    return org_id, is_personal


async def resolve_org_id(db: AsyncSession, owner_user_id: str) -> Optional[str]:
    """Org stamp for pipeline-created rows (see resolve_org_context)."""
    org_id, _ = await resolve_org_context(db, owner_user_id)
    return org_id
