"""Organization API keys: generation, hashing, validation, revocation (ORG-1).

Keys authenticate SERVER-TO-SERVER calls to the org-scoped gateway via the
``org_authorization`` header. Design constraints:

- Only the SHA-256 hash is stored. The plaintext is returned exactly once by
  the create endpoint and never persisted or logged. (SHA-256 — not bcrypt —
  is the right primitive here: keys are 32-byte random secrets with no
  entropy to brute-force, and validation must be an indexed exact-match
  lookup. No new dependency is required.)
- Validation runs BEFORE any user/org identity is known (no useful
  ``app.user_id`` GUC), so the ORM read path cannot see
  ``organization_api_keys`` rows at all — every permissive policy is gone
  (migration 0016, ORG-FIX-1). The narrow escape is the SECURITY DEFINER
  ``cyberguard.validate_org_api_key(p_hash)`` function: an exact-match hash
  lookup returning only the columns validation needs. Writes (create /
  revoke / last_used_at) and listing run as normal ORM statements under the
  gated admin policies, with the caller's identity in the GUC.
- After a successful validation the request's RLS identity (``app.user_id``
  GUC) is stamped as the org owner so gateway writes satisfy the
  owner-scoped policies on ``events``/``alerts``.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import UnauthorizedError
from app.db.models import Organization, OrganizationAPIKey, ProjectAPIKey
from app.db.session import current_user_id, get_db

logger = logging.getLogger("cyberguard.api_keys")

API_KEY_PREFIX = "cg_live_"

# SECURITY DEFINER exact-match lookup (migration 0016). Returns only what
# validation needs: key id/status/expiry plus the owning org's status and
# owner id (so the suspended-org check and the owner-identity stamp need no
# second pre-identity read).
_VALIDATE_KEY_SQL = text(
    "select organization_id, key_id, status, expires_at, organization_status, owner_user_id "
    "from cyberguard.validate_org_api_key(:key_hash)"
)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest of the raw key (stored in ``key_hash``)."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> str:
    """``cg_live_<43 url-safe chars>`` — ~256 bits of entropy."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


async def create_api_key(
    db: AsyncSession,
    *,
    organization_id: str,
    name: str,
    expires_at: Optional[datetime] = None,
    created_by: Optional[str] = None,
) -> dict[str, Any]:
    """Create an API key. Returns the plaintext ONCE — never store or log it."""
    raw_key = generate_api_key()
    api_key = OrganizationAPIKey(
        organization_id=organization_id,
        name=name,
        key_hash=hash_api_key(raw_key),
        key_prefix=raw_key[:16],
        expires_at=expires_at,
        created_by=created_by,
    )
    db.add(api_key)
    await db.commit()
    return {
        "id": api_key.id,
        "key": raw_key,
        "prefix": api_key.key_prefix,
        "name": name,
        "expires_at": expires_at,
    }


async def validate_api_key(db: AsyncSession, raw_key: str) -> Optional[Organization]:
    """Resolve an ``org_authorization`` header value to an active Organization.

    Returns None when the key is unknown, revoked, expired, or the org is
    suspended. On success, stamps the request's RLS identity as the org owner
    (see module docstring).
    """
    if not raw_key:
        return None
    raw_key = raw_key.strip()
    if raw_key.lower().startswith("bearer "):
        raw_key = raw_key[7:].strip()

    key_hash = hash_api_key(raw_key)

    # Pre-identity lookup: no useful app.user_id GUC exists yet, so the
    # app-role ORM path is blind to organization_api_keys by design (RLS).
    # The SECURITY DEFINER function performs the exact-match lookup instead.
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        row = (await db.execute(_VALIDATE_KEY_SQL, {"key_hash": key_hash})).first()
        if row is None or row.status != "active":
            return None
        org_id = row.organization_id
        key_id = row.key_id
        expires_at = row.expires_at
        owner_id = row.owner_user_id
        org_status = row.organization_status
    else:
        # SQLite (unit-test mode, RLS not enforced): plain ORM lookup.
        result = await db.execute(
            select(OrganizationAPIKey).where(OrganizationAPIKey.key_hash == key_hash)
        )
        api_key = result.scalar_one_or_none()
        if api_key is None or api_key.status != "active":
            return None
        org_id = api_key.organization_id
        key_id = None  # last_used_at bumped below via the live ORM object
        expires_at = api_key.expires_at
        owner_id = None
        org_status = None

    now = datetime.now(timezone.utc)
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            return None

    # Close the read-only transaction, then re-read the org and touch
    # last_used_at under the org owner's RLS identity (the gated policies
    # need the GUC). Telemetry only — never fail authentication because of it.
    await db.commit()
    current_user_id.set(owner_id)
    try:
        org = await db.get(Organization, org_id)
        if org is None or org.status != "active":
            return None
        if org_status is not None and org_status != "active":
            return None

        if key_id is not None:
            # PG: re-read the key row under the owner's identity (gated
            # policies resolve the owner to 'admin') and bump last_used_at.
            api_key = await db.get(OrganizationAPIKey, key_id)
            if api_key is not None:
                api_key.last_used_at = now
                await db.commit()
        else:
            api_key.last_used_at = now  # SQLite path: live ORM object
            await db.commit()
    except Exception as exc:  # noqa: BLE001 - last_used_at is best-effort
        await db.rollback()
        logger.debug("could not update last_used_at for key %s: %s", org_id, exc)

    return org


async def get_org_from_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Organization:
    """FastAPI dependency: authenticate a server-to-server request via the
    ``org_authorization`` header and return the key's organization."""
    raw_key = request.headers.get("org_authorization") or ""
    if not raw_key:
        raise UnauthorizedError("Missing org_authorization header")
    org = await validate_api_key(db, raw_key)
    if org is None:
        raise UnauthorizedError("Invalid or expired API key")
    return org


# ---------------------------------------------------------------------------
# Project-scoped keys (ORG-REDESIGN) — exactly one active key per
# (project, role): master = all gateway actions, viewer = read-only actions.
# ---------------------------------------------------------------------------

PROJECT_KEY_PREFIX = "cg_prj_"

_VALIDATE_PROJECT_KEY_SQL = text(
    "select project_id, organization_id, role, status, key_id, owner_user_id "
    "from cyberguard.validate_project_api_key(:key_hash)"
)


def generate_project_key() -> str:
    """``cg_prj_<43 url-safe chars>`` — ~256 bits of entropy."""
    return f"{PROJECT_KEY_PREFIX}{secrets.token_urlsafe(32)}"


async def create_project_key(
    db: AsyncSession,
    *,
    project_id: str,
    organization_id: str,
    role: str,
    name: str,
    actor_user_id: str,
) -> dict[str, Any]:
    """Create the project's master or viewer key. Returns the plaintext ONCE.

    Raises ConflictError when an active key already exists for the
    (project, role) slot — revoke it first to free the slot.
    """
    from app.core.errors import ConflictError, ValidationError

    if role not in ("master", "viewer"):
        raise ValidationError("role must be 'master' or 'viewer'")

    existing = await db.execute(
        select(ProjectAPIKey).where(
            ProjectAPIKey.project_id == project_id,
            ProjectAPIKey.role == role,
            ProjectAPIKey.status == "active",
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"An active {role} key already exists for this project — revoke it first")

    raw_key = generate_project_key()
    key = ProjectAPIKey(
        project_id=project_id,
        organization_id=organization_id,
        name=name or f"{role} key",
        role=role,
        key_hash=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        status="active",
        created_by=actor_user_id,
    )
    db.add(key)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - partial unique index race
        await db.rollback()
        raise ConflictError(f"An active {role} key already exists for this project — revoke it first") from exc
    return {
        "id": key.id,
        "key": raw_key,
        "prefix": key.key_prefix,
        "name": key.name,
        "role": role,
    }


async def list_project_keys(
    db: AsyncSession, *, project_id: str, organization_id: str
) -> list[ProjectAPIKey]:
    """All keys for a project (no plaintext), newest first."""
    result = await db.execute(
        select(ProjectAPIKey)
        .where(
            ProjectAPIKey.project_id == project_id,
            ProjectAPIKey.organization_id == organization_id,
        )
        .order_by(ProjectAPIKey.created_at.desc())
    )
    return list(result.scalars().all())


async def revoke_project_key(
    db: AsyncSession,
    *,
    key_id: str,
    project_id: str,
    organization_id: str,
    actor_user_id: str,
) -> Optional[ProjectAPIKey]:
    """Set status='revoked' — frees the (project, role) slot. Returns the
    revoked key, or None when the key does not belong to project/org."""
    result = await db.execute(
        select(ProjectAPIKey).where(
            ProjectAPIKey.id == key_id,
            ProjectAPIKey.project_id == project_id,
            ProjectAPIKey.organization_id == organization_id,
        )
    )
    key = result.scalar_one_or_none()
    if key is None:
        return None
    key.status = "revoked"
    key.last_used_at = key.last_used_at  # unchanged; kept explicit for clarity
    await db.commit()
    logger.info("project key %s (%s) revoked by %s", key_id, key.role, actor_user_id)
    return key


async def validate_project_key(
    db: AsyncSession, raw_key: str
) -> Optional[dict[str, Any]]:
    """Resolve an ``org_authorization`` header value to project-key claims.

    Returns ``{"project_id", "organization_id", "role", "key_id"}`` for an
    ACTIVE key, else None. Pre-identity lookup goes through the SECURITY
    DEFINER ``cyberguard.validate_project_api_key`` (same rationale as
    validate_api_key); SQLite falls back to plain ORM. On success the RLS
    identity is stamped as the key's org owner so gateway writes satisfy
    the org-branch policies.
    """
    if not raw_key:
        return None
    raw_key = raw_key.strip()
    if raw_key.lower().startswith("bearer "):
        raw_key = raw_key[7:].strip()

    key_hash = hash_api_key(raw_key)

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        row = (await db.execute(_VALIDATE_PROJECT_KEY_SQL, {"key_hash": key_hash})).first()
        if row is None or row.status != "active":
            return None
        claims = {
            "project_id": row.project_id,
            "organization_id": row.organization_id,
            "role": row.role,
            "key_id": row.key_id,
            "owner_user_id": row.owner_user_id,
        }
    else:
        result = await db.execute(
            select(ProjectAPIKey).where(ProjectAPIKey.key_hash == key_hash)
        )
        key = result.scalar_one_or_none()
        if key is None or key.status != "active":
            return None
        claims = {
            "project_id": key.project_id,
            "organization_id": key.organization_id,
            "role": key.role,
            "key_id": key.id,
            "owner_user_id": None,
        }

    await db.commit()
    # Stamp the org-owner identity BEFORE any RLS-gated read (same as the
    # org gateway path): with an empty GUC the organizations row is invisible.
    current_user_id.set(claims["owner_user_id"])
    try:
        org = await db.get(Organization, claims["organization_id"])
        if org is None or org.status != "active":
            return None
        if claims["owner_user_id"] is None:
            current_user_id.set(org.owner_id)
        # Bump last_used_at (best-effort) under the owner identity.
        if claims["key_id"] is not None:
            key = await db.get(ProjectAPIKey, claims["key_id"])
            if key is not None:
                key.last_used_at = datetime.now(timezone.utc)
                await db.commit()
    except Exception as exc:  # noqa: BLE001 - telemetry only
        await db.rollback()
        logger.debug("could not update project key last_used_at: %s", exc)

    return claims
