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
from app.db.models import Organization, OrganizationAPIKey
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
