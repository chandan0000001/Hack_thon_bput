"""MEMBER-INVITE-P1: token-based organization invitations.

Revision ID: 0026_org_member_invitations
Revises: 0025_org_dashboard_counters
Create Date: 2026-10-01

Replaces the stub-user invite flow (precreate_user_for_invite → status='invited'
→ claim on first login) with secure token-based invitations:

- organization_invitations stores ONLY the SHA-256 token hash — the raw token
  is returned once at creation and never persisted.
- The accept path runs on the service role (the acceptor is by definition not
  yet a member, so org_members admin-insert RLS would reject it — same pattern
  as claim_invited_stub / project deletion).
- RLS on the table itself is admin-write/admin-read via
  cyberguard.org_member_role(organization_id, app.user_id), mirroring
  org_projects / org_api_keys.

NOTE: asyncpg rejects multiple commands per prepared statement — one execute each.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0026_org_member_invitations"
down_revision: Union[str, Sequence[str], None] = "0025_org_dashboard_counters"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_member_invitations")

SCHEMA = "cyberguard"
TABLE = f"{SCHEMA}.organization_invitations"
_GUC = "current_setting('app.user_id', true)::text"

CREATE_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    invited_by VARCHAR(64) NOT NULL REFERENCES {SCHEMA}.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
    accepted_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'expired', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

IDX_ORG_EMAIL_DDL = (
    f"CREATE INDEX IF NOT EXISTS ix_org_invitations_org_email "
    f"ON {TABLE} (organization_id, email)"
)

IDX_TOKEN_HASH_DDL = (
    f"CREATE INDEX IF NOT EXISTS ix_org_invitations_token_hash "
    f"ON {TABLE} (token_hash)"
)

ENABLE_RLS_DDL = f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"
FORCE_RLS_DDL = f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"

GRANT_DDL = f"GRANT ALL ON {TABLE} TO cyberguard_api"

# Admin-only access; the accept flow runs on the service role.
# Each CREATE is preceded by DROP IF EXISTS: fresh DBs already get these
# policies from the 0102 squash baseline (env.py fresh-DB optimization stops
# at 0102, then a later `upgrade head` re-runs this chain — 0026 must no-op).
POLICY_DDLS = [
    f"DROP POLICY IF EXISTS org_invitations_admin_select ON {TABLE}",
    f"""
CREATE POLICY org_invitations_admin_select ON {TABLE}
FOR SELECT TO cyberguard_api, authenticated
USING (cyberguard.org_member_role(organization_id, {_GUC}) = 'admin')
""",
    f"DROP POLICY IF EXISTS org_invitations_admin_insert ON {TABLE}",
    f"""
CREATE POLICY org_invitations_admin_insert ON {TABLE}
FOR INSERT TO cyberguard_api, authenticated
WITH CHECK (cyberguard.org_member_role(organization_id, {_GUC}) = 'admin')
""",
    f"DROP POLICY IF EXISTS org_invitations_admin_update ON {TABLE}",
    f"""
CREATE POLICY org_invitations_admin_update ON {TABLE}
FOR UPDATE TO cyberguard_api, authenticated
USING (cyberguard.org_member_role(organization_id, {_GUC}) = 'admin')
WITH CHECK (cyberguard.org_member_role(organization_id, {_GUC}) = 'admin')
""",
    f"DROP POLICY IF EXISTS org_invitations_admin_delete ON {TABLE}",
    f"""
CREATE POLICY org_invitations_admin_delete ON {TABLE}
FOR DELETE TO cyberguard_api, authenticated
USING (cyberguard.org_member_role(organization_id, {_GUC}) = 'admin')
""",
]

DROP_POLICY_DDLS = [
    f"DROP POLICY IF EXISTS org_invitations_admin_select ON {TABLE}",
    f"DROP POLICY IF EXISTS org_invitations_admin_insert ON {TABLE}",
    f"DROP POLICY IF EXISTS org_invitations_admin_update ON {TABLE}",
    f"DROP POLICY IF EXISTS org_invitations_admin_delete ON {TABLE}",
]

DOWNGRADE_DDL = f"DROP TABLE IF EXISTS {TABLE}"


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(text(CREATE_TABLE_DDL))
    bind.execute(text(IDX_ORG_EMAIL_DDL))
    bind.execute(text(IDX_TOKEN_HASH_DDL))
    bind.execute(text(ENABLE_RLS_DDL))
    bind.execute(text(FORCE_RLS_DDL))
    bind.execute(text(GRANT_DDL))
    for ddl in POLICY_DDLS:
        bind.execute(text(ddl))
    logger.info("created %s with admin-only RLS + token_hash/org_email indexes", TABLE)


def downgrade() -> None:
    bind = op.get_bind()
    for ddl in DROP_POLICY_DDLS:
        bind.execute(text(ddl))
    bind.execute(text(DOWNGRADE_DDL))
    logger.info("dropped %s", TABLE)
