"""SCENARIO-2: org-scoped verified_identities table for the identity-fraud analyzer.

Revision ID: 0104_verified_identities
Revises: 0103_account_type_realm
Create Date: 2026-10-03

- Creates cyberguard.verified_identities (org-scoped trusted personnel roster).
- Enables RLS with member-read / member-insert policies using the shared
  org_member_role definer + app.user_id GUC pattern from 0100.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "0104_verified_identities"
down_revision: Union[str, Sequence[str], None] = "0026_org_member_invitations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"


def _role_exists(bind, role: str) -> bool:
    res = bind.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role})
    return res.first() is not None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # Test harness builds the schema from ORM metadata via create_all.
        return

    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.verified_identities (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL
                REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            project_id VARCHAR(36)
                REFERENCES {SCHEMA}.org_projects(id) ON DELETE SET NULL,
            owner_user_id VARCHAR(64),
            name VARCHAR(120) NOT NULL,
            role_title VARCHAR(120),
            email VARCHAR(255),
            username VARCHAR(64),
            created_by VARCHAR(64),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    bind.execute(text(
        f"CREATE INDEX IF NOT EXISTS ix_verified_identities_org "
        f"ON {SCHEMA}.verified_identities (organization_id)"
    ))
    bind.execute(text(
        f"CREATE INDEX IF NOT EXISTS ix_verified_identities_project "
        f"ON {SCHEMA}.verified_identities (project_id)"
    ))
    bind.execute(text(
        f"CREATE INDEX IF NOT EXISTS ix_verified_identities_owner "
        f"ON {SCHEMA}.verified_identities (owner_user_id)"
    ))

    bind.execute(text(f"ALTER TABLE {SCHEMA}.verified_identities ENABLE ROW LEVEL SECURITY"))
    bind.execute(text(f"ALTER TABLE {SCHEMA}.verified_identities FORCE ROW LEVEL SECURITY"))

    target_roles = ", ".join(
        [r for r in ("cyberguard_api", "authenticated") if _role_exists(bind, r)]
    ) or "cyberguard_api"

    for role_name in ("cyberguard_api", "authenticated"):
        if _role_exists(bind, role_name):
            bind.execute(text(f"GRANT ALL ON TABLE {SCHEMA}.verified_identities TO {role_name}"))

    # Idempotent policies: on databases provisioned via the 0102 fresh-DB fast
    # path a later `alembic upgrade head` replays this revision, so drop-then-
    # create keeps it a no-op.
    for policy in ("verified_identities_member_select", "verified_identities_member_insert", "verified_identities_admin_delete"):
        bind.execute(text(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.verified_identities"))

    bind.execute(text(f"""
        CREATE POLICY verified_identities_member_select ON {SCHEMA}.verified_identities
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL
               OR owner_user_id = {_GUC})
    """))
    bind.execute(text(f"""
        CREATE POLICY verified_identities_member_insert ON {SCHEMA}.verified_identities
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL
               OR owner_user_id = {_GUC})
    """))
    bind.execute(text(f"""
        CREATE POLICY verified_identities_admin_delete ON {SCHEMA}.verified_identities
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin'
               OR owner_user_id = {_GUC})
    """))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    bind.execute(text(f"DROP TABLE IF EXISTS {SCHEMA}.verified_identities CASCADE"))
