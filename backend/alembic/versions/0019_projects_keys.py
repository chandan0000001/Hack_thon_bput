"""ORG-REDESIGN: multi-project architecture + project-scoped API keys.

Revision ID: 0019_projects_keys
Revises: 0018_org_branch_policies
Create Date: 2026-09-21

Why
---
An organization is no longer one flat gateway surface: work is organized into
PROJECTS, each with its own gateway endpoint and exactly two active API keys
(master = all actions, viewer = read-only actions). See DECISIONS.md
("Two keys per project", "Slug-in-URL gateway endpoints").

Tables
------
- ``projects``: org-scoped project registry (slug unique per org).
- ``project_api_keys``: project-scoped keys with role master|viewer. A
  partial unique index ((project_id, role) WHERE status='active') enforces
  the two-slot rule at the DB level; revocation frees the slot.

RLS (app role cyberguard_api, GUC app.user_id — the 0016/0018 pattern):
- ``projects``: SELECT for org members (org_member_role IS NOT NULL);
  INSERT/UPDATE/DELETE for org admins.
- ``project_api_keys``: admin-only SELECT/INSERT/UPDATE/DELETE (mirrors the
  organization_api_keys gating — key material is admin-sensitive).

Pre-identity validation runs through the SECURITY DEFINER
``cyberguard.validate_project_api_key(p_hash)`` — an exact-match hash lookup
returning only the columns the gateway needs — including the org owner id
so the post-validation RLS identity stamp needs no pre-auth org read (same
escape hatch as ``validate_org_api_key`` in 0016, because no useful app.user_id GUC exists
before authentication).

Plain SQL only; zero auth-schema references; guarded on table existence;
downgrade drops in reverse order.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0019_projects_keys"
down_revision: Union[str, Sequence[str], None] = "0018_org_branch_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.projects_keys")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

_PROJECTS_DDL = f"""
CREATE TABLE IF NOT EXISTS {SCHEMA}.projects (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.organizations(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(60) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug)
)
"""

_PROJECT_KEYS_DDL = f"""
CREATE TABLE IF NOT EXISTS {SCHEMA}.project_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    project_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.projects(id) ON DELETE CASCADE,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(120) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('master','viewer')),
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    key_prefix VARCHAR(12) NOT NULL,
    last_used_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

_VALIDATE_FN = f"""
create or replace function {SCHEMA}.validate_project_api_key(p_hash text)
returns table (project_id text, organization_id text, role text, status text,
               key_id text, owner_user_id text)
language sql stable security definer
set search_path = {SCHEMA}, pg_catalog
as $$
    select k.project_id::text, k.organization_id::text, k.role, k.status,
           k.id::text, o.owner_id::text
    from {SCHEMA}.project_api_keys k
    join {SCHEMA}.organizations o on o.id = k.organization_id
    where k.key_hash = p_hash
$$
"""


def _has_table(bind, table: str) -> bool:
    return bool(
        bind.execute(
            text(
                "select 1 from information_schema.tables "
                "where table_schema = :s and table_name = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).first()
    )


def _has_column(bind, table: str, column: str) -> bool:
    return bool(
        bind.execute(
            text(
                "select 1 from information_schema.columns "
                "where table_schema = :s and table_name = :t and column_name = :c"
            ),
            {"s": SCHEMA, "t": table, "c": column},
        ).first()
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return

    if not _has_table(bind, "projects"):
        bind.execute(text(_PROJECTS_DDL))
        bind.execute(
            text(f"CREATE INDEX IF NOT EXISTS projects_org_idx ON {SCHEMA}.projects(organization_id)")
        )
    if not _has_table(bind, "project_api_keys"):
        bind.execute(text(_PROJECT_KEYS_DDL))
        bind.execute(
            text(
                f"CREATE UNIQUE INDEX IF NOT EXISTS project_api_keys_role_uq "
                f"ON {SCHEMA}.project_api_keys(project_id, role) WHERE status='active'"
            )
        )

    # RLS: enable + force on both tables (forced so table owners cannot
    # accidentally bypass; the migration role stays exempt via superuser).
    for table in ("projects", "project_api_keys"):
        if _has_table(bind, table):
            bind.execute(text(f"ALTER TABLE {SCHEMA}.{table} ENABLE ROW LEVEL SECURITY"))
            bind.execute(text(f"ALTER TABLE {SCHEMA}.{table} FORCE ROW LEVEL SECURITY"))

    member_pred = f"{SCHEMA}.org_member_role(projects.organization_id, {_GUC}) IS NOT NULL"
    admin_pred = f"{SCHEMA}.org_member_role(projects.organization_id, {_GUC}) = 'admin'"

    project_policies = (
        f"CREATE POLICY projects_member_select ON {SCHEMA}.projects "
        f"FOR SELECT TO cyberguard_api USING ({member_pred})",
        f"CREATE POLICY projects_admin_insert ON {SCHEMA}.projects "
        f"FOR INSERT TO cyberguard_api WITH CHECK ({admin_pred})",
        f"CREATE POLICY projects_admin_update ON {SCHEMA}.projects "
        f"FOR UPDATE TO cyberguard_api USING ({admin_pred}) WITH CHECK ({admin_pred})",
        f"CREATE POLICY projects_admin_delete ON {SCHEMA}.projects "
        f"FOR DELETE TO cyberguard_api USING ({admin_pred})",
    )
    key_admin_pred = (
        f"{SCHEMA}.org_member_role(project_api_keys.organization_id, {_GUC}) = 'admin'"
    )
    key_policies = (
        f"CREATE POLICY project_api_keys_admin_select ON {SCHEMA}.project_api_keys "
        f"FOR SELECT TO cyberguard_api USING ({key_admin_pred})",
        f"CREATE POLICY project_api_keys_admin_insert ON {SCHEMA}.project_api_keys "
        f"FOR INSERT TO cyberguard_api WITH CHECK ({key_admin_pred})",
        f"CREATE POLICY project_api_keys_admin_update ON {SCHEMA}.project_api_keys "
        f"FOR UPDATE TO cyberguard_api USING ({key_admin_pred}) WITH CHECK ({key_admin_pred})",
        f"CREATE POLICY project_api_keys_admin_delete ON {SCHEMA}.project_api_keys "
        f"FOR DELETE TO cyberguard_api USING ({key_admin_pred})",
    )
    for table, policies in (("projects", project_policies), ("project_api_keys", key_policies)):
        if not _has_table(bind, table):
            continue
        for ddl in policies:
            policy_name = ddl.split("POLICY ")[1].split(" ON ")[0]
            bind.execute(text(f"DROP POLICY IF EXISTS {policy_name} ON {SCHEMA}.{table}"))
            bind.execute(text(ddl))

    bind.execute(text(_VALIDATE_FN))
    bind.execute(text(f"REVOKE ALL ON FUNCTION {SCHEMA}.validate_project_api_key(text) FROM public"))
    bind.execute(
        text(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.validate_project_api_key(text) TO cyberguard_api")
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    bind.execute(text(f"DROP FUNCTION IF EXISTS {SCHEMA}.validate_project_api_key(text)"))
    for table in ("project_api_keys", "projects"):
        if not _has_table(bind, table):
            continue
        rows = bind.execute(
            text("select policy_name from pg_policies where schemaname = :s and tablename = :t"),
            {"s": SCHEMA, "t": table},
        ).fetchall()
        for (policy_name,) in rows:
            bind.execute(text(f"DROP POLICY IF EXISTS {policy_name} ON {SCHEMA}.{table}"))
        bind.execute(text(f"ALTER TABLE {SCHEMA}.{table} DISABLE ROW LEVEL SECURITY"))
        bind.execute(text(f"DROP TABLE IF EXISTS {SCHEMA}.{table}"))
