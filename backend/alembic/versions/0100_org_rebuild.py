"""ORG-REBUILD: Full teardown + rebuild of the organization system (3-level architecture).

Revision ID: 0100_org_rebuild
Revises: 0023_gmail_full_clear
Create Date: 2026-09-23

Drops:
- Legacy org tables: organizations, organization_members, organization_api_keys,
  organization_settings, org_log_events, org_mail_servers, org_mail_server_settings,
  org_mail_server_logs, org_notification_emails, org_notification_settings,
  org_notification_logs, projects, project_api_keys IF EXISTS + cascade.
- Legacy functions: validate_org_api_key, validate_project_api_key.
- Legacy publication table members from supabase_realtime.

Creates:
- Level 1 Org: org_organizations, org_members
- Level 2 Project Gateway: org_projects, org_api_keys
- Level 3 Event & Indicator Monitoring: org_events, org_blocked_indicators
- Helper functions: org_member_role(p_org, p_user), validate_org_api_key(p_hash)
- RLS policies: member-gated, admin-write, NO permissive USING(true)
- Supabase Realtime publication membership for cyberguard.org_events.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0100_org_rebuild"
down_revision: Union[str, Sequence[str], None] = "0023_gmail_full_clear"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_rebuild")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

_DROP_LEGACY_TABLES = (
    "project_api_keys",
    "projects",
    "org_notification_logs",
    "org_notification_settings",
    "org_notification_emails",
    "org_mail_server_logs",
    "org_mail_server_settings",
    "org_mail_servers",
    "org_log_events",
    "organization_settings",
    "organization_api_keys",
    "organization_members",
    "organizations",
)


def _publication_exists(bind, pub_name: str) -> bool:
    if bind.dialect.name == "sqlite":
        return False
    row = bind.execute(
        text("SELECT 1 FROM pg_publication WHERE pubname = :pub"),
        {"pub": pub_name},
    ).first()
    return bool(row)


def _table_in_publication(bind, pub_name: str, table_name: str) -> bool:
    if bind.dialect.name == "sqlite":
        return False
    row = bind.execute(
        text(
            "SELECT 1 FROM pg_publication_tables "
            "WHERE pubname = :pub AND schemaname = :s AND tablename = :t"
        ),
        {"pub": pub_name, "s": SCHEMA, "t": table_name},
    ).first()
    return bool(row)


def _role_exists(bind, role_name: str) -> bool:
    if bind.dialect.name == "sqlite":
        return False
    row = bind.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :r"),
        {"r": role_name},
    ).first()
    return bool(row)


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name != "sqlite"

    # 1. Remove legacy tables from publication
    if is_pg and _publication_exists(bind, "supabase_realtime"):
        for tbl in ("org_log_events", "projects", "organizations"):
            if _table_in_publication(bind, "supabase_realtime", tbl):
                try:
                    bind.execute(text(f"ALTER PUBLICATION supabase_realtime DROP TABLE {SCHEMA}.{tbl}"))
                except Exception as exc:
                    logger.warning("Could not drop %s from supabase_realtime: %s", tbl, exc)

    # 2. DROP legacy functions
    if is_pg:
        bind.execute(text(f"DROP FUNCTION IF EXISTS {SCHEMA}.validate_project_api_key(text) CASCADE"))
        bind.execute(text(f"DROP FUNCTION IF EXISTS {SCHEMA}.validate_org_api_key(text) CASCADE"))

    # 3. DROP legacy tables
    for tbl in _DROP_LEGACY_TABLES:
        if is_pg:
            bind.execute(text(f"DROP TABLE IF EXISTS {SCHEMA}.{tbl} CASCADE"))
        else:
            bind.execute(text(f"DROP TABLE IF EXISTS {tbl}"))

    # 4. CREATE new schema
    # 4a. org_organizations
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_organizations (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            owner_id VARCHAR(36) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))

    # 4b. org_members
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_members (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            user_id VARCHAR(36) NOT NULL,
            role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
            joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_org_members_org_user UNIQUE (organization_id, user_id)
        )
    """))

    # 4c. org_projects
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_projects (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            name VARCHAR(120) NOT NULL,
            slug VARCHAR(60) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_org_projects_org_slug UNIQUE (organization_id, slug)
        )
    """))

    # 4d. org_api_keys
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_api_keys (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_projects(id) ON DELETE CASCADE,
            organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            name VARCHAR(120) NOT NULL,
            role VARCHAR(20) NOT NULL CHECK (role IN ('master', 'viewer')),
            key_hash VARCHAR(128) NOT NULL UNIQUE,
            key_prefix VARCHAR(16) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            last_used_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))
    bind.execute(text(f"""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_org_api_keys_active_role
        ON {SCHEMA}.org_api_keys (project_id, role)
        WHERE status = 'active'
    """))

    # 4e. org_events
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_events (
            id VARCHAR(36) PRIMARY KEY,
            project_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_projects(id) ON DELETE CASCADE,
            organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            event_type VARCHAR(32) NOT NULL CHECK (event_type IN ('log_event', 'ato_event', 'network_event')),
            severity VARCHAR(20) NOT NULL,
            source VARCHAR(20) NOT NULL DEFAULT 'gateway' CHECK (source IN ('gateway', 'manual')),
            raw_data JSONB NOT NULL DEFAULT '{{}}'::jsonb,
            analysis_result JSONB NOT NULL DEFAULT '{{}}'::jsonb,
            verdict VARCHAR(32) NOT NULL DEFAULT 'pending_review' CHECK (verdict IN ('pending_review', 'released', 'blocked_permanently', 'false_positive')),
            user_action VARCHAR(32) NULL,
            acted_by VARCHAR(36) NULL,
            acted_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))

    # 4f. org_blocked_indicators
    bind.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.org_blocked_indicators (
            id VARCHAR(36) PRIMARY KEY,
            organization_id VARCHAR(36) NOT NULL REFERENCES {SCHEMA}.org_organizations(id) ON DELETE CASCADE,
            project_id VARCHAR(36) NULL REFERENCES {SCHEMA}.org_projects(id) ON DELETE CASCADE,
            indicator_type VARCHAR(20) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'email', 'hash', 'actor')),
            indicator_value VARCHAR(255) NOT NULL,
            reason TEXT NULL,
            blocked_by VARCHAR(36) NULL,
            blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_org_blocked_indicators UNIQUE (organization_id, indicator_type, indicator_value)
        )
    """))

    # Indexes
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_members_user ON {SCHEMA}.org_members(user_id)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_projects_org ON {SCHEMA}.org_projects(organization_id)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_api_keys_proj ON {SCHEMA}.org_api_keys(project_id)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_events_proj ON {SCHEMA}.org_events(project_id)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_events_org ON {SCHEMA}.org_events(organization_id)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_events_created ON {SCHEMA}.org_events(created_at)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_events_verdict ON {SCHEMA}.org_events(verdict)"))
    bind.execute(text(f"CREATE INDEX IF NOT EXISTS idx_org_blocked_org ON {SCHEMA}.org_blocked_indicators(organization_id)"))

    if not is_pg:
        return

    # 5. Functions
    # 5a. org_member_role helper
    bind.execute(text(f"""
        CREATE OR REPLACE FUNCTION {SCHEMA}.org_member_role(p_org text, p_user text)
        RETURNS text
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = {SCHEMA}, pg_temp
        AS $$
            SELECT coalesce(
                (SELECT m.role
                 FROM {SCHEMA}.org_members m
                 WHERE m.organization_id = p_org
                   AND m.user_id = p_user
                 LIMIT 1),
                (SELECT 'admin'
                 WHERE EXISTS (
                     SELECT 1 FROM {SCHEMA}.org_organizations o
                     WHERE o.id = p_org AND o.owner_id = p_user))
            )
        $$;
    """))

    # 5b. validate_org_api_key
    bind.execute(text(f"""
        CREATE OR REPLACE FUNCTION {SCHEMA}.validate_org_api_key(p_hash text)
        RETURNS TABLE (
            key_id text,
            project_id text,
            organization_id text,
            role text,
            owner_user_id text,
            status text
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = {SCHEMA}, pg_catalog
        AS $$
            SELECT k.id::text, k.project_id::text, k.organization_id::text, k.role,
                   o.owner_id::text, k.status
            FROM {SCHEMA}.org_api_keys k
            JOIN {SCHEMA}.org_organizations o ON o.id = k.organization_id
            WHERE k.key_hash = p_hash
        $$;
    """))

    # Grants for helper functions
    valid_roles = [r for r in ("cyberguard_api", "authenticated", "service_role") if _role_exists(bind, r)]
    for role_name in valid_roles:
        bind.execute(text(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.org_member_role(text, text) TO {role_name}"))
        bind.execute(text(f"GRANT EXECUTE ON FUNCTION {SCHEMA}.validate_org_api_key(text) TO {role_name}"))

    # 6. RLS Policies
    new_tables = (
        "org_organizations",
        "org_members",
        "org_projects",
        "org_api_keys",
        "org_events",
        "org_blocked_indicators",
    )
    for tbl in new_tables:
        bind.execute(text(f"ALTER TABLE {SCHEMA}.{tbl} ENABLE ROW LEVEL SECURITY"))
        bind.execute(text(f"ALTER TABLE {SCHEMA}.{tbl} FORCE ROW LEVEL SECURITY"))
        for role_name in valid_roles:
            bind.execute(text(f"GRANT ALL ON TABLE {SCHEMA}.{tbl} TO {role_name}"))

    target_roles = ", ".join([r for r in ("cyberguard_api", "authenticated") if _role_exists(bind, r)]) or "cyberguard_api"

    # org_organizations
    bind.execute(text(f"""
        CREATE POLICY org_organizations_member_select ON {SCHEMA}.org_organizations
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_organizations_creator_insert ON {SCHEMA}.org_organizations
        FOR INSERT TO {target_roles}
        WITH CHECK (owner_id = {_GUC})
    """))
    bind.execute(text(f"""
        CREATE POLICY org_organizations_admin_update ON {SCHEMA}.org_organizations
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin')
        WITH CHECK ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_organizations_admin_delete ON {SCHEMA}.org_organizations
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(id, {_GUC}) = 'admin')
    """))

    # org_members
    bind.execute(text(f"""
        CREATE POLICY org_members_member_select ON {SCHEMA}.org_members
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_members_admin_insert ON {SCHEMA}.org_members
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_members_admin_update ON {SCHEMA}.org_members
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_members_admin_delete ON {SCHEMA}.org_members
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))

    # org_projects
    bind.execute(text(f"""
        CREATE POLICY org_projects_member_select ON {SCHEMA}.org_projects
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_projects_admin_insert ON {SCHEMA}.org_projects
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_projects_admin_update ON {SCHEMA}.org_projects
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_projects_admin_delete ON {SCHEMA}.org_projects
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))

    # org_api_keys (admin-read, admin-write)
    bind.execute(text(f"""
        CREATE POLICY org_api_keys_admin_select ON {SCHEMA}.org_api_keys
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_api_keys_admin_insert ON {SCHEMA}.org_api_keys
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_api_keys_admin_update ON {SCHEMA}.org_api_keys
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_api_keys_admin_delete ON {SCHEMA}.org_api_keys
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))

    # org_events (member-read, member-update, member-insert)
    bind.execute(text(f"""
        CREATE POLICY org_events_member_select ON {SCHEMA}.org_events
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_events_member_insert ON {SCHEMA}.org_events
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_events_member_update ON {SCHEMA}.org_events
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))

    # org_blocked_indicators (member-read, admin-write)
    bind.execute(text(f"""
        CREATE POLICY org_blocked_indicators_member_select ON {SCHEMA}.org_blocked_indicators
        FOR SELECT TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) IS NOT NULL)
    """))
    bind.execute(text(f"""
        CREATE POLICY org_blocked_indicators_admin_insert ON {SCHEMA}.org_blocked_indicators
        FOR INSERT TO {target_roles}
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_blocked_indicators_admin_update ON {SCHEMA}.org_blocked_indicators
        FOR UPDATE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
        WITH CHECK ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))
    bind.execute(text(f"""
        CREATE POLICY org_blocked_indicators_admin_delete ON {SCHEMA}.org_blocked_indicators
        FOR DELETE TO {target_roles}
        USING ({SCHEMA}.org_member_role(organization_id, {_GUC}) = 'admin')
    """))

    # 7. Realtime configuration
    bind.execute(text(f"ALTER TABLE {SCHEMA}.org_events REPLICA IDENTITY FULL"))
    if _publication_exists(bind, "supabase_realtime"):
        if not _table_in_publication(bind, "supabase_realtime", "org_events"):
            bind.execute(text(f"ALTER PUBLICATION supabase_realtime ADD TABLE {SCHEMA}.org_events"))
            logger.info("Added cyberguard.org_events to supabase_realtime publication")


def downgrade() -> None:
    """One-way migration.

    Downgrade drops the new rebuilt org tables and functions.
    Legacy state restoration is performed via the pre-org-rebuild-backup tag.
    """
    bind = op.get_bind()
    is_pg = bind.dialect.name != "sqlite"

    if is_pg and _publication_exists(bind, "supabase_realtime"):
        if _table_in_publication(bind, "supabase_realtime", "org_events"):
            try:
                bind.execute(text(f"ALTER PUBLICATION supabase_realtime DROP TABLE {SCHEMA}.org_events"))
            except Exception:
                pass

    if is_pg:
        bind.execute(text(f"DROP FUNCTION IF EXISTS {SCHEMA}.validate_org_api_key(text) CASCADE"))
        bind.execute(text(f"DROP FUNCTION IF EXISTS {SCHEMA}.org_member_role(text, text) CASCADE"))

    new_tables_reverse = (
        "org_blocked_indicators",
        "org_events",
        "org_api_keys",
        "org_projects",
        "org_members",
        "org_organizations",
    )
    for tbl in new_tables_reverse:
        if is_pg:
            bind.execute(text(f"DROP TABLE IF EXISTS {SCHEMA}.{tbl} CASCADE"))
        else:
            bind.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
