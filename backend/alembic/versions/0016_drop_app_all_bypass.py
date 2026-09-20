"""ORG-FIX-1: drop the permissive *_app_all RLS bypass on org tables.

Revision ID: 0016_drop_app_all_bypass
Revises: 0015_email_verdict_columns
Create Date: 2026-09-21

Why
---
The ORG-1 baseline (0001) stamps policy helpers over the ENTIRE ORM metadata
— including org tables that later migrations were going to manage. Tables
without an ``owner_user_id`` column fell through to ``_app_only_policies``:
``FOR ALL TO cyberguard_api USING (true) WITH CHECK (true)``. Later org
migrations (0008/0009/0010/0011) added correct membership-gated policies but
never dropped that permissive fallback. PostgreSQL OR-combines permissive
policies, so ``USING (true)`` silently defeated every gated policy: the app
role could read/write every org's rows regardless of the ``app.user_id`` GUC.

Commit 58170da documented a manual RUNBOOK prune step for these policies,
which is why some environments (wiped + re-run) don't exhibit the leak — the
fix lived in ops lore, not in migration code. This migration makes it code.

What this does (plain SQL only — no ``auth`` schema references; applies
identically on local Postgres and Supabase):

1. Enumerate ``pg_policies`` and DROP every permissive policy on the org
   tables whose name is ``*_app_all`` / ``*_app_select``, targets
   ``cyberguard_api``, and carries ``qual = 'true'`` (dynamic — only what
   actually exists is dropped).
2. For any org table/command left WITHOUT a non-permissive policy, add the
   generic gated fallback:
   - SELECT/UPDATE/DELETE: ``org_member_role(organization_id, app.user_id) IS NOT NULL``
   - INSERT: the same, AND ``owner_id``/``created_by`` = ``app.user_id``
     when such a column exists.
   ``organizations`` is special-cased (its tenant key IS the row id; INSERT
   checks ``owner_id``). In practice only ``organizations`` needs the
   fallback today — every other org table already carries gated policies
   from 0008/0009/0010/0011.
3. ``organization_api_keys`` special handling (pre-identity hash validation):
   - Replace the blanket table privilege with an explicit minimal set
     (SELECT/INSERT/UPDATE/DELETE). The SELECT privilege must remain because
     the ORM admin-listing path runs under the gated policies (a hard REVOKE
     would break ``GET /orgs/{id}/api-keys`` with permission-denied, not
     0 rows); row-level narrowing is enforced by the POLICIES (the permissive
     ``app_select``/``app_all`` are gone; admins read via
     ``organization_api_keys_admin_write``/``_admin_select``).
   - Create ``cyberguard.validate_org_api_key(p_hash)`` — SECURITY DEFINER,
     returns exactly one row for an exact hash match. This is the narrow
     escape hatch that lets gateway key validation resolve a key BEFORE any
     user/org identity (and therefore any useful GUC) exists, without
     re-opening a permissive table policy.
   - Add ``organization_api_keys_admin_select`` (explicit admin-gated
     SELECT) for clarity alongside the FOR ALL admin-write policy.

Downgrade recreates the dropped permissive policies verbatim (baseline
``_app_all`` shape, 0008's ``app_select`` shape) and removes everything this
migration added.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0016_drop_app_all_bypass"
down_revision: Union[str, Sequence[str], None] = "0015_email_verdict_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.drop_app_all_bypass")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

# The 11 org tables (audit A2.2). ``org_mail_server_settings``/``_logs`` are
# keyed by mail_server_id — their predicates resolve the org through
# org_mail_servers, exactly like the 0010 policies.
ORG_TABLES = (
    "organizations",
    "organization_members",
    "organization_api_keys",
    "organization_settings",
    "org_log_events",
    "org_mail_servers",
    "org_mail_server_settings",
    "org_mail_server_logs",
    "org_notification_emails",
    "org_notification_settings",
    "org_notification_logs",
)


def _member_pred(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC}) IS NOT NULL"


def _admin_pred(tbl: str) -> str:
    return f"cyberguard.org_member_role({tbl}.organization_id, {_GUC}) = 'admin'"


def _org_key_column(bind, table: str) -> str | None:
    """The column carrying the tenant key ('id' for organizations itself)."""
    if table == "organizations":
        return "id"
    col = bind.execute(
        text(
            "select column_name from information_schema.columns "
            "where table_schema = :s and table_name = :t and column_name = 'organization_id'"
        ),
        {"s": SCHEMA, "t": table},
    ).scalar()
    return "organization_id" if col else None


def _gated_fallback_ddl(bind, table: str) -> list[str]:
    """Generic gated policies for commands no remaining policy covers.

    Spec (ORG-FIX-1 D1): SELECT/UPDATE/DELETE gate on membership; INSERT also
    pins owner_id/created_by to the calling identity when such a column
    exists. Tables that already carry a gated policy for a command (e.g. the
    0009 admin-only INSERT on org_log_events) are left untouched — the
    stricter existing policy wins by simply not being touched.
    """
    q = f"{SCHEMA}.{table}"
    key = _org_key_column(bind, table)
    if key is None:
        return []

    if table == "organizations":
        member = f"cyberguard.org_member_role({table}.id, {_GUC}) IS NOT NULL"
        insert_check = f"owner_id = {_GUC}"
    else:
        member = _member_pred(table)
        owner_col = bind.execute(
            text(
                "select column_name from information_schema.columns "
                "where table_schema = :s and table_name = :t "
                "and column_name in ('owner_id', 'created_by') order by column_name limit 1"
            ),
            {"s": SCHEMA, "t": table},
        ).scalar()
        insert_check = member
        if owner_col:
            insert_check = f"{member} AND {owner_col} = {_GUC}"

    existing = bind.execute(
        text(
            "select cmd from pg_policies "
            "where schemaname = :s and tablename = :t "
            "and 'cyberguard_api' = any (roles)"
        ),
        {"s": SCHEMA, "t": table},
    ).all()
    # The permissive policies are dropped before this runs; what remains is
    # the gated set FOR cyberguard_api. Policies TO other roles (e.g. the
    # TO-authenticated realtime readers) never cover an app-role command.
    # 'ALL' covers every command.
    covered = {row[0] for row in existing}
    covered_all = "ALL" in covered

    ddl: list[str] = []
    per_command = {
        "SELECT": f"CREATE POLICY {table}_member_select ON {q} FOR SELECT TO cyberguard_api USING ({member})",
        "INSERT": f"CREATE POLICY {table}_gated_insert ON {q} FOR INSERT TO cyberguard_api WITH CHECK ({insert_check})",
        "UPDATE": f"CREATE POLICY {table}_member_update ON {q} FOR UPDATE TO cyberguard_api USING ({member}) WITH CHECK ({member})",
        "DELETE": f"CREATE POLICY {table}_member_delete ON {q} FOR DELETE TO cyberguard_api USING ({member})",
    }
    for cmd, stmt in per_command.items():
        if covered_all or cmd in covered:
            continue
        ddl.append(stmt)
    return ddl


def _validate_key_function() -> str:
    """Narrow pre-identity key validation (SECURITY DEFINER).

    Spec signature deviation, recorded in DECISIONS.md: id columns are
    ``varchar(36)`` in this schema (not ``uuid``), and the function also
    returns ``organization_status``/``owner_user_id`` so the single definer
    call covers the suspended-org check and the owner-identity stamping the
    gateway needs — no second pre-identity read exists.
    """
    return f"""
        create or replace function {SCHEMA}.validate_org_api_key(p_hash text)
        returns table (
            organization_id text,
            key_id text,
            status text,
            expires_at timestamptz,
            organization_status text,
            owner_user_id text
        )
        language sql
        stable
        security definer
        set search_path = {SCHEMA}, pg_catalog
        as $$
            select k.organization_id::text,
                   k.id::text,
                   k.status,
                   k.expires_at,
                   o.status,
                   o.owner_id::text
            from {SCHEMA}.organization_api_keys k
            join {SCHEMA}.organizations o on o.id = k.organization_id
            where k.key_hash = p_hash
        $$;
    """


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        logger.info("SQLite — RLS bypass drop not applicable")
        return

    # 1. Drop every permissive *_app_all / *_app_select policy TO
    #    cyberguard_api (qual literally 'true') on the org tables.
    tables_sql = ", ".join(f"'{t}'" for t in ORG_TABLES)  # constant list, not input
    permissive = bind.execute(
        text(
            "select tablename, policyname from pg_policies "
            f"where schemaname = '{SCHEMA}' "
            f"  and tablename in ({tables_sql}) "
            "  and 'cyberguard_api' = any (roles) "
            "  and (policyname like '%_app_all' or policyname like '%_app_select') "
            "  and qual = 'true'"
        )
    ).all()
    for tablename, policyname in permissive:
        op.execute(f"DROP POLICY IF EXISTS {policyname} ON {SCHEMA}.{tablename}")
        logger.info("dropped permissive policy %s on %s", policyname, tablename)

    # 2. Fill command gaps with the generic gated fallback (no-op for tables
    #    whose gated policies from 0008/0009/0010/0011 already cover them).
    for table in ORG_TABLES:
        exists = bind.execute(
            text("select to_regclass(:t) is not null"),
            {"t": f"{SCHEMA}.{table}"},
        ).scalar()
        if not exists:
            continue
        for stmt in _gated_fallback_ddl(bind, table):
            op.execute(stmt)
            logger.info("added gated policy: %s", stmt.split("ON")[0].split("POLICY")[1].strip())

    # 3. organization_api_keys special handling.
    keys_q = f"{SCHEMA}.organization_api_keys"
    # Minimal explicit privilege set instead of blanket ALL. SELECT stays
    # (ORM admin listing runs under gated policies); narrowing is enforced by
    # the policy layer, not the privilege layer — see migration docstring.
    op.execute(f"REVOKE ALL ON {keys_q} FROM cyberguard_api")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {keys_q} TO cyberguard_api")
    op.execute(_validate_key_function())
    op.execute(f"revoke all on function {SCHEMA}.validate_org_api_key(text) from public")
    op.execute(f"grant execute on function {SCHEMA}.validate_org_api_key(text) to cyberguard_api")
    op.execute(
        f"CREATE POLICY organization_api_keys_admin_select ON {keys_q} "
        f"FOR SELECT TO cyberguard_api USING ({_admin_pred('organization_api_keys')})"
    )
    logger.info("installed validate_org_api_key definer function + admin_select policy")

    # 4. Grants defensively re-issued (baseline parity).
    op.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA {SCHEMA} TO cyberguard_api")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return

    # Remove what upgrade added.
    op.execute(f"DROP POLICY IF EXISTS organization_api_keys_admin_select ON {SCHEMA}.organization_api_keys")
    op.execute(f"DROP FUNCTION IF EXISTS {SCHEMA}.validate_org_api_key(text)")
    op.execute(f"DROP POLICY IF EXISTS organizations_member_select ON {SCHEMA}.organizations")
    op.execute(f"DROP POLICY IF EXISTS organizations_owner_insert ON {SCHEMA}.organizations")
    op.execute(f"DROP POLICY IF EXISTS organizations_member_update ON {SCHEMA}.organizations")
    op.execute(f"DROP POLICY IF EXISTS organizations_member_delete ON {SCHEMA}.organizations")
    op.execute(f"DROP POLICY IF EXISTS organizations_gated_insert ON {SCHEMA}.organizations")

    # Restore the permissive bypass policies VERBATIM (baseline 0001
    # _app_only_policies / _shared_policies shape; 0008 app_select shape).
    for table in ORG_TABLES:
        exists = bind.execute(
            text("select to_regclass(:t) is not null"),
            {"t": f"{SCHEMA}.{table}"},
        ).scalar()
        if not exists:
            continue
        op.execute(
            f"CREATE POLICY {table}_app_all ON {SCHEMA}.{table} "
            f"FOR ALL TO cyberguard_api USING (true) WITH CHECK (true)"
        )
    op.execute(
        f"CREATE POLICY organization_api_keys_app_select ON {SCHEMA}.organization_api_keys "
        f"FOR SELECT TO cyberguard_api USING (true)"
    )
    op.execute(f"GRANT ALL ON {SCHEMA}.organization_api_keys TO cyberguard_api")
