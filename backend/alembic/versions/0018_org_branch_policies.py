"""ORG-WIRE: org-branch RLS on security tables + security_events org column.

Revision ID: 0018_org_branch_policies
Revises: 0017_gated_realtime_reader
Create Date: 2026-09-21

Why
---
ORG-FIX-1 (0016) removed the permissive `_app_all` bypass and, as a side
effect, EXPOSED a gap: `events`, `alerts`, `action_executions`, `audit_logs`
carry only owner-scoped policies, so an org-plane read by a NON-owner admin
(e.g. the org dashboard aggregating `events` by `organization_id`) returned
only that admin's own rows. This migration widens the security tables with
permissive OR-branch policies (the 0008 `enforcement_policies` pattern):

    owner_user_id = current_setting('app.user_id', true)
    OR (organization_id IS NOT NULL
        AND cyberguard.org_member_role(organization_id,
                                       current_setting('app.user_id', true))
             IS NOT NULL)

Permissive policies OR-combine with the existing owner policies, so nothing
is replaced; the downgrade drops exactly what was added.

Scope guard — mailbox artifacts stay owner-only:
`processed_emails`, `gmail_accounts`, `scan_results`, and the attachment
metadata inside `processed_emails.attachments_meta` are deliberately NOT
touched. A connected mailbox is a personal artifact even when its owner
works in an org; org colleagues see pipeline VERDICTS (stamped
events/alerts/notifications), never the mailbox itself.

`security_events` had no `organization_id` column — the pipeline's
event-of-record could not be org-stamped at all. The column is added here
(nullable, indexed, idempotent) so `realtime_notifier` /
`security_history_service` can stamp it; the policies follow the same
guarded pattern.

Plain SQL only (no `auth` schema references); every step guards on column
existence so it applies identically on local Postgres and Supabase.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0018_org_branch_policies"
down_revision: Union[str, Sequence[str], None] = "0017_gated_realtime_reader"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_branch_security")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

# (table, needs_new_org_column) — the security plane. Mailbox artifacts
# (processed_emails, gmail_accounts, scan_results) are intentionally absent.
SECURITY_TABLES = (
    "events",
    "alerts",
    "action_executions",
    "security_events",
    "audit_logs",
)

NEW_ORG_COLUMN_TABLES = ("security_events",)


def _has_column(bind, table: str, column: str) -> bool:
    return bool(
        bind.execute(
            text(
                "select 1 from information_schema.columns "
                "where table_schema = :s and table_name = :t and column_name = :c"
            ),
            {"s": SCHEMA, "t": table, "c": column},
        ).scalar()
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        logger.info("SQLite — org-branch security policies not applicable")
        return

    # 1. security_events: add the missing org stamp column.
    for table in NEW_ORG_COLUMN_TABLES:
        op.execute(
            f"ALTER TABLE {SCHEMA}.{table} "
            f"ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        )
        op.execute(
            f"CREATE INDEX IF NOT EXISTS ix_{table}_organization_id "
            f"ON {SCHEMA}.{table} (organization_id)"
        )
        logger.info("ensured column %s.%s + index", table, "organization_id")

    # 2. Permissive OR-branch policies (owner OR org-member).
    for table in SECURITY_TABLES:
        if not (_has_column(bind, table, "organization_id") and _has_column(bind, table, "owner_user_id")):
            logger.warning("skipping %s — missing organization_id/owner_user_id", table)
            continue
        q = f"{SCHEMA}.{table}"
        pred = (
            f"({table}.owner_user_id = {_GUC} "
            f"OR ({table}.organization_id IS NOT NULL AND "
            f"cyberguard.org_member_role({table}.organization_id, {_GUC}) IS NOT NULL))"
        )
        op.execute(
            f"CREATE POLICY {table}_org_select ON {q} "
            f"FOR SELECT TO cyberguard_api USING ({pred})"
        )
        op.execute(
            f"CREATE POLICY {table}_org_insert ON {q} "
            f"FOR INSERT TO cyberguard_api WITH CHECK ({pred})"
        )
        op.execute(
            f"CREATE POLICY {table}_org_update ON {q} "
            f"FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})"
        )
        logger.info("added org-branch policies on %s (select/insert/update)", table)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return

    for table in SECURITY_TABLES:
        for cmd in ("select", "insert", "update"):
            op.execute(f"DROP POLICY IF EXISTS {table}_org_{cmd} ON {SCHEMA}.{table}")
    for table in NEW_ORG_COLUMN_TABLES:
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_organization_id")
        op.execute(f"ALTER TABLE {SCHEMA}.{table} DROP COLUMN IF EXISTS organization_id")
