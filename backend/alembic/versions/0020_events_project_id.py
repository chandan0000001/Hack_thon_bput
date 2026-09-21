"""ORG-REDESIGN: project_id stamping on the security plane.

Revision ID: 0020_events_project_id
Revises: 0019_projects_keys
Create Date: 2026-09-21

Why
---
Gateway calls are now project-scoped (``POST /org/{org_id}/projects/{slug}/
gateway``), so every stamped row must carry WHICH project produced it —
otherwise per-project dashboards cannot aggregate and auditing cannot answer
"which project saw this threat". Nullable columns keep every existing writer
valid: personal-mode and legacy org-gateway rows simply have
``project_id IS NULL``.

Columns added (nullable VARCHAR(36), indexed, guarded on existence):
    events, alerts, action_executions, security_events, org_log_events,
    audit_logs  ->  project_id
    users       ->  active_project_id  (persists the project switcher, the
                   same pattern as active_organization_id)

Row visibility does NOT change: a project belongs to exactly one org, so the
permissive OR-branch policies (owner OR org-member-of-the-project's-org) from
0018 already expose project rows to exactly the right people. This migration
re-applies those policies idempotently (drop + create) across the six tables
so they provably cover the widened plane, and documents in DECISIONS.md why
"direct project membership" collapses to org membership (no project_members
table exists; inventing one would duplicate org RBAC).

Plain SQL only; zero auth-schema references; downgrade drops in reverse.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0020_events_project_id"
down_revision: Union[str, Sequence[str], None] = "0019_projects_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.events_project_id")

SCHEMA = "cyberguard"
_GUC = "current_setting('app.user_id', true)::text"

# The security plane + the org log stream (mailbox artifacts stay owner-only).
STAMP_TABLES = (
    "events",
    "alerts",
    "action_executions",
    "security_events",
    "org_log_events",
    "audit_logs",
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


def _add_project_column(bind, table: str) -> None:
    if not _has_column(bind, table, "project_id"):
        bind.execute(
            text(f"ALTER TABLE {SCHEMA}.{table} ADD COLUMN project_id VARCHAR(36)")
        )
    bind.execute(
        text(
            f"CREATE INDEX IF NOT EXISTS {table}_project_idx "
            f"ON {SCHEMA}.{table}(project_id)"
        )
    )


def _org_branch_policies(bind, table: str) -> None:
    """Re-apply the 0018 permissive OR-branch policies (owner OR org-member).

    Same predicate as migration 0018 — project rows inherit visibility from
    their organization, which is the intended scope (see DECISIONS.md).

    ``org_log_events`` has no ``owner_user_id`` column (org-plane only by
    schema), so its predicate is the org-member branch alone.
    """
    member_branch = (
        f"({SCHEMA}.{table}.organization_id IS NOT NULL AND "
        f"{SCHEMA}.org_member_role({SCHEMA}.{table}.organization_id, {_GUC}) IS NOT NULL)"
    )
    if _has_column(bind, table, "owner_user_id"):
        pred = f"({SCHEMA}.{table}.owner_user_id = {_GUC} OR {member_branch})"
    else:
        pred = member_branch
    plans = (
        (f"{table}_org_select", f"FOR SELECT TO cyberguard_api USING ({pred})"),
        (f"{table}_org_insert", f"FOR INSERT TO cyberguard_api WITH CHECK ({pred})"),
        (
            f"{table}_org_update",
            f"FOR UPDATE TO cyberguard_api USING ({pred}) WITH CHECK ({pred})",
        ),
    )
    for name, body in plans:
        bind.execute(text(f"DROP POLICY IF EXISTS {name} ON {SCHEMA}.{table}"))
        bind.execute(text(f"CREATE POLICY {name} ON {SCHEMA}.{table} {body}"))


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return

    for table in STAMP_TABLES:
        _add_project_column(bind, table)
        _org_branch_policies(bind, table)

    if not _has_column(bind, "users", "active_project_id"):
        bind.execute(
            text(f"ALTER TABLE {SCHEMA}.users ADD COLUMN active_project_id VARCHAR(36)")
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return

    if _has_column(bind, "users", "active_project_id"):
        bind.execute(text(f"ALTER TABLE {SCHEMA}.users DROP COLUMN active_project_id"))

    for table in STAMP_TABLES:
        for name in (f"{table}_org_select", f"{table}_org_insert", f"{table}_org_update"):
            bind.execute(text(f"DROP POLICY IF EXISTS {name} ON {SCHEMA}.{table}"))
        if _has_column(bind, table, "project_id"):
            bind.execute(
                text(f"DROP INDEX IF EXISTS {table}_project_idx")
            )
            bind.execute(
                text(f"ALTER TABLE {SCHEMA}.{table} DROP COLUMN project_id")
            )
