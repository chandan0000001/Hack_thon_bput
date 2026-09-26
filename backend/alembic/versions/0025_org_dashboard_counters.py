"""ORG-DASHBOARD-P1: realtime publication guard + counters composite index.

Revision ID: 0025_org_dashboard_counters
Revises: 0024_org_member_emails_fn
Create Date: 2026-09-26

Two guarded idempotent steps for the org dashboard live counters:

1. Ensure cyberguard.org_events is a member of the supabase_realtime
   publication so postgres_changes INSERT/UPDATE payloads reach subscribed
   dashboards. Migration 0100_org_rebuild already adds it on current
   databases — this guard makes the requirement explicit and repairs
   databases restored from states where it is missing. Skipped cleanly
   when the publication does not exist (plain Postgres hosts).
2. Composite index (project_id, created_at) backing the counters seed
   endpoint's 24h aggregate (single-table count FILTER query).

Downgrade drops the composite index only: dropping the publication
membership would regress migration 0100's intent on databases where the
table was already a member before this revision ran.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0025_org_dashboard_counters"
down_revision: Union[str, Sequence[str], None] = "0024_org_member_emails_fn"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_dashboard_counters")

SCHEMA = "cyberguard"
PUBLICATION = "supabase_realtime"
TABLE = "org_events"
INDEX_NAME = "idx_org_events_project_created"

# asyncpg rejects multiple commands per prepared statement — one per execute.
_PUBLICATION_EXISTS = text("SELECT 1 FROM pg_publication WHERE pubname = :pub")
_TABLE_IN_PUBLICATION = text(
    "SELECT 1 FROM pg_publication_tables "
    "WHERE pubname = :pub AND schemaname = :schema AND tablename = :table"
)
_ADD_TO_PUBLICATION = f"ALTER PUBLICATION {PUBLICATION} ADD TABLE {SCHEMA}.{TABLE}"
_CREATE_INDEX = f"""
CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON {SCHEMA}.{TABLE} (project_id, created_at)
"""
_DROP_INDEX = f"DROP INDEX IF EXISTS {SCHEMA}.{INDEX_NAME}"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        logger.info("sqlite backend — publication/index management is Postgres-only")
        return

    pub_exists = bind.execute(_PUBLICATION_EXISTS, {"pub": PUBLICATION}).scalar()
    if not pub_exists:
        logger.info(
            "publication %s does not exist (plain Postgres host) — "
            "org_events realtime delivery stays disabled",
            PUBLICATION,
        )
    else:
        already = bind.execute(
            _TABLE_IN_PUBLICATION,
            {"pub": PUBLICATION, "schema": SCHEMA, "table": TABLE},
        ).scalar()
        if already:
            logger.info("%s.%s already in %s — skipping", SCHEMA, TABLE, PUBLICATION)
        else:
            bind.execute(text(_ADD_TO_PUBLICATION))
            logger.info("added %s.%s to publication %s", SCHEMA, TABLE, PUBLICATION)

    bind.execute(text(_CREATE_INDEX))
    logger.info("ensured composite index %s on %s.%s", INDEX_NAME, SCHEMA, TABLE)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    bind.execute(text(_DROP_INDEX))
    # Publication membership intentionally NOT dropped: 0100_org_rebuild
    # requires it, and this revision only guaranteed (never claimed) it.
    logger.info("dropped composite index %s", INDEX_NAME)
