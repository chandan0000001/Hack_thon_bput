"""ORG-LIVE-VIEWS: add `events` to the supabase_realtime publication.

Revision ID: 0021_events_realtime_publication
Revises: 0020_events_project_id
Create Date: 2026-09-21

Why
---
The org live-stream views merge realtime pushes for the three security-plane
tables. `alerts` and `org_log_events` were added to `supabase_realtime` by
migration 0009 (ORG-2); `events` — the generic ingestion row the gateway and
pipelines write first — was not, so live views driven by gateway ingestion
would only refresh on the poll fallback for those rows. This migration adds
`cyberguard.events` to the publication.

Guarded like 0017: on plain Postgres (no Supabase) the publication does not
exist and the migration is a clean no-op; when it exists, the table is added
only if not already a member. INSERT-only realtime does not require a
REPLICA IDENTITY change (full-row INSERT payloads are published as-is);
UPDATE/DELETE events are not part of the live-view contract.

Plain SQL only; zero auth-schema references; downgrade removes exactly what
was added (only if the publication exists).
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0021_events_realtime_publication"
down_revision: Union[str, Sequence[str], None] = "0020_events_project_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.events_realtime")

SCHEMA = "cyberguard"
PUBLICATION = "supabase_realtime"

_PUBLICATION_EXISTS = (
    "select 1 from pg_publication where pubname = :pub"
)
_TABLE_IN_PUBLICATION = (
    "select 1 from pg_publication_tables "
    "where pubname = :pub and schemaname = :s and tablename = 'events'"
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    if not bind.execute(text(_PUBLICATION_EXISTS), {"pub": PUBLICATION}).first():
        logger.info("%s publication not present — clean no-op (plain Postgres)", PUBLICATION)
        return
    if bind.execute(text(_TABLE_IN_PUBLICATION), {"pub": PUBLICATION, "s": SCHEMA}).first():
        return
    bind.execute(text(f"ALTER PUBLICATION {PUBLICATION} ADD TABLE {SCHEMA}.events"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    if not bind.execute(text(_PUBLICATION_EXISTS), {"pub": PUBLICATION}).first():
        return
    if not bind.execute(text(_TABLE_IN_PUBLICATION), {"pub": PUBLICATION, "s": SCHEMA}).first():
        return
    bind.execute(text(f"ALTER PUBLICATION {PUBLICATION} DROP TABLE {SCHEMA}.events"))
