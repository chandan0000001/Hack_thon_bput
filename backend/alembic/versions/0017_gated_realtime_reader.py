"""ORG-FIX-1 (D4): install 0012's gated realtime reader policies idempotently.

Revision ID: 0017_gated_realtime_reader
Revises: 0016_drop_app_all_bypass
Create Date: 2026-09-21

Migration 0012 drops the ORG-2 permissive ``USING (true) TO authenticated``
reader policies everywhere, but only CREATES the membership-gated
``org_log_events_realtime_select`` / ``alerts_realtime_select`` policies when
``auth.uid()`` exists (Supabase). On environments where the migration ran
before the ``auth`` schema existed — plain Postgres before the app's
``_ensure_schema_if_privileged`` bootstrap emulated it — the gated policies
were never installed and ORG-5's consistency check fails.

This migration re-runs 0012's creation step, idempotently:

- Detection uses the EXACT probe 0012 uses (``to_regprocedure('auth.uid()')
  is not null``) — one shared SQL probe, defined identically in both
  migrations and asserted by scripts/test_org_realtime_policies.py.
- When ``auth.uid()`` exists: (re)create both gated policies verbatim from
  0012's definitions.
- When it does not: clean no-op — plain Postgres keeps realtime readers
  denied (no policy TO ``authenticated`` means no rows for that role), which
  is the same outcome 0012 documents.

No ``auth`` schema object is referenced beyond the existence probe; the
policy bodies reference ``auth.uid()`` only when the probe proved it exists.
"""
import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0017_gated_realtime_reader"
down_revision: Union[str, Sequence[str], None] = "0016_drop_app_all_bypass"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.gated_realtime_reader")

SCHEMA = "cyberguard"

# Single shared SQL probe — byte-identical to 0012._has_auth_uid's query and
# to the assertion in scripts/test_org_realtime_policies.py (Suite 21).
AUTH_UID_PROBE = "select to_regprocedure('auth.uid()') is not null"

# Verbatim from 0012.GATED_POLICIES.
GATED_POLICIES = {
    "org_log_events": f"""
        CREATE POLICY org_log_events_realtime_select ON {SCHEMA}.org_log_events
        FOR SELECT TO authenticated
        USING (
            cyberguard.org_member_role(
                org_log_events.organization_id,
                auth.uid()::text
            ) IS NOT NULL
        )
    """,
    "alerts": f"""
        CREATE POLICY alerts_realtime_select ON {SCHEMA}.alerts
        FOR SELECT TO authenticated
        USING (
            (alerts.organization_id IS NOT NULL
             AND cyberguard.org_member_role(alerts.organization_id, auth.uid()::text) IS NOT NULL)
            OR
            (alerts.organization_id IS NULL AND alerts.owner_user_id = auth.uid()::text)
        )
    """,
}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        logger.info("SQLite — realtime reader policies not applicable")
        return

    if not bind.execute(text(AUTH_UID_PROBE)).scalar():
        logger.info(
            "auth-uid lookup unavailable (plain Postgres) — clean no-op; realtime "
            "readers stay denied for the 'authenticated' role, as 0012 documents"
        )
        return

    for table, ddl in GATED_POLICIES.items():
        policy = f"{table}_realtime_select"
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {SCHEMA}.{table}")
        op.execute(text(ddl))
        logger.info("ensured gated realtime policy %s on %s", policy, table)


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS org_log_events_realtime_select ON {SCHEMA}.org_log_events")
    op.execute(f"DROP POLICY IF EXISTS alerts_realtime_select ON {SCHEMA}.alerts")
