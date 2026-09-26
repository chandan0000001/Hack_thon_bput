"""ORG-SETTINGS-P6: SECURITY DEFINER helper returning real member emails.

Revision ID: 0024_org_member_emails_fn
Revises: 0103_account_type_realm
Create Date: 2026-09-26

list_members outer-joins cyberguard.users inside the tenant session, where
the users_select RLS policy (USING id = app.user_id) hides every row but the
caller's own — so non-self member emails came back NULL and the UI fell back
to raw user_ids. This definer function returns emails scoped to the ids
present in org_members of the requested org only; EXECUTE is granted to
cyberguard_api only (revoked from PUBLIC). RLS is otherwise untouched.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0024_org_member_emails_fn"
down_revision: Union[str, Sequence[str], None] = "0103_account_type_realm"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.org_member_emails_fn")

SCHEMA = "cyberguard"

FN_NAME = "org_member_emails"

# asyncpg rejects multiple commands per prepared statement — keep one per execute.
CREATE_FN_DDL = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.{FN_NAME}(p_org text)
RETURNS TABLE(user_id text, email text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = {SCHEMA}, pg_temp
AS $fn$
    SELECT DISTINCT om.user_id, u.email
    FROM {SCHEMA}.org_members om
    JOIN {SCHEMA}.users u ON u.id = om.user_id
    WHERE om.organization_id = p_org;
$fn$;
"""

REVOKE_DDL = f"REVOKE EXECUTE ON FUNCTION {SCHEMA}.{FN_NAME}(text) FROM PUBLIC;"
# Supabase-managed stacks auto-grant EXECUTE to authenticated/service_role via
# default privileges — revoke them (role may not exist on plain Postgres hosts).
REVOKE_DEFAULT_PRIVS_DDL = f"""
DO $do$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION {SCHEMA}.{FN_NAME}(text) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION {SCHEMA}.{FN_NAME}(text) FROM service_role';
    END IF;
END
$do$;
"""
GRANT_DDL = f"GRANT EXECUTE ON FUNCTION {SCHEMA}.{FN_NAME}(text) TO cyberguard_api;"

DOWNGRADE_DDL = f"""
DROP FUNCTION IF EXISTS {SCHEMA}.{FN_NAME}(text);
"""


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(text(CREATE_FN_DDL))
    bind.execute(text(REVOKE_DDL))
    bind.execute(text(REVOKE_DEFAULT_PRIVS_DDL))
    bind.execute(text(GRANT_DDL))
    logger.info("created definer fn %s.%s (EXECUTE -> cyberguard_api only)", SCHEMA, FN_NAME)


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(text(DOWNGRADE_DDL))
    logger.info("dropped definer fn %s.%s", SCHEMA, FN_NAME)
