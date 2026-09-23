"""Enforce account realm on users table (ACCOUNT-REALM-FIX).

Revision ID: 0103_account_type_realm
Revises: 0102_squash_baseline
Create Date: 2026-09-23
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0103_account_type_realm"
down_revision: Union[str, Sequence[str], None] = "0102_squash_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.account_type_realm")
SCHEMA = "cyberguard"


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name != "sqlite"

    if is_pg:
        # Check if cyberguard schema exists
        schema_res = bind.execute(text("SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'cyberguard'"))
        target_schema = SCHEMA if schema_res.scalar_one_or_none() else "public"

        # Check if account_type column exists
        col_res = bind.execute(text(f"""
            SELECT column_name, column_default 
            FROM information_schema.columns 
            WHERE table_schema = '{target_schema}' AND table_name = 'users' AND column_name = 'account_type'
        """))
        col_info = col_res.fetchone()

        if col_info is None:
            logger.info("Adding account_type column to %s.users", target_schema)
            bind.execute(text(f"ALTER TABLE {target_schema}.users ADD COLUMN account_type VARCHAR(16) NOT NULL DEFAULT 'personal'"))
        else:
            logger.info("Updating account_type default on %s.users", target_schema)
            bind.execute(text(f"ALTER TABLE {target_schema}.users ALTER COLUMN account_type SET DEFAULT 'personal'"))

        # Backfill all existing 'user' or null rows to 'personal'
        logger.info("Backfilling %s.users account_type to 'personal'", target_schema)
        bind.execute(text(f"UPDATE {target_schema}.users SET account_type = 'personal' WHERE account_type = 'user' OR account_type IS NULL"))
    else:
        # SQLite path for local/testing
        try:
            bind.execute(text("ALTER TABLE users ADD COLUMN account_type VARCHAR(16) NOT NULL DEFAULT 'personal'"))
        except Exception:
            pass
        bind.execute(text("UPDATE users SET account_type = 'personal' WHERE account_type = 'user' OR account_type IS NULL"))


def downgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name != "sqlite"
    if is_pg:
        schema_res = bind.execute(text("SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'cyberguard'"))
        target_schema = SCHEMA if schema_res.scalar_one_or_none() else "public"
        bind.execute(text(f"ALTER TABLE {target_schema}.users ALTER COLUMN account_type SET DEFAULT 'user'"))
        bind.execute(text(f"UPDATE {target_schema}.users SET account_type = 'user' WHERE account_type = 'personal'"))
    else:
        bind.execute(text("UPDATE users SET account_type = 'user' WHERE account_type = 'personal'"))
