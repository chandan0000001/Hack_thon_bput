"""GMAIL-FULL-CLEAR: add last_push_at, pubsub_stopped_at, paused_at, and extend status with 'paused'.

Revision ID: 0023_gmail_full_clear
Revises: 0022_gmail_account_status
Create Date: 2026-09-22

Adds:
- last_push_at TIMESTAMPTZ NULL (recorded on every accepted or dropped push notification)
- pubsub_stopped_at TIMESTAMPTZ NULL (recorded when disconnect stops Google watch)
- paused_at TIMESTAMPTZ NULL (recorded when account sync is paused)
- status constraint updated to include 'paused': ('connected', 'paused', 'disconnected', 'purged')
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = "0023_gmail_full_clear"
down_revision: Union[str, Sequence[str], None] = "0022_gmail_account_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.gmail_account_full_clear_pause")

SCHEMA = "cyberguard"


def _has_column(bind, table: str, column: str) -> bool:
    if bind.dialect.name == "sqlite":
        res = bind.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return any(row[1] == column for row in res)
    return bool(
        bind.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = :s AND table_name = :t AND column_name = :c"
            ),
            {"s": SCHEMA, "t": table, "c": column},
        ).first()
    )


def upgrade() -> None:
    bind = op.get_bind()
    table_name = "gmail_accounts"
    full_table = f"{SCHEMA}.{table_name}" if bind.dialect.name != "sqlite" else table_name

    # 1. Add last_push_at
    if not _has_column(bind, table_name, "last_push_at"):
        op.add_column(
            table_name,
            sa.Column("last_push_at", sa.DateTime(timezone=True), nullable=True),
            schema=SCHEMA if bind.dialect.name != "sqlite" else None,
        )
        logger.info("Added last_push_at column to %s", full_table)

    # 2. Add pubsub_stopped_at
    if not _has_column(bind, table_name, "pubsub_stopped_at"):
        op.add_column(
            table_name,
            sa.Column("pubsub_stopped_at", sa.DateTime(timezone=True), nullable=True),
            schema=SCHEMA if bind.dialect.name != "sqlite" else None,
        )
        logger.info("Added pubsub_stopped_at column to %s", full_table)

    # 3. Add paused_at
    if not _has_column(bind, table_name, "paused_at"):
        op.add_column(
            table_name,
            sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
            schema=SCHEMA if bind.dialect.name != "sqlite" else None,
        )
        logger.info("Added paused_at column to %s", full_table)

    # 4. Update check constraint on status for postgres
    if bind.dialect.name != "sqlite":
        op.execute(
            text(
                f"ALTER TABLE {full_table} DROP CONSTRAINT IF EXISTS gmail_accounts_status_check"
            )
        )
        op.execute(
            text(
                f"ALTER TABLE {full_table} ADD CONSTRAINT gmail_accounts_status_check "
                "CHECK (status IN ('connected', 'paused', 'disconnected', 'purged'))"
            )
        )
        logger.info("Updated status CHECK constraint on %s to include 'paused'", full_table)


def downgrade() -> None:
    bind = op.get_bind()
    table_name = "gmail_accounts"
    full_table = f"{SCHEMA}.{table_name}" if bind.dialect.name != "sqlite" else table_name

    if bind.dialect.name != "sqlite":
        op.execute(
            text(
                f"ALTER TABLE {full_table} DROP CONSTRAINT IF EXISTS gmail_accounts_status_check"
            )
        )
        op.execute(
            text(
                f"ALTER TABLE {full_table} ADD CONSTRAINT gmail_accounts_status_check "
                "CHECK (status IN ('connected', 'disconnected', 'purged'))"
            )
        )

    for col in ("paused_at", "pubsub_stopped_at", "last_push_at"):
        if _has_column(bind, table_name, col):
            op.drop_column(table_name, col, schema=SCHEMA if bind.dialect.name != "sqlite" else None)
