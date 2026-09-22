"""GMAIL-RECONNECT-UX: add status and disconnected_at to gmail_accounts.

Revision ID: 0022_gmail_account_status
Revises: 0021_events_realtime_publication
Create Date: 2026-09-22

Adds:
- status VARCHAR(32) DEFAULT 'connected' NOT NULL (valid: 'connected', 'disconnected', 'purged')
- disconnected_at TIMESTAMPTZ NULL
- Drops NOT NULL on refresh_token_encrypted to allow credential clearing on disconnect.
- Backfill: rows with NULL refresh_token → status='disconnected', disconnected_at=now() at migration time.
"""
from __future__ import annotations

import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = "0022_gmail_account_status"
down_revision: Union[str, Sequence[str], None] = "0021_events_realtime_publication"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.gmail_account_status")

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

    # 1. Add status column if not present
    if not _has_column(bind, table_name, "status"):
        op.add_column(
            table_name,
            sa.Column(
                "status",
                sa.String(32),
                nullable=False,
                server_default="connected",
            ),
            schema=SCHEMA if bind.dialect.name != "sqlite" else None,
        )
        logger.info("Added status column to %s", full_table)

    # 2. Add disconnected_at column if not present
    if not _has_column(bind, table_name, "disconnected_at"):
        op.add_column(
            table_name,
            sa.Column(
                "disconnected_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            schema=SCHEMA if bind.dialect.name != "sqlite" else None,
        )
        logger.info("Added disconnected_at column to %s", full_table)

    # 3. Make refresh_token_encrypted nullable if on PostgreSQL
    if bind.dialect.name != "sqlite":
        try:
            op.alter_column(
                table_name,
                "refresh_token_encrypted",
                existing_type=sa.Text(),
                nullable=True,
                schema=SCHEMA,
            )
            logger.info("Altered refresh_token_encrypted to nullable on %s", full_table)
        except Exception as exc:
            logger.warning("Could not alter refresh_token_encrypted nullability: %s", exc)

    # 4. Backfill: rows with NULL or empty refresh_token_encrypted -> status='disconnected', disconnected_at=now()
    try:
        bind.execute(
            text(
                f"UPDATE {full_table} "
                "SET status = 'disconnected', disconnected_at = CURRENT_TIMESTAMP "
                "WHERE refresh_token_encrypted IS NULL OR refresh_token_encrypted = ''"
            )
        )
        logger.info("Backfilled disconnected rows on %s", full_table)
    except Exception as exc:
        logger.warning("Backfill query failed: %s", exc)


def downgrade() -> None:
    bind = op.get_bind()
    table_name = "gmail_accounts"

    if _has_column(bind, table_name, "disconnected_at"):
        op.drop_column(table_name, "disconnected_at", schema=SCHEMA if bind.dialect.name != "sqlite" else None)
    if _has_column(bind, table_name, "status"):
        op.drop_column(table_name, "status", schema=SCHEMA if bind.dialect.name != "sqlite" else None)
