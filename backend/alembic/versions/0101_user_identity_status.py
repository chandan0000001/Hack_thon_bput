"""ORG-IDENTITY-FIX: Single identity per email, user status (active/invited), and unique email.

Revision ID: 0101_user_identity_status
Revises: 0100_org_rebuild
Create Date: 2026-09-23

- Adds status column to cyberguard.users (default: 'active').
- Enforces unique index on cyberguard.users(email).
"""
from __future__ import annotations

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "0101_user_identity_status"
down_revision: Union[str, Sequence[str], None] = "0100_org_rebuild"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA = "cyberguard"


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    if is_sqlite:
        with op.batch_alter_table("users", schema=SCHEMA) as batch_op:
            try:
                batch_op.add_column(
                    op.f("status"),
                    server_default="active",
                )
            except Exception:
                pass
        return

    # PostgreSQL DDL
    bind.execute(text(f"""
        ALTER TABLE "{SCHEMA}".users 
        ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
    """))

    bind.execute(text(f"""
        UPDATE "{SCHEMA}".users 
        SET status = 'active' 
        WHERE status IS NULL;
    """))

    # Deduplicate any pre-existing duplicates in users table for non-null emails
    bind.execute(text(f"""
        DELETE FROM "{SCHEMA}".users u1
        WHERE u1.email IS NOT NULL
          AND EXISTS (
              SELECT 1 FROM "{SCHEMA}".users u2
              WHERE u2.email = u1.email
                AND (
                    (u2.username IS NOT NULL AND u1.username IS NULL)
                    OR (u2.username IS NOT NULL AND u1.username IS NOT NULL AND u2.id > u1.id)
                    OR (u2.username IS NULL AND u1.username IS NULL AND u2.id > u1.id)
                )
          );
    """))

    # Drop existing non-unique index if present, and recreate as unique
    bind.execute(text(f"""
        DROP INDEX IF EXISTS "{SCHEMA}".ix_cyberguard_users_email;
    """))
    bind.execute(text(f"""
        CREATE UNIQUE INDEX IF NOT EXISTS ix_cyberguard_users_email 
        ON "{SCHEMA}".users (email) 
        WHERE email IS NOT NULL;
    """))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        bind.execute(text(f'DROP INDEX IF EXISTS "{SCHEMA}".ix_cyberguard_users_email;'))
        bind.execute(text(f'ALTER TABLE "{SCHEMA}".users DROP COLUMN IF EXISTS status;'))
        bind.execute(text(f'CREATE INDEX IF NOT EXISTS ix_cyberguard_users_email ON "{SCHEMA}".users (email);'))
