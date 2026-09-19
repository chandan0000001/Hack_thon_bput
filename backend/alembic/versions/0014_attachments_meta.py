"""ATTACH-SCAN-1: add processed_emails.attachments_meta (scan metadata JSON).

Revision ID: 0014_attachments_meta
Revises: 0013_rt_pipeline_models
Create Date: 2026-09-19
"""

import logging
from typing import Sequence, Union

from alembic import op

revision: str = "0014_attachments_meta"
down_revision: Union[str, Sequence[str], None] = "0013_rt_pipeline_models"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.attachments_meta")

SCHEMA = "cyberguard"


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        # Metadata + scan results only; attachment files are never persisted.
        op.execute(f"""
            ALTER TABLE {SCHEMA}.processed_emails
            ADD COLUMN IF NOT EXISTS attachments_meta JSONB NULL;
        """)
    else:
        # SQLite dev/test path: create_all mirrors the model, so a plain
        # additive guard is enough here.
        logger.info("Non-postgresql dialect; attachments_meta handled by create_all")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {SCHEMA}.processed_emails DROP COLUMN IF EXISTS attachments_meta;")
