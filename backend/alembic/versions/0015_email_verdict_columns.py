"""ATTACH-SCAN-4: processed_emails verdict/severity/explanation columns.

Revision ID: 0015_email_verdict_columns
Revises: 0014_attachments_meta
Create Date: 2026-09-20
"""

import logging
from typing import Sequence, Union

from alembic import op

revision: str = "0015_email_verdict_columns"
down_revision: Union[str, Sequence[str], None] = "0014_attachments_meta"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.email_verdict_columns")

SCHEMA = "cyberguard"

COLUMNS = [
    ("verdict", "VARCHAR(32)"),
    ("severity", "VARCHAR(32)"),
    ("explanation", "TEXT"),
]


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for name, col_type in COLUMNS:
            op.execute(
                f"ALTER TABLE {SCHEMA}.processed_emails ADD COLUMN IF NOT EXISTS {name} {col_type} NULL;"
            )
    else:
        logger.info("Non-postgresql dialect; verdict columns handled by create_all")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for name, _ in COLUMNS:
            op.execute(f"ALTER TABLE {SCHEMA}.processed_emails DROP COLUMN IF EXISTS {name};")
