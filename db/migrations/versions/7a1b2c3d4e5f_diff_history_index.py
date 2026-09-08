"""diff history lookup index

Revision ID: 7a1b2c3d4e5f
Revises: 6eee628502f5
Create Date: 2026-09-06

"""
from __future__ import annotations

from alembic import op

revision: str = "7a1b2c3d4e5f"
down_revision: str | None = "6eee628502f5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_index(
        "ix_scans_user_url_created",
        "scans",
        ["user_id", "normalized_url", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_user_url_created", table_name="scans")
