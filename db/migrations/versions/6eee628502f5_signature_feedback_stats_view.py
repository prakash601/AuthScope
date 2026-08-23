"""signature feedback stats view

Revision ID: 6eee628502f5
Revises: 64c54a3f3595
Create Date: 2026-08-23

"""
from __future__ import annotations

from alembic import op

revision: str = "6eee628502f5"
down_revision: str | None = "64c54a3f3595"
branch_labels: str | None = None
depends_on: str | None = None


VIEW_SQL = """
CREATE VIEW signature_feedback_stats AS
SELECT
    signature_name,
    count(*) FILTER (WHERE verdict = 'correct') AS confirmed,
    count(*) FILTER (WHERE verdict = 'false_positive') AS false_positives,
    round(
        count(*) FILTER (WHERE verdict = 'false_positive')::numeric
        / NULLIF(count(*), 0), 3
    ) AS fp_rate
FROM feedback
GROUP BY signature_name
"""


def upgrade() -> None:
    op.execute(VIEW_SQL)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS signature_feedback_stats")
