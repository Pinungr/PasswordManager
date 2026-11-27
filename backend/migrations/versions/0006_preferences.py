"""Add application security policies."""

import sqlalchemy as sa
from alembic import op

revision = "0006_preferences"
down_revision = "0005_shared"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("policy", sa.Text, nullable=False),
        sa.CheckConstraint("id = 1", name="ck_app_settings_singleton"),
    )


def downgrade():
    op.drop_table("app_settings")
