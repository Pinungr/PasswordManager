"""Distinguish self-service accounts from managed accounts."""

import sqlalchemy as sa
from alembic import op

revision = "0007_self_signup"
down_revision = "0006_preferences"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column("self_registered", sa.Boolean, nullable=False, server_default=sa.false()),
    )


def downgrade():
    op.drop_column("users", "self_registered")
