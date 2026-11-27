"""Initialize the encrypted application instance."""

import sqlalchemy as sa
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = op.create_table(
        "application_instance",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("format_version", sa.Integer, nullable=False),
        sa.CheckConstraint("id = 1", name="ck_application_instance_singleton"),
    )
    op.bulk_insert(table, [{"id": 1, "format_version": 1}])


def downgrade() -> None:
    op.drop_table("application_instance")
