"""Add administrator-managed categories and environments."""

import sqlalchemy as sa
from alembic import op

revision = "0004_catalog"
down_revision = "0003_personal"
branch_labels = None
depends_on = None


def upgrade():
    table = op.create_table(
        "catalog",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200, collation="NOCASE"), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("appearance", sa.String(32), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.UniqueConstraint("kind", "name", name="uq_catalog_kind_name"),
        sa.CheckConstraint("kind IN ('categories', 'environments')", name="ck_catalog_kind"),
    )
    environments = (
        ("DEV", "#2563eb"),
        ("SIT", "#0284c7"),
        ("UAT", "#7c3aed"),
        ("PSUP", "#0f766e"),
        ("PROD", "#dc2626"),
        ("OTHER", "#64748b"),
    )
    categories = (
        "Generic",
        "Website Login",
        "Application Login",
        "Database",
        "API Token",
        "Azure",
        "Databricks",
        "GitHub",
        "Kubernetes / AKS",
        "SSH",
        "ServiceNow",
        "Service Account",
        "Secure Notes",
        "Custom",
    )
    op.bulk_insert(
        table,
        [
            {
                "id": "environment-" + name.lower(),
                "name": name,
                "kind": "environments",
                "description": "",
                "appearance": color,
                "active": True,
            }
            for name, color in environments
        ]
        + [
            {
                "id": "category-" + str(index + 1),
                "name": name,
                "kind": "categories",
                "description": "",
                "appearance": "key",
                "active": True,
            }
            for index, name in enumerate(categories)
        ],
    )


def downgrade():
    op.drop_table("catalog")
