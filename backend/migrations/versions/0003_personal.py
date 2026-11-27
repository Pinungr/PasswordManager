"""Add private vault envelopes and versioned ciphertext."""

import sqlalchemy as sa
from alembic import op

revision = "0003_personal"
down_revision = "0002_accounts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "personal_vaults",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner", sa.String(36), sa.ForeignKey("users.id"), unique=True, nullable=False),
        sa.Column("keys", sa.Text, nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
    )
    op.create_table(
        "credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vault_id", sa.String(36), sa.ForeignKey("personal_vaults.id"), nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("crypto_version", sa.Integer, nullable=False),
        sa.Column("created_at", sa.BigInteger, nullable=False),
        sa.Column("modified_at", sa.BigInteger, nullable=False),
        sa.Column("deleted_at", sa.BigInteger),
        sa.Column("last_used", sa.BigInteger),
    )
    op.create_index("ix_credentials_vault_cursor", "credentials", ["vault_id", "id"])
    op.create_index("ix_credentials_deleted", "credentials", ["deleted_at"])
    op.create_table(
        "credential_history",
        sa.Column(
            "credential_id",
            sa.String(36),
            sa.ForeignKey("credentials.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer, primary_key=True),
        sa.Column("crypto_version", sa.Integer, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("modified_at", sa.BigInteger, nullable=False),
    )


def downgrade():
    op.drop_table("credential_history")
    op.drop_table("credentials")
    op.drop_table("personal_vaults")
