"""Add shared vault identities, grants, and epoch-scoped encrypted credentials."""

import sqlalchemy as sa
from alembic import op

revision = "0005_shared"
down_revision = "0004_catalog"
branch_labels = None
depends_on = None


def key(name, reference, **options):
    return sa.Column(name, sa.String(36), sa.ForeignKey(reference, ondelete="CASCADE"), **options)


def upgrade():
    op.create_table(
        "shared_identities",
        key("user_id", "users.id", primary_key=True),
        sa.Column("public_keys", sa.Text, nullable=False),
        sa.Column("private_envelope", sa.Text, nullable=False),
    )
    op.create_table(
        "shared_vaults",
        sa.Column("id", sa.String(36), primary_key=True),
        key("team_id", "teams.id", nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("epoch", sa.Integer, nullable=False),
        sa.Column("rotating", sa.Boolean, nullable=False),
        sa.Column("membership_version", sa.Integer, nullable=False),
        sa.Column("active_generation", sa.String(36), nullable=False, server_default=""),
        sa.Column("stage_id", sa.String(36)),
        sa.Column("stage_actor", sa.String(36)),
        sa.UniqueConstraint("team_id", "name", name="uq_shared_vault_team_name"),
    )
    op.create_table(
        "shared_access",
        key("vault_id", "shared_vaults.id", primary_key=True),
        key("user_id", "users.id", primary_key=True),
        key("grantor", "users.id", nullable=False),
        sa.Column("permissions", sa.Integer, nullable=False),
        sa.Column("grant", sa.Text, nullable=False),
    )
    op.create_index("ix_shared_access_user", "shared_access", ["user_id"])
    op.create_table(
        "shared_records",
        key("vault_id", "shared_vaults.id", primary_key=True),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("crypto_version", sa.Integer, nullable=False),
        sa.Column("created_at", sa.BigInteger, nullable=False),
        sa.Column("modified_at", sa.BigInteger, nullable=False),
        sa.Column("deleted_at", sa.BigInteger),
    )
    op.create_table(
        "shared_payloads",
        sa.Column("vault_id", sa.String(36), primary_key=True),
        sa.Column("record_id", sa.String(36), primary_key=True),
        sa.Column("epoch", sa.Integer, primary_key=True),
        sa.Column("generation", sa.String(36), primary_key=True),
        sa.Column("crypto_version", sa.Integer, primary_key=True),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("modified_by", sa.String(36), nullable=False),
        sa.Column("modified_at", sa.BigInteger, nullable=False),
        sa.ForeignKeyConstraint(
            ["vault_id", "record_id"],
            ["shared_records.vault_id", "shared_records.id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_shared_payloads_epoch", "shared_payloads", ["vault_id", "epoch"])


def downgrade():
    for table in (
        "shared_payloads",
        "shared_records",
        "shared_access",
        "shared_vaults",
        "shared_identities",
    ):
        op.drop_table(table)
