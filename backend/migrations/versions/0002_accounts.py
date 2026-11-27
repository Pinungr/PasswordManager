"""Create accounts, sessions, rate limiting, teams and audit records."""

import sqlalchemy as sa
from alembic import op

revision = "0002_accounts"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(64), unique=True, nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(254)),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(12), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("must_change", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.BigInteger, nullable=False),
        sa.Column("last_login", sa.BigInteger),
        sa.CheckConstraint("role IN ('ADMIN', 'TEAM_LEAD', 'MEMBER')", name="ck_user_role"),
    )
    op.create_table(
        "user_sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("expires_at", sa.BigInteger, nullable=False),
    )
    op.create_index("ix_sessions_user", "user_sessions", ["user_id"])
    op.create_index("ix_sessions_expiry", "user_sessions", ["expires_at"])
    op.create_table(
        "login_limits",
        sa.Column("scope", sa.String(64), primary_key=True),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("expires_at", sa.BigInteger, nullable=False),
    )
    op.create_index("ix_login_limits_expiry", "login_limits", ["expires_at"])
    op.create_table(
        "teams",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100, collation="NOCASE"), nullable=False, unique=True),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("lead_id", sa.String(36), sa.ForeignKey("users.id")),
        sa.Column("active", sa.Boolean, nullable=False),
    )
    op.create_table(
        "team_members",
        sa.Column(
            "team_id",
            sa.String(36),
            sa.ForeignKey("teams.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_index("ix_team_members_user", "team_members", ["user_id"])
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("event", sa.Text, nullable=False),
        sa.Column("mac", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    for name in ("audit_logs", "team_members", "teams", "login_limits", "user_sessions", "users"):
        op.drop_table(name)
