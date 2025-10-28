"""create tables"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, default="operator"),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("logs", sa.Text(), nullable=False, server_default=""),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("id_local", sa.String(), nullable=False, unique=True),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("parameter", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("cvss_v3", sa.Float(), nullable=True),
        sa.Column("cve", sa.JSON(), nullable=False, server_default='[]'),
        sa.Column("confidence", sa.String(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False, server_default='{}'),
        sa.Column("references", sa.JSON(), nullable=False, server_default='[]'),
        sa.Column("timestamp", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("priority_score", sa.Float(), nullable=True),
        sa.Column("exploitability_notes", sa.Text(), nullable=True),
        sa.Column("enrichment_metadata", sa.JSON(), nullable=True),
    )



def downgrade() -> None:
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("users")
