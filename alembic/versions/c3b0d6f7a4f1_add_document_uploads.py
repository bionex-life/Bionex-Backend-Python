"""add_document_uploads

Revision ID: c3b0d6f7a4f1
Revises: 2a5d8e1f3b9c
Create Date: 2026-06-02 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c3b0d6f7a4f1"
down_revision: Union[str, None] = "2a5d8e1f3b9c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("original_filename", sa.String(length=1024), nullable=False),
        sa.Column("content_type", sa.String(length=100), nullable=False),
        sa.Column("file_path", sa.String(length=2000), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_user_id"], ["bionex.users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="bionex",
    )
    op.create_index(
        op.f("ix_bionex_documents_id"),
        "documents",
        ["id"],
        unique=False,
        schema="bionex",
    )
    op.create_index(
        op.f("ix_bionex_documents_owner_user_id"),
        "documents",
        ["owner_user_id"],
        unique=False,
        schema="bionex",
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_bionex_documents_owner_user_id"),
        table_name="documents",
        schema="bionex",
    )
    op.drop_index(
        op.f("ix_bionex_documents_id"), table_name="documents", schema="bionex"
    )
    op.drop_table("documents", schema="bionex")
