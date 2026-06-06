"""add_email_verification_columns

Revision ID: 8b6b3a7282c0
Revises: 2a5d8e1f3b9c
Create Date: 2026-04-25 11:43:16.650662

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = '8b6b3a7282c0'
down_revision: Union[str, None] = '2a5d8e1f3b9c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('is_email_verified', sa.Boolean(), nullable=False, server_default='false'), schema='bionex')
    op.add_column('users', sa.Column('email_verify_token', sa.String(length=255), nullable=True), schema='bionex')
    op.add_column('users', sa.Column('email_verify_token_expires', sa.DateTime(), nullable=True), schema='bionex')


def downgrade() -> None:
    op.drop_column('users', 'email_verify_token_expires', schema='bionex')
    op.drop_column('users', 'email_verify_token', schema='bionex')
    op.drop_column('users', 'is_email_verified', schema='bionex')
    # ### end Alembic commands ###
