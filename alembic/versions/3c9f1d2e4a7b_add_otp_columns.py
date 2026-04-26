"""add_otp_columns

Revision ID: 3c9f1d2e4a7b
Revises: 8b6b3a7282c0
Create Date: 2025-04-26

"""
from alembic import op
import sqlalchemy as sa

revision = '3c9f1d2e4a7b'
down_revision = '8b6b3a7282c0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('otp_code', sa.String(length=6), nullable=True), schema='bionex')
    op.add_column('users', sa.Column('otp_expires_at', sa.DateTime(), nullable=True), schema='bionex')
    op.add_column('users', sa.Column('otp_verified', sa.Boolean(), nullable=False, server_default='false'), schema='bionex')


def downgrade() -> None:
    op.drop_column('users', 'otp_verified', schema='bionex')
    op.drop_column('users', 'otp_expires_at', schema='bionex')
    op.drop_column('users', 'otp_code', schema='bionex')