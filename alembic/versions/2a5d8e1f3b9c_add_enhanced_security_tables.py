"""add_enhanced_security_tables

Revision ID: 2a5d8e1f3b9c
Revises: f9b39b741c92
Create Date: 2026-04-14 11:15:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "2a5d8e1f3b9c"
down_revision: Union[str, None] = "f9b39b741c92"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to users table
    op.add_column("users", sa.Column("is_locked", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("last_failed_login", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("last_password_change", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("password_expires_at", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("is_2fa_enabled", sa.Boolean(), nullable=False, server_default="false"))
    
    # Create login_attempts table
    op.create_table(
        "login_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("phone", sa.String(20), nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("is_successful", sa.Boolean(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("account_locked_until", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_login_attempts_user_id", "user_id"),
        sa.Index("ix_login_attempts_phone", "phone"),
        sa.Index("ix_login_attempts_timestamp", "timestamp"),
    )
    
    # Create password_history table
    op.create_table(
        "password_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("changed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_password_history_user_id", "user_id"),
        sa.Index("ix_password_history_changed_at", "changed_at"),
    )
    
    # Create api_keys table
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", sa.String(500), nullable=False),
        sa.Column("ip_whitelist", sa.String(500), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_used", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_api_keys_user_id", "user_id"),
        sa.Index("ix_api_keys_key_hash", "key_hash"),
        sa.Index("ix_api_keys_is_active", "is_active"),
    )
    
    # Create totp_secrets table
    op.create_table(
        "totp_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("secret", sa.String(32), nullable=False),
        sa.Column("backup_codes", sa.String(2000), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_totp_secrets_user_id", "user_id"),
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table("totp_secrets")
    op.drop_table("api_keys")
    op.drop_table("password_history")
    op.drop_table("login_attempts")
    
    # Remove columns from users table
    op.drop_column("users", "is_2fa_enabled")
    op.drop_column("users", "password_expires_at")
    op.drop_column("users", "last_password_change")
    op.drop_column("users", "last_failed_login")
    op.drop_column("users", "failed_login_attempts")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "is_locked")
