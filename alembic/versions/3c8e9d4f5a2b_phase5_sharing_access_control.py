"""Phase 5: Add sharing requests and access control tables

Revision ID: 3c8e9d4f5a2b
Revises: 2b7c4f8a1e3d
Create Date: 2026-04-25 12:30:00.000000

Tables created:
- sharing_requests: Patient sharing requests to doctors with approval workflows
- Enums:
  - sharing_request_status: PENDING, APPROVED, DENIED, EXPIRED, REVOKED

This migration enables Phase 5 access control and session management.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# Revision identifiers (auto-updated by Alembic)
revision = '3c8e9d4f5a2b'
down_revision = '2b7c4f8a1e3d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Phase 5 sharing requests and access control tables"""
    
    conn = op.get_bind()
    
    # Create ENUM type for sharing request status
    try:
        conn.execute(sa.text("""
            CREATE TYPE sharing_request_status AS ENUM ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED')
        """))
    except:
        pass  # ENUM already exists
    
    # Create sharing_requests table
    op.create_table(
        'sharing_requests',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('patient_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('doctor_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scope', sa.String(length=20), nullable=False, server_default='read'),
        sa.Column(
            'status',
            postgresql.ENUM(
                'PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED',
                name='sharing_request_status',
                create_type=False
            ),
            nullable=False,
            server_default='PENDING'
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('denied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('denial_reason', sa.Text(), nullable=True),
        sa.Column('revocation_reason', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['doctor_id'], ['bionex.users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['patient_id'], ['bionex.patients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='bionex'
    )
    
    # Create indexes for query performance
    op.create_index(
        'ix_sharing_requests_patient_id',
        'sharing_requests',
        ['patient_id'],
        schema='bionex'
    )
    op.create_index(
        'ix_sharing_requests_doctor_id',
        'sharing_requests',
        ['doctor_id'],
        schema='bionex'
    )
    op.create_index(
        'ix_sharing_requests_status',
        'sharing_requests',
        ['status'],
        schema='bionex'
    )
    op.create_index(
        'ix_sharing_requests_created_at',
        'sharing_requests',
        ['created_at'],
        schema='bionex'
    )
    op.create_index(
        'ix_sharing_requests_expires_at',
        'sharing_requests',
        ['expires_at'],
        schema='bionex'
    )


def downgrade() -> None:
    """Drop Phase 5 sharing requests and access control tables"""
    
    # Drop indexes
    op.drop_index(
        'ix_sharing_requests_expires_at',
        table_name='sharing_requests',
        schema='bionex'
    )
    op.drop_index(
        'ix_sharing_requests_created_at',
        table_name='sharing_requests',
        schema='bionex'
    )
    op.drop_index(
        'ix_sharing_requests_status',
        table_name='sharing_requests',
        schema='bionex'
    )
    op.drop_index(
        'ix_sharing_requests_doctor_id',
        table_name='sharing_requests',
        schema='bionex'
    )
    op.drop_index(
        'ix_sharing_requests_patient_id',
        table_name='sharing_requests',
        schema='bionex'
    )
    
    # Drop table
    op.drop_table('sharing_requests', schema='bionex')
    
    # Drop ENUM type
    op.execute(sa.text("DROP TYPE IF EXISTS sharing_request_status CASCADE"))
