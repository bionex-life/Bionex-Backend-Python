"""Phase 2: Add encryption infrastructure tables

Revision ID: 2b7c4f8a1e3d
Revises: 2a5d8e1f3b9c
Create Date: 2026-04-21 12:00:00.000000

Tables created:
- user_keypairs: Stores ECDH P-256 public keys
- session_keys: Ephemeral session keys for doctor-patient access
- encrypted_record_vaults: Server-side encrypted medical records
- cryptographic_audit_logs: Immutable audit trail with signatures
- key_rotation_history: Tracks key rotation operations

All tables include proper indexes for production performance.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# Revision identifiers (auto-updated by Alembic)
revision = '2b7c4f8a1e3d'
down_revision = '2a5d8e1f3b9c'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Phase 2 encryption infrastructure tables"""
    
    # Create custom ENUM types (using raw SQL for idempotency)
    conn = op.get_bind()
    
    # Create ENUMs using raw SQL with IF NOT EXISTS equivalent
    try:
        conn.execute(sa.text("""
            CREATE TYPE session_key_status AS ENUM ('ACTIVE', 'ROTATED', 'REVOKED', 'EXPIRED')
        """))
    except:
        pass  # ENUM already exists
    
    try:
        conn.execute(sa.text("""
            CREATE TYPE key_rotation_status AS ENUM ('PENDING', 'COMPLETED', 'FAILED')
        """))
    except:
        pass  # ENUM already exists
    
    try:
        conn.execute(sa.text("""
            CREATE TYPE crypto_audit_log_status AS ENUM ('SUCCESS', 'FAILED', 'DENIED')
        """))
    except:
        pass  # ENUM already exists
    
    try:
        conn.execute(sa.text("""
            CREATE TYPE actor_type AS ENUM ('PATIENT', 'DOCTOR', 'ADMIN', 'SYSTEM')
        """))
    except:
        pass  # ENUM already exists
    
    # ────────────────────────────────────────────────────────────────
    # Table 1: user_keypairs
    # ────────────────────────────────────────────────────────────────
    op.create_table(
        'user_keypairs',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('public_key_pem', sa.Text(), nullable=False),
        sa.Column('public_key_fingerprint', sa.VARCHAR(64), nullable=False),
        sa.Column('key_algorithm', sa.VARCHAR(50), server_default='ECDH_P256', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('rotated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.VARCHAR(255), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_user_keypairs'),
        sa.ForeignKeyConstraint(['user_id'], ['bionex.users.id'], ondelete='CASCADE', name='fk_user_keypairs_user_id'),
        sa.UniqueConstraint('user_id', name='uq_user_keypairs_user_id'),
        sa.UniqueConstraint('public_key_fingerprint', name='uq_user_keypairs_fingerprint'),
        schema='bionex'
    )
    
    # Indexes for user_keypairs
    op.create_index('ix_user_keypairs_user_id', 'user_keypairs', ['user_id'], schema='bionex')
    op.create_index('ix_user_keypairs_fingerprint', 'user_keypairs', ['public_key_fingerprint'], schema='bionex')
    op.create_index('ix_user_keypairs_created', 'user_keypairs', ['created_at'], schema='bionex')
    op.create_index('ix_user_keypairs_user_active', 'user_keypairs', ['user_id', 'is_revoked'], schema='bionex')
    
    # ────────────────────────────────────────────────────────────────
    # Table 2: session_keys
    # ────────────────────────────────────────────────────────────────
    op.create_table(
        'session_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('patient_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('doctor_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_key_hash', sa.VARCHAR(64), nullable=False),
        sa.Column('encrypted_session_key', sa.Text(), nullable=False),
        sa.Column('nonce', sa.VARCHAR(32), nullable=False),
        sa.Column('auth_tag', sa.VARCHAR(32), nullable=False),
        sa.Column('status', postgresql.ENUM('ACTIVE', 'ROTATED', 'REVOKED', 'EXPIRED', name='session_key_status', create_type=False), server_default='ACTIVE', nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.VARCHAR(255), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_session_keys'),
        sa.ForeignKeyConstraint(['patient_id'], ['bionex.patients.id'], ondelete='CASCADE', name='fk_session_keys_patient_id'),
        sa.ForeignKeyConstraint(['doctor_id'], ['bionex.users.id'], ondelete='CASCADE', name='fk_session_keys_doctor_id'),
        sa.UniqueConstraint('session_key_hash', name='uq_session_keys_hash'),
        schema='bionex'
    )
    
    # Indexes for session_keys
    op.create_index('ix_session_keys_patient_doctor', 'session_keys', ['patient_id', 'doctor_id'], schema='bionex')
    op.create_index('ix_session_keys_hash', 'session_keys', ['session_key_hash'], schema='bionex')
    op.create_index('ix_session_keys_expires', 'session_keys', ['expires_at'], schema='bionex')
    op.create_index('ix_session_keys_active', 'session_keys', ['status', 'expires_at'], schema='bionex')
    
    # ────────────────────────────────────────────────────────────────
    # Table 3: encrypted_record_vaults
    # ────────────────────────────────────────────────────────────────
    op.create_table(
        'encrypted_record_vaults',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('patient_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('original_record_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('ciphertext', sa.Text(), nullable=False),
        sa.Column('nonce', sa.VARCHAR(32), nullable=False),
        sa.Column('auth_tag', sa.VARCHAR(32), nullable=False),
        sa.Column('record_type', sa.VARCHAR(50), nullable=False),
        sa.Column('record_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('record_title', sa.VARCHAR(255), nullable=True),
        sa.Column('record_title_hash', sa.VARCHAR(64), nullable=True),
        sa.Column('encryption_algorithm', sa.VARCHAR(50), server_default='CHACHA20_POLY1305', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_encrypted_record_vaults'),
        sa.ForeignKeyConstraint(['patient_id'], ['bionex.patients.id'], ondelete='CASCADE', name='fk_encrypted_vaults_patient_id'),
        sa.ForeignKeyConstraint(['original_record_id'], ['bionex.medical_records.id'], ondelete='CASCADE', name='fk_encrypted_vaults_record_id'),
        schema='bionex'
    )
    
    # Indexes for encrypted_record_vaults
    op.create_index('ix_encrypted_vaults_patient', 'encrypted_record_vaults', ['patient_id'], schema='bionex')
    op.create_index('ix_encrypted_vaults_type', 'encrypted_record_vaults', ['record_type'], schema='bionex')
    op.create_index('ix_encrypted_vaults_date', 'encrypted_record_vaults', ['record_date'], schema='bionex')
    op.create_index('ix_encrypted_vaults_title_hash', 'encrypted_record_vaults', ['record_title_hash'], schema='bionex')
    op.create_index('ix_encrypted_vaults_deleted', 'encrypted_record_vaults', ['is_deleted'], schema='bionex')
    op.create_index('ix_encrypted_vaults_type_date', 'encrypted_record_vaults', ['record_type', 'record_date'], schema='bionex')
    op.create_index('ix_encrypted_vaults_active', 'encrypted_record_vaults', ['is_deleted', 'patient_id'], schema='bionex')
    op.create_index('ix_encrypted_vaults_patient_type', 'encrypted_record_vaults', ['patient_id', 'record_type'], schema='bionex')
    
    # ────────────────────────────────────────────────────────────────
    # Table 4: cryptographic_audit_logs (IMMUTABLE)
    # ────────────────────────────────────────────────────────────────
    op.create_table(
        'cryptographic_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('actor_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('actor_type', postgresql.ENUM('PATIENT', 'DOCTOR', 'ADMIN', 'SYSTEM', name='actor_type', create_type=False), nullable=False),
        sa.Column('action', sa.VARCHAR(50), nullable=False),
        sa.Column('resource_type', sa.VARCHAR(50), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_data', postgresql.JSONB(), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('signature_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ip_address', sa.VARCHAR(45), nullable=False),
        sa.Column('user_agent', sa.VARCHAR(255), nullable=True),
        sa.Column('request_id', sa.VARCHAR(50), nullable=False),
        sa.Column('status', postgresql.ENUM('SUCCESS', 'FAILED', 'DENIED', name='crypto_audit_log_status', create_type=False), server_default='SUCCESS', nullable=False),
        sa.Column('status_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_cryptographic_audit_logs'),
        sa.ForeignKeyConstraint(['actor_id'], ['bionex.users.id'], ondelete='SET NULL', name='fk_audit_logs_actor_id'),
        schema='bionex'
    )
    
    # Indexes for cryptographic_audit_logs
    op.create_index('ix_audit_logs_actor', 'cryptographic_audit_logs', ['actor_id'], schema='bionex')
    op.create_index('ix_audit_logs_resource', 'cryptographic_audit_logs', ['resource_type', 'resource_id'], schema='bionex')
    op.create_index('ix_audit_logs_action', 'cryptographic_audit_logs', ['action'], schema='bionex')
    op.create_index('ix_audit_logs_created', 'cryptographic_audit_logs', ['created_at'], schema='bionex')
    op.create_index('ix_audit_logs_request_id', 'cryptographic_audit_logs', ['request_id'], schema='bionex')
    op.create_index('ix_audit_logs_action_status', 'cryptographic_audit_logs', ['action', 'status'], schema='bionex')
    op.create_index('ix_audit_logs_actor_type', 'cryptographic_audit_logs', ['actor_id', 'actor_type'], schema='bionex')
    
    # ────────────────────────────────────────────────────────────────
    # Table 5: key_rotation_history
    # ────────────────────────────────────────────────────────────────
    op.create_table(
        'key_rotation_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('old_key_fingerprint', sa.VARCHAR(64), nullable=False),
        sa.Column('new_key_fingerprint', sa.VARCHAR(64), nullable=False),
        sa.Column('rotation_reason', sa.VARCHAR(255), nullable=False),
        sa.Column('status', postgresql.ENUM('PENDING', 'COMPLETED', 'FAILED', name='key_rotation_status', create_type=False), server_default='PENDING', nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('rotated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_key_rotation_history'),
        sa.ForeignKeyConstraint(['user_id'], ['bionex.users.id'], ondelete='CASCADE', name='fk_rotation_history_user_id'),
        schema='bionex'
    )
    
    # Indexes for key_rotation_history
    op.create_index('ix_rotation_history_user', 'key_rotation_history', ['user_id'], schema='bionex')
    op.create_index('ix_rotation_history_status', 'key_rotation_history', ['user_id', 'status'], schema='bionex')
    op.create_index('ix_rotation_history_created', 'key_rotation_history', ['rotated_at'], schema='bionex')


def downgrade() -> None:
    """Drop Phase 2 encryption infrastructure tables"""
    
    # Drop tables in reverse order of dependencies
    op.drop_table('key_rotation_history', schema='bionex')
    op.drop_table('cryptographic_audit_logs', schema='bionex')
    op.drop_table('encrypted_record_vaults', schema='bionex')
    op.drop_table('session_keys', schema='bionex')
    op.drop_table('user_keypairs', schema='bionex')
    
    # Drop ENUM types
    op.execute('DROP TYPE IF EXISTS actor_type')
    op.execute('DROP TYPE IF EXISTS crypto_audit_log_status')
    op.execute('DROP TYPE IF EXISTS key_rotation_status')
    op.execute('DROP TYPE IF EXISTS session_key_status')
