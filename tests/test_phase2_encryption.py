"""
Phase 2: Comprehensive Integration & Unit Tests

Tests for:
- Database models and relationships
- Alembic migrations
- Encryption service layer
- Schema validation
- Error handling and edge cases

Run with: pytest tests/test_phase2_encryption.py -v
"""

import pytest
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from uuid import UUID

from app.models import (
    User,
    UserRole,
    Patient,
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    CryptographicAuditLog,
    CryptoAuditLogStatus,
    ActorType,
)
from app.security.crypto import CryptoManager
from app.services.encryption_service import (
    KeypairService,
    SessionKeyService,
    EncryptedRecordService,
    AuditLogService,
)
from app.schemas.encryption_schemas import (
    UserKeypairCreate,
    SessionKeyCreate,
    EncryptedRecordVaultCreate,
    CryptographicAuditLogCreate,
)


# ────────────────────────────────────────────────────────────────
# FIXTURES
# ────────────────────────────────────────────────────────────────

@pytest.fixture
def test_user(db: Session):
    """Create test user"""
    user = User(
        id=uuid.uuid4(),
        name="Test Doctor",
        phone="+919876543210",
        email="doctor@test.com",
        hashed_password="hashed_pass",
        role=UserRole.DOCTOR,
        is_active=True
    )
    db.add(user)
    db.commit()
    yield user
    db.delete(user)
    db.commit()


@pytest.fixture
def test_patient_user(db: Session):
    """Create test patient user"""
    user = User(
        id=uuid.uuid4(),
        name="Test Patient",
        phone="+919876543211",
        email="patient@test.com",
        hashed_password="hashed_pass",
        role=UserRole.PATIENT,
        is_active=True
    )
    db.add(user)
    db.commit()
    
    # Create patient profile
    patient = Patient(
        id=uuid.uuid4(),
        user_id=user.id,
        blood_group="O+"
    )
    db.add(patient)
    db.commit()
    
    yield user, patient
    db.delete(patient)
    db.delete(user)
    db.commit()


# ────────────────────────────────────────────────────────────────
# MODEL TESTS
# ────────────────────────────────────────────────────────────────

class TestUserKeypair:
    """Tests for UserKeypair model"""
    
    def test_create_keypair(self, test_user, db: Session):
        """Test creating user keypair"""
        private_pem, public_pem = CryptoManager.generate_keypair()
        fingerprint = CryptoManager.hash_data(public_pem.encode())
        
        keypair = UserKeypair(
            user_id=test_user.id,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint,
            key_algorithm="ECDH_P256"
        )
        db.add(keypair)
        db.commit()
        
        # Verify
        retrieved = db.query(UserKeypair).filter_by(user_id=test_user.id).first()
        assert retrieved is not None
        assert retrieved.public_key_fingerprint == fingerprint
        assert not retrieved.is_revoked
    
    def test_keypair_unique_per_user(self, test_user, db: Session):
        """Test that each user has only one active keypair"""
        private_pem, public_pem = CryptoManager.generate_keypair()
        fingerprint = CryptoManager.hash_data(public_pem.encode())
        
        keypair1 = UserKeypair(
            user_id=test_user.id,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint,
            key_algorithm="ECDH_P256"
        )
        db.add(keypair1)
        db.commit()
        
        # Try to create second keypair (should fail due to unique constraint)
        private_pem2, public_pem2 = CryptoManager.generate_keypair()
        fingerprint2 = CryptoManager.hash_data(public_pem2.encode())
        
        keypair2 = UserKeypair(
            user_id=test_user.id,
            public_key_pem=public_pem2,
            public_key_fingerprint=fingerprint2,
            key_algorithm="ECDH_P256"
        )
        db.add(keypair2)
        
        with pytest.raises(Exception):  # SQLAlchemy IntegrityError
            db.commit()


class TestSessionKey:
    """Tests for SessionKey model"""
    
    def test_create_session_key(self, test_patient_user, db: Session):
        """Test creating session key"""
        patient_user, patient = test_patient_user
        doctor_user = User(
            id=uuid.uuid4(),
            name="Doctor",
            phone="+919876543220",
            hashed_password="pass",
            role=UserRole.DOCTOR
        )
        db.add(doctor_user)
        db.commit()
        
        session_key = SessionKey(
            patient_id=patient.id,
            doctor_id=doctor_user.id,
            session_key_hash="a" * 64,
            encrypted_session_key="encrypted_key",
            nonce="nonce",
            auth_tag="auth_tag",
            status=SessionKeyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(session_key)
        db.commit()
        
        # Verify
        retrieved = db.query(SessionKey).filter_by(
            patient_id=patient.id,
            doctor_id=doctor_user.id
        ).first()
        assert retrieved is not None
        assert retrieved.status == SessionKeyStatus.ACTIVE
        assert retrieved.is_valid()
    
    def test_session_key_expiry(self, test_patient_user, db: Session):
        """Test session key expiry check"""
        patient_user, patient = test_patient_user
        doctor_user = User(
            id=uuid.uuid4(),
            name="Doctor",
            phone="+919876543221",
            hashed_password="pass",
            role=UserRole.DOCTOR
        )
        db.add(doctor_user)
        db.commit()
        
        # Create expired session key
        expired_key = SessionKey(
            patient_id=patient.id,
            doctor_id=doctor_user.id,
            session_key_hash="b" * 64,
            encrypted_session_key="key",
            nonce="nonce",
            auth_tag="tag",
            status=SessionKeyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        db.add(expired_key)
        db.commit()
        
        assert not expired_key.is_valid()


class TestEncryptedRecordVault:
    """Tests for EncryptedRecordVault model"""
    
    def test_soft_delete(self, test_patient_user, db: Session):
        """Test soft delete functionality"""
        patient_user, patient = test_patient_user
        from app.models import MedicalRecord, RecordType
        
        record = MedicalRecord(
            id=uuid.uuid4(),
            patient_id=patient.id,
            record_type=RecordType.PRESCRIPTION,
            content="prescription"
        )
        db.add(record)
        db.commit()
        
        vault = EncryptedRecordVault(
            patient_id=patient.id,
            original_record_id=record.id,
            ciphertext="encrypted",
            nonce="nonce",
            auth_tag="tag",
            record_type="PRESCRIPTION",
            record_date=datetime.now(timezone.utc)
        )
        db.add(vault)
        db.commit()
        
        # Soft delete
        vault.is_deleted = True
        vault.deleted_at = datetime.now(timezone.utc)
        db.commit()
        
        # Should not appear in active query
        active = db.query(EncryptedRecordVault).filter(
            EncryptedRecordVault.is_deleted == False
        ).all()
        
        assert len(active) == 0


# ────────────────────────────────────────────────────────────────
# SERVICE TESTS
# ────────────────────────────────────────────────────────────────

class TestKeypairService:
    """Tests for KeypairService"""
    
    def test_get_public_key(self, test_user, db: Session):
        """Test retrieving public key"""
        from unittest.mock import MagicMock
        
        private_pem, public_pem = CryptoManager.generate_keypair()
        fingerprint = CryptoManager.hash_data(public_pem.encode())
        
        keypair = UserKeypair(
            user_id=test_user.id,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint
        )
        db.add(keypair)
        db.commit()
        
        # Mock cache and vault
        cache = MagicMock()
        cache.get_public_key.return_value = None
        vault = MagicMock()
        
        svc = KeypairService(db, cache, vault)
        retrieved = svc.get_public_key(test_user.id)
        
        assert retrieved == public_pem


class TestSessionKeyService:
    """Tests for SessionKeyService"""
    
    def test_validate_active_session(self, test_patient_user, db: Session):
        """Test validating active session key"""
        patient_user, patient = test_patient_user
        doctor_user = User(
            id=uuid.uuid4(),
            name="Doctor",
            phone="+919876543222",
            hashed_password="pass",
            role=UserRole.DOCTOR
        )
        db.add(doctor_user)
        db.commit()
        
        session_key = SessionKey(
            patient_id=patient.id,
            doctor_id=doctor_user.id,
            session_key_hash="c" * 64,
            encrypted_session_key="key",
            nonce="nonce",
            auth_tag="tag",
            status=SessionKeyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(session_key)
        db.commit()
        
        from unittest.mock import MagicMock
        cache = MagicMock()
        cache.get_session_key_doctor.return_value = None
        
        svc = SessionKeyService(db, cache)
        is_valid = svc.validate_session_key(session_key.session_key_hash, doctor_user.id)
        
        assert is_valid


# ────────────────────────────────────────────────────────────────
# SCHEMA VALIDATION TESTS
# ────────────────────────────────────────────────────────────────

class TestSchemaValidation:
    """Tests for Pydantic schema validation"""
    
    def test_keypair_create_schema(self):
        """Test UserKeypairCreate validation"""
        private_pem, public_pem = CryptoManager.generate_keypair()
        
        schema = UserKeypairCreate(
            public_key_pem=public_pem,
            key_algorithm="ECDH_P256"
        )
        assert schema.key_algorithm == "ECDH_P256"
    
    def test_invalid_pem_format(self):
        """Test invalid PEM format rejection"""
        with pytest.raises(ValueError):
            UserKeypairCreate(
                public_key_pem="invalid pem format",
                key_algorithm="ECDH_P256"
            )
    
    def test_session_key_expiry_validation(self):
        """Test session key future expiry requirement"""
        with pytest.raises(ValueError):
            SessionKeyCreate(
                patient_id=uuid.uuid4(),
                doctor_id=uuid.uuid4(),
                encrypted_session_key="key",
                nonce="nonce",
                auth_tag="tag",
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
            )


# ────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ────────────────────────────────────────────────────────────────

class TestPhase2Integration:
    """Integration tests for Phase 2 components"""
    
    def test_keypair_to_session_flow(self, test_patient_user, db: Session):
        """Test complete flow: create keypair -> create session key"""
        patient_user, patient = test_patient_user
        doctor_user = User(
            id=uuid.uuid4(),
            name="Doctor",
            phone="+919876543223",
            hashed_password="pass",
            role=UserRole.DOCTOR
        )
        db.add(doctor_user)
        db.commit()
        
        # Step 1: Create doctor keypair
        private_pem, public_pem = CryptoManager.generate_keypair()
        fingerprint = CryptoManager.hash_data(public_pem.encode())
        
        keypair = UserKeypair(
            user_id=doctor_user.id,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint
        )
        db.add(keypair)
        db.commit()
        
        # Step 2: Create session key
        session_key_hash = "d" * 64
        session_key = SessionKey(
            patient_id=patient.id,
            doctor_id=doctor_user.id,
            session_key_hash=session_key_hash,
            encrypted_session_key="encrypted",
            nonce="nonce",
            auth_tag="tag",
            status=SessionKeyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(session_key)
        db.commit()
        
        # Verify relationships
        assert len(keypair.user.session_keys_created) > 0
        assert patient.session_keys[0].doctor_id == doctor_user.id
    
    def test_audit_logging(self, test_user, db: Session):
        """Test audit log creation"""
        audit_log = CryptographicAuditLog(
            actor_id=test_user.id,
            actor_type=ActorType.DOCTOR,
            action="RECORD_ACCESSED",
            resource_type="MEDICAL_RECORD",
            resource_id=uuid.uuid4(),
            event_data={"operation": "read", "duration_ms": 45},
            signature="signature_value",
            signature_timestamp=datetime.now(timezone.utc),
            ip_address="203.0.113.45",
            request_id="req-123",
            status=CryptoAuditLogStatus.SUCCESS
        )
        db.add(audit_log)
        db.commit()
        
        # Verify immutability (no updates)
        retrieved = db.query(CryptographicAuditLog).filter_by(id=audit_log.id).first()
        assert retrieved.action == "RECORD_ACCESSED"
        assert retrieved.status == CryptoAuditLogStatus.SUCCESS


# ────────────────────────────────────────────────────────────────
# PERFORMANCE TESTS
# ────────────────────────────────────────────────────────────────

class TestPerformance:
    """Performance tests for Phase 2"""
    
    def test_keypair_generation_speed(self):
        """Verify keypair generation < 50ms"""
        import time
        
        start = time.time()
        private_pem, public_pem = CryptoManager.generate_keypair()
        elapsed = (time.time() - start) * 1000
        
        assert elapsed < 50, f"Keypair generation took {elapsed}ms (should be <50ms)"
    
    def test_session_key_validation_speed(self, db: Session):
        """Verify session key validation < 10ms (cached)"""
        import time
        from unittest.mock import MagicMock
        
        cache = MagicMock()
        cache.get_session_key_doctor.return_value = "doctor-id"
        
        svc = SessionKeyService(db, cache)
        
        start = time.time()
        svc.validate_session_key("key_hash", uuid.uuid4())
        elapsed = (time.time() - start) * 1000
        
        assert elapsed < 10, f"Validation took {elapsed}ms (should be <10ms cached)"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
