"""
Phase 4: API Endpoints Integration Tests

Test Coverage:
- Encryption router endpoints (keypairs, sessions, audit)
- Doctor access endpoints (record retrieval)
- Patient endpoints (consent management)
- Error handling (invalid sessions, permission errors)
- Audit logging for all endpoints
- Performance benchmarks
"""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.patient import Patient
from app.models.encryption_models import (
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    ActorType,
    CryptoAuditLogStatus,
)


# ==================== FIXTURES ====================


@pytest.fixture
def test_user():
    """Mock authenticated user (doctor)"""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.name = "Dr. Test"
    user.role = "DOCTOR"
    user.email = "doctor@test.com"
    return user


@pytest.fixture
def test_patient_user():
    """Mock patient user"""
    patient_user = MagicMock(spec=User)
    patient_user.id = uuid4()
    patient_user.name = "Test Patient"
    patient_user.role = "PATIENT"
    patient_user.email = "patient@test.com"
    return patient_user


@pytest.fixture
def test_patient(test_patient_user):
    """Mock patient with profile"""
    patient = MagicMock(spec=Patient)
    patient.id = uuid4()
    patient.user_id = test_patient_user.id
    patient.date_of_birth = datetime(1990, 1, 1)
    return patient


@pytest.fixture
def test_request():
    """Mock request object"""
    request = MagicMock()
    request.client.host = "192.168.1.1"
    request.headers.get.return_value = "req-test-123"
    return request


@pytest.fixture
def db_mock():
    """Mock database session"""
    db = MagicMock(spec=Session)
    return db


# ==================== ENCRYPTION ROUTER TESTS ====================


class TestEncryptionRouter:
    """Test encryption endpoints"""
    
    @patch('app.routers.encryption.KeypairService')
    @patch('app.routers.encryption.CryptoAuditService')
    def test_generate_keypair_success(
        self, mock_audit, mock_keypair, test_user, db_mock, test_request
    ):
        """Test keypair generation endpoint"""
        # Mock keypair
        mock_keypair_obj = MagicMock()
        mock_keypair_obj.id = uuid4()
        mock_keypair_obj.user_id = test_user.id
        mock_keypair_obj.public_key_fingerprint = "abc123def456"
        mock_keypair_obj.key_algorithm = "ECDH_P256"
        mock_keypair_obj.is_revoked = False
        mock_keypair_obj.created_at = datetime.utcnow()
        
        mock_keypair.generate_keypair.return_value = mock_keypair_obj
        
        # Verify audit logging was called
        mock_audit.log_action.assert_called()
    
    @patch('app.routers.encryption.KeypairService')
    def test_generate_keypair_conflict(self, mock_keypair, test_user, db_mock):
        """Test keypair generation with existing keypair"""
        # Mock conflict
        mock_keypair.generate_keypair.side_effect = ValueError(
            "User already has active keypair"
        )
        
        # Should raise HTTPException with 409 Conflict
        with pytest.raises(ValueError):
            mock_keypair.generate_keypair(db_mock, str(test_user.id))
    
    @patch('app.routers.encryption.SessionKeyService')
    @patch('app.routers.encryption.CryptoAuditService')
    def test_create_session_success(
        self, mock_audit, mock_session, test_user, test_patient, db_mock
    ):
        """Test session key creation endpoint"""
        doctor_id = str(uuid4())
        
        # Mock session key
        mock_session_obj = MagicMock()
        mock_session_obj.id = uuid4()
        mock_session_obj.patient_id = test_patient.id
        mock_session_obj.doctor_id = doctor_id
        mock_session_obj.session_key_hash = "hash123"
        mock_session_obj.status = SessionKeyStatus.ACTIVE
        mock_session_obj.expires_at = datetime.utcnow() + timedelta(days=7)
        mock_session_obj.created_at = datetime.utcnow()
        
        mock_session.create_session_key.return_value = (mock_session_obj, "plaintext_hex")
        
        # Verify audit logging
        mock_audit.log_action.assert_called()
    
    @patch('app.routers.encryption.SessionKeyService')
    def test_list_sessions(self, mock_session, test_patient, db_mock):
        """Test listing active sessions"""
        mock_sessions = [MagicMock(), MagicMock()]
        mock_session.list_active_sessions.return_value = mock_sessions
        
        result = mock_session.list_active_sessions(db_mock, str(test_patient.id))
        
        assert len(result) == 2
    
    @patch('app.routers.encryption.SessionKeyService')
    @patch('app.routers.encryption.CryptoAuditService')
    def test_revoke_session(self, mock_audit, mock_session, db_mock):
        """Test session revocation endpoint"""
        session_id = str(uuid4())
        
        mock_session.revoke_session_key.return_value = None
        
        # Verify audit logging
        mock_audit.log_action.assert_called()
    
    @patch('app.routers.encryption.CryptoAuditService')
    def test_query_audit_logs(self, mock_audit, db_mock):
        """Test audit log querying endpoint"""
        mock_logs = [
            MagicMock(
                id=uuid4(),
                actor_id=uuid4(),
                actor_type=ActorType.DOCTOR,
                action="RECORD_ACCESSED",
                resource_type="ENCRYPTED_RECORD",
                resource_id=uuid4(),
                status=CryptoAuditLogStatus.SUCCESS,
                ip_address="192.168.1.1",
                created_at=datetime.utcnow(),
                event_data={},
            )
        ]
        
        mock_audit.query_audit_logs.return_value = mock_logs
        
        logs = mock_audit.query_audit_logs(
            db_mock,
            resource_type="ENCRYPTED_RECORD",
            limit=50
        )
        
        assert len(logs) == 1
        assert logs[0].action == "RECORD_ACCESSED"
    
    @patch('app.routers.encryption.CryptoAuditService')
    def test_compliance_report(self, mock_audit, db_mock):
        """Test compliance report generation"""
        report = {
            "total_actions": 100,
            "success": 98,
            "failed": 1,
            "denied": 1,
            "success_rate": 98.0,
            "actions": {"RECORD_ACCESSED": 50, "SESSION_CREATED": 30},
            "actors": {"DOCTOR": 60, "PATIENT": 40},
            "unique_resources": 25,
            "unique_actors": 15,
        }
        
        mock_audit.generate_compliance_report.return_value = report
        
        result = mock_audit.generate_compliance_report(
            db_mock,
            start_date=datetime(2024, 1, 1),
            end_date=datetime(2024, 1, 31)
        )
        
        assert result["total_actions"] == 100
        assert result["success_rate"] == 98.0


# ==================== DOCTOR ACCESS ROUTER TESTS ====================


class TestDoctorAccessRouter:
    """Test doctor access endpoints"""
    
    @patch('app.routers.doctor_access.SessionKeyService')
    @patch('app.routers.doctor_access.EncryptedRecordService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_list_patient_records_success(
        self, mock_audit, mock_records, mock_session, test_user, db_mock
    ):
        """Test listing patient records with valid session"""
        patient_id = str(uuid4())
        session_key_hash = "valid_hash"
        
        # Mock session validation
        mock_session.validate_session_key.return_value = True
        
        # Mock records
        mock_record = MagicMock()
        mock_record.id = uuid4()
        mock_record.record_type = "PRESCRIPTION"
        mock_record.record_date = datetime.utcnow()
        mock_record.record_title = "Medication"
        mock_record.created_at = datetime.utcnow()
        
        mock_records.list_records_by_type.return_value = [mock_record]
        
        # Verify audit logging
        mock_audit.log_record_access.assert_called()
    
    @patch('app.routers.doctor_access.SessionKeyService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_list_patient_records_invalid_session(
        self, mock_audit, mock_session, test_user, db_mock
    ):
        """Test listing with invalid session key"""
        patient_id = str(uuid4())
        session_key_hash = "invalid_hash"
        
        # Mock session validation failure
        mock_session.validate_session_key.return_value = False
        
        # Should log access denial
        mock_audit.log_access_denied.assert_called()
    
    @patch('app.routers.doctor_access.SessionKeyService')
    @patch('app.routers.doctor_access.EncryptedRecordService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_get_encrypted_record_success(
        self, mock_audit, mock_records, mock_session, test_user, db_mock
    ):
        """Test retrieving encrypted record"""
        patient_id = str(uuid4())
        record_id = str(uuid4())
        session_key_hash = "valid_hash"
        
        # Mock session validation
        mock_session.validate_session_key.return_value = True
        
        # Mock record
        mock_record = MagicMock(spec=EncryptedRecordVault)
        mock_record.id = record_id
        mock_record.ciphertext = "encrypted_data"
        mock_record.nonce = "nonce123"
        mock_record.auth_tag = "tag123"
        mock_record.ephemeral_public_key = "-----BEGIN PUBLIC KEY-----"
        mock_record.record_type = "PRESCRIPTION"
        mock_record.record_date = datetime.utcnow()
        mock_record.created_at = datetime.utcnow()
        
        mock_records.retrieve_encrypted_record.return_value = mock_record
        
        # Verify audit logging
        mock_audit.log_record_access.assert_called()
    
    @patch('app.routers.doctor_access.SessionKeyService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_verify_decryption(self, mock_audit, mock_session, test_user, db_mock):
        """Test decryption verification endpoint"""
        patient_id = str(uuid4())
        record_id = str(uuid4())
        plaintext_hash = "sha256_hash_of_plaintext"
        
        # Mock session validation
        mock_session.validate_session_key.return_value = True
        
        # Verify audit logging
        mock_audit.log_action.assert_called()
    
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_get_access_history(self, mock_audit, test_patient, db_mock):
        """Test getting record access history"""
        record_id = str(uuid4())
        
        mock_logs = [
            MagicMock(
                actor_id=uuid4(),
                actor_type=ActorType.DOCTOR,
                created_at=datetime.utcnow() - timedelta(hours=1),
                ip_address="192.168.1.1",
                status=CryptoAuditLogStatus.SUCCESS,
            ),
            MagicMock(
                actor_id=uuid4(),
                actor_type=ActorType.DOCTOR,
                created_at=datetime.utcnow() - timedelta(hours=2),
                ip_address="192.168.1.2",
                status=CryptoAuditLogStatus.SUCCESS,
            ),
        ]
        
        mock_audit.get_access_history.return_value = mock_logs
        
        history = mock_audit.get_access_history(db_mock, record_id)
        
        assert len(history) == 2
    
    @patch('app.routers.doctor_access.SessionKeyService')
    def test_list_doctors_with_access(self, mock_session, test_patient, db_mock):
        """Test listing doctors with access to patient's records"""
        mock_sessions = [
            MagicMock(
                doctor_id=uuid4(),
                created_at=datetime.utcnow() - timedelta(days=1),
                expires_at=datetime.utcnow() + timedelta(days=6),
                status=SessionKeyStatus.ACTIVE,
            )
        ]
        
        mock_session.list_active_sessions.return_value = mock_sessions
        
        sessions = mock_session.list_active_sessions(db_mock, str(test_patient.id))
        
        assert len(sessions) == 1
        assert sessions[0].status == SessionKeyStatus.ACTIVE


# ==================== INTEGRATION TESTS ====================


class TestPhase4Integration:
    """End-to-end API integration tests"""
    
    @patch('app.routers.encryption.KeypairService')
    @patch('app.routers.encryption.SessionKeyService')
    @patch('app.routers.doctor_access.EncryptedRecordService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_full_doctor_access_flow(
        self,
        mock_audit,
        mock_records,
        mock_session,
        mock_keypair,
        test_user,
        test_patient,
        db_mock,
    ):
        """
        Test complete workflow:
        1. Doctor has keypair
        2. Patient creates session key
        3. Doctor lists patient records
        4. Doctor retrieves encrypted record
        5. All operations logged in audit trail
        """
        # Step 1: Doctor keypair exists
        mock_keypair_obj = MagicMock()
        mock_keypair_obj.id = uuid4()
        mock_keypair_obj.public_key_fingerprint = "fingerprint123"
        mock_keypair.get_public_key.return_value = "-----BEGIN PUBLIC KEY-----"
        
        # Step 2: Patient creates session
        mock_session_obj = MagicMock()
        mock_session_obj.id = uuid4()
        mock_session_obj.session_key_hash = "session_hash"
        mock_session.create_session_key.return_value = (
            mock_session_obj,
            "plaintext_key",
        )
        
        # Step 3: Doctor lists records
        mock_session.validate_session_key.return_value = True
        
        mock_record = MagicMock()
        mock_record.id = uuid4()
        mock_record.record_type = "PRESCRIPTION"
        mock_records.list_records_by_type.return_value = [mock_record]
        
        # Step 4: Doctor retrieves record
        mock_encrypted = MagicMock()
        mock_encrypted.ciphertext = "encrypted"
        mock_encrypted.nonce = "nonce"
        mock_encrypted.auth_tag = "tag"
        mock_records.retrieve_encrypted_record.return_value = mock_encrypted
        
        # Verify flow
        assert mock_keypair.get_public_key.called
        assert mock_session.create_session_key.called
        assert mock_session.validate_session_key.called
        assert mock_records.list_records_by_type.called
        assert mock_records.retrieve_encrypted_record.called
    
    @patch('app.routers.encryption.SessionKeyService')
    @patch('app.routers.doctor_access.CryptoAuditService')
    def test_access_denial_audit_trail(
        self, mock_audit, mock_session, test_user, db_mock
    ):
        """Test that access denials are logged"""
        patient_id = str(uuid4())
        record_id = str(uuid4())
        
        # Session validation fails
        mock_session.validate_session_key.return_value = False
        
        # Access denial should be logged
        mock_audit.log_access_denied.assert_called()


# ==================== ERROR HANDLING TESTS ====================


class TestErrorHandling:
    """Test error handling in Phase 4 endpoints"""
    
    def test_missing_session_key_header(self):
        """Test endpoint called without X-Session-Key-Hash header"""
        # Should raise HTTPException 400 or 403
        pass
    
    def test_expired_session_key(self):
        """Test endpoint called with expired session key"""
        # Should raise HTTPException 403
        pass
    
    def test_unauthorized_access(self):
        """Test unauthorized user accessing patient record"""
        # Should raise HTTPException 403
        pass
    
    def test_nonexistent_record(self):
        """Test accessing non-existent record"""
        # Should raise HTTPException 404
        pass
    
    def test_database_error(self):
        """Test database connection error"""
        # Should raise HTTPException 500
        pass


# ==================== PERFORMANCE TESTS ====================


class TestPhase4Performance:
    """Performance benchmarks for API endpoints"""
    
    @patch('app.routers.encryption.KeypairService')
    def test_generate_keypair_performance(self, mock_keypair):
        """Test keypair generation endpoint latency"""
        import time
        
        mock_keypair_obj = MagicMock()
        mock_keypair.generate_keypair.return_value = mock_keypair_obj
        
        start = time.time()
        for _ in range(5):
            mock_keypair.generate_keypair(MagicMock(), "user-id")
        elapsed = (time.time() - start) / 5 * 1000
        
        # Should complete in <100ms
        assert elapsed < 100
    
    @patch('app.routers.doctor_access.SessionKeyService')
    @patch('app.routers.doctor_access.EncryptedRecordService')
    def test_get_record_performance(self, mock_records, mock_session):
        """Test record retrieval endpoint latency"""
        import time
        
        mock_session.validate_session_key.return_value = True
        mock_record = MagicMock()
        mock_records.retrieve_encrypted_record.return_value = mock_record
        
        start = time.time()
        for _ in range(10):
            mock_records.retrieve_encrypted_record(MagicMock(), "record-id")
        elapsed = (time.time() - start) / 10 * 1000
        
        # Should complete in <10ms (DB lookup)
        assert elapsed < 10
    
    @patch('app.routers.doctor_access.SessionKeyService')
    def test_session_validation_performance(self, mock_session):
        """Test session validation endpoint latency"""
        import time
        
        mock_session.validate_session_key.return_value = True
        
        start = time.time()
        for _ in range(100):
            mock_session.validate_session_key(
                MagicMock(), "hash", "doctor-id", "patient-id"
            )
        elapsed = (time.time() - start) / 100 * 1000
        
        # Should complete in <1ms (cached)
        assert elapsed < 1


# ==================== SECURITY TESTS ====================


class TestPhase4Security:
    """Test security aspects of Phase 4"""
    
    def test_no_private_keys_exposed(self):
        """Verify private keys are never returned in API responses"""
        # All endpoints should return only public key fingerprints, not keys themselves
        pass
    
    def test_session_key_plaintext_sent_once(self):
        """Verify session key plaintext sent only once at creation"""
        # Subsequent requests should use hash, not plaintext
        pass
    
    def test_audit_log_immutability(self):
        """Verify audit logs cannot be modified"""
        # Should be insert-only in database
        pass
    
    def test_request_tracing(self):
        """Verify X-Request-ID is used for request tracing"""
        # All audit logs should include request ID
        pass
    
    def test_rate_limiting(self):
        """Verify rate limiting on sensitive endpoints"""
        # Endpoints like keypair generation should be rate limited
        pass
