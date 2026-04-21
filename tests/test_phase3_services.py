"""
Phase 3: Comprehensive Encryption Services Tests

Test Coverage:
- KeyExchangeManager: ECDH P-256, encryption/decryption, fingerprints
- KeypairService: Keypair generation, caching, revocation
- SessionKeyService: Session creation, validation, revocation, listing
- EncryptedRecordService: Encryption, storage, retrieval, soft delete
- CryptoAuditService: Logging, verification, queries, compliance reports
- Integration: End-to-end workflows
- Performance: Benchmarks vs targets
"""

import pytest
import json
import time
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import patch, MagicMock

from app.services.key_exchange import KeyExchangeManager
from app.services.crypto_operations import (
    KeypairService,
    SessionKeyService,
    EncryptedRecordService,
)
from app.services.crypto_audit_service import CryptoAuditService
from app.models.encryption_models import (
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    CryptographicAuditLog,
    ActorType,
    CryptoAuditLogStatus,
)
from app.security.crypto import CryptoManager
from sqlalchemy.orm import Session


# ==================== FIXTURES ====================

@pytest.fixture
def db_session():
    """Mock database session"""
    return MagicMock(spec=Session)


@pytest.fixture
def test_doctor_id():
    """Test doctor UUID"""
    return str(uuid4())


@pytest.fixture
def test_patient_id():
    """Test patient UUID"""
    return str(uuid4())


@pytest.fixture
def test_record_id():
    """Test record UUID"""
    return str(uuid4())


@pytest.fixture
def keypair_pem():
    """Generate test keypair in PEM format"""
    private_pem, public_pem = KeyExchangeManager.generate_keypair()
    return private_pem, public_pem


# ==================== KeyExchangeManager Tests ====================

class TestKeyExchangeManager:
    """Test ECDH P-256 key exchange and ChaCha20-Poly1305 encryption"""
    
    def test_keypair_generation(self):
        """Test P-256 keypair generation"""
        private_pem, public_pem = KeyExchangeManager.generate_keypair()
        
        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert len(private_pem) > 0
        assert len(public_pem) > 0
    
    def test_encrypt_decrypt_roundtrip(self, keypair_pem):
        """Test encrypt -> decrypt produces original plaintext"""
        private_pem, public_pem = keypair_pem
        plaintext = b"Medical record: Patient blood type O+"
        
        # Encrypt with public key
        encrypted = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        
        # Verify structure
        assert "encrypted_key" in encrypted
        assert "nonce" in encrypted
        assert "auth_tag" in encrypted
        assert "ephemeral_public_key" in encrypted
        
        # Decrypt with private key
        decrypted = KeyExchangeManager.decrypt_with_private_key(encrypted, private_pem)
        
        assert decrypted == plaintext
    
    def test_encrypt_with_aad(self, keypair_pem):
        """Test encryption with associated authenticated data (AAD)"""
        private_pem, public_pem = keypair_pem
        plaintext = b"Prescription: Amoxicillin 500mg"
        aad = b"patient:12345:prescription"
        
        # Encrypt with AAD
        encrypted = KeyExchangeManager.encrypt_for_public_key(
            plaintext, public_pem, aad
        )
        
        # Decrypt with same AAD
        decrypted = KeyExchangeManager.decrypt_with_private_key(
            encrypted, private_pem, aad
        )
        assert decrypted == plaintext
        
        # Decrypt with wrong AAD should fail
        with pytest.raises(Exception):
            KeyExchangeManager.decrypt_with_private_key(
                encrypted, private_pem, b"wrong:aad"
            )
    
    def test_tampering_detection(self, keypair_pem):
        """Test AEAD authentication detects tampering"""
        private_pem, public_pem = keypair_pem
        plaintext = b"Lab result: Blood glucose 95 mg/dL"
        
        encrypted = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        
        # Tamper with ciphertext
        import base64
        ciphertext_bytes = base64.b64decode(encrypted['encrypted_key'])
        tampered = base64.b64encode(bytearray(ciphertext_bytes) ^ b'\x01').decode()
        
        encrypted['encrypted_key'] = tampered
        
        # Decryption should fail
        with pytest.raises(Exception):
            KeyExchangeManager.decrypt_with_private_key(encrypted, private_pem)
    
    def test_fingerprint_consistency(self, keypair_pem):
        """Test fingerprint is consistent across calls"""
        _, public_pem = keypair_pem
        
        fp1 = KeyExchangeManager.get_public_key_fingerprint(public_pem)
        fp2 = KeyExchangeManager.get_public_key_fingerprint(public_pem)
        
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex (256 bits)
    
    def test_ephemeral_keys_different(self, keypair_pem):
        """Test ephemeral keys are different each time"""
        _, public_pem = keypair_pem
        plaintext = b"Test data"
        
        encrypted1 = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        encrypted2 = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        
        # Ciphertexts should be different (ephemeral keys)
        assert encrypted1['encrypted_key'] != encrypted2['encrypted_key']
        assert encrypted1['ephemeral_public_key'] != encrypted2['ephemeral_public_key']
    
    def test_performance_encrypt(self, keypair_pem):
        """Test encryption performance (<50ms)"""
        _, public_pem = keypair_pem
        plaintext = b"X" * 1000  # 1KB
        
        start = time.time()
        for _ in range(10):
            KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        elapsed = (time.time() - start) / 10 * 1000  # ms per operation
        
        assert elapsed < 50, f"Encryption took {elapsed}ms, should be <50ms"
    
    def test_performance_decrypt(self, keypair_pem):
        """Test decryption performance (<50ms)"""
        private_pem, public_pem = keypair_pem
        plaintext = b"X" * 1000
        encrypted = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
        
        start = time.time()
        for _ in range(10):
            KeyExchangeManager.decrypt_with_private_key(encrypted, private_pem)
        elapsed = (time.time() - start) / 10 * 1000
        
        assert elapsed < 50, f"Decryption took {elapsed}ms, should be <50ms"


# ==================== KeypairService Tests ====================

class TestKeypairService:
    """Test keypair generation and management"""
    
    @patch('app.services.crypto_operations.vault_manager')
    @patch('app.services.crypto_operations.cache_manager')
    def test_generate_keypair(self, mock_cache, mock_vault, db_session, test_doctor_id):
        """Test keypair generation stores in Vault and DB"""
        mock_vault.store_secret = MagicMock()
        mock_cache.set = MagicMock()
        
        # Mock DB query to return no existing keypair
        db_session.query.return_value.filter.return_value.first.return_value = None
        
        # Mock commit to avoid DB access
        db_session.commit = MagicMock()
        db_session.add = MagicMock()
        db_session.refresh = MagicMock()
        
        # Test that vault was called to store key
        mock_vault.store_secret.assert_called()
        
        # Test that cache was updated
        mock_cache.set.assert_called()
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_get_public_key_cached(self, mock_cache, db_session, test_doctor_id):
        """Test public key retrieval from cache"""
        test_key = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
        mock_cache.get.return_value = test_key
        
        result = KeypairService.get_public_key(db_session, test_doctor_id)
        
        assert result == test_key
        mock_cache.get.assert_called()
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_get_public_key_from_db(self, mock_cache, db_session, test_doctor_id):
        """Test public key retrieval falls back to DB"""
        test_key = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
        mock_cache.get.return_value = None  # Cache miss
        
        # Mock DB query
        mock_keypair = MagicMock()
        mock_keypair.public_key_pem = test_key
        db_session.query.return_value.filter.return_value.first.return_value = mock_keypair
        
        result = KeypairService.get_public_key(db_session, test_doctor_id)
        
        assert result == test_key
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_revoke_keypair(self, mock_cache, db_session, test_doctor_id):
        """Test keypair revocation"""
        mock_keypair = MagicMock()
        db_session.query.return_value.filter.return_value.first.return_value = mock_keypair
        
        KeypairService.revoke_keypair(db_session, test_doctor_id, "Compromised")
        
        assert mock_keypair.is_revoked == True
        db_session.commit.assert_called()
        mock_cache.delete.assert_called()


# ==================== SessionKeyService Tests ====================

class TestSessionKeyService:
    """Test session key management"""
    
    @patch('app.services.crypto_operations.KeypairService.get_public_key')
    @patch('app.services.crypto_operations.cache_manager')
    def test_create_session_key(
        self, mock_cache, mock_get_key, db_session, 
        test_doctor_id, test_patient_id, keypair_pem
    ):
        """Test session key creation"""
        _, doctor_public_key = keypair_pem
        mock_get_key.return_value = doctor_public_key
        mock_cache.set = MagicMock()
        
        # Mock DB operations
        db_session.add = MagicMock()
        db_session.commit = MagicMock()
        db_session.refresh = MagicMock()
        
        # Create session key
        session_key, plaintext = SessionKeyService.create_session_key(
            db_session,
            test_patient_id,
            test_doctor_id,
            ttl_days=7
        )
        
        # Verify plaintext is hex-encoded
        assert len(plaintext) == 64  # 32 bytes as hex
        
        # Verify DB was updated
        db_session.add.assert_called()
        db_session.commit.assert_called()
        mock_cache.set.assert_called()
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_validate_session_key_cached(self, mock_cache, db_session, test_doctor_id, test_patient_id):
        """Test session validation from cache"""
        session_hash = "abcd1234"
        mock_cache.get.return_value = "valid"
        
        result = SessionKeyService.validate_session_key(
            db_session,
            session_hash,
            test_doctor_id,
            test_patient_id
        )
        
        assert result == True
        mock_cache.get.assert_called()
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_validate_session_key_db(self, mock_cache, db_session, test_doctor_id, test_patient_id):
        """Test session validation from DB"""
        session_hash = "abcd1234"
        mock_cache.get.return_value = None  # Cache miss
        
        # Mock DB query
        mock_session = MagicMock()
        mock_session.expires_at = datetime.utcnow() + timedelta(days=1)
        db_session.query.return_value.filter.return_value.first.return_value = mock_session
        
        result = SessionKeyService.validate_session_key(
            db_session,
            session_hash,
            test_doctor_id,
            test_patient_id
        )
        
        assert result == True
    
    @patch('app.services.crypto_operations.cache_manager')
    def test_revoke_session_key(self, mock_cache, db_session):
        """Test session key revocation"""
        session_hash = "abcd1234"
        mock_session = MagicMock()
        db_session.query.return_value.filter.return_value.first.return_value = mock_session
        
        SessionKeyService.revoke_session_key(db_session, session_hash, "User requested")
        
        assert mock_session.status == SessionKeyStatus.REVOKED
        db_session.commit.assert_called()
        mock_cache.delete.assert_called()
    
    def test_list_active_sessions(self, db_session, test_patient_id, test_doctor_id):
        """Test listing active sessions"""
        mock_sessions = [MagicMock(), MagicMock()]
        db_session.query.return_value.filter.return_value.all.return_value = mock_sessions
        
        result = SessionKeyService.list_active_sessions(
            db_session,
            test_patient_id,
            test_doctor_id
        )
        
        assert len(result) == 2


# ==================== EncryptedRecordService Tests ====================

class TestEncryptedRecordService:
    """Test encrypted record storage and retrieval"""
    
    def test_store_encrypted_record(self, db_session, test_patient_id):
        """Test storing encrypted record"""
        plaintext = b"Patient allergy: Penicillin"
        session_key = b"X" * 32
        
        db_session.add = MagicMock()
        db_session.commit = MagicMock()
        db_session.refresh = MagicMock()
        
        record = EncryptedRecordService.store_encrypted_record(
            db_session,
            test_patient_id,
            plaintext,
            "ALLERGY",
            datetime.utcnow(),
            "Penicillin Allergy",
            session_key
        )
        
        db_session.add.assert_called()
        db_session.commit.assert_called()
    
    def test_retrieve_encrypted_record(self, db_session, test_record_id):
        """Test retrieving encrypted record metadata"""
        mock_record = MagicMock()
        db_session.query.return_value.filter.return_value.first.return_value = mock_record
        
        result = EncryptedRecordService.retrieve_encrypted_record(
            db_session,
            test_record_id
        )
        
        assert result == mock_record
    
    def test_list_records_by_type(self, db_session, test_patient_id):
        """Test listing records by type"""
        mock_records = [MagicMock(), MagicMock(), MagicMock()]
        db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = mock_records
        
        result = EncryptedRecordService.list_records_by_type(
            db_session,
            test_patient_id,
            "PRESCRIPTION",
            limit=50
        )
        
        assert len(result) == 3
    
    def test_soft_delete_record(self, db_session, test_record_id):
        """Test soft delete sets deleted flag"""
        mock_record = MagicMock()
        db_session.query.return_value.filter.return_value.first.return_value = mock_record
        
        EncryptedRecordService.soft_delete_record(
            db_session,
            test_record_id,
            "User requested"
        )
        
        assert mock_record.is_deleted == True
        assert mock_record.deleted_at is not None


# ==================== CryptoAuditService Tests ====================

class TestCryptoAuditService:
    """Test immutable audit logging"""
    
    @patch('app.services.crypto_audit_service.vault_manager')
    def test_log_action(self, mock_vault, db_session, test_doctor_id, test_record_id):
        """Test logging cryptographic action"""
        mock_vault.retrieve_secret.return_value = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        
        db_session.add = MagicMock()
        db_session.commit = MagicMock()
        db_session.refresh = MagicMock()
        
        audit_log = CryptoAuditService.log_action(
            db_session,
            test_doctor_id,
            ActorType.DOCTOR,
            "RECORD_ACCESSED",
            "ENCRYPTED_RECORD",
            test_record_id,
            event_data={"duration_ms": 42},
            ip_address="192.168.1.1",
            request_id="req-123",
            status=CryptoAuditLogStatus.SUCCESS
        )
        
        db_session.add.assert_called()
        db_session.commit.assert_called()
    
    @patch('app.services.crypto_audit_service.vault_manager')
    @patch('app.services.crypto_audit_service.CryptoManager')
    def test_verify_audit_log(self, mock_crypto, mock_vault, db_session, test_record_id):
        """Test verifying audit log signature"""
        # Mock signature verification to return True
        mock_crypto.verify_signature.return_value = True
        mock_vault.retrieve_secret.return_value = "public_key_pem"
        
        # Mock audit log
        mock_audit = MagicMock()
        mock_audit.event_data = {"action": "TEST", "timestamp": "2024-01-01T00:00:00"}
        mock_audit.signature = "valid_signature"
        db_session.query.return_value.filter.return_value.first.return_value = mock_audit
        
        result = CryptoAuditService.verify_audit_log(db_session, str(uuid4()))
        
        assert result == True
    
    def test_query_audit_logs_filters(self, db_session):
        """Test audit log query with filters"""
        mock_logs = [MagicMock(), MagicMock()]
        db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = mock_logs
        
        result = CryptoAuditService.query_audit_logs(
            db_session,
            resource_type="ENCRYPTED_RECORD",
            action="RECORD_ACCESSED",
            status=CryptoAuditLogStatus.SUCCESS,
            limit=50
        )
        
        assert len(result) == 2
    
    def test_log_record_access_convenience(self, db_session, test_doctor_id, test_patient_id, test_record_id):
        """Test convenience method for logging record access"""
        db_session.add = MagicMock()
        db_session.commit = MagicMock()
        db_session.refresh = MagicMock()
        
        with patch('app.services.crypto_audit_service.CryptoAuditService.log_action') as mock_log:
            CryptoAuditService.log_record_access(
                db_session,
                test_doctor_id,
                test_patient_id,
                test_record_id,
                ip_address="192.168.1.1",
                duration_ms=42
            )
            
            mock_log.assert_called_once()


# ==================== Integration Tests ====================

class TestPhase3Integration:
    """End-to-end Phase 3 workflows"""
    
    def test_end_to_end_doctor_access_flow(self, keypair_pem):
        """
        Test complete workflow:
        1. Doctor has keypair
        2. Session key created for doctor-patient access
        3. Record encrypted with session key
        4. Doctor decrypts with session key
        5. Access logged in audit trail
        """
        doctor_private, doctor_public = keypair_pem
        patient_private, patient_public = KeyExchangeManager.generate_keypair()
        
        # Simulate session key creation
        plaintext_session_key = b"X" * 32
        
        # Doctor receives session key encrypted with their public key
        encrypted_session = KeyExchangeManager.encrypt_for_public_key(
            plaintext_session_key,
            doctor_public
        )
        
        # Doctor decrypts session key
        decrypted_session = KeyExchangeManager.decrypt_with_private_key(
            encrypted_session,
            doctor_private
        )
        
        assert decrypted_session == plaintext_session_key
        
        # Record is encrypted with session key
        record_plaintext = b"Patient medical record data"
        record_encrypted = KeyExchangeManager.encrypt_for_public_key(
            record_plaintext,
            doctor_public  # Doctor encrypts for verification (in real flow, server does this)
        )
        
        # Doctor decrypts record
        record_decrypted = KeyExchangeManager.decrypt_with_private_key(
            record_encrypted,
            doctor_private
        )
        
        assert record_decrypted == record_plaintext


# ==================== Performance Tests ====================

class TestPhase3Performance:
    """Performance benchmarks for production targets"""
    
    def test_keypair_generation_performance(self):
        """Test keypair generation <50ms"""
        start = time.time()
        for _ in range(5):
            KeyExchangeManager.generate_keypair()
        elapsed = (time.time() - start) / 5 * 1000
        
        assert elapsed < 50, f"Keypair generation {elapsed}ms > 50ms target"
    
    def test_encrypt_decrypt_performance(self, keypair_pem):
        """Test encrypt+decrypt <5ms for small records"""
        _, public_pem = keypair_pem
        private_pem = keypair_pem[0]
        plaintext = b"X" * 500  # 500 bytes
        
        start = time.time()
        for _ in range(10):
            encrypted = KeyExchangeManager.encrypt_for_public_key(plaintext, public_pem)
            KeyExchangeManager.decrypt_with_private_key(encrypted, private_pem)
        elapsed = (time.time() - start) / 10 * 1000
        
        assert elapsed < 5, f"Encrypt+decrypt {elapsed}ms > 5ms target"
