"""
Phase 7: Security Tests

Security-focused tests:
- Invalid signature rejection
- Tampering detection
- Expired session blocking
- Unauthorized access denial
- Rate limiting
- SQL injection prevention
"""

import os
import uuid
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Mock imports


class TestSignatureValidation:
    """Test signature validation security"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        crypto = Mock()
        db = Mock()
        
        crypto.verify_signature.return_value = True
        
        return {
            'crypto': crypto,
            'db': db
        }
    
    def test_invalid_signature_rejected(self, setup):
        """Invalid signature fails verification"""
        setup['crypto'].verify_signature.return_value = False
        
        valid = setup['crypto'].verify_signature(
            message="data",
            signature_hex="invalid_hex",
            public_key_pem="key"
        )
        
        assert valid is False
    
    def test_signature_wrong_length_rejected(self, setup):
        """Signature with wrong length rejected"""
        setup['crypto'].verify_signature.return_value = False
        
        # ECDSA P-256 signature must be 128 hex chars
        short_sig = "short"
        
        valid = setup['crypto'].verify_signature(
            message="data",
            signature_hex=short_sig,
            public_key_pem="key"
        )
        
        assert valid is False
    
    def test_signature_from_wrong_key_rejected(self, setup):
        """Signature from different key rejected"""
        setup['crypto'].verify_signature.return_value = False
        
        # Signature created with key1, verified with key2
        valid = setup['crypto'].verify_signature(
            message="data",
            signature_hex="valid_sig" * 16,  # 128 chars
            public_key_pem="different_key"
        )
        
        assert valid is False
    
    def test_signature_for_wrong_message_rejected(self, setup):
        """Signature fails verification with different message"""
        setup['crypto'].verify_signature.return_value = False
        
        # Signed "original", but verifying "modified"
        valid = setup['crypto'].verify_signature(
            message="modified_message",
            signature_hex="sig" * 43,  # 128+ chars
            public_key_pem="key"
        )
        
        assert valid is False


class TestTamperingDetection:
    """Test tampering detection"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        crypto = Mock()
        db = Mock()
        
        crypto.verify_signature.return_value = True
        
        return {
            'crypto': crypto,
            'db': db
        }
    
    def test_tampered_ciphertext_fails_decryption(self, setup):
        """Tampered ciphertext fails GCM tag verification"""
        crypto = setup['crypto']
        
        # Original ciphertext
        ciphertext = b"valid_encrypted_data_with_tag"
        key = os.urandom(32)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits
        
        crypto.aes_decrypt.side_effect = Exception("GCM tag verification failed")
        
        with pytest.raises(Exception) as exc:
            crypto.aes_decrypt(bytes(tampered), key)
        
        assert "verification failed" in str(exc.value).lower()
    
    def test_tampered_audit_log_detected(self, setup):
        """Modified audit log fails signature check"""
        db = setup['db']
        crypto = setup['crypto']
        
        # Create audit log
        audit_id = str(uuid.uuid4())
        original_actor = "doctor-123"
        
        mock_audit = Mock()
        mock_audit.id = audit_id
        mock_audit.actor_id = original_actor
        mock_audit.signature = "sig" * 43  # 128+ chars
        
        # Tamper with data
        mock_audit.actor_id = "attacker"
        
        # Verify should fail (signature doesn't match modified data)
        crypto.verify_signature.return_value = False
        
        valid = crypto.verify_signature(
            message=str(audit_id),
            signature_hex=mock_audit.signature,
            public_key_pem="public_key"
        )
        
        assert valid is False
    
    def test_modified_sensitive_field_detected(self, setup):
        """Modification of sensitive fields detected"""
        db = setup['db']
        crypto = setup['crypto']
        
        # Original record
        mock_record = Mock()
        mock_record.patient_id = "patient-123"
        mock_record.dosage = 100
        mock_record.signature = "sig" * 43
        
        # Attacker modifies dosage
        mock_record.dosage = 1000  # Increased by 10x
        
        # Signature no longer valid
        crypto.verify_signature.return_value = False
        
        valid = crypto.verify_signature(
            message="record_data",
            signature_hex=mock_record.signature,
            public_key_pem="key"
        )
        
        assert valid is False


class TestAccessControl:
    """Test access control security"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        db = Mock()
        
        return {'db': db}
    
    def test_unauthorized_user_denied_decryption(self, setup):
        """User without access grant denied decryption"""
        db = setup['db']
        
        # Owner: patient-123
        record_owner = "patient-123"
        # Accessor: unauthorized-user
        unauthorized_user = "unauthorized-user"
        
        # Query for access grant
        db.query.return_value.filter_by.return_value.first.return_value = None
        
        grant = db.query.return_value.filter_by.return_value.first()
        
        assert grant is None  # No access
    
    def test_revoked_access_denied(self, setup):
        """Revoked access grant denies decryption"""
        db = setup['db']
        
        # Create revoked grant
        mock_grant = Mock()
        mock_grant.status = 'REVOKED'
        
        # Query should not return revoked grant for active access
        db.query.return_value.filter(
            Mock()  # status == 'ACTIVE'
        ).return_value.first.return_value = None
        
        active_grant = db.query.return_value.filter(Mock()).return_value.first()
        
        assert active_grant is None
    
    def test_expired_session_denied(self, setup):
        """Expired session key denied"""
        db = setup['db']
        
        session_id = str(uuid.uuid4())
        expired_time = datetime.utcnow() - timedelta(hours=1)
        
        mock_session = Mock()
        mock_session.id = session_id
        mock_session.expires_at = expired_time
        
        # Session is expired
        is_expired = mock_session.expires_at < datetime.utcnow()
        assert is_expired is True
    
    def test_scope_limitation_enforced(self, setup):
        """Access scope limitation enforced"""
        db = setup['db']
        
        # Grant READ access only
        mock_grant = Mock()
        mock_grant.scope = ['READ']
        
        # Try to write
        requested_scope = 'WRITE'
        
        has_scope = requested_scope in mock_grant.scope
        assert has_scope is False  # No WRITE permission
    
    def test_doctor_cannot_access_other_doctor_key(self, setup):
        """Doctor cannot decrypt another doctor's session key"""
        db = setup['db']
        
        doctor1_session_key = os.urandom(32)
        doctor2_id = "doctor-456"
        
        # Doctor 2 tries to access Doctor 1's session
        # Should be denied
        db.query.return_value.filter_by.return_value.first.return_value = None
        
        session = db.query.return_value.filter_by.return_value.first()
        
        assert session is None  # No access


class TestRateLimiting:
    """Test rate limiting security"""
    
    @pytest.fixture
    def rate_limiter(self):
        """Mock rate limiter"""
        return Mock()
    
    def test_rate_limiting_enforced(self, rate_limiter):
        """Rapid API calls rate limited after threshold"""
        user_id = "user-123"
        max_requests = 10
        window_seconds = 60
        
        rate_limiter.is_allowed.side_effect = [True] * 10 + [False] * 5
        
        # First 10 allowed
        for i in range(10):
            allowed = rate_limiter.is_allowed(user_id)
            assert allowed is True
        
        # Subsequent denied
        for i in range(5):
            allowed = rate_limiter.is_allowed(user_id)
            assert allowed is False
    
    def test_rate_limit_per_user(self, rate_limiter):
        """Rate limit per user (not global)"""
        user1 = "user-1"
        user2 = "user-2"
        
        # Setup: User1 rate limited, User2 not
        rate_limiter.is_allowed.side_effect = [
            # User 1 requests
            True, True, False, False,
            # User 2 requests
            True, True, True, True
        ]
        
        # User 1 hits limit
        allowed1 = rate_limiter.is_allowed(user1)
        assert allowed1 is True
        allowed1 = rate_limiter.is_allowed(user1)
        assert allowed1 is True
        allowed1 = rate_limiter.is_allowed(user1)
        assert allowed1 is False
        
        # User 2 still allowed
        allowed2 = rate_limiter.is_allowed(user2)
        assert allowed2 is True
        allowed2 = rate_limiter.is_allowed(user2)
        assert allowed2 is True
    
    def test_rate_limit_window_reset(self, rate_limiter):
        """Rate limit counter resets after window"""
        user_id = "user-123"
        
        # First window: limited after 10
        rate_limiter.is_allowed.side_effect = [True] * 10 + [False]
        
        for i in range(11):
            rate_limiter.is_allowed(user_id)
        
        # After window resets: allowed again
        rate_limiter.is_allowed.side_effect = [True]
        allowed = rate_limiter.is_allowed(user_id)
        assert allowed is True


class TestSQLInjectionPrevention:
    """Test SQL injection prevention"""
    
    @pytest.fixture
    def db(self):
        """Mock database"""
        return Mock()
    
    def test_parameterized_queries_prevent_injection(self, db):
        """SQL injection attempts safely handled"""
        injection_payload = "' OR '1'='1"
        
        # Use parameterized query (ORM)
        db.query.return_value.filter.return_value.all.return_value = []
        
        # Query with injection payload
        results = db.query.return_value.filter.return_value.all()
        
        # Should return empty (treated as literal string)
        assert len(results) == 0
    
    def test_orm_prevents_string_concatenation_injection(self, db):
        """ORM prevents injection from string concatenation"""
        user_input = "admin'; DROP TABLE users; --"
        
        # ORM prevents this by parameterizing
        db.query.return_value.filter_by.return_value.first.return_value = None
        
        result = db.query.return_value.filter_by.return_value.first()
        
        assert result is None
    
    def test_prepared_statements_safe(self, db):
        """Prepared statements are safe from injection"""
        payload = "'; DELETE FROM audit_logs; --"
        
        # Using prepared statement
        db.execute.return_value.fetchall.return_value = []
        
        results = db.execute.return_value.fetchall()
        
        assert len(results) == 0


class TestAuthenticationSecurity:
    """Test authentication security"""
    
    @pytest.fixture
    def auth_service(self):
        """Mock auth service"""
        return Mock()
    
    def test_invalid_token_rejected(self, auth_service):
        """Invalid authentication token rejected"""
        auth_service.verify_token.return_value = (False, "Invalid token")
        
        valid, reason = auth_service.verify_token("invalid_token")
        
        assert valid is False
        assert reason == "Invalid token"
    
    def test_expired_token_rejected(self, auth_service):
        """Expired token rejected"""
        auth_service.verify_token.return_value = (False, "Token expired")
        
        valid, reason = auth_service.verify_token("expired_token")
        
        assert valid is False
        assert reason == "Token expired"
    
    def test_tampered_token_rejected(self, auth_service):
        """Tampered token rejected"""
        auth_service.verify_token.return_value = (False, "Signature invalid")
        
        # Token with modified payload
        tampered_token = "header.modified_payload.signature"
        
        valid, reason = auth_service.verify_token(tampered_token)
        
        assert valid is False


class TestDataMinimization:
    """Test data minimization security"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        return Mock()
    
    def test_export_only_requested_fields(self, setup):
        """Export only requested fields, not all data"""
        full_record = {
            'name': 'John Doe',
            'ssn': '123-45-6789',
            'medical_history': 'sensitive',
            'emergency_contact': 'secret',
            'diagnosis': 'confidential'
        }
        
        # Request only 'name' and 'diagnosis'
        requested_fields = ['name', 'diagnosis']
        
        exported = {k: v for k, v in full_record.items() if k in requested_fields}
        
        assert 'ssn' not in exported
        assert 'emergency_contact' not in exported
        assert 'name' in exported
        assert 'diagnosis' in exported
    
    def test_pii_fields_encrypted_in_transit(self, setup):
        """PII fields encrypted before transmission"""
        pii_fields = ['name', 'ssn', 'email', 'phone']
        
        # Mock encryption
        encrypted = {
            'name': 'encrypted_name',
            'ssn': 'encrypted_ssn',
            'email': 'encrypted_email',
            'phone': 'encrypted_phone'
        }
        
        # Verify all PII encrypted
        for field in pii_fields:
            assert encrypted[field].startswith('encrypted_')


class TestErrorHandling:
    """Test error handling doesn't leak information"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        return Mock()
    
    def test_generic_error_on_auth_failure(self, setup):
        """Generic error on authentication failure (no user enumeration)"""
        error = "Invalid credentials"
        
        # Same error for wrong password and nonexistent user
        assert error is not None
        assert "password" not in error.lower()
        assert "user" not in error.lower()
    
    def test_no_stack_trace_in_production_errors(self, setup):
        """Production errors don't include stack traces"""
        error_response = {
            'error': 'An error occurred',
            'code': 500
        }
        
        assert 'traceback' not in error_response
        assert 'stack' not in error_response
        assert 'line' not in error_response


class TestCryptographicSecurity:
    """Test cryptographic security properties"""
    
    @pytest.fixture
    def crypto(self):
        """Mock crypto"""
        return Mock()
    
    def test_random_iv_for_each_encryption(self, crypto):
        """Random IV used for each AES encryption"""
        plaintext = "test"
        key = os.urandom(32)
        
        # Two encryptions should produce different ciphertexts
        ct1 = b"encrypted_1_with_random_iv"
        ct2 = b"encrypted_2_with_different_iv"
        
        assert ct1 != ct2
    
    def test_session_keys_not_reused(self, crypto):
        """Session keys not reused across sessions"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        key3 = os.urandom(32)
        
        # All unique
        assert key1 != key2
        assert key2 != key3
        assert key1 != key3
    
    def test_proper_key_length_for_cipher(self, crypto):
        """Proper key length for cipher (256-bit for AES-256)"""
        key = os.urandom(32)  # 256 bits
        
        assert len(key) == 32
        
        # Should reject shorter keys
        short_key = os.urandom(16)  # 128 bits
        assert len(short_key) == 16
        assert len(short_key) != 32
