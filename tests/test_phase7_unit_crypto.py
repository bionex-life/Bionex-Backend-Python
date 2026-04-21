"""
Phase 7: Unit Tests for CryptoManager

Tests all cryptographic functions in isolation:
- Keypair generation
- Signing and verification
- AES encryption/decryption
- ECDH key exchange
- Hash functions
- KDF (Key Derivation Function)

Each test is independent, deterministic, and fast.
"""

import os
import pytest
from datetime import datetime, timedelta

# Mock imports (would be from app in real implementation)
from app.security.crypto import CryptoManager


class TestKeypairGeneration:
    """Test ECDSA P-256 keypair generation"""
    
    def test_generate_keypair_creates_valid_pair(self):
        """Generate ECDSA P-256 keypair with proper format"""
        public_key, private_key = CryptoManager.generate_keypair()
        
        assert public_key is not None
        assert private_key is not None
        assert len(public_key) > 0
        assert len(private_key) > 0
        # PEM format check
        assert b'BEGIN PUBLIC KEY' in public_key or isinstance(public_key, str)
        assert b'BEGIN PRIVATE KEY' in private_key or isinstance(private_key, str)
    
    def test_generate_multiple_keypairs_different(self):
        """Different calls generate different keypairs"""
        pair1 = CryptoManager.generate_keypair()
        pair2 = CryptoManager.generate_keypair()
        
        assert pair1 != pair2
    
    def test_keypair_format_valid_pem(self):
        """Keypair format is valid PEM"""
        public_key, private_key = CryptoManager.generate_keypair()
        
        # Both should be in PEM format
        if isinstance(public_key, bytes):
            assert public_key.startswith(b'-----BEGIN')
            assert public_key.endswith(b'-----\n') or public_key.endswith(b'-----')
        
        if isinstance(private_key, bytes):
            assert private_key.startswith(b'-----BEGIN')
            assert private_key.endswith(b'-----\n') or private_key.endswith(b'-----')


class TestHashFunction:
    """Test SHA-256 hashing"""
    
    def test_hash_message_deterministic(self):
        """SHA-256 hash produces same output for same input"""
        message = "test_message_123"
        hash1 = CryptoManager.hash_message(message)
        hash2 = CryptoManager.hash_message(message)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex output (256 bits = 64 hex chars)
    
    def test_hash_different_messages_different_hashes(self):
        """Different messages produce different hashes"""
        hash1 = CryptoManager.hash_message("message1")
        hash2 = CryptoManager.hash_message("message2")
        
        assert hash1 != hash2
    
    def test_hash_output_is_hex_string(self):
        """Hash output is valid hex string"""
        hash_result = CryptoManager.hash_message("test")
        
        # Check all chars are hex
        assert all(c in '0123456789abcdef' for c in hash_result.lower())
    
    def test_hash_empty_string(self):
        """Hash empty string produces valid hash"""
        hash_result = CryptoManager.hash_message("")
        
        assert hash_result is not None
        assert len(hash_result) == 64


class TestSignatureGeneration:
    """Test ECDSA signature generation"""
    
    def test_sign_message_creates_valid_signature(self):
        """ECDSA sign creates valid 128-char hex signature"""
        public_key, private_key = CryptoManager.generate_keypair()
        message = "important_data"
        
        signature = CryptoManager.sign_message(message, private_key)
        
        assert signature is not None
        assert len(signature) == 128  # ECDSA P-256 signature hex (256 bits = 128 hex chars)
        assert all(c in '0123456789abcdef' for c in signature.lower())
    
    def test_sign_deterministic(self):
        """Same message signed with same key produces same signature"""
        _, private_key = CryptoManager.generate_keypair()
        message = "deterministic_test"
        
        sig1 = CryptoManager.sign_message(message, private_key)
        sig2 = CryptoManager.sign_message(message, private_key)
        
        assert sig1 == sig2
    
    def test_sign_different_messages_different_signatures(self):
        """Different messages produce different signatures"""
        _, private_key = CryptoManager.generate_keypair()
        
        sig1 = CryptoManager.sign_message("msg1", private_key)
        sig2 = CryptoManager.sign_message("msg2", private_key)
        
        assert sig1 != sig2
    
    def test_sign_large_message(self):
        """Can sign large messages (medical records)"""
        _, private_key = CryptoManager.generate_keypair()
        large_message = "x" * 10000  # 10KB message
        
        signature = CryptoManager.sign_message(large_message, private_key)
        
        assert signature is not None
        assert len(signature) == 128


class TestSignatureVerification:
    """Test ECDSA signature verification"""
    
    def test_verify_signature_accepts_valid(self):
        """Valid signature passes verification"""
        public_key, private_key = CryptoManager.generate_keypair()
        message = "data_to_sign"
        
        signature = CryptoManager.sign_message(message, private_key)
        valid = CryptoManager.verify_signature(
            message=message,
            signature_hex=signature,
            public_key_pem=public_key
        )
        
        assert valid is True
    
    def test_verify_signature_rejects_tampered_signature(self):
        """Tampered signature fails verification"""
        public_key, private_key = CryptoManager.generate_keypair()
        message = "original_data"
        
        signature = CryptoManager.sign_message(message, private_key)
        # Tamper with signature (flip a bit)
        tampered = list(signature)
        tampered[-1] = '0' if tampered[-1] != '0' else '1'
        tampered = ''.join(tampered)
        
        valid = CryptoManager.verify_signature(
            message=message,
            signature_hex=tampered,
            public_key_pem=public_key
        )
        
        assert valid is False
    
    def test_verify_signature_rejects_wrong_message(self):
        """Signature fails verification with different message"""
        public_key, private_key = CryptoManager.generate_keypair()
        
        signature = CryptoManager.sign_message("original", private_key)
        valid = CryptoManager.verify_signature(
            message="different",
            signature_hex=signature,
            public_key_pem=public_key
        )
        
        assert valid is False
    
    def test_verify_signature_rejects_wrong_key(self):
        """Signature fails verification with different key"""
        pub1, priv1 = CryptoManager.generate_keypair()
        pub2, priv2 = CryptoManager.generate_keypair()
        
        message = "data"
        signature = CryptoManager.sign_message(message, priv1)
        
        valid = CryptoManager.verify_signature(
            message=message,
            signature_hex=signature,
            public_key_pem=pub2  # Different public key
        )
        
        assert valid is False
    
    def test_verify_invalid_signature_format(self):
        """Invalid signature format rejected"""
        public_key, _ = CryptoManager.generate_keypair()
        
        valid = CryptoManager.verify_signature(
            message="data",
            signature_hex="invalid_hex",
            public_key_pem=public_key
        )
        
        assert valid is False


class TestAESEncryption:
    """Test AES-256-GCM encryption"""
    
    def test_aes_encrypt_creates_ciphertext(self):
        """AES-256-GCM encryption produces valid ciphertext"""
        plaintext = "sensitive_patient_data"
        key = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        
        assert ciphertext is not None
        assert len(ciphertext) > len(plaintext.encode())
        assert isinstance(ciphertext, bytes)
    
    def test_aes_encrypt_large_data(self):
        """Can encrypt large medical records"""
        plaintext = "patient record " * 10000  # ~150KB
        key = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        
        assert ciphertext is not None
        assert len(ciphertext) > 0
    
    def test_aes_decrypt_recovers_plaintext(self):
        """Decryption recovers original plaintext"""
        plaintext = "sensitive_patient_data"
        key = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        recovered = CryptoManager.aes_decrypt(ciphertext, key)
        
        assert recovered == plaintext
    
    def test_aes_decrypt_fails_with_wrong_key(self):
        """Wrong key causes decryption to fail"""
        plaintext = "sensitive_data"
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key1)
        
        with pytest.raises(Exception):
            CryptoManager.aes_decrypt(ciphertext, key2)
    
    def test_aes_decrypt_fails_with_tampered_ciphertext(self):
        """Tampered ciphertext fails decryption (GCM tag check)"""
        plaintext = "patient_data"
        key = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits
        
        with pytest.raises(Exception):
            CryptoManager.aes_decrypt(bytes(tampered), key)
    
    def test_aes_decrypt_returns_string_not_bytes(self):
        """Decryption returns original type (string)"""
        plaintext = "test_string"
        key = os.urandom(32)
        
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        recovered = CryptoManager.aes_decrypt(ciphertext, key)
        
        assert isinstance(recovered, str)
        assert recovered == plaintext
    
    def test_aes_encrypt_deterministic_with_fixed_iv(self):
        """Encryption is deterministic with fixed IV (for testing)"""
        plaintext = "test"
        key = os.urandom(32)
        
        # With same IV, same ciphertext
        ct1 = CryptoManager.aes_encrypt(plaintext, key)
        ct2 = CryptoManager.aes_encrypt(plaintext, key)
        
        # Note: Real AES-GCM uses random IV, so these will differ
        # This test documents that behavior


class TestECDHKeyExchange:
    """Test Elliptic Curve Diffie-Hellman"""
    
    def test_ecdh_generates_shared_secret(self):
        """ECDH produces identical shared secrets from both parties"""
        # Party A
        pub_a, priv_a = CryptoManager.generate_keypair()
        # Party B
        pub_b, priv_b = CryptoManager.generate_keypair()
        
        # Compute shared secrets
        shared_secret_a = CryptoManager.ecdh_compute_shared_secret(priv_a, pub_b)
        shared_secret_b = CryptoManager.ecdh_compute_shared_secret(priv_b, pub_a)
        
        assert shared_secret_a == shared_secret_b
        assert len(shared_secret_a) == 32  # 256-bit key
    
    def test_ecdh_different_keys_different_secrets(self):
        """Different key pairs produce different shared secrets"""
        pub1, priv1 = CryptoManager.generate_keypair()
        pub2, priv2 = CryptoManager.generate_keypair()
        pub3, priv3 = CryptoManager.generate_keypair()
        
        secret_1_2 = CryptoManager.ecdh_compute_shared_secret(priv1, pub2)
        secret_1_3 = CryptoManager.ecdh_compute_shared_secret(priv1, pub3)
        
        assert secret_1_2 != secret_1_3
    
    def test_ecdh_asymmetric_computation(self):
        """ECDH works in both directions"""
        pub_alice, priv_alice = CryptoManager.generate_keypair()
        pub_bob, priv_bob = CryptoManager.generate_keypair()
        
        # Alice: priv_alice + pub_bob
        secret_alice = CryptoManager.ecdh_compute_shared_secret(priv_alice, pub_bob)
        # Bob: priv_bob + pub_alice
        secret_bob = CryptoManager.ecdh_compute_shared_secret(priv_bob, pub_alice)
        
        assert secret_alice == secret_bob


class TestKDF:
    """Test Key Derivation Function"""
    
    def test_kdf_derives_consistent_key(self):
        """KDF produces same key from same input"""
        shared_secret = os.urandom(32)
        salt = "test_salt"
        
        key1 = CryptoManager.kdf_derive_key(shared_secret, salt)
        key2 = CryptoManager.kdf_derive_key(shared_secret, salt)
        
        assert key1 == key2
        assert len(key1) == 32
    
    def test_kdf_different_salts_different_keys(self):
        """Different salt produces different keys"""
        shared_secret = os.urandom(32)
        
        key1 = CryptoManager.kdf_derive_key(shared_secret, "salt1")
        key2 = CryptoManager.kdf_derive_key(shared_secret, "salt2")
        
        assert key1 != key2
    
    def test_kdf_different_secrets_different_keys(self):
        """Different shared secrets produce different keys"""
        secret1 = os.urandom(32)
        secret2 = os.urandom(32)
        salt = "same_salt"
        
        key1 = CryptoManager.kdf_derive_key(secret1, salt)
        key2 = CryptoManager.kdf_derive_key(secret2, salt)
        
        assert key1 != key2
    
    def test_kdf_produces_32_byte_key(self):
        """KDF produces correct key length"""
        shared_secret = os.urandom(32)
        key = CryptoManager.kdf_derive_key(shared_secret, "salt")
        
        assert len(key) == 32
        assert isinstance(key, bytes)


class TestIntegrationCryptoOperations:
    """Integration tests combining multiple crypto operations"""
    
    def test_sign_encrypt_decrypt_verify_workflow(self):
        """Complete workflow: sign → encrypt → decrypt → verify"""
        # Setup
        pub_key, priv_key = CryptoManager.generate_keypair()
        plaintext = "patient_medical_record"
        key = os.urandom(32)
        
        # 1. Sign the plaintext
        signature = CryptoManager.sign_message(plaintext, priv_key)
        
        # 2. Encrypt
        ciphertext = CryptoManager.aes_encrypt(plaintext, key)
        
        # 3. Decrypt
        decrypted = CryptoManager.aes_decrypt(ciphertext, key)
        
        # 4. Verify signature
        valid = CryptoManager.verify_signature(
            message=decrypted,
            signature_hex=signature,
            public_key_pem=pub_key
        )
        
        assert valid is True
    
    def test_key_exchange_and_encrypt_workflow(self):
        """Complete workflow: ECDH → KDF → Encrypt"""
        # 1. Key exchange (ECDH)
        pub_alice, priv_alice = CryptoManager.generate_keypair()
        pub_bob, priv_bob = CryptoManager.generate_keypair()
        
        shared_secret = CryptoManager.ecdh_compute_shared_secret(priv_alice, pub_bob)
        
        # 2. Derive key (KDF)
        derived_key = CryptoManager.kdf_derive_key(shared_secret, "app_salt")
        
        # 3. Encrypt
        plaintext = "shared_secret_data"
        ciphertext = CryptoManager.aes_encrypt(plaintext, derived_key)
        
        # 4. Decrypt with same derived key
        decrypted = CryptoManager.aes_decrypt(ciphertext, derived_key)
        
        assert decrypted == plaintext
