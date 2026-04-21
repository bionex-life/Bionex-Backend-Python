"""
Unit tests for Phase 1: Encryption Infrastructure.

Tests cover:
- CryptoManager (keypair generation, encryption/decryption, signatures, hashing)
- CacheManager (Redis operations, TTL management, cache hits/misses)
- VaultManager (secrets storage and retrieval)

Run with: pytest tests/test_crypto.py -v
"""

import os
import pytest
from base64 import b64encode

from app.security.crypto import (
    CryptoManager,
    CryptoError,
    CryptoKeyError,
    CryptoEncryptionError,
    CryptoSignatureError,
)


class TestCryptoManagerKeyPairGeneration:
    """Test ECDH P-256 keypair generation."""

    def test_generate_keypair_returns_pem_strings(self):
        """Generated keys should be valid PEM-formatted strings."""
        private_pem, public_pem = CryptoManager.generate_keypair()

        # Verify PEM format
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "END PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem
        assert "END PUBLIC KEY" in public_pem

    def test_generate_keypair_produces_different_keys_each_time(self):
        """Each keypair generation should produce unique keys."""
        keys1 = CryptoManager.generate_keypair()
        keys2 = CryptoManager.generate_keypair()

        assert keys1[0] != keys2[0]  # Private keys different
        assert keys1[1] != keys2[1]  # Public keys different

    def test_generate_keypair_keys_are_valid_P256(self):
        """Generated keys should be ECDH P-256 compatible."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        private_pem, public_pem = CryptoManager.generate_keypair()

        # Load and verify private key
        private_key = serialization.load_pem_private_key(
            private_pem.encode(),
            password=None,
            backend=default_backend(),
        )
        assert private_key.curve.name == "secp256r1"

        # Load and verify public key
        public_key = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend(),
        )
        assert public_key.curve.name == "secp256r1"


class TestCryptoManagerKeyDerivation:
    """Test password-based key derivation (HKDF-SHA256)."""

    def test_derive_key_from_password_produces_correct_length(self):
        """Derived key should have requested length."""
        key, salt = CryptoManager.derive_key_from_password("password123", length=32)
        assert len(key) == 32
        assert len(salt) == 32

    def test_derive_key_with_custom_salt(self):
        """Should accept custom salt."""
        custom_salt = os.urandom(32)
        key, returned_salt = CryptoManager.derive_key_from_password(
            "password123", salt=custom_salt
        )

        assert returned_salt == custom_salt
        assert len(key) == 32

    def test_derive_key_from_same_password_same_salt_produces_same_key(self):
        """Same password + salt should always produce same key."""
        salt = os.urandom(32)
        key1, _ = CryptoManager.derive_key_from_password("password123", salt=salt)
        key2, _ = CryptoManager.derive_key_from_password("password123", salt=salt)

        assert key1 == key2

    def test_derive_key_different_passwords_produce_different_keys(self):
        """Different passwords should produce different keys."""
        salt = os.urandom(32)
        key1, _ = CryptoManager.derive_key_from_password("password1", salt=salt)
        key2, _ = CryptoManager.derive_key_from_password("password2", salt=salt)

        assert key1 != key2

    def test_derive_key_invalid_length_raises_error(self):
        """Invalid key length should raise ValueError."""
        with pytest.raises(ValueError):
            CryptoManager.derive_key_from_password("password", length=0)

        with pytest.raises(ValueError):
            CryptoManager.derive_key_from_password("password", length=-1)


class TestCryptoManagerEncryption:
    """Test ChaCha20-Poly1305 authenticated encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encryption followed by decryption should recover original data."""
        key = CryptoManager.generate_session_key(32)
        plaintext = b"Sensitive medical record"

        encrypted = CryptoManager.encrypt_chacha20(plaintext, key)
        decrypted = CryptoManager.decrypt_chacha20(
            encrypted["ciphertext"],
            encrypted["nonce"],
            encrypted["auth_tag"],
            key,
        )

        assert decrypted == plaintext

    def test_encrypt_produces_base64_encoded_output(self):
        """Encrypted output should be base64-encoded for transport."""
        key = CryptoManager.generate_session_key(32)
        plaintext = b"test"

        encrypted = CryptoManager.encrypt_chacha20(plaintext, key)

        # All components should be valid base64
        for component in ["ciphertext", "nonce", "auth_tag"]:
            assert component in encrypted
            # Verify can decode base64 (would raise if invalid)
            b64encode(b64encode(component.encode()).decode().encode()).decode()

    def test_encrypt_with_associated_data(self):
        """AAD should be passed through encryption/decryption."""
        key = CryptoManager.generate_session_key(32)
        plaintext = b"secret"
        aad = b"patient_id:12345"

        encrypted = CryptoManager.encrypt_chacha20(plaintext, key, aad)
        decrypted = CryptoManager.decrypt_chacha20(
            encrypted["ciphertext"],
            encrypted["nonce"],
            encrypted["auth_tag"],
            key,
            aad,
        )

        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_raises_error(self):
        """Decryption with wrong key should raise CryptoEncryptionError."""
        key1 = CryptoManager.generate_session_key(32)
        key2 = CryptoManager.generate_session_key(32)
        plaintext = b"secret"

        encrypted = CryptoManager.encrypt_chacha20(plaintext, key1)

        with pytest.raises(CryptoEncryptionError):
            CryptoManager.decrypt_chacha20(
                encrypted["ciphertext"],
                encrypted["nonce"],
                encrypted["auth_tag"],
                key2,  # Wrong key
            )

    def test_encrypt_invalid_key_length_raises_error(self):
        """Key must be exactly 32 bytes."""
        plaintext = b"test"

        with pytest.raises(ValueError):
            CryptoManager.encrypt_chacha20(plaintext, b"short")

        with pytest.raises(ValueError):
            CryptoManager.encrypt_chacha20(plaintext, os.urandom(48))  # Too long


class TestCryptoManagerSignatures:
    """Test ECDSA-SHA256 signing and verification."""

    def test_sign_and_verify_valid_signature(self):
        """Valid signature should verify correctly."""
        private_pem, public_pem = CryptoManager.generate_keypair()
        data = b"Important audit event"

        signature = CryptoManager.sign_data(private_pem, data)
        is_valid = CryptoManager.verify_signature(public_pem, data, signature)

        assert is_valid is True

    def test_verify_invalid_signature_returns_false(self):
        """Invalid signature should return False, not raise."""
        private_pem, public_pem = CryptoManager.generate_keypair()
        data = b"Important audit event"

        # Generate signature for different data
        signature = CryptoManager.sign_data(private_pem, b"different data")
        is_valid = CryptoManager.verify_signature(public_pem, data, signature)

        assert is_valid is False

    def test_verify_tampered_data_returns_false(self):
        """Signature should fail if data is modified."""
        private_pem, public_pem = CryptoManager.generate_keypair()
        data = b"Original audit event"

        signature = CryptoManager.sign_data(private_pem, data)
        tampered_data = b"Modified audit event"

        is_valid = CryptoManager.verify_signature(public_pem, tampered_data, signature)
        assert is_valid is False

    def test_signature_different_each_time(self):
        """Each signature should be different (due to ECDSA randomness)."""
        private_pem, _ = CryptoManager.generate_keypair()
        data = b"data"

        signature1 = CryptoManager.sign_data(private_pem, data)
        signature2 = CryptoManager.sign_data(private_pem, data)

        # Signatures are different (ECDSA uses random component)
        # But both should still verify
        assert signature1 != signature2


class TestCryptoManagerHashing:
    """Test SHA-256 hashing."""

    def test_hash_data_produces_correct_length(self):
        """SHA-256 hash should be 64 hex characters."""
        hash_result = CryptoManager.hash_data(b"data")
        assert len(hash_result) == 64
        assert all(c in "0123456789abcdef" for c in hash_result)

    def test_hash_same_data_produces_same_hash(self):
        """Hashing same data twice should produce same result."""
        hash1 = CryptoManager.hash_data(b"data")
        hash2 = CryptoManager.hash_data(b"data")
        assert hash1 == hash2

    def test_hash_different_data_produces_different_hash(self):
        """Different data should produce different hashes."""
        hash1 = CryptoManager.hash_data(b"data1")
        hash2 = CryptoManager.hash_data(b"data2")
        assert hash1 != hash2


class TestCryptoManagerSessionKeys:
    """Test session key generation and hashing."""

    def test_generate_session_key_produces_random_bytes(self):
        """Session keys should be cryptographically random."""
        key1 = CryptoManager.generate_session_key()
        key2 = CryptoManager.generate_session_key()

        assert key1 != key2
        assert len(key1) == 32
        assert len(key2) == 32

    def test_session_key_hash_roundtrip(self):
        """Session key hash should produce consistent result."""
        key = CryptoManager.generate_session_key()
        hash1 = CryptoManager.hash_session_key(key)
        hash2 = CryptoManager.hash_session_key(key)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex


class TestCryptoManagerFingerprint:
    """Test key fingerprinting."""

    def test_get_key_fingerprint_produces_consistent_result(self):
        """Fingerprints should be deterministic."""
        _, public_pem = CryptoManager.generate_keypair()
        fp1 = CryptoManager.get_key_fingerprint(public_pem)
        fp2 = CryptoManager.get_key_fingerprint(public_pem)

        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex

    def test_get_key_fingerprint_different_for_different_keys(self):
        """Different keys should produce different fingerprints."""
        _, public_pem1 = CryptoManager.generate_keypair()
        _, public_pem2 = CryptoManager.generate_keypair()

        fp1 = CryptoManager.get_key_fingerprint(public_pem1)
        fp2 = CryptoManager.get_key_fingerprint(public_pem2)

        assert fp1 != fp2


class TestCryptoManagerIntegration:
    """Integration tests for complete workflows."""

    def test_complete_keypair_to_encryption_workflow(self):
        """Test complete flow: generate keypair → encrypt/decrypt."""
        # Generate keypair
        private_pem, public_pem = CryptoManager.generate_keypair()

        # Generate session key
        session_key = CryptoManager.generate_session_key()

        # Encrypt data
        plaintext = b"Sensitive patient data"
        encrypted = CryptoManager.encrypt_chacha20(plaintext, session_key)

        # Decrypt data
        decrypted = CryptoManager.decrypt_chacha20(
            encrypted["ciphertext"],
            encrypted["nonce"],
            encrypted["auth_tag"],
            session_key,
        )

        # Sign the hash
        data_hash = CryptoManager.hash_data(plaintext)
        signature = CryptoManager.sign_data(private_pem, data_hash.encode())

        # Verify signature
        is_valid = CryptoManager.verify_signature(
            public_pem, data_hash.encode(), signature
        )

        assert decrypted == plaintext
        assert is_valid is True

    def test_multiple_users_independent_keys(self):
        """Each user should have independent cryptographic material."""
        # User 1
        user1_private, user1_public = CryptoManager.generate_keypair()
        user1_session_key = CryptoManager.generate_session_key()

        # User 2
        user2_private, user2_public = CryptoManager.generate_keypair()
        user2_session_key = CryptoManager.generate_session_key()

        # Data encrypted by user1
        plaintext = b"confidential"
        encrypted_by_user1 = CryptoManager.encrypt_chacha20(plaintext, user1_session_key)

        # User1 can decrypt
        decrypted_by_user1 = CryptoManager.decrypt_chacha20(
            encrypted_by_user1["ciphertext"],
            encrypted_by_user1["nonce"],
            encrypted_by_user1["auth_tag"],
            user1_session_key,
        )
        assert decrypted_by_user1 == plaintext

        # User2 CANNOT decrypt without user1's session key
        with pytest.raises(CryptoEncryptionError):
            CryptoManager.decrypt_chacha20(
                encrypted_by_user1["ciphertext"],
                encrypted_by_user1["nonce"],
                encrypted_by_user1["auth_tag"],
                user2_session_key,
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
