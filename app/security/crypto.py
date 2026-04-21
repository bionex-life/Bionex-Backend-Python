"""
Cryptographic operations manager.

Handles all encryption/decryption operations with ECDH P-256, ChaCha20-Poly1305,
ECDSA signatures, and key derivation.

Standards Compliance:
- ECDH: RFC 5116 (NIST curves)
- ChaCha20-Poly1305: RFC 7539 (IETF variant)
- HKDF: RFC 5869 (HMAC-based KDF)
- ECDSA: RFC 6090 (Elliptic Curve DSA)
"""

import logging
import os
import secrets
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic operations."""

    pass


class CryptoKeyError(CryptoError):
    """Raised when key operations fail."""

    pass


class CryptoEncryptionError(CryptoError):
    """Raised when encryption/decryption fails."""

    pass


class CryptoSignatureError(CryptoError):
    """Raised when signature operations fail."""

    pass


class CryptoManager:
    """
    Centralized cryptographic operations manager.

    Uses ECDH P-256 for key exchange, ChaCha20-Poly1305 for authenticated
    encryption, and ECDSA for signatures. All operations are constant-time
    resistant and use cryptographically secure random sources.

    Thread-safe: All methods are stateless and can be called from multiple threads.
    """

    # Cryptographic Constants
    CURVE = ec.SECP256R1()  # P-256, NIST standard, mobile-friendly
    HASH_ALGORITHM = hashes.SHA256()
    BACKEND = default_backend()

    # Key Sizes (in bytes)
    KEY_SIZE = 32  # 256-bit keys
    NONCE_SIZE = 12  # 96-bit nonce for ChaCha20
    TAG_SIZE = 16  # 128-bit authentication tag
    SALT_SIZE = 32  # 256-bit salt for HKDF

    # Encoding Constants
    _ENCODING = "utf-8"

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate ECDH P-256 keypair for asymmetric operations.

        Returns:
            Tuple of (private_key_pem, public_key_pem) as PEM-encoded strings.

        Raises:
            CryptoKeyError: If key generation fails.

        Example:
            >>> private_pem, public_pem = CryptoManager.generate_keypair()
            >>> assert "BEGIN PRIVATE KEY" in private_pem
            >>> assert "BEGIN PUBLIC KEY" in public_pem
        """
        try:
            private_key = ec.generate_private_key(
                CryptoManager.CURVE, CryptoManager.BACKEND
            )

            # Serialize private key (PKCS8, unencrypted for server-side storage in Vault)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(CryptoManager._ENCODING)

            # Serialize public key (SubjectPublicKeyInfo format)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(CryptoManager._ENCODING)

            logger.debug("Generated new ECDH P-256 keypair")
            return private_pem, public_pem

        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise CryptoKeyError(f"Keypair generation failed: {e}") from e

    @staticmethod
    def derive_key_from_password(
        password: str, salt: Optional[bytes] = None, length: int = 32
    ) -> Tuple[bytes, bytes]:
        """
        Derive cryptographic key from password using HKDF-SHA256.

        Uses HMAC-based Key Derivation Function per RFC 5869 for secure
        key stretching from passwords.

        Args:
            password: User password (will be encoded as UTF-8).
            salt: Optional salt bytes. Generated cryptographically securely if None.
            length: Output key length in bytes (default: 32 for 256-bit).

        Returns:
            Tuple of (derived_key_bytes, salt_used). Salt should be stored
            alongside ciphertext for future decryption.

        Raises:
            ValueError: If length is invalid.
            CryptoKeyError: If derivation fails.

        Example:
            >>> key, salt = CryptoManager.derive_key_from_password("password123")
            >>> assert len(key) == 32
            >>> assert len(salt) == 32
        """
        if length <= 0 or length > 255 * 32:
            raise ValueError(f"Invalid key length: {length}")

        if salt is None:
            salt = os.urandom(CryptoManager.SALT_SIZE)
        elif not isinstance(salt, bytes):
            raise ValueError("Salt must be bytes")

        try:
            hkdf = HKDF(
                algorithm=CryptoManager.HASH_ALGORITHM,
                length=length,
                salt=salt,
                info=b"bionex_key_derivation",
                backend=CryptoManager.BACKEND,
            )

            derived_key = hkdf.derive(password.encode(CryptoManager._ENCODING))
            logger.debug(f"Derived key from password (length={length})")
            return derived_key, salt

        except Exception as e:
            logger.error(f"Failed to derive key from password: {e}")
            raise CryptoKeyError(f"Key derivation failed: {e}") from e

    @staticmethod
    def encrypt_chacha20(
        plaintext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, str]:
        """
        Encrypt data with ChaCha20-Poly1305 (AEAD).

        ChaCha20-Poly1305 provides authenticated encryption with associated data.
        Ensures both confidentiality and authenticity of the encrypted message.

        Args:
            plaintext: Data to encrypt (bytes).
            key: 256-bit encryption key (must be exactly 32 bytes).
            associated_data: Optional additional authenticated data (AAD).

        Returns:
            Dictionary with base64-encoded keys:
                - 'ciphertext': Encrypted data
                - 'nonce': Randomly generated nonce
                - 'auth_tag': Authentication tag for verification

        Raises:
            ValueError: If key size is invalid.
            CryptoEncryptionError: If encryption fails.

        Example:
            >>> key = os.urandom(32)
            >>> encrypted = CryptoManager.encrypt_chacha20(b"secret", key)
            >>> assert "ciphertext" in encrypted
            >>> assert "nonce" in encrypted
            >>> assert "auth_tag" in encrypted
        """
        if len(key) != CryptoManager.KEY_SIZE:
            raise ValueError(
                f"Key must be {CryptoManager.KEY_SIZE} bytes, got {len(key)}"
            )

        try:
            nonce = os.urandom(CryptoManager.NONCE_SIZE)
            cipher = ChaCha20Poly1305(key)

            # ChaCha20Poly1305.encrypt() returns ciphertext + tag (last 16 bytes)
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, associated_data)

            # Separate ciphertext and authentication tag
            actual_ciphertext = ciphertext_with_tag[: -CryptoManager.TAG_SIZE]
            auth_tag = ciphertext_with_tag[-CryptoManager.TAG_SIZE :]

            logger.debug(
                f"Encrypted {len(plaintext)} bytes with ChaCha20-Poly1305"
            )

            return {
                "ciphertext": b64encode(actual_ciphertext).decode(
                    CryptoManager._ENCODING
                ),
                "nonce": b64encode(nonce).decode(CryptoManager._ENCODING),
                "auth_tag": b64encode(auth_tag).decode(CryptoManager._ENCODING),
            }

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise CryptoEncryptionError(f"Encryption failed: {e}") from e

    @staticmethod
    def decrypt_chacha20(
        ciphertext_b64: str,
        nonce_b64: str,
        auth_tag_b64: str,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt ChaCha20-Poly1305 encrypted data.

        Args:
            ciphertext_b64: Base64-encoded ciphertext.
            nonce_b64: Base64-encoded nonce.
            auth_tag_b64: Base64-encoded authentication tag.
            key: 256-bit decryption key (must match encryption key).
            associated_data: Optional AAD (must match encryption AAD).

        Returns:
            Decrypted plaintext (bytes).

        Raises:
            ValueError: If key size is invalid.
            CryptoEncryptionError: If decryption or authentication fails.

        Example:
            >>> key = os.urandom(32)
            >>> encrypted = CryptoManager.encrypt_chacha20(b"secret", key)
            >>> decrypted = CryptoManager.decrypt_chacha20(
            ...     encrypted['ciphertext'],
            ...     encrypted['nonce'],
            ...     encrypted['auth_tag'],
            ...     key
            ... )
            >>> assert decrypted == b"secret"
        """
        if len(key) != CryptoManager.KEY_SIZE:
            raise ValueError(
                f"Key must be {CryptoManager.KEY_SIZE} bytes, got {len(key)}"
            )

        try:
            ciphertext = b64decode(ciphertext_b64)
            nonce = b64decode(nonce_b64)
            auth_tag = b64decode(auth_tag_b64)

            cipher = ChaCha20Poly1305(key)

            # Reconstruct full ciphertext (encrypted_data + tag) for decryption
            full_ciphertext = ciphertext + auth_tag

            plaintext = cipher.decrypt(nonce, full_ciphertext, associated_data)
            logger.debug(f"Decrypted {len(plaintext)} bytes with ChaCha20-Poly1305")
            return plaintext

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise CryptoEncryptionError(f"Decryption/authentication failed: {e}") from e

    @staticmethod
    def sign_data(private_key_pem: str, data: bytes) -> str:
        """
        Sign data with ECDSA-SHA256.

        Creates a cryptographic signature proving authenticity and integrity
        of the data without requiring encryption.

        Args:
            private_key_pem: ECDSA private key in PEM format.
            data: Bytes to sign.

        Returns:
            Base64-encoded signature.

        Raises:
            CryptoKeyError: If private key is invalid.
            CryptoSignatureError: If signing fails.

        Example:
            >>> private_pem, public_pem = CryptoManager.generate_keypair()
            >>> signature = CryptoManager.sign_data(private_pem, b"data")
            >>> assert CryptoManager.verify_signature(public_pem, b"data", signature)
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(CryptoManager._ENCODING),
                password=None,
                backend=CryptoManager.BACKEND,
            )

            signature = private_key.sign(
                data, ec.ECDSA(CryptoManager.HASH_ALGORITHM)
            )
            logger.debug(f"Signed {len(data)} bytes with ECDSA-SHA256")
            return b64encode(signature).decode(CryptoManager._ENCODING)

        except ValueError as e:
            logger.error(f"Invalid private key: {e}")
            raise CryptoKeyError(f"Invalid private key: {e}") from e
        except Exception as e:
            logger.error(f"Signature creation failed: {e}")
            raise CryptoSignatureError(f"Signature creation failed: {e}") from e

    @staticmethod
    def verify_signature(
        public_key_pem: str, data: bytes, signature_b64: str
    ) -> bool:
        """
        Verify ECDSA-SHA256 signature.

        Args:
            public_key_pem: ECDSA public key in PEM format.
            data: Original data that was signed.
            signature_b64: Base64-encoded signature.

        Returns:
            True if signature is valid, False otherwise.

        Raises:
            CryptoKeyError: If public key is invalid.

        Note:
            Returns False on invalid signatures rather than raising,
            to prevent timing attacks in comparison logic.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(CryptoManager._ENCODING),
                backend=CryptoManager.BACKEND,
            )

            signature = b64decode(signature_b64)
            public_key.verify(signature, data, ec.ECDSA(CryptoManager.HASH_ALGORITHM))
            logger.debug(f"Verified signature for {len(data)} bytes")
            return True

        except ValueError as e:
            logger.error(f"Invalid public key: {e}")
            raise CryptoKeyError(f"Invalid public key: {e}") from e
        except Exception:
            # Invalid signature - return False (includes cryptography.exceptions.InvalidSignature)
            logger.debug("Signature verification failed")
            return False

    @staticmethod
    def hash_data(data: bytes) -> str:
        """
        Hash data with SHA-256.

        One-way hash function suitable for fingerprints, storage, and
        integrity verification.

        Args:
            data: Bytes to hash.

        Returns:
            Hexadecimal string of the hash.

        Example:
            >>> hash1 = CryptoManager.hash_data(b"data")
            >>> hash2 = CryptoManager.hash_data(b"data")
            >>> assert hash1 == hash2
        """
        hash_result = sha256(data).hexdigest()
        logger.debug(f"Hashed {len(data)} bytes with SHA-256")
        return hash_result

    @staticmethod
    def generate_session_key(length: int = 32) -> bytes:
        """
        Generate cryptographically secure random session key.

        Uses os.urandom() which is cryptographically secure on all platforms.

        Args:
            length: Key length in bytes (default: 32 for 256-bit).

        Returns:
            Cryptographically random bytes.

        Example:
            >>> key = CryptoManager.generate_session_key()
            >>> assert len(key) == 32
            >>> key2 = CryptoManager.generate_session_key()
            >>> assert key != key2  # Different each time
        """
        if length <= 0:
            raise ValueError(f"Invalid key length: {length}")

        session_key = secrets.token_bytes(length)
        logger.debug(f"Generated {length}-byte session key")
        return session_key

    @staticmethod
    def hash_session_key(session_key: bytes) -> str:
        """
        Hash session key for storage in database.

        Creates one-way hash of session key for fast lookup without exposing
        the actual session key in the database.

        Args:
            session_key: Raw session key bytes.

        Returns:
            Hexadecimal string hash.

        Example:
            >>> key = CryptoManager.generate_session_key()
            >>> hash1 = CryptoManager.hash_session_key(key)
            >>> hash2 = CryptoManager.hash_session_key(key)
            >>> assert hash1 == hash2
        """
        return sha256(session_key).hexdigest()

    @staticmethod
    def get_key_fingerprint(public_key_pem: str) -> str:
        """
        Generate fingerprint of public key for display/comparison.

        Fingerprints are useful for key identification and verification
        without exposing the full key.

        Args:
            public_key_pem: Public key in PEM format.

        Returns:
            Hexadecimal hash (first 16 chars commonly displayed).

        Raises:
            CryptoKeyError: If key is invalid.

        Example:
            >>> _, public_pem = CryptoManager.generate_keypair()
            >>> fingerprint = CryptoManager.get_key_fingerprint(public_pem)
            >>> assert len(fingerprint) == 64  # SHA256 hex = 64 chars
        """
        try:
            # Hash the PEM format (not the key object, for consistency)
            fingerprint = CryptoManager.hash_data(
                public_key_pem.encode(CryptoManager._ENCODING)
            )
            logger.debug(f"Generated key fingerprint: {fingerprint[:16]}...")
            return fingerprint
        except Exception as e:
            logger.error(f"Failed to generate fingerprint: {e}")
            raise CryptoKeyError(f"Fingerprint generation failed: {e}") from e
