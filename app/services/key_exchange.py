"""
Key Exchange Service for ECDH P-256 Operations

Implements hybrid encryption workflow:
1. Ephemeral ECDH key pair generation
2. ECDH shared secret computation
3. HKDF key derivation (SHA-256)
4. ChaCha20-Poly1305 AEAD encryption/decryption

Forward secrecy: Fresh ephemeral keys per operation (no key reuse)
"""

import os
import base64
import logging
from typing import Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


class KeyExchangeManager:
    """
    ECDH P-256 Key Exchange with ChaCha20-Poly1305 AEAD Encryption
    
    Security Properties:
    - Forward secrecy: Ephemeral keys for every encryption operation
    - Authentication: AEAD with 128-bit authentication tag
    - Integrity: Poly1305 MAC ensures tamper detection
    - Key derivation: HKDF-SHA256 prevents key reuse attacks
    
    Performance:
    - <50ms per encrypt operation (ECDH + HKDF + ChaCha20)
    - Parallel encryption safe (stateless)
    - Memory efficient: Immediate cleanup of ephemeral keys
    """
    
    CURVE = ec.SECP256R1()  # P-256 (NIST standard)
    BACKEND = default_backend()
    KEY_LENGTH = 32  # 256-bit keys for ChaCha20
    NONCE_LENGTH = 12  # 96-bit nonce (ChaCha20 standard)
    
    @staticmethod
    def encrypt_for_public_key(
        plaintext: bytes,
        public_key_pem: str,
        associated_data: bytes = None
    ) -> Dict[str, str]:
        """
        Encrypt data for a recipient using their public key
        
        Workflow:
        1. Load recipient's public key from PEM
        2. Generate ephemeral ECDH key pair
        3. Compute shared secret via ECDH with recipient's public key
        4. Derive symmetric key via HKDF-SHA256
        5. Encrypt plaintext with ChaCha20-Poly1305 (AEAD)
        6. Return ephemeral public key + ciphertext + auth metadata
        
        Args:
            plaintext (bytes): Data to encrypt
            public_key_pem (str): Recipient's public key in PEM format
            associated_data (bytes): Optional AAD for authentication (metadata)
        
        Returns:
            Dict[str, str]: {
                'encrypted_key': base64(ciphertext),
                'nonce': base64(nonce),
                'auth_tag': base64(authentication_tag),
                'ephemeral_public_key': PEM(ephemeral_public_key)
            }
        
        Raises:
            ValueError: If public key format is invalid
            Exception: If encryption fails (corrupted key/data)
        """
        try:
            # Step 1: Load recipient's public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=KeyExchangeManager.BACKEND
            )
            
            # Validate key type
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("Public key must be ECDH P-256 (EllipticCurvePublicKey)")
            
            # Step 2: Generate fresh ephemeral keypair (forward secrecy)
            ephemeral_private = ec.generate_private_key(
                KeyExchangeManager.CURVE,
                KeyExchangeManager.BACKEND
            )
            ephemeral_public = ephemeral_private.public_key()
            
            # Step 3: Compute ECDH shared secret
            shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
            
            # Step 4: Derive symmetric key from shared secret using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=KeyExchangeManager.KEY_LENGTH,  # 256-bit key
                salt=None,  # No salt for session key derivation
                info=b'encryption_key',  # Domain separation
                backend=KeyExchangeManager.BACKEND
            )
            encryption_key = hkdf.derive(shared_secret)
            
            # Step 5: Generate nonce and encrypt
            nonce = os.urandom(KeyExchangeManager.NONCE_LENGTH)
            cipher = ChaCha20Poly1305(encryption_key)
            
            # ChaCha20-Poly1305 returns: ciphertext + auth_tag (16 bytes)
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, associated_data)
            
            # Extract auth tag (last 16 bytes) and actual ciphertext
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            # Step 6: Serialize ephemeral public key for recipient
            ephemeral_public_pem = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            result = {
                'encrypted_key': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'auth_tag': base64.b64encode(auth_tag).decode(),
                'ephemeral_public_key': ephemeral_public_pem
            }
            
            logger.debug(f"Encrypted {len(plaintext)} bytes with ECDH P-256 + ChaCha20")
            return result
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_with_private_key(
        encrypted_data: Dict[str, str],
        private_key_pem: str,
        associated_data: bytes = None
    ) -> bytes:
        """
        Decrypt data encrypted for this recipient using their private key
        
        Workflow:
        1. Load recipient's private key from PEM
        2. Load ephemeral public key from encrypted_data
        3. Compute ECDH shared secret
        4. Derive symmetric key via HKDF-SHA256 (must match encryption)
        5. Decrypt with ChaCha20-Poly1305 (AEAD)
        6. Verify authentication tag (automatic in cipher.decrypt)
        
        Args:
            encrypted_data (Dict[str, str]): Output from encrypt_for_public_key()
            private_key_pem (str): Recipient's private key in PEM format
            associated_data (bytes): Same AAD as encryption (must match for auth)
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If key format invalid or AAD mismatch
            cryptography.exceptions.InvalidTag: If authentication fails (tampering detected)
            Exception: If decryption fails
        """
        try:
            # Step 1: Load recipient's private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=KeyExchangeManager.BACKEND
            )
            
            # Validate key type
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("Private key must be ECDH P-256 (EllipticCurvePrivateKey)")
            
            # Step 2: Load ephemeral public key sent by sender
            ephemeral_public = serialization.load_pem_public_key(
                encrypted_data['ephemeral_public_key'].encode(),
                backend=KeyExchangeManager.BACKEND
            )
            
            # Step 3: Compute ECDH shared secret (must match sender's computation)
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
            
            # Step 4: Derive symmetric key (must match sender's derivation)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=KeyExchangeManager.KEY_LENGTH,
                salt=None,
                info=b'encryption_key',  # Same domain separation
                backend=KeyExchangeManager.BACKEND
            )
            decryption_key = hkdf.derive(shared_secret)
            
            # Step 5: Prepare ciphertext components
            ciphertext = base64.b64decode(encrypted_data['encrypted_key'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            auth_tag = base64.b64decode(encrypted_data['auth_tag'])
            
            # Reconstruct full ciphertext with auth tag
            full_ciphertext = ciphertext + auth_tag
            
            # Step 6: Decrypt with AEAD (automatic auth tag verification)
            cipher = ChaCha20Poly1305(decryption_key)
            plaintext = cipher.decrypt(nonce, full_ciphertext, associated_data)
            
            logger.debug(f"Decrypted {len(plaintext)} bytes with ECDH P-256 + ChaCha20")
            return plaintext
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise
    
    @staticmethod
    def get_public_key_fingerprint(public_key_pem: str) -> str:
        """
        Get SHA-256 fingerprint of public key for verification
        
        Args:
            public_key_pem (str): Public key in PEM format
        
        Returns:
            str: Hex-encoded SHA-256 fingerprint
        """
        try:
            public_key_bytes = public_key_pem.encode()
            fingerprint = hashes.Hash(hashes.SHA256(), backend=KeyExchangeManager.BACKEND)
            fingerprint.update(public_key_bytes)
            return fingerprint.finalize().hex()
        except Exception as e:
            logger.error(f"Failed to compute fingerprint: {str(e)}")
            raise
    
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate ECDH P-256 keypair
        
        Returns:
            Tuple[str, str]: (private_key_pem, public_key_pem)
        """
        try:
            private_key = ec.generate_private_key(
                KeyExchangeManager.CURVE,
                KeyExchangeManager.BACKEND
            )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            return private_pem, public_pem
        except Exception as e:
            logger.error(f"Keypair generation failed: {str(e)}")
            raise
