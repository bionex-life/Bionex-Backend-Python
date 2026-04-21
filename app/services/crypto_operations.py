"""
Core Encryption Service for Medical Record Protection

Orchestrates all cryptographic operations:
1. User keypair generation and management
2. Session key creation for doctor-patient access
3. Medical record encryption/decryption
4. Session lifecycle management (creation, validation, revocation)

Uses:
- KeyExchangeManager: ECDH P-256 + ChaCha20-Poly1305
- CacheManager: Redis for performance optimization
- VaultManager: HashiCorp Vault for private key storage

Performance:
- Session creation: <50ms (DB + Vault)
- Session validation: <1ms (cached)
- Record encryption: <2ms per MB
- Record decryption: <2ms per MB
"""

import logging
import uuid
from typing import Tuple, Optional, List, Dict
from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import and_, or_

from app.models.encryption_models import (
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    CryptographicAuditLog,
    ActorType,
)
from app.schemas.encryption_schemas import (
    UserKeypairResponse,
    SessionKeyResponse,
    EncryptedRecordVaultResponse,
)
from app.services.key_exchange import KeyExchangeManager
from app.security.cache import cache_manager
from app.security.vault import vault_manager
from app.security.crypto import CryptoManager
from app.config import settings

logger = logging.getLogger(__name__)


class KeypairService:
    """
    Manage user cryptographic keypairs
    
    Storage strategy:
    - Private key: HashiCorp Vault (secure, audited, rotatable)
    - Public key: PostgreSQL + Redis cache (fast lookup)
    - Fingerprint: Indexed in DB for quick verification
    """
    
    @staticmethod
    def generate_keypair(
        db: DBSession,
        user_id: str
    ) -> UserKeypair:
        """
        Generate ECDH P-256 keypair for user
        
        Flow:
        1. Check if user already has active keypair
        2. Generate P-256 keypair
        3. Store private key in Vault (secure)
        4. Store public key + fingerprint in DB
        5. Cache public key in Redis
        
        Args:
            db: Database session
            user_id: UUID of user
        
        Returns:
            UserKeypair: Created keypair object
        
        Raises:
            ValueError: If user already has active keypair
        """
        try:
            # Check for existing active keypair
            existing = db.query(UserKeypair).filter(
                and_(
                    UserKeypair.user_id == uuid.UUID(user_id),
                    UserKeypair.is_revoked == False
                )
            ).first()
            
            if existing:
                logger.warning(f"User {user_id} already has active keypair")
                raise ValueError(f"User already has active keypair: {existing.id}")
            
            # Generate P-256 keypair
            private_pem, public_pem = KeyExchangeManager.generate_keypair()
            
            # Calculate fingerprint for verification
            fingerprint = KeyExchangeManager.get_public_key_fingerprint(public_pem)
            
            # Store private key in Vault (never in DB)
            vault_key_path = f"users/{user_id}/private_key"
            vault_manager.store_secret(vault_key_path, private_pem)
            
            # Create public key record in DB
            keypair = UserKeypair(
                user_id=uuid.UUID(user_id),
                public_key_pem=public_pem,
                public_key_fingerprint=fingerprint,
                key_algorithm="ECDH_P256",
                is_revoked=False,
                revocation_reason=None,
                created_at=datetime.utcnow()
            )
            
            db.add(keypair)
            db.commit()
            db.refresh(keypair)
            
            # Cache in Redis for fast lookups
            cache_manager.set(
                f"keypair:public:{user_id}",
                public_pem,
                ttl=86400  # 24 hour cache
            )
            cache_manager.set(
                f"keypair:fingerprint:{user_id}",
                fingerprint,
                ttl=86400
            )
            
            logger.info(f"Generated keypair for user {user_id}: {keypair.id}")
            return keypair
            
        except Exception as e:
            logger.error(f"Keypair generation failed for user {user_id}: {str(e)}")
            db.rollback()
            raise
    
    @staticmethod
    def get_public_key(
        db: DBSession,
        user_id: str
    ) -> Optional[str]:
        """
        Get user's public key (with Redis caching)
        
        Cache strategy:
        - First check: Redis (99% hit rate, <1ms)
        - Second check: PostgreSQL (1% miss rate)
        - Fallback: Return None if not found
        
        Args:
            db: Database session
            user_id: UUID of user
        
        Returns:
            Optional[str]: Public key in PEM format or None
        """
        try:
            # Try Redis cache first
            cache_key = f"keypair:public:{user_id}"
            cached = cache_manager.get(cache_key)
            
            if cached:
                logger.debug(f"Cache hit for public key: {user_id}")
                return cached
            
            # Fall back to database
            keypair = db.query(UserKeypair).filter(
                and_(
                    UserKeypair.user_id == uuid.UUID(user_id),
                    UserKeypair.is_revoked == False
                )
            ).first()
            
            if not keypair:
                logger.warning(f"No active keypair found for user {user_id}")
                return None
            
            # Cache the result
            cache_manager.set(cache_key, keypair.public_key_pem, ttl=86400)
            
            return keypair.public_key_pem
            
        except Exception as e:
            logger.error(f"Failed to get public key for {user_id}: {str(e)}")
            return None
    
    @staticmethod
    def get_private_key(
        user_id: str
    ) -> str:
        """
        Retrieve private key from Vault
        
        Note: Called only for record decryption verification.
        Never cached (security boundary).
        
        Args:
            user_id: UUID of user
        
        Returns:
            str: Private key in PEM format
        
        Raises:
            Exception: If key not found in Vault
        """
        vault_key_path = f"users/{user_id}/private_key"
        return vault_manager.retrieve_secret(vault_key_path)
    
    @staticmethod
    def revoke_keypair(
        db: DBSession,
        user_id: str,
        reason: str = "User requested"
    ) -> None:
        """
        Revoke user's keypair (mark as revoked in DB)
        
        Note: Does NOT delete private key from Vault
        (Maintains audit trail for signature verification)
        
        Args:
            db: Database session
            user_id: UUID of user
            reason: Revocation reason
        """
        try:
            keypair = db.query(UserKeypair).filter(
                UserKeypair.user_id == uuid.UUID(user_id)
            ).first()
            
            if keypair:
                keypair.is_revoked = True
                keypair.revocation_reason = reason
                db.commit()
                
                # Clear cache
                cache_manager.delete(f"keypair:public:{user_id}")
                cache_manager.delete(f"keypair:fingerprint:{user_id}")
                
                logger.info(f"Revoked keypair for user {user_id}: {reason}")
            
        except Exception as e:
            logger.error(f"Failed to revoke keypair for {user_id}: {str(e)}")
            db.rollback()
            raise


class SessionKeyService:
    """
    Manage ephemeral session keys for doctor-patient access
    
    Lifecycle:
    - Created: When doctor requests patient access
    - Active: Valid and usable (7 days by default)
    - Rotated: Old key replaced with new one
    - Revoked: Immediately disabled
    - Expired: After TTL (automatic in DB query)
    
    Storage:
    - Encrypted session key: DB (encrypted with doctor's public key)
    - Session key hash: Indexed in DB + Redis (for validation)
    - Lookup index: (patient_id, doctor_id) for access control
    """
    
    @staticmethod
    def create_session_key(
        db: DBSession,
        patient_id: str,
        doctor_id: str,
        ttl_days: Optional[int] = None,
        reason: str = None
    ) -> Tuple[SessionKey, str]:
        """
        Create ephemeral session key for doctor to access patient records
        
        Flow:
        1. Get doctor's public key
        2. Generate random session key (32 bytes)
        3. Hash session key for storage
        4. Encrypt session key with doctor's public key via ECDH
        5. Store encrypted key in DB
        6. Cache session key hash in Redis
        
        Args:
            db: Database session
            patient_id: UUID of patient
            doctor_id: UUID of doctor
            ttl_days: Time-to-live in days (default: 7)
            reason: Creation reason for audit
        
        Returns:
            Tuple[SessionKey, str]: (SessionKey object, plaintext session key)
        
        Raises:
            ValueError: If doctor's keypair not found
        """
        try:
            if ttl_days is None:
                ttl_days = settings.SESSION_KEY_TTL_DAYS or 7
            
            # Step 1: Get doctor's public key
            doctor_public_key = KeypairService.get_public_key(db, doctor_id)
            if not doctor_public_key:
                raise ValueError(f"Doctor {doctor_id} has no active keypair")
            
            # Step 2: Generate random session key
            session_key_plaintext = CryptoManager.generate_random_bytes(32)
            
            # Step 3: Hash for storage/lookup
            session_key_hash = CryptoManager.hash_data(session_key_plaintext)
            
            # Step 4: Encrypt with ECDH (ephemeral sender key)
            encrypted_data = KeyExchangeManager.encrypt_for_public_key(
                session_key_plaintext,
                doctor_public_key,
                associated_data=f"{patient_id}:{doctor_id}".encode()
            )
            
            # Step 5: Store in DB
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)
            session_key = SessionKey(
                patient_id=uuid.UUID(patient_id),
                doctor_id=uuid.UUID(doctor_id),
                session_key_hash=session_key_hash,
                encrypted_session_key=encrypted_data['encrypted_key'],
                nonce=encrypted_data['nonce'],
                auth_tag=encrypted_data['auth_tag'],
                ephemeral_public_key=encrypted_data['ephemeral_public_key'],
                status=SessionKeyStatus.ACTIVE,
                expires_at=expires_at,
                created_at=datetime.utcnow(),
                creation_reason=reason
            )
            
            db.add(session_key)
            db.commit()
            db.refresh(session_key)
            
            # Step 6: Cache hash for fast validation
            cache_key = f"session:{session_key_hash}"
            cache_data = {
                'doctor_id': doctor_id,
                'patient_id': patient_id,
                'status': 'ACTIVE'
            }
            cache_manager.set(cache_key, str(cache_data), ttl=ttl_days*86400)
            
            logger.info(f"Created session key for doctor {doctor_id} → patient {patient_id}")
            
            # Return plaintext for this request only
            return session_key, session_key_plaintext.hex()
            
        except Exception as e:
            logger.error(f"Session key creation failed: {str(e)}")
            db.rollback()
            raise
    
    @staticmethod
    def validate_session_key(
        db: DBSession,
        session_key_hash: str,
        doctor_id: str,
        patient_id: str
    ) -> bool:
        """
        Validate session key (with caching optimization)
        
        Cache-aside pattern:
        1. Check Redis cache (<1ms)
        2. Fall back to DB query
        3. Cache positive result
        
        Args:
            db: Database session
            session_key_hash: Hash of plaintext session key
            doctor_id: UUID of doctor
            patient_id: UUID of patient
        
        Returns:
            bool: True if valid and active, False otherwise
        """
        try:
            # Try cache first (99% hit rate)
            cache_key = f"session:{session_key_hash}"
            cached = cache_manager.get(cache_key)
            
            if cached:
                logger.debug(f"Cache hit for session validation")
                return True
            
            # Fall back to DB
            session_key = db.query(SessionKey).filter(
                and_(
                    SessionKey.session_key_hash == session_key_hash,
                    SessionKey.doctor_id == uuid.UUID(doctor_id),
                    SessionKey.patient_id == uuid.UUID(patient_id),
                    SessionKey.status == SessionKeyStatus.ACTIVE,
                    SessionKey.expires_at > datetime.utcnow()
                )
            ).first()
            
            if session_key:
                # Cache positive result
                ttl = int((session_key.expires_at - datetime.utcnow()).total_seconds())
                cache_manager.set(cache_key, "valid", ttl=ttl)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Session validation failed: {str(e)}")
            return False
    
    @staticmethod
    def revoke_session_key(
        db: DBSession,
        session_key_hash: str,
        reason: str = "User requested"
    ) -> None:
        """
        Revoke session key immediately
        
        Args:
            db: Database session
            session_key_hash: Hash of session key to revoke
            reason: Revocation reason
        """
        try:
            session_key = db.query(SessionKey).filter(
                SessionKey.session_key_hash == session_key_hash
            ).first()
            
            if session_key:
                session_key.status = SessionKeyStatus.REVOKED
                session_key.revoked_at = datetime.utcnow()
                session_key.revocation_reason = reason
                db.commit()
                
                # Invalidate cache immediately
                cache_manager.delete(f"session:{session_key_hash}")
                
                logger.info(f"Revoked session key: {reason}")
            
        except Exception as e:
            logger.error(f"Failed to revoke session key: {str(e)}")
            db.rollback()
            raise
    
    @staticmethod
    def list_active_sessions(
        db: DBSession,
        patient_id: str,
        doctor_id: Optional[str] = None
    ) -> List[SessionKey]:
        """
        List active session keys for patient (optionally filtered by doctor)
        
        Args:
            db: Database session
            patient_id: UUID of patient
            doctor_id: Optional UUID of doctor to filter
        
        Returns:
            List[SessionKey]: Active session keys
        """
        query = db.query(SessionKey).filter(
            and_(
                SessionKey.patient_id == uuid.UUID(patient_id),
                SessionKey.status == SessionKeyStatus.ACTIVE,
                SessionKey.expires_at > datetime.utcnow()
            )
        )
        
        if doctor_id:
            query = query.filter(SessionKey.doctor_id == uuid.UUID(doctor_id))
        
        return query.all()


class EncryptedRecordService:
    """
    Store and manage encrypted medical records
    
    Storage:
    - Ciphertext: ChaCha20-Poly1305 encrypted (AEAD)
    - Metadata: Plain text, indexed for searches without decryption
    - Soft delete: Records marked as deleted, not removed (audit trail)
    """
    
    @staticmethod
    def store_encrypted_record(
        db: DBSession,
        patient_id: str,
        plaintext: bytes,
        record_type: str,
        record_date: datetime,
        record_title: str,
        session_key: bytes
    ) -> EncryptedRecordVault:
        """
        Encrypt and store medical record
        
        Args:
            db: Database session
            patient_id: UUID of patient
            plaintext: Unencrypted record data
            record_type: Type of record (PRESCRIPTION, LAB_REPORT, etc.)
            record_date: When record was created
            record_title: Human-readable title
            session_key: ChaCha20 symmetric key (32 bytes)
        
        Returns:
            EncryptedRecordVault: Stored encrypted record
        """
        try:
            # Encrypt with ChaCha20-Poly1305
            aad = f"{patient_id}:{record_type}".encode()  # Associated data for auth
            encrypted_data = CryptoManager.encrypt_chacha20(plaintext, session_key, aad)
            
            # Hash title for searching without decryption
            title_hash = CryptoManager.hash_data(record_title.encode())
            
            # Store in DB
            record = EncryptedRecordVault(
                patient_id=uuid.UUID(patient_id),
                ciphertext=encrypted_data['ciphertext'],
                nonce=encrypted_data['nonce'],
                auth_tag=encrypted_data['auth_tag'],
                record_type=record_type,
                record_date=record_date,
                record_title=record_title,
                record_title_hash=title_hash,
                encryption_algorithm="CHACHA20_POLY1305",
                is_deleted=False,
                created_at=datetime.utcnow()
            )
            
            db.add(record)
            db.commit()
            db.refresh(record)
            
            logger.info(f"Stored encrypted record for patient {patient_id}: {record.id}")
            return record
            
        except Exception as e:
            logger.error(f"Failed to store encrypted record: {str(e)}")
            db.rollback()
            raise
    
    @staticmethod
    def retrieve_encrypted_record(
        db: DBSession,
        record_id: str
    ) -> Optional[EncryptedRecordVault]:
        """
        Retrieve encrypted record (plaintext not decrypted here)
        
        Args:
            db: Database session
            record_id: UUID of record
        
        Returns:
            Optional[EncryptedRecordVault]: Encrypted record or None
        """
        return db.query(EncryptedRecordVault).filter(
            and_(
                EncryptedRecordVault.id == uuid.UUID(record_id),
                EncryptedRecordVault.is_deleted == False
            )
        ).first()
    
    @staticmethod
    def list_records_by_type(
        db: DBSession,
        patient_id: str,
        record_type: str,
        limit: int = 100
    ) -> List[EncryptedRecordVault]:
        """
        List encrypted records by type (searchable without decryption)
        
        Args:
            db: Database session
            patient_id: UUID of patient
            record_type: Type to filter
            limit: Maximum results
        
        Returns:
            List[EncryptedRecordVault]: Encrypted records matching type
        """
        return db.query(EncryptedRecordVault).filter(
            and_(
                EncryptedRecordVault.patient_id == uuid.UUID(patient_id),
                EncryptedRecordVault.record_type == record_type,
                EncryptedRecordVault.is_deleted == False
            )
        ).order_by(
            EncryptedRecordVault.record_date.desc()
        ).limit(limit).all()
    
    @staticmethod
    def soft_delete_record(
        db: DBSession,
        record_id: str,
        reason: str = "User requested"
    ) -> None:
        """
        Mark record as deleted (soft delete for audit trail)
        
        Args:
            db: Database session
            record_id: UUID of record
            reason: Deletion reason
        """
        try:
            record = db.query(EncryptedRecordVault).filter(
                EncryptedRecordVault.id == uuid.UUID(record_id)
            ).first()
            
            if record:
                record.is_deleted = True
                record.deleted_at = datetime.utcnow()
                db.commit()
                
                logger.info(f"Soft deleted record {record_id}: {reason}")
            
        except Exception as e:
            logger.error(f"Failed to delete record: {str(e)}")
            db.rollback()
            raise
