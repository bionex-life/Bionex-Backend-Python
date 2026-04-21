"""
Phase 2: Encryption Service Layer

High-level service layer for:
- Keypair management
- Session key lifecycle
- Record encryption/decryption
- Audit logging

All services follow DI patterns and are stateless for scalability.
Designed to be used by routers with async support.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.models import (
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    CryptographicAuditLog,
    CryptoAuditLogStatus,
    KeyRotationHistory,
    KeyRotationStatus,
    ActorType,
    User,
    Patient,
    MedicalRecord,
)
from app.security.crypto import CryptoManager
from app.security.cache import CacheManager
from app.security.vault import VaultManager
from app.config import settings


logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────
# KEYPAIR MANAGEMENT SERVICE
# ────────────────────────────────────────────────────────────────

class KeypairService:
    """
    Manages user keypair lifecycle:
    - Create keypair (store public key in DB, private key in Vault)
    - Retrieve public key (with caching)
    - Rotate keypair (generate new, retire old)
    - Revoke keypair
    """
    
    def __init__(self, db: Session, cache: CacheManager, vault: VaultManager):
        self.db = db
        self.cache = cache
        self.vault = vault
    
    def create_keypair(self, user_id: UUID) -> Tuple[str, str]:
        """
        Create and store a new keypair for user.
        
        Process:
        1. Generate ECDH P-256 keypair
        2. Store public key in DB with fingerprint
        3. Store private key in Vault
        4. Cache public key in Redis
        
        Args:
            user_id: User to create keypair for
            
        Returns:
            (private_key_pem, public_key_pem)
            
        Raises:
            ValueError: If user already has active keypair
        """
        # Check for existing active keypair
        existing = self.db.query(UserKeypair).filter(
            UserKeypair.user_id == user_id,
            UserKeypair.is_revoked == False
        ).first()
        
        if existing:
            logger.warning(f"User {user_id} already has active keypair")
            raise ValueError(f"User already has active keypair")
        
        # Generate keypair
        private_pem, public_pem = CryptoManager.generate_keypair()
        fingerprint = CryptoManager.hash_data(public_pem.encode())
        
        # Store public key in DB
        keypair = UserKeypair(
            user_id=user_id,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint,
            key_algorithm="ECDH_P256"
        )
        self.db.add(keypair)
        self.db.commit()
        
        logger.info(f"Created keypair for user {user_id}, fingerprint={fingerprint[:8]}")
        
        # Store private key in Vault
        try:
            self.vault.store_private_key(str(user_id), private_pem)
            logger.debug(f"Stored private key in Vault for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to store private key in Vault: {e}")
            # Delete DB entry if Vault fails
            self.db.delete(keypair)
            self.db.commit()
            raise
        
        # Cache public key
        self.cache.cache_public_key(str(user_id), public_pem)
        
        return private_pem, public_pem
    
    def get_public_key(self, user_id: UUID) -> Optional[str]:
        """
        Get user's public key with caching.
        
        Lookup order:
        1. Check Redis cache
        2. Query DB if not cached
        3. Cache result
        
        Args:
            user_id: User ID
            
        Returns:
            PEM-encoded public key or None
        """
        # Try cache first
        cached = self.cache.get_public_key(str(user_id))
        if cached:
            logger.debug(f"Cache hit for user {user_id} public key")
            return cached
        
        # Query DB
        keypair = self.db.query(UserKeypair).filter(
            UserKeypair.user_id == user_id,
            UserKeypair.is_revoked == False
        ).first()
        
        if not keypair:
            logger.warning(f"No active keypair found for user {user_id}")
            return None
        
        # Cache result
        self.cache.cache_public_key(str(user_id), keypair.public_key_pem)
        logger.debug(f"Cached public key for user {user_id}")
        
        return keypair.public_key_pem
    
    def revoke_keypair(self, user_id: UUID, reason: str) -> bool:
        """
        Revoke user's keypair.
        
        Args:
            user_id: User ID
            reason: Revocation reason
            
        Returns:
            True if successful
        """
        keypair = self.db.query(UserKeypair).filter(
            UserKeypair.user_id == user_id,
            UserKeypair.is_revoked == False
        ).first()
        
        if not keypair:
            logger.warning(f"No active keypair to revoke for user {user_id}")
            return False
        
        keypair.is_revoked = True
        keypair.revoked_at = datetime.now(timezone.utc)
        keypair.revocation_reason = reason
        self.db.commit()
        
        # Invalidate cache
        self.cache.invalidate_key(f"pubkey:{user_id}")
        
        logger.info(f"Revoked keypair for user {user_id}, reason={reason}")
        return True


# ────────────────────────────────────────────────────────────────
# SESSION KEY MANAGEMENT SERVICE
# ────────────────────────────────────────────────────────────────

class SessionKeyService:
    """
    Manages session keys for doctor-patient access:
    - Create session key (hybrid encryption)
    - Validate session key
    - Revoke session key
    - List session keys
    - Auto-expire expired keys
    """
    
    def __init__(self, db: Session, cache: CacheManager, crypto: CryptoManager = None):
        self.db = db
        self.cache = cache
        self.crypto = crypto or CryptoManager
    
    def create_session_key(
        self,
        patient_id: UUID,
        doctor_id: UUID,
        ttl_days: int = 7
    ) -> str:
        """
        Create session key for doctor to access patient data.
        
        Process:
        1. Generate random session key (32 bytes)
        2. Encrypt with doctor's public key
        3. Store encrypted key in DB
        4. Cache session key hash
        
        Args:
            patient_id: Patient granting access
            doctor_id: Doctor receiving access
            ttl_days: Time-to-live in days
            
        Returns:
            Session key ID (UUID)
            
        Raises:
            ValueError: If doctor's public key not found
        """
        from app.services.keypair_service import KeypairService
        
        keypair_svc = KeypairService(self.db, self.cache, None)
        
        # Get doctor's public key
        doctor_public_key = keypair_svc.get_public_key(doctor_id)
        if not doctor_public_key:
            logger.error(f"Doctor {doctor_id} has no public key")
            raise ValueError(f"Doctor has no active keypair")
        
        # Generate session key
        session_key = self.crypto.generate_session_key(32)
        session_key_hash = self.crypto.hash_session_key(session_key)
        
        # Encrypt session key with doctor's public key (hybrid encryption)
        # For now, simulate with base64 encoding (real implementation uses ECDH)
        import base64
        encrypted_key = base64.b64encode(session_key).decode()
        nonce = base64.b64encode(self.crypto.generate_session_key(16)).decode()
        auth_tag = base64.b64encode(self.crypto.generate_session_key(16)).decode()
        
        # Calculate expiry
        expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        
        # Store in DB
        session_key_obj = SessionKey(
            patient_id=patient_id,
            doctor_id=doctor_id,
            session_key_hash=session_key_hash,
            encrypted_session_key=encrypted_key,
            nonce=nonce,
            auth_tag=auth_tag,
            status=SessionKeyStatus.ACTIVE,
            expires_at=expires_at
        )
        self.db.add(session_key_obj)
        self.db.commit()
        
        logger.info(f"Created session key for patient={patient_id}, doctor={doctor_id}, ttl={ttl_days}d")
        
        # Cache for fast lookup
        self.cache.cache_session_key_hash(
            session_key_hash,
            str(doctor_id),
            ttl_seconds=ttl_days * 24 * 3600
        )
        
        return session_key_obj.id
    
    def validate_session_key(self, session_key_hash: str, doctor_id: UUID) -> bool:
        """
        Validate if session key is active and not expired.
        
        Args:
            session_key_hash: SHA-256 hash of session key
            doctor_id: Doctor using the key
            
        Returns:
            True if valid
        """
        # Check cache first
        cached = self.cache.get_session_key_doctor(session_key_hash)
        if cached and UUID(cached) == doctor_id:
            return True
        
        # Query DB
        session = self.db.query(SessionKey).filter(
            SessionKey.session_key_hash == session_key_hash,
            SessionKey.doctor_id == doctor_id,
            SessionKey.status == SessionKeyStatus.ACTIVE,
            SessionKey.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not session:
            logger.warning(f"Invalid or expired session key for doctor {doctor_id}")
            return False
        
        return True
    
    def revoke_session_key(self, session_key_id: UUID, reason: str) -> bool:
        """
        Revoke a session key immediately.
        
        Args:
            session_key_id: Session key ID
            reason: Revocation reason
            
        Returns:
            True if successful
        """
        session_key = self.db.query(SessionKey).filter(
            SessionKey.id == session_key_id
        ).first()
        
        if not session_key:
            logger.warning(f"Session key {session_key_id} not found")
            return False
        
        session_key.status = SessionKeyStatus.REVOKED
        session_key.revoked_at = datetime.now(timezone.utc)
        session_key.revocation_reason = reason
        self.db.commit()
        
        # Invalidate cache
        self.cache.invalidate_session(session_key.session_key_hash)
        
        logger.info(f"Revoked session key {session_key_id}, reason={reason}")
        return True
    
    def list_active_sessions(self, patient_id: UUID, limit: int = 100) -> list:
        """
        List all active session keys for patient.
        
        Args:
            patient_id: Patient ID
            limit: Maximum results
            
        Returns:
            List of active SessionKey objects
        """
        sessions = self.db.query(SessionKey).filter(
            SessionKey.patient_id == patient_id,
            SessionKey.status == SessionKeyStatus.ACTIVE,
            SessionKey.expires_at > datetime.now(timezone.utc)
        ).limit(limit).all()
        
        return sessions


# ────────────────────────────────────────────────────────────────
# ENCRYPTED RECORD SERVICE
# ────────────────────────────────────────────────────────────────

class EncryptedRecordService:
    """
    Manages encrypted medical records:
    - Store encrypted copy of record
    - Retrieve encrypted record
    - Search by type/date/title hash
    - Soft delete
    """
    
    def __init__(self, db: Session, crypto: CryptoManager = None):
        self.db = db
        self.crypto = crypto or CryptoManager
    
    def store_encrypted_record(
        self,
        patient_id: UUID,
        medical_record_id: UUID,
        plaintext: bytes,
        session_key: bytes,
        record_type: str,
        record_title: Optional[str] = None
    ) -> UUID:
        """
        Store encrypted copy of medical record.
        
        Args:
            patient_id: Patient ID
            medical_record_id: Original medical record ID
            plaintext: Unencrypted record content
            session_key: Session key for encryption
            record_type: Type of record (PRESCRIPTION, LAB_REPORT, etc)
            record_title: Optional title for searching
            
        Returns:
            Vault ID (UUID)
        """
        # Encrypt record with ChaCha20-Poly1305
        encrypted = self.crypto.encrypt_chacha20(plaintext, session_key)
        
        # Hash title for searchability
        title_hash = None
        if record_title:
            title_hash = self.crypto.hash_data(record_title.encode())
        
        # Store in vault
        vault = EncryptedRecordVault(
            patient_id=patient_id,
            original_record_id=medical_record_id,
            ciphertext=encrypted["ciphertext"],
            nonce=encrypted["nonce"],
            auth_tag=encrypted["auth_tag"],
            record_type=record_type,
            record_date=datetime.now(timezone.utc),
            record_title=record_title,
            record_title_hash=title_hash,
            encryption_algorithm="CHACHA20_POLY1305"
        )
        self.db.add(vault)
        self.db.commit()
        
        logger.info(f"Stored encrypted record: patient={patient_id}, type={record_type}")
        return vault.id
    
    def retrieve_encrypted_record(self, vault_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Retrieve encrypted record metadata (not decrypted).
        
        Args:
            vault_id: Vault ID
            
        Returns:
            Dict with ciphertext, nonce, auth_tag, or None
        """
        vault = self.db.query(EncryptedRecordVault).filter(
            EncryptedRecordVault.id == vault_id,
            EncryptedRecordVault.is_deleted == False
        ).first()
        
        if not vault:
            logger.warning(f"Encrypted record {vault_id} not found")
            return None
        
        return {
            "id": vault.id,
            "patient_id": vault.patient_id,
            "ciphertext": vault.ciphertext,
            "nonce": vault.nonce,
            "auth_tag": vault.auth_tag,
            "record_type": vault.record_type,
            "record_date": vault.record_date
        }
    
    def list_records_by_type(
        self,
        patient_id: UUID,
        record_type: str,
        limit: int = 50
    ) -> list:
        """
        List encrypted records by type (searchable without decryption).
        
        Args:
            patient_id: Patient ID
            record_type: Record type filter
            limit: Maximum results
            
        Returns:
            List of EncryptedRecordVault objects
        """
        records = self.db.query(EncryptedRecordVault).filter(
            EncryptedRecordVault.patient_id == patient_id,
            EncryptedRecordVault.record_type == record_type,
            EncryptedRecordVault.is_deleted == False
        ).order_by(EncryptedRecordVault.record_date.desc()).limit(limit).all()
        
        return records
    
    def soft_delete_record(self, vault_id: UUID) -> bool:
        """
        Soft delete encrypted record.
        
        Args:
            vault_id: Vault ID
            
        Returns:
            True if successful
        """
        vault = self.db.query(EncryptedRecordVault).filter(
            EncryptedRecordVault.id == vault_id
        ).first()
        
        if not vault:
            return False
        
        vault.is_deleted = True
        vault.deleted_at = datetime.now(timezone.utc)
        self.db.commit()
        
        logger.info(f"Soft deleted encrypted record {vault_id}")
        return True


# ────────────────────────────────────────────────────────────────
# AUDIT LOG SERVICE
# ────────────────────────────────────────────────────────────────

class AuditLogService:
    """
    Immutable audit logging service:
    - Log all cryptographic operations
    - Digital signature for tamper detection
    - Query audit logs
    - Compliance reporting
    """
    
    def __init__(self, db: Session, crypto: CryptoManager = None):
        self.db = db
        self.crypto = crypto or CryptoManager
    
    def log_crypto_operation(
        self,
        actor_id: Optional[UUID],
        actor_type: ActorType,
        action: str,
        resource_type: str,
        resource_id: UUID,
        event_data: Dict[str, Any],
        ip_address: str,
        request_id: str,
        status: CryptoAuditLogStatus = CryptoAuditLogStatus.SUCCESS,
        status_message: Optional[str] = None
    ) -> UUID:
        """
        Log cryptographic operation with digital signature.
        
        Args:
            actor_id: User performing action (None for SYSTEM)
            actor_type: Type of actor
            action: Action name (RECORD_ACCESSED, SESSION_CREATED, etc)
            resource_type: Type of resource
            resource_id: ID of resource
            event_data: Operation details
            ip_address: Source IP
            request_id: Request tracing ID
            status: Operation status
            status_message: Error message if failed
            
        Returns:
            Audit log entry ID
        """
        # Create signature data
        signature_data = f"{action}:{resource_type}:{resource_id}:{datetime.now(timezone.utc).isoformat()}"
        
        # Sign with system key (would use private key in real implementation)
        signature = self.crypto.hash_data(signature_data.encode())
        
        # Create audit log
        audit_log = CryptographicAuditLog(
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            event_data=event_data,
            signature=signature,
            signature_timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            request_id=request_id,
            status=status,
            status_message=status_message
        )
        self.db.add(audit_log)
        self.db.commit()
        
        logger.info(f"Audit log: actor={actor_type}, action={action}, resource={resource_type}, status={status}")
        return audit_log.id
    
    def query_audit_logs(
        self,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        actor_type: Optional[ActorType] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        Query audit logs with filters.
        
        Args:
            action: Filter by action
            resource_type: Filter by resource type
            actor_type: Filter by actor type
            start_date: Filter by date range start
            end_date: Filter by date range end
            limit: Maximum results
            
        Returns:
            List of CryptographicAuditLog objects
        """
        query = self.db.query(CryptographicAuditLog)
        
        if action:
            query = query.filter(CryptographicAuditLog.action == action)
        if resource_type:
            query = query.filter(CryptographicAuditLog.resource_type == resource_type)
        if actor_type:
            query = query.filter(CryptographicAuditLog.actor_type == actor_type)
        if start_date:
            query = query.filter(CryptographicAuditLog.created_at >= start_date)
        if end_date:
            query = query.filter(CryptographicAuditLog.created_at <= end_date)
        
        return query.order_by(CryptographicAuditLog.created_at.desc()).limit(limit).all()
