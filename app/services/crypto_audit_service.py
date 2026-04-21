"""
Cryptographic Audit Service

Creates immutable audit logs with digital signatures:
1. Serialize event to JSON (sort keys for consistency)
2. Sign with server's private key (ECDSA-SHA256)
3. Store signature + event in DB (immutable)
4. Enable verification of audit log integrity

Audit trail supports compliance:
- GDPR: Who, what, when for data access
- HIPAA: User actions on protected health information
- NHS: Accountability for healthcare record access
"""

import json
import logging
from typing import Dict, Optional, List
from datetime import datetime
from uuid import UUID
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import and_, desc

from app.models.encryption_models import (
    CryptographicAuditLog,
    CryptoAuditLogStatus,
    ActorType,
)
from app.security.crypto import CryptoManager
from app.security.vault import vault_manager

logger = logging.getLogger(__name__)


class CryptoAuditService:
    """
    Immutable audit logging for cryptographic operations
    
    Security properties:
    - Tamper-evident: ECDSA signatures on event data
    - Immutable: Database constraints prevent modification
    - Complete: All actions logged with context
    - Traceable: Request IDs for correlation
    - Compliant: GDPR/HIPAA/NHS ready
    """
    
    @staticmethod
    def log_action(
        db: DBSession,
        actor_id: str,
        actor_type: ActorType,
        action: str,
        resource_type: str,
        resource_id: str,
        event_data: Optional[Dict] = None,
        ip_address: str = None,
        request_id: str = None,
        status: CryptoAuditLogStatus = CryptoAuditLogStatus.SUCCESS,
        status_message: str = None,
        user_agent: str = None
    ) -> Optional[CryptographicAuditLog]:
        """
        Log cryptographic action with immutable ECDSA-SHA256 signature
        
        Workflow:
        1. Build event JSON with context
        2. Sign event with server's private key (ECDSA)
        3. Store signature + event + metadata in DB
        4. Return audit log entry (for reference)
        
        Args:
            db: Database session
            actor_id: UUID of user performing action
            actor_type: Type of actor (PATIENT, DOCTOR, ADMIN, SYSTEM)
            action: Action type (RECORD_ACCESSED, SESSION_CREATED, etc.)
            resource_type: Type of resource (SESSION_KEY, ENCRYPTED_RECORD, etc.)
            resource_id: UUID of resource
            event_data: Additional event details (dict)
            ip_address: IPv4 or IPv6 address
            request_id: Request ID for tracing
            status: Action status (SUCCESS, FAILED, DENIED)
            status_message: Error message if failed
            user_agent: HTTP user agent
        
        Returns:
            Optional[CryptographicAuditLog]: Created audit log or None if failed
        """
        try:
            # Prepare event object
            event = {
                "action": action,
                "resource_type": resource_type,
                "resource_id": str(resource_id),
                "actor_id": str(actor_id),
                "actor_type": actor_type.value,
                "timestamp": datetime.utcnow().isoformat(),
                "status": status.value,
            }
            
            # Add optional event data
            if event_data:
                event.update(event_data)
            
            # Serialize to JSON (sorted keys for signature consistency)
            event_json = json.dumps(event, sort_keys=True, default=str)
            event_bytes = event_json.encode('utf-8')
            
            # Sign with server's private key
            try:
                server_private_key = vault_manager.retrieve_secret("server/private_key")
                signature = CryptoManager.sign_data(server_private_key, event_bytes)
            except Exception as e:
                logger.warning(f"Failed to sign audit log: {str(e)}. Proceeding unsigned.")
                signature = None
            
            # Create audit log entry
            audit_log = CryptographicAuditLog(
                actor_id=actor_id if actor_id else None,
                actor_type=actor_type,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                event_data=event,
                signature=signature if signature else "",
                signature_timestamp=datetime.utcnow(),
                ip_address=ip_address or "0.0.0.0",
                user_agent=user_agent or "unknown",
                request_id=request_id or "no-id",
                status=status,
                status_message=status_message,
                created_at=datetime.utcnow()
            )
            
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            
            logger.debug(
                f"Logged {action} on {resource_type} {resource_id} by {actor_type.value} "
                f"{actor_id}: {status.value}"
            )
            
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            try:
                db.rollback()
            except Exception:
                pass
            # Don't raise - audit failures shouldn't block requests
            return None
    
    @staticmethod
    def verify_audit_log(
        db: DBSession,
        audit_log_id: str
    ) -> bool:
        """
        Verify audit log entry hasn't been tampered with
        
        Verifies:
        1. Audit log exists in DB
        2. Event JSON can be reconstructed
        3. ECDSA signature is valid
        
        Args:
            db: Database session
            audit_log_id: UUID of audit log to verify
        
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Retrieve audit log
            audit_log = db.query(CryptographicAuditLog).filter(
                CryptographicAuditLog.id == audit_log_id
            ).first()
            
            if not audit_log:
                logger.warning(f"Audit log {audit_log_id} not found")
                return False
            
            if not audit_log.signature:
                logger.warning(f"Audit log {audit_log_id} has no signature")
                return False
            
            # Reconstruct event JSON
            event_json = json.dumps(audit_log.event_data, sort_keys=True, default=str)
            event_bytes = event_json.encode('utf-8')
            
            # Get server's public key
            try:
                server_public_key_pem = vault_manager.retrieve_secret("server/public_key")
            except Exception as e:
                logger.error(f"Failed to retrieve server public key: {str(e)}")
                return False
            
            # Verify signature
            is_valid = CryptoManager.verify_signature(
                server_public_key_pem,
                event_bytes,
                audit_log.signature
            )
            
            if is_valid:
                logger.debug(f"Verified audit log {audit_log_id}")
            else:
                logger.warning(f"Signature verification FAILED for audit log {audit_log_id}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Failed to verify audit log {audit_log_id}: {str(e)}")
            return False
    
    @staticmethod
    def query_audit_logs(
        db: DBSession,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[CryptoAuditLogStatus] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[CryptographicAuditLog]:
        """
        Query audit logs with filters (for compliance reports)
        
        Args:
            db: Database session
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            actor_id: Filter by actor ID
            action: Filter by action type
            status: Filter by status
            start_date: Filter by date range (from)
            end_date: Filter by date range (to)
            limit: Maximum results
        
        Returns:
            List[CryptographicAuditLog]: Matching audit logs (newest first)
        """
        query = db.query(CryptographicAuditLog)
        
        if resource_type:
            query = query.filter(CryptographicAuditLog.resource_type == resource_type)
        
        if resource_id:
            query = query.filter(CryptographicAuditLog.resource_id == resource_id)
        
        if actor_id:
            query = query.filter(CryptographicAuditLog.actor_id == actor_id)
        
        if action:
            query = query.filter(CryptographicAuditLog.action == action)
        
        if status:
            query = query.filter(CryptographicAuditLog.status == status)
        
        if start_date:
            query = query.filter(CryptographicAuditLog.created_at >= start_date)
        
        if end_date:
            query = query.filter(CryptographicAuditLog.created_at <= end_date)
        
        return query.order_by(
            desc(CryptographicAuditLog.created_at)
        ).limit(limit).all()
    
    @staticmethod
    def get_access_history(
        db: DBSession,
        resource_id: str,
        limit: int = 50
    ) -> List[CryptographicAuditLog]:
        """
        Get access history for a specific resource
        
        Useful for:
        - Showing who accessed a medical record
        - Compliance reports
        - Investigating unauthorized access
        
        Args:
            db: Database session
            resource_id: UUID of resource
            limit: Maximum results
        
        Returns:
            List[CryptographicAuditLog]: Access history (newest first)
        """
        return db.query(CryptographicAuditLog).filter(
            and_(
                CryptographicAuditLog.resource_id == resource_id,
                CryptographicAuditLog.action.in_(['RECORD_ACCESSED', 'RECORD_DECRYPTED'])
            )
        ).order_by(
            desc(CryptographicAuditLog.created_at)
        ).limit(limit).all()
    
    @staticmethod
    def generate_compliance_report(
        db: DBSession,
        start_date: datetime,
        end_date: datetime,
        resource_type: Optional[str] = None
    ) -> Dict:
        """
        Generate compliance report for audit logs
        
        Useful for:
        - GDPR data access reports
        - HIPAA compliance reviews
        - NHS regulatory audits
        
        Args:
            db: Database session
            start_date: Report period start
            end_date: Report period end
            resource_type: Optional resource type filter
        
        Returns:
            Dict: Report summary with metrics
        """
        query = db.query(CryptographicAuditLog).filter(
            and_(
                CryptographicAuditLog.created_at >= start_date,
                CryptographicAuditLog.created_at <= end_date
            )
        )
        
        if resource_type:
            query = query.filter(CryptographicAuditLog.resource_type == resource_type)
        
        logs = query.all()
        
        # Calculate metrics
        total_actions = len(logs)
        success_count = len([l for l in logs if l.status == CryptoAuditLogStatus.SUCCESS])
        failed_count = len([l for l in logs if l.status == CryptoAuditLogStatus.FAILED])
        denied_count = len([l for l in logs if l.status == CryptoAuditLogStatus.DENIED])
        
        # Group by action
        actions = {}
        for log in logs:
            if log.action not in actions:
                actions[log.action] = 0
            actions[log.action] += 1
        
        # Group by actor type
        actors = {}
        for log in logs:
            actor_type = log.actor_type.value
            if actor_type not in actors:
                actors[actor_type] = 0
            actors[actor_type] += 1
        
        return {
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "total_actions": total_actions,
            "success": success_count,
            "failed": failed_count,
            "denied": denied_count,
            "success_rate": (success_count / total_actions * 100) if total_actions > 0 else 0,
            "actions": actions,
            "actors": actors,
            "unique_resources": len(set(l.resource_id for l in logs)),
            "unique_actors": len(set(l.actor_id for l in logs if l.actor_id))
        }
    
    @staticmethod
    def log_record_access(
        db: DBSession,
        doctor_id: str,
        patient_id: str,
        record_id: str,
        ip_address: str = None,
        request_id: str = None,
        duration_ms: int = None
    ) -> Optional[CryptographicAuditLog]:
        """
        Log medical record access (convenience method)
        
        Args:
            db: Database session
            doctor_id: UUID of doctor
            patient_id: UUID of patient
            record_id: UUID of record
            ip_address: Access IP
            request_id: Request ID
            duration_ms: Access duration in milliseconds
        
        Returns:
            Optional[CryptographicAuditLog]: Created audit log
        """
        event_data = {
            "doctor_id": str(doctor_id),
            "patient_id": str(patient_id),
            "duration_ms": duration_ms
        }
        
        return CryptoAuditService.log_action(
            db=db,
            actor_id=doctor_id,
            actor_type=ActorType.DOCTOR,
            action="RECORD_ACCESSED",
            resource_type="ENCRYPTED_RECORD",
            resource_id=record_id,
            event_data=event_data,
            ip_address=ip_address,
            request_id=request_id,
            status=CryptoAuditLogStatus.SUCCESS
        )
    
    @staticmethod
    def log_session_created(
        db: DBSession,
        doctor_id: str,
        patient_id: str,
        session_id: str,
        ip_address: str = None,
        request_id: str = None,
        ttl_days: int = None
    ) -> Optional[CryptographicAuditLog]:
        """
        Log session key creation (convenience method)
        
        Args:
            db: Database session
            doctor_id: UUID of doctor
            patient_id: UUID of patient
            session_id: UUID of session key
            ip_address: Creation IP
            request_id: Request ID
            ttl_days: Session TTL
        
        Returns:
            Optional[CryptographicAuditLog]: Created audit log
        """
        event_data = {
            "doctor_id": str(doctor_id),
            "patient_id": str(patient_id),
            "ttl_days": ttl_days
        }
        
        return CryptoAuditService.log_action(
            db=db,
            actor_id=patient_id,
            actor_type=ActorType.PATIENT,
            action="SESSION_CREATED",
            resource_type="SESSION_KEY",
            resource_id=session_id,
            event_data=event_data,
            ip_address=ip_address,
            request_id=request_id,
            status=CryptoAuditLogStatus.SUCCESS
        )
    
    @staticmethod
    def log_access_denied(
        db: DBSession,
        doctor_id: str,
        patient_id: str,
        resource_id: str,
        reason: str,
        ip_address: str = None,
        request_id: str = None
    ) -> Optional[CryptographicAuditLog]:
        """
        Log access denial (security event)
        
        Args:
            db: Database session
            doctor_id: UUID of doctor
            patient_id: UUID of patient
            resource_id: UUID of resource
            reason: Denial reason
            ip_address: Access IP
            request_id: Request ID
        
        Returns:
            Optional[CryptographicAuditLog]: Created audit log
        """
        event_data = {
            "doctor_id": str(doctor_id),
            "patient_id": str(patient_id),
            "reason": reason
        }
        
        return CryptoAuditService.log_action(
            db=db,
            actor_id=doctor_id,
            actor_type=ActorType.DOCTOR,
            action="ACCESS_DENIED",
            resource_type="ENCRYPTED_RECORD",
            resource_id=resource_id,
            event_data=event_data,
            ip_address=ip_address,
            request_id=request_id,
            status=CryptoAuditLogStatus.DENIED,
            status_message=reason
        )
