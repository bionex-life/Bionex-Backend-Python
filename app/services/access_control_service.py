"""
Access Control Service - Phase 5

Manages:
- Permission scopes (read, read_write)
- Session scope enforcement
- Access control validation
- Revocation management
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.encryption_models import SessionKey, SessionKeyStatus
from app.security.cache import cache_manager

logger = logging.getLogger(__name__)


class AccessControlService:
    """Permission and access control management"""

    @staticmethod
    def get_session_scope(
        db: Session, session_id: str, user_id: str
    ) -> dict:
        """Get permission scope for session"""
        session = db.query(SessionKey).filter(
            SessionKey.id == session_id
        ).first()

        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Scope typically stored in session metadata
        scope = getattr(session, "scope", "read")  # Default: read-only

        return {
            "scope": scope,
            "can_read": True,
            "can_write": scope == "read_write",
            "resources": [],
        }

    @staticmethod
    def update_session_scope(
        db: Session, session_id: str, patient_id: str, new_scope: str
    ) -> SessionKey:
        """Update permission scope for session"""
        session = db.query(SessionKey).filter(
            SessionKey.id == session_id
        ).first()

        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Update scope
        session.scope = new_scope
        session.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(session)

        logger.info(f"Updated session {session_id} scope to {new_scope}")
        return session

    @staticmethod
    def revoke_session_immediately(
        db: Session, session_id: str, patient_id: str, reason: str = None
    ) -> SessionKey:
        """Revoke session immediately"""
        session = db.query(SessionKey).filter(
            SessionKey.id == session_id
        ).first()

        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Revoke
        session.status = SessionKeyStatus.REVOKED
        session.revoked_at = datetime.utcnow()
        session.revocation_reason = reason or "Patient revoked access"
        db.commit()
        db.refresh(session)

        # Invalidate cache immediately
        cache_manager.invalidate_session(session.session_key_hash)

        logger.info(f"Revoked session {session_id}: {reason}")
        return session

    @staticmethod
    def revoke_all_sessions(db: Session, patient_id: str, reason: str = None) -> int:
        """Revoke all active sessions for patient"""
        from app.models.patient import Patient

        patient = db.query(Patient).filter(
            Patient.user_id == patient_id
        ).first()

        if not patient:
            raise ValueError(f"Patient not found for user {patient_id}")

        # Get all active sessions
        active_sessions = db.query(SessionKey).filter(
            SessionKey.patient_id == str(patient.id),
            SessionKey.status == SessionKeyStatus.ACTIVE,
        ).all()

        # Revoke each
        for session in active_sessions:
            session.status = SessionKeyStatus.REVOKED
            session.revoked_at = datetime.utcnow()
            session.revocation_reason = reason or "Patient revoked all access"

            # Invalidate cache
            cache_manager.invalidate_session(session.session_key_hash)

        db.commit()

        logger.info(
            f"Revoked {len(active_sessions)} sessions for patient {patient_id}"
        )
        return len(active_sessions)

    @staticmethod
    def check_write_permission(db: Session, session_id: str) -> bool:
        """Check if session has write permission"""
        session = db.query(SessionKey).filter(
            SessionKey.id == session_id
        ).first()

        if not session:
            return False

        scope = getattr(session, "scope", "read")
        return scope == "read_write"

    @staticmethod
    def check_read_permission(db: Session, session_id: str) -> bool:
        """Check if session has read permission"""
        session = db.query(SessionKey).filter(
            SessionKey.id == session_id,
            SessionKey.status == SessionKeyStatus.ACTIVE,
        ).first()

        return session is not None
