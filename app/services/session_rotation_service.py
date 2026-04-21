"""
Session Rotation Service - Phase 5

Manages:
- Automatic daily session key rotation (Celery)
- Manual session rotation
- Rotation history
- Expired session cleanup
"""

import logging
from datetime import datetime, timedelta
from uuid import uuid4
from sqlalchemy.orm import Session
from app.models.encryption_models import SessionKey, SessionKeyStatus
from app.services.crypto_audit_service import CryptoAuditService
from app.security.cache import cache_manager

logger = logging.getLogger(__name__)


class SessionRotationService:
    """Manage session key rotation"""

    ROTATION_INTERVAL_DAYS = 1  # Rotate daily
    EXPIRY_DAYS = 7  # Sessions valid for 7 days

    @staticmethod
    def rotate_session_key(
        db: Session,
        session_id: str,
        actor_id: str,
    ) -> tuple:
        """
        Rotate session key: create new key, mark old as expired
        
        Returns: (old_session, new_session)
        """
        old_session = db.query(SessionKey).filter(
            SessionKey.id == session_id
        ).first()

        if not old_session:
            raise ValueError(f"Session {session_id} not found")

        # Create new session key
        new_session = SessionKey(
            id=uuid4(),
            patient_id=old_session.patient_id,
            doctor_id=old_session.doctor_id,
            session_key_hash=uuid4().hex,
            status=SessionKeyStatus.ACTIVE,
            scope=getattr(old_session, "scope", "read"),
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=SessionRotationService.EXPIRY_DAYS),
            rotated_from_id=session_id,
        )

        # Mark old as archived
        old_session.status = SessionKeyStatus.ARCHIVED
        old_session.archived_at = datetime.utcnow()

        db.add(new_session)
        db.commit()
        db.refresh(new_session)

        # Invalidate old session cache
        cache_manager.invalidate_session(old_session.session_key_hash)

        logger.info(
            f"Rotated session {session_id} → {new_session.id}"
        )

        return old_session, new_session

    @staticmethod
    def auto_rotate_expired_sessions(db: Session) -> int:
        """
        Automatic rotation of sessions approaching expiry
        Called by Celery Beat (daily scheduler)
        """
        # Find sessions expiring in 24 hours
        expiry_threshold = datetime.utcnow() + timedelta(days=1)

        sessions_to_rotate = db.query(SessionKey).filter(
            SessionKey.status == SessionKeyStatus.ACTIVE,
            SessionKey.expires_at <= expiry_threshold,
            SessionKey.expires_at > datetime.utcnow(),
        ).all()

        rotated_count = 0

        for session in sessions_to_rotate:
            try:
                # Rotate
                old_session, new_session = SessionRotationService.rotate_session_key(
                    db, str(session.id), "system"
                )

                logger.info(f"Auto-rotated session {session.id}")
                rotated_count += 1

            except Exception as e:
                logger.error(f"Failed to auto-rotate session {session.id}: {str(e)}")

        return rotated_count

    @staticmethod
    def cleanup_expired_sessions(db: Session) -> int:
        """
        Clean up expired sessions (older than 30 days)
        Called by Celery Beat (weekly)
        """
        cutoff_date = datetime.utcnow() - timedelta(days=30)

        expired_sessions = db.query(SessionKey).filter(
            SessionKey.expires_at <= cutoff_date,
        ).all()

        deleted_count = 0

        for session in expired_sessions:
            try:
                # Invalidate cache
                cache_manager.invalidate_session(session.session_key_hash)

                # Mark as EXPIRED instead of hard delete
                session.status = SessionKeyStatus.EXPIRED
                deleted_count += 1

            except Exception as e:
                logger.error(f"Failed to expire session {session.id}: {str(e)}")

        db.commit()
        logger.info(f"Cleaned up {deleted_count} expired sessions")
        return deleted_count

    @staticmethod
    def get_rotation_schedule(db: Session, patient_id: str) -> list:
        """Get upcoming rotation schedule for patient"""
        sessions = db.query(SessionKey).filter(
            SessionKey.patient_id == patient_id,
            SessionKey.status == SessionKeyStatus.ACTIVE,
        ).all()

        schedule = []
        for session in sessions:
            days_until_rotation = (
                session.expires_at - datetime.utcnow()
            ).days

            schedule.append(
                {
                    "session_id": str(session.id),
                    "doctor_id": str(session.doctor_id),
                    "expires_at": session.expires_at,
                    "days_until_rotation": max(0, days_until_rotation),
                }
            )

        return sorted(schedule, key=lambda x: x["days_until_rotation"])
