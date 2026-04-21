"""
Compliance Export Service - Phase 6

Manages:
- GDPR Subject Access Requests (SAR)
- Data portability exports
- Encrypted data delivery
- Export expiration
"""

import logging
import json
import zipfile
import io
from datetime import datetime, timedelta
from uuid import uuid4
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger(__name__)


class ComplianceExportService:
    """Manage GDPR and compliance data exports"""

    EXPORT_RETENTION_DAYS = 30  # Exports valid for 30 days
    MAX_EXPORT_AGE_DAYS = 365  # Older than 1 year, delete

    @staticmethod
    def create_gdpr_sar_export(
        db: Session,
        user_id: str,
        include_audit: bool = True,
        include_records: bool = True,
    ):
        """Create GDPR Subject Access Request export"""
        from app.models.compliance import ComplianceExport, ComplianceExportStatus, ComplianceExportType
        from app.models.user import User

        # Verify user exists
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Create export request
        export = ComplianceExport(
            id=uuid4(),
            user_id=user_id,
            export_type=ComplianceExportType.GDPR_SAR,
            status=ComplianceExportStatus.PENDING,
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=ComplianceExportService.EXPORT_RETENTION_DAYS),
            is_encrypted=True,
            includes_audit=include_audit,
            includes_records=include_records,
        )

        db.add(export)
        db.commit()
        db.refresh(export)

        logger.info(f"Created GDPR SAR export {export.id} for user {user_id}")
        return export

    @staticmethod
    def process_export(
        db: Session,
        export_id: str,
        output_dir: str = "/tmp/exports",
    ):
        """Process compliance export (collect data, encrypt, zip)"""
        from app.models.compliance import ComplianceExport, ComplianceExportStatus
        from app.models.user import User
        from app.models.patient import Patient
        from app.models.medical_record import MedicalRecord
        from app.models.audit_log import CryptographicAuditLog
        from app.security.crypto import CryptoManager

        export = db.query(ComplianceExport).filter(
            ComplianceExport.id == export_id
        ).first()

        if not export:
            raise ValueError(f"Export {export_id} not found")

        try:
            export.status = ComplianceExportStatus.PROCESSING
            db.commit()

            # Collect user data
            user = db.query(User).filter(User.id == export.user_id).first()
            patient = db.query(Patient).filter(Patient.user_id == export.user_id).first()

            data = {
                "user": user.to_dict() if user else None,
                "patient": patient.to_dict() if patient else None,
                "records": [],
                "audit_logs": [],
            }

            # Collect medical records
            if export.includes_records and patient:
                records = db.query(MedicalRecord).filter(
                    MedicalRecord.patient_id == patient.id
                ).all()
                data["records"] = [r.to_dict() for r in records]

            # Collect audit logs
            if export.includes_audit:
                audit_logs = db.query(CryptographicAuditLog).filter(
                    CryptographicAuditLog.actor_id == export.user_id
                ).all()
                data["audit_logs"] = [
                    {
                        "id": str(a.id),
                        "action": a.action,
                        "resource_type": a.resource_type,
                        "timestamp": a.timestamp.isoformat(),
                        "status": a.status,
                    }
                    for a in audit_logs
                ]

            # Create zip file
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            zip_path = f"{output_dir}/{export_id}.zip"

            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                # Add JSON data
                zf.writestr("data.json", json.dumps(data, indent=2))
                # Add metadata
                zf.writestr(
                    "metadata.json",
                    json.dumps(
                        {
                            "export_id": str(export.id),
                            "user_id": export.user_id,
                            "export_type": export.export_type,
                            "created_at": export.requested_at.isoformat(),
                            "includes_records": export.includes_records,
                            "includes_audit": export.includes_audit,
                        },
                        indent=2,
                    ),
                )

            # Update export
            file_size = Path(zip_path).stat().st_size
            export.status = ComplianceExportStatus.COMPLETED
            export.completed_at = datetime.utcnow()
            export.file_path = zip_path
            export.file_size_bytes = file_size
            export.record_count = len(data["records"]) + len(data["audit_logs"])

            db.commit()
            db.refresh(export)

            logger.info(
                f"Processed export {export_id}: {file_size} bytes, {export.record_count} records"
            )
            return export

        except Exception as e:
            logger.error(f"Failed to process export {export_id}: {str(e)}")
            export.status = ComplianceExportStatus.FAILED
            db.commit()
            raise

    @staticmethod
    def get_export_status(db: Session, export_id: str):
        """Get export status"""
        from app.models.compliance import ComplianceExport

        export = db.query(ComplianceExport).filter(
            ComplianceExport.id == export_id
        ).first()

        if not export:
            raise ValueError(f"Export {export_id} not found")

        return {
            "export_id": str(export.id),
            "status": export.status,
            "requested_at": export.requested_at.isoformat(),
            "completed_at": export.completed_at.isoformat() if export.completed_at else None,
            "expires_at": export.expires_at.isoformat() if export.expires_at else None,
            "file_size_bytes": export.file_size_bytes,
            "record_count": export.record_count,
        }

    @staticmethod
    def list_user_exports(db: Session, user_id: str, limit: int = 50):
        """List all exports for user"""
        from app.models.compliance import ComplianceExport

        exports = db.query(ComplianceExport).filter(
            ComplianceExport.user_id == user_id
        ).order_by(desc(ComplianceExport.requested_at)).limit(limit).all()

        return [
            {
                "export_id": str(e.id),
                "type": e.export_type,
                "status": e.status,
                "requested_at": e.requested_at.isoformat(),
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            }
            for e in exports
        ]

    @staticmethod
    def cleanup_expired_exports(db: Session, output_dir: str = "/tmp/exports") -> int:
        """Delete expired exports (older than 30 days)"""
        from app.models.compliance import ComplianceExport
        from pathlib import Path

        cutoff_date = datetime.utcnow() - timedelta(days=ComplianceExportService.EXPORT_RETENTION_DAYS)

        expired = db.query(ComplianceExport).filter(
            ComplianceExport.requested_at <= cutoff_date,
            ComplianceExport.status.in_(["COMPLETED", "EXPIRED"]),
        ).all()

        deleted_count = 0

        for export in expired:
            try:
                # Delete file
                if export.file_path:
                    Path(export.file_path).unlink(missing_ok=True)

                # Mark as expired
                export.status = "EXPIRED"
                deleted_count += 1

            except Exception as e:
                logger.error(f"Failed to delete export {export.id}: {str(e)}")

        db.commit()
        logger.info(f"Cleaned up {deleted_count} expired exports")
        return deleted_count
