"""
Phase 6: Compliance & Audit Router

Endpoints for:
- GDPR data exports (SAR, portability)
- Audit log verification and integrity
- Compliance reports
- Retention policy management
"""

import logging
from typing import Optional
from uuid import uuid4
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, BackgroundTasks
from sqlalchemy.orm import Session

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.services.compliance_export_service import ComplianceExportService
from app.services.audit_verification_service import AuditVerificationService
from app.services.compliance_report_service import ComplianceReportService, RetentionPolicyService
from app.services.crypto_audit_service import CryptoAuditService
from app.models.encryption_models import ActorType, CryptoAuditLogStatus

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance",
    tags=["compliance"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Not authorized"},
        404: {"description": "Resource not found"},
        500: {"description": "Internal server error"},
    },
)


# ==================== GDPR DATA EXPORT ENDPOINTS ====================


@router.post(
    "/exports/gdpr-sar",
    summary="Request GDPR Subject Access Report",
    description="Patient requests all personal data (GDPR Article 15)",
    status_code=201,
)
async def request_gdpr_sar(
    background_tasks: BackgroundTasks,
    include_audit: bool = Query(True),
    include_records: bool = Query(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Request GDPR Subject Access Request (SAR)
    
    **GDPR Compliance:**
    - Patient can request all personal data
    - Must be provided within 30 days
    - Encrypted delivery
    - Expires after 30 days
    
    **Parameters:**
    - `include_audit`: Include audit trail of access
    - `include_records`: Include medical records
    
    **Response:**
    ```json
    {
      "export_id": "uuid",
      "status": "PENDING",
      "requested_at": "2024-01-01T10:00:00Z",
      "expires_at": "2024-01-31T10:00:00Z",
      "includes_audit": true,
      "includes_records": true
    }
    ```
    """
    try:
        # Create export
        export = ComplianceExportService.create_gdpr_sar_export(
            db,
            str(current_user.id),
            include_audit=include_audit,
            include_records=include_records,
        )

        # Process in background
        background_tasks.add_task(
            ComplianceExportService.process_export,
            db,
            str(export.id),
        )

        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="GDPR_SAR_REQUESTED",
            resource_type="COMPLIANCE_EXPORT",
            resource_id=str(export.id),
            event_data={
                "include_audit": include_audit,
                "include_records": include_records,
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )

        return {
            "export_id": str(export.id),
            "status": export.status,
            "requested_at": export.requested_at.isoformat(),
            "expires_at": export.expires_at.isoformat(),
            "includes_audit": export.includes_audit,
            "includes_records": export.includes_records,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to request GDPR SAR: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to request export")


@router.get(
    "/exports/{export_id}",
    summary="Get export status",
    description="Retrieve status of GDPR export request",
)
async def get_export_status(
    export_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get GDPR export status
    
    **Response:**
    ```json
    {
      "export_id": "uuid",
      "status": "COMPLETED",
      "requested_at": "2024-01-01T10:00:00Z",
      "completed_at": "2024-01-02T10:00:00Z",
      "expires_at": "2024-01-31T10:00:00Z",
      "file_size_bytes": 102400,
      "record_count": 42
    }
    ```
    """
    try:
        status = ComplianceExportService.get_export_status(db, export_id)
        return status
    except Exception as e:
        logger.error(f"Failed to get export status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get status")


@router.get(
    "/exports",
    summary="List user exports",
    description="List all GDPR exports for authenticated user",
)
async def list_exports(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List GDPR exports for user
    
    **Response:** Array of exports with status
    """
    try:
        exports = ComplianceExportService.list_user_exports(
            db, str(current_user.id), limit
        )
        return exports
    except Exception as e:
        logger.error(f"Failed to list exports: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list exports")


# ==================== AUDIT VERIFICATION ENDPOINTS ====================


@router.post(
    "/audit-logs/{audit_log_id}/verify",
    summary="Verify audit log integrity",
    description="Verify ECDSA signature and check for tampering",
)
async def verify_audit_log(
    audit_log_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify audit log signature and integrity
    
    **Checks:**
    - ECDSA signature validity
    - Immutability constraints
    - Tampering detection
    
    **Response:**
    ```json
    {
      "valid": true,
      "reason": "Signature verified",
      "verification_id": "uuid",
      "checks": [
        {"check": "signature", "passed": true},
        {"check": "creation_immutable", "passed": true}
      ]
    }
    ```
    """
    try:
        result = AuditVerificationService.verify_audit_log_signature(
            db, audit_log_id
        )
        return result
    except Exception as e:
        logger.error(f"Failed to verify audit log: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")


@router.post(
    "/audit-logs/{audit_log_id}/check-tampering",
    summary="Check for tampering",
    description="Comprehensive check for audit log tampering",
)
async def check_tampering(
    audit_log_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Check if audit log has been tampered with
    
    **Response:**
    ```json
    {
      "tampered": false,
      "status": "CLEAN",
      "checks": [
        {"check": "signature", "passed": true},
        {"check": "creation_immutable", "passed": true},
        {"check": "resource_id_immutable", "passed": true}
      ]
    }
    ```
    """
    try:
        result = AuditVerificationService.check_audit_log_tampering(db, audit_log_id)
        return result
    except Exception as e:
        logger.error(f"Failed to check tampering: {str(e)}")
        raise HTTPException(status_code=500, detail="Check failed")


@router.get(
    "/audit-logs/{audit_log_id}/verifications",
    summary="Get verification history",
    description="View all verification records for audit log",
)
async def get_verification_history(
    audit_log_id: str,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get verification history for audit log
    
    **Response:** List of verification records with timestamps
    """
    try:
        history = AuditVerificationService.get_verification_history(
            db, audit_log_id, limit
        )
        return history
    except Exception as e:
        logger.error(f"Failed to get history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get history")


@router.post(
    "/audit-logs/batch-verify",
    summary="Batch verify audit logs",
    description="Verify multiple audit logs for integrity",
)
async def batch_verify_logs(
    audit_log_ids: list = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify multiple audit logs at once
    
    **Parameters:**
    - `audit_log_ids`: List of audit log UUIDs
    
    **Response:**
    ```json
    {
      "total": 100,
      "valid": 100,
      "invalid": 0,
      "status": "ALL_VALID",
      "logs": [
        {"audit_log_id": "uuid", "valid": true},
        ...
      ]
    }
    ```
    """
    try:
        result = AuditVerificationService.batch_verify_audit_logs(db, audit_log_ids)
        return result
    except Exception as e:
        logger.error(f"Failed to batch verify: {str(e)}")
        raise HTTPException(status_code=500, detail="Batch verification failed")


# ==================== COMPLIANCE REPORT ENDPOINTS ====================


@router.get(
    "/reports/audit-summary",
    summary="Audit trail summary",
    description="Generate audit summary for compliance reporting",
)
async def audit_summary_report(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate audit trail summary report
    
    **Response:**
    ```json
    {
      "period": {
        "start": "2023-12-02T00:00:00Z",
        "end": "2024-01-01T00:00:00Z"
      },
      "total_events": 1234,
      "actions": {
        "RECORD_VIEWED": 500,
        "RECORD_MODIFIED": 300,
        ...
      },
      "actors": {
        "DOCTOR:uuid-1": 400,
        "PATIENT:uuid-2": 300
      },
      "resources_accessed": 50,
      "summary": {
        "total_logs": 1234,
        "unique_actors": 2,
        "unique_resources": 50,
        "log_integrity": "OK"
      }
    }
    ```
    """
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        report = ComplianceReportService.generate_audit_summary(db, start_date)
        return report
    except Exception as e:
        logger.error(f"Failed to generate audit summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Report generation failed")


@router.get(
    "/reports/access-patterns/{patient_id}",
    summary="Patient access patterns",
    description="Show who accessed patient's records and when",
)
async def access_patterns_report(
    patient_id: str,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate access patterns report for patient
    
    **Shows:**
    - Which doctors accessed records
    - How many times each accessed
    - What actions were performed
    - Timeline of access
    
    **Response:**
    ```json
    {
      "patient_id": "uuid",
      "period_days": 30,
      "total_accesses": 42,
      "doctors_with_access": 2,
      "access_by_doctor": [
        {
          "doctor_id": "uuid",
          "accesses": 30,
          "first_access": "2023-12-05T10:00:00Z",
          "last_access": "2024-01-01T15:30:00Z",
          "actions": ["RECORD_VIEWED", "RECORD_VIEWED", ...]
        }
      ],
      "timeline": [...]
    }
    ```
    """
    try:
        report = ComplianceReportService.generate_access_patterns_report(
            db, patient_id, days
        )
        return report
    except Exception as e:
        logger.error(f"Failed to generate access report: {str(e)}")
        raise HTTPException(status_code=500, detail="Report generation failed")


@router.get(
    "/reports/compliance-status",
    summary="Overall compliance status",
    description="System-wide compliance status report",
)
async def compliance_status_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate overall compliance status
    
    **Shows:**
    - Retention policies active
    - GDPR export availability
    - Audit trail immutability
    - Encryption status
    
    **Response:**
    ```json
    {
      "compliance_status": "COMPLIANT",
      "retention_policies": {
        "total": 5,
        "active": 5,
        "policies": [...]
      },
      "gdpr_status": {
        "exports_available": "YES",
        "sar_processing_time_days": 30
      },
      "audit_trail": {
        "immutable": "YES",
        "retention_years": 7
      },
      "data_protection": {
        "encryption": "ENABLED",
        "audit_logging": "ENABLED"
      }
    }
    ```
    """
    try:
        report = ComplianceReportService.generate_compliance_status_report(db)
        return report
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {str(e)}")
        raise HTTPException(status_code=500, detail="Report generation failed")


# ==================== RETENTION POLICY ENDPOINTS ====================


@router.get(
    "/retention-policies/{resource_type}",
    summary="Get retention policy",
    description="Get retention policy for resource type",
)
async def get_retention_policy(
    resource_type: str,
    jurisdiction: str = Query("UK"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get retention policy
    
    **Resource Types:**
    - audit_logs: 7 years (UK requirement)
    - medical_records: 7 years
    - encryption_keys: 7 years
    - session_keys: 1 year
    
    **Response:**
    ```json
    {
      "resource_type": "audit_logs",
      "retention_years": 7,
      "jurisdiction": "UK",
      "requires_immutability": true
    }
    ```
    """
    try:
        policy = RetentionPolicyService.get_retention_policy(
            db, resource_type, jurisdiction
        )
        return policy
    except Exception as e:
        logger.error(f"Failed to get retention policy: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get policy")


@router.get(
    "/immutability-constraints",
    summary="Check immutability constraints",
    description="Verify database immutability constraints are enforced",
)
async def check_immutability_constraints(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify immutability constraints on audit table
    
    **Response:**
    ```json
    {
      "immutable": true,
      "status": "VERIFIED",
      "constraints": ["audit_logs_immutable", ...]
    }
    ```
    """
    try:
        result = AuditVerificationService.verify_immutability_constraints(db)
        return result
    except Exception as e:
        logger.error(f"Failed to check constraints: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")
