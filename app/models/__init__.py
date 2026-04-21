# Import all models here so Alembic's autogenerate and the app can discover them.
from app.models.access_permission import AccessPermission, InitiatedBy, RequestStatus
from app.models.audit_log import AuditLog
from app.models.doctor_access_log import DoctorAccessLog
from app.models.family_member import FamilyMember, Relation
from app.models.lab_order import CollectionType, LabOrder, OrderStatus
from app.models.lab_test import LabTest
from app.models.login_attempt import APIKey, LoginAttempt, PasswordHistory, TOTPSecret
from app.models.medical_record import MedicalRecord, RecordType
from app.models.medication import Medication
from app.models.patient import Gender, Patient
from app.models.payment import Payment, PaymentStatus
from app.models.reminder import Reminder, ReminderFrequency, ReminderLog, ReminderStatus
from app.models.user import User, UserRole

# Phase 2: Encryption Infrastructure Models
from app.models.encryption_models import (
    UserKeypair,
    SessionKey,
    SessionKeyStatus,
    EncryptedRecordVault,
    CryptographicAuditLog,
    CryptoAuditLogStatus,
    KeyRotationHistory,
    KeyRotationStatus,
    ActorType,
)

__all__ = [
    "User",
    "UserRole",
    "Patient",
    "Gender",
    "FamilyMember",
    "Relation",
    "MedicalRecord",
    "RecordType",
    "Medication",
    "Reminder",
    "ReminderLog",
    "ReminderFrequency",
    "ReminderStatus",
    "LabTest",
    "LabOrder",
    "OrderStatus",
    "CollectionType",
    "Payment",
    "PaymentStatus",
    "AccessPermission",
    "InitiatedBy",
    "RequestStatus",
    "AuditLog",
    "DoctorAccessLog",
    "LoginAttempt",
    "PasswordHistory",
    "APIKey",
    "TOTPSecret",
    # Phase 2: Encryption Infrastructure
    "UserKeypair",
    "SessionKey",
    "SessionKeyStatus",
    "EncryptedRecordVault",
    "CryptographicAuditLog",
    "CryptoAuditLogStatus",
    "KeyRotationHistory",
    "KeyRotationStatus",
    "ActorType",
]
