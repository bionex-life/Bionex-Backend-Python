# Bionex Hybrid Encryption Architecture

**Version:** 1.0  
**Date:** April 18, 2026  
**Status:** Design Phase (Ready for Implementation)  
**Target:** Patient-Centric Decentralized Data Protection

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Layers](#architecture-layers)
3. [Cryptographic Algorithms](#cryptographic-algorithms)
4. [Data Models & Database Schema](#data-models--database-schema)
5. [Complete Workflows](#complete-workflows)
6. [API Endpoints](#api-endpoints)
7. [Implementation Phases](#implementation-phases)
8. [Security Considerations](#security-considerations)
9. [Code Structure](#code-structure)
10. [Testing Strategy](#testing-strategy)

---

## Overview

### Vision
Medical records are stored **encrypted on patient devices** (not on server). Server acts as:
- **Key Authority** - manages doctor session keys
- **Audit Ledger** - immutable log of access
- **Permission Manager** - controls who can access what

### Core Principle
**Zero-Knowledge Server**: Your backend never holds plaintext patient data. Ever.

### Key Players
- **Patient**: Owns data, grants access, controls encryption keys
- **Doctor**: Has temporary session key, can decrypt for defined period
- **Server**: Enforces permissions, logs access, doesn't decrypt

---

## Architecture Layers

### Layer 1: Patient Vault (Device Storage)
```
Patient Device (Phone/App)
├── Master Key (derived from password)
├── Encrypted Medical Records
│   ├── Heart Report (encrypted with Master Key)
│   ├── Lab Results (encrypted with Master Key)
│   └── Medications (encrypted with Master Key)
└── Public Key Pair (for sharing)
```

**How it works:**
- Patient has app on phone
- All records stored locally on phone's encrypted storage (iOS Keychain / Android KeyStore)
- Master key = `HKDF(password + device_id)` (so same password on different device = different key)
- Private key never leaves device
- Patient can read their own records anytime (offline support)

### Layer 2: Sharing Mechanism (Server-Mediated)
```
Server Database
├── Encrypted Session Keys (for each doctor)
│   ├── Doctor A: encrypted_session_key_1 (TTL: 7 days)
│   ├── Doctor B: encrypted_session_key_2 (TTL: 3 days)
│   └── Doctor C: encrypted_session_key_3 (TTL: 30 mins)
├── Access Permissions (metadata only)
│   ├── Patient X → Doctor A: approved (scope: all records)
│   ├── Patient X → Doctor B: approved (scope: lab reports only)
│   └── Patient X → Doctor C: pending (awaiting approval)
└── Immutable Audit Log (signed events)
    ├── "Dr. A accessed 3 records" [signature] [timestamp]
    ├── "Patient X revoked Dr. C" [signature] [timestamp]
    └── "Session key expired for Dr. B" [signature] [timestamp]
```

**How it works:**
- When patient wants to share with doctor, generate unique **session key** for that doctor
- Encrypt session key using doctor's public key
- Store encrypted session key in database
- Doctor uses their private key to decrypt session key
- Doctor uses session key to access encrypted records

### Layer 3: Access Control (Permission Enforcement)
```
Request Flow:
Doctor App Request
    ↓
[Header: X-Sharing-Token: {token}]
[Header: X-Session-Key: {decrypted_session_key}]
    ↓
Server Validation
├── Is token valid? (not expired, not revoked)
├── Does session key match token? (cryptographic verification)
├── Is doctor still allowed? (permission check)
├── Is session key not expired? (TTL check)
    ↓
If All Pass → Return encrypted records
If Any Fail → 403 Forbidden + log attempt
    ↓
Doctor App
├── Receive encrypted records
├── Decrypt using session key
├── Display plaintext to doctor
```

---

## Cryptographic Algorithms

### Algorithm Selection Philosophy
**Proven**: Use established algorithms, not custom crypto  
**Fast**: Prioritize performance for real-time access  
**Flexible**: Support future upgrades (quantum-resistant migration)  
**Simple**: Junior developers can understand and maintain

### 1. Key Exchange: ECDH (Elliptic Curve Diffie-Hellman)

**Purpose**: Doctor and patient agree on shared session key without exposing keys

**Algorithm Details**:
- **Curve**: P-256 (secp256r1) or Curve25519
  - P-256: NIST standard, widely supported (use this first)
  - Curve25519: Modern, simpler math, slightly faster (use if performance needed)
- **Key Size**: 256-bit (128-bit security equivalent)
- **Process**:

```
Patient Side:
├── Generate keypair: (Patient Private Key, Patient Public Key)
└── Public key shared with doctor's app (non-sensitive)

Doctor Side:
├── Generate keypair: (Doctor Private Key, Doctor Public Key)
└── Public key registered on server

Sharing Process:
├── Server generates ephemeral keypair (temp_private, temp_public)
├── Server computes shared secret:
│   shared_secret = ECDH(Server Private, Doctor Public)
└── shared_secret becomes the session key

Server stores:
├── encrypted_session_key = Encrypt(shared_secret, Doctor Public)
└── Doctor decrypts using Doctor Private Key
```

**Why ECDH?**
- Fast key agreement (no need to send key over network)
- Small keys (256-bit, not 2048-bit like RSA)
- Perfect for mobile devices
- Standard in TLS 1.3 (already in use)

**Implementation Library**: `cryptography.hazmat.primitives.asymmetric.ec`

---

### 2. Symmetric Encryption: ChaCha20-Poly1305

**Purpose**: Encrypt actual medical records and session keys

**Algorithm Details**:
- **Cipher**: ChaCha20 (stream cipher)
- **Authentication**: Poly1305 (AEAD - Authenticated Encryption with Associated Data)
- **Key Size**: 256-bit
- **Nonce**: 96-bit random (never reused with same key)
- **Process**:

```
Encrypting a medical record:
├── Input: plaintext_record = "Patient has diabetes, on Metformin"
├── Key: session_key[256-bit]
├── Nonce: random[96-bit] (generated fresh, not reused)
├── AAD (Associated Data): doctor_id + record_id (not encrypted, but authenticated)
└── Output: ciphertext + authentication_tag

Result in database:
{
  "encrypted_data": base64(ciphertext),
  "auth_tag": base64(authentication_tag),
  "nonce": base64(nonce),
  "aad": "doctor_a_record_xyz"
}

Decrypting (on doctor's app):
├── Use stored session_key
├── Use stored nonce
├── Verify auth_tag (protects against tampering)
├── If tag valid → decrypt to plaintext
└── If tag invalid → reject (someone modified ciphertext)
```

**Why ChaCha20-Poly1305?**
- Faster than AES on devices without hardware acceleration (mobile phones)
- Built-in authentication (detects tampering)
- Modern, IETF standard (RFC 7539)
- Used in WireGuard, Signal, TLS 1.3

**Implementation Library**: `cryptography.hazmat.primitives.ciphers.aead`

---

### 3. Key Derivation: HKDF-SHA256

**Purpose**: Derive multiple independent keys from a single master key or shared secret

**Algorithm Details**:
- **Hash Function**: SHA-256
- **Process**: Extract-then-Expand (two-stage)
- **Use Cases**:
  - Derive patient's master key from password
  - Derive unique session sub-keys (forward secrecy)
  - Derive authentication keys

```
Deriving patient's master key:
password = "MySecure@Pass123"
salt = device_id (unique per device)
info = "bionex_patient_master_key"

master_key = HKDF-SHA256(
  ikm=password,
  salt=salt[32-byte],
  info=info,
  length=32
)
Result: A strong 256-bit key, even if password is weak

---

Deriving session sub-keys (forward secrecy):
session_key_base = shared_secret_from_ECDH[256-bit]

For access #1:
sub_key_1 = HKDF-SHA256(
  ikm=session_key_base,
  salt=counter_1,
  info="access_1",
  length=32
)

For access #2:
sub_key_2 = HKDF-SHA256(
  ikm=session_key_base,
  salt=counter_2,
  info="access_2",
  length=32
)

Key property: Can't derive sub_key_1 from sub_key_2 (one-way)
Benefit: If doctor's device hacked on day 5, hacker can't decrypt day 1-4 records
```

**Why HKDF?**
- Fast (no expensive operations)
- Cryptographically sound (proven secure)
- Generates salt automatically (no need for random salt in some cases)
- Standard (RFC 5869)

**Implementation Library**: `cryptography.hazmat.primitives.kdf.hkdf`

---

### 4. Digital Signatures: ECDSA-SHA256

**Purpose**: Sign audit log entries so they can't be modified

**Algorithm Details**:
- **Algorithm**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curve**: P-256 (same as ECDH for consistency)
- **Hash**: SHA-256
- **Signature Size**: 512 bits (~64 bytes)
- **Process**:

```
Creating an audit log entry:
event = {
  "action": "DOCTOR_ACCESSED_RECORD",
  "doctor_id": "doc_123",
  "record_id": "rec_456",
  "timestamp": "2026-04-18T10:30:00Z",
  "ip_address": "192.168.1.5"
}

Server signs it:
signature = ECDSA_Sign(server_private_key, SHA256(event))

Audit log stored:
{
  "event": event,
  "signature": base64(signature),
  "server_public_key": base64(server_public_key)
}

---

Verifying audit log (by auditor):
signature_valid = ECDSA_Verify(
  server_public_key,
  event,
  signature
)

If signature_valid AND server_public_key_registered:
  → Audit log entry is authentic (not tampered with)
Else:
  → Someone modified the event (red flag!)
```

**Why ECDSA?**
- Fast verification (auditors can verify logs on their laptops)
- Small signatures (efficient storage)
- Paired with ECDH (consistent key types across system)
- Legal standard in many jurisdictions

**Implementation Library**: `cryptography.hazmat.primitives.asymmetric.ec` with `ECDSA(SHA256())`

---

### 5. Hashing for IDs: SHA-256

**Purpose**: Hash sensitive data for database indexing/lookups without exposing plaintext

**Algorithm Details**:
- **Output**: 256-bit hash (64 hex characters)
- **Process**: One-way (can't reverse to get original)
- **Use Cases**:
  - Hash session keys before storing in DB (compare hash, not plaintext)
  - Hash email/phone for duplicate detection

```
Session Key Hashing:
session_key_plaintext = "abc123def456..." [256-bit]
session_key_hash = SHA256(session_key_plaintext)
  = "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f..."

Store in database:
INSERT INTO session_keys (
  token_hash,
  doctor_id,
  expires_at,
  ...
) VALUES (
  "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f...",
  "doc_123",
  "2026-04-25T10:30:00Z",
  ...
)

Verification (during request):
received_key = "abc123def456..."
compute_hash = SHA256(received_key)
stored_hash = query database

If compute_hash == stored_hash:
  → Key is valid
Else:
  → Key is invalid/doesn't exist
```

**Why SHA-256?**
- Fast (even for high-volume comparisons)
- Collision-resistant (no two different keys create same hash)
- Industry standard (blockchain, TLS, etc.)
- Can't reverse (one-way)

**Implementation Library**: `hashlib` (built-in Python)

---

### 6. Random Number Generation: os.urandom()

**Purpose**: Generate cryptographically random session keys, nonces, salts

**Algorithm Details**:
- **Source**: OS entropy pool (Linux `/dev/urandom`, Windows CryptoAPI)
- **Quality**: Cryptographically secure (not pseudo-random)
- **Use Cases**:
  - Generate session keys
  - Generate nonces for ChaCha20-Poly1305
  - Generate salts for HKDF

```
Generating a session key:
session_key = os.urandom(32)  # 256 bits
  = b'\x4a\x3f\x9e\x2c\x1b\x7d\x5a\x8f...'

Properties:
- Each call produces different bytes
- Zero patterns (no correlation between keys)
- Suitable for cryptographic use (not just "random enough")

Use in code:
import secrets  # More explicit for crypto
session_key = secrets.token_bytes(32)
```

**Why os.urandom()?**
- Backed by OS entropy
- No predictability
- Industry standard

**Implementation Library**: `os.urandom()` or `secrets` module

---

### Summary Table: Algorithms Used

| Purpose | Algorithm | Key Size | Library | Why |
|---------|-----------|----------|---------|-----|
| Key Exchange | ECDH P-256 | 256-bit | `cryptography.ec` | Fast, small keys |
| Encryption | ChaCha20-Poly1305 | 256-bit | `cryptography.aead` | Mobile-friendly, AEAD |
| Key Derivation | HKDF-SHA256 | 256-bit | `cryptography.kdf` | RFC standard, proven |
| Signing | ECDSA-SHA256 | 256-bit | `cryptography.ec` | Fast verify, small sig |
| Hashing | SHA-256 | 256-bit | `hashlib` (built-in) | One-way, collision-proof |
| Random | os.urandom | N/A | `secrets` | OS entropy, secure |

---

## Data Models & Database Schema

### Current State (What Exists)
```
Users
├── id: UUID
├── email: String (encrypted)
├── phone: String (encrypted)
├── password: String (hashed)
├── role: Enum (PATIENT / DOCTOR / ADMIN)
└── created_at: DateTime

Patients
├── id: UUID
├── user_id: FK(Users.id)
├── medical_records: [MedicalRecord]
└── access_permissions: [AccessPermission]

MedicalRecords
├── id: UUID
├── patient_id: FK(Patients.id)
├── type: Enum (PRESCRIPTION, LAB_REPORT, etc)
├── title: String
├── notes: String (encrypted)
├── file_url: String
└── record_date: Date

AccessPermission
├── id: UUID
├── patient_id: FK(Patients.id)
├── granted_to_user_id: FK(Users.id)
├── access_token: String (unique)
├── expires_at: DateTime
├── request_status: Enum (PENDING/APPROVED/REVOKED)
└── scope: String (comma-separated)

AuditLog
├── id: UUID
├── action: String
├── resource_type: String
├── resource_id: String
├── ip_address: String
└── created_at: DateTime
```

### New Tables for Hybrid Encryption

#### Table 1: `user_keypairs`
Stores doctor and patient public keys (not sensitive, can be public)

```sql
CREATE TABLE user_keypairs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Public keys (not sensitive, can be cached)
    public_key_pem TEXT NOT NULL,  -- ECDH P-256 public key in PEM format
    public_key_fingerprint VARCHAR(64) NOT NULL UNIQUE,  -- SHA256(public_key_pem) for quick lookup
    
    -- Metadata
    key_algorithm VARCHAR(50) NOT NULL DEFAULT 'ECDH_P256',  -- Future: support different algos
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    
    -- Revocation
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason VARCHAR(255)
);

INDEX: user_id (unique lookup by user)
INDEX: public_key_fingerprint (find key by fingerprint)
```

**Purpose**: Store doctor/patient public keys so either can encrypt session keys for the other

**Why separate table?**
- Keys change independently from user profile
- Can revoke old key without deleting user
- Supports key rotation (doctor generates new keypair every year)

---

#### Table 2: `session_keys`
Stores temporary per-doctor session keys (TLL-based, auto-cleanup)

```sql
CREATE TABLE session_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Session key (stored encrypted at rest in DB)
    session_key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hash, never the actual key
    session_key_encrypted BYTEA NOT NULL,  -- AES-256-GCM encrypted session key
    
    -- Encryption metadata
    encrypted_for_doctor_public_key_fingerprint VARCHAR(64) NOT NULL,
      -- Which doctor public key was used to encrypt this?
      -- Used to validate key rotation
    
    -- Permissions & scope
    access_scope TEXT DEFAULT 'all_records',
      -- Values: 'all_records', 'lab_only', 'prescription_only'
      -- Granular control (future enhancement)
    
    -- TTL (Time To Live)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_at TIMESTAMP WITH TIME ZONE,  -- When to generate next session key
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'ACTIVE',
      -- Values: ACTIVE, ROTATED, REVOKED, EXPIRED
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit
    created_by_action VARCHAR(50),
      -- Values: 'PATIENT_INITIATED', 'DOCTOR_REQUESTED'
    ip_address_created INET,
    
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);

INDEXES:
- patient_id + doctor_id (find session for patient-doctor pair)
- session_key_hash (verify incoming session key)
- expires_at (cleanup expired keys)
- status (find all active sessions)
```

**Purpose**: Store temporary session keys that doctors use to decrypt records

**Why this design?**
- `session_key_hash`: Store hash, not plaintext. When doctor sends session key, verify hash matches.
- `encrypted_for_doctor_public_key_fingerprint`: If doctor rotates key, old encrypted session keys become invalid (forced re-sharing for new key)
- `expires_at`: Auto-expire after 7 days (or whatever TTL)
- `status`: Track lifecycle (ACTIVE → ROTATED/REVOKED/EXPIRED)

---

#### Table 3: `encrypted_record_vaults`
Stores encrypted copies of medical records on server

```sql
CREATE TABLE encrypted_record_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    
    -- Link to original medical record (metadata)
    medical_record_id UUID NOT NULL,  -- FK to medical_records table (loose coupling)
    
    -- Encrypted content
    encrypted_data BYTEA NOT NULL,  -- ChaCha20-Poly1305 encrypted
    authentication_tag BYTEA NOT NULL,  -- Poly1305 AEAD tag (check tampering)
    nonce BYTEA NOT NULL,  -- 96-bit random nonce (never reused with same key)
    
    -- Metadata (unencrypted for search)
    record_type VARCHAR(50) NOT NULL,
      -- LAB_REPORT, PRESCRIPTION, DIAGNOSIS, IMAGING, etc
    record_title VARCHAR(500),  -- Not encrypted (allows search)
    record_date DATE,  -- Date of medical record (not encrypted, allows date range search)
    
    -- Encryption key information
    encrypted_with_session_key_fingerprint VARCHAR(64),
      -- Which session key encrypted this record?
      -- Used to invalidate if session key compromised
    
    -- Audit trail
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    created_by_user_id UUID REFERENCES users(id),
    created_by_action VARCHAR(50),  -- 'PATIENT_UPLOAD' or 'DOCTOR_SHARED'
    
    -- Version (for future updates)
    version INT DEFAULT 1,
    
    -- Deletion (soft delete with reason)
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    deletion_reason VARCHAR(255),
    
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

INDEXES:
- patient_id (find all encrypted records for patient)
- record_type (filter by type)
- record_date (filter by date range)
- is_deleted (exclude deleted records)
```

**Purpose**: Server-side encrypted storage (patient's phone has plaintext original, server has encrypted backup)

**Why this design?**
- `authentication_tag`: Ensure ciphertext wasn't tampered with
- `nonce`: Required for AEAD decryption (stored with ciphertext)
- `record_type, record_title, record_date`: Unencrypted metadata for search + filtering
- Soft delete: Never actually delete (compliance + recovery)

---

#### Table 4: `cryptographic_audit_logs`
Immutable, signed audit trail for compliance

```sql
CREATE TABLE cryptographic_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Event details
    action VARCHAR(100) NOT NULL,
      -- Values: DOCTOR_ACCESSED_RECORD, PATIENT_SHARED, SESSION_KEY_REVOKED, etc
    resource_type VARCHAR(50) NOT NULL,
      -- Values: MEDICAL_RECORD, USER, SESSION_KEY, etc
    resource_id VARCHAR(255),
    
    -- Actors
    initiator_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      -- Who triggered this (doctor, patient, system, admin)
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      -- Who was affected (doctor, patient)
    
    -- Event metadata
    event_data JSONB,
      -- Flexible field for event context
      -- Example: {"record_count": 3, "scope": "lab_reports"}
    
    -- Network info
    ip_address INET,
    user_agent TEXT,
    request_id UUID,  -- Links to X-Request-ID header
    
    -- Cryptographic signature (proof of non-tampering)
    event_signature VARCHAR(1024),  -- Base64-encoded ECDSA signature
    server_public_key_fingerprint VARCHAR(64),  -- Which server key signed this
    
    -- Timestamps (immutable once created)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    
    -- Compliance fields
    compliance_note VARCHAR(500),  -- For auditor context
    
    -- IMMUTABLE: No updates allowed after insert
    CHECK (true)  -- Database constraints prevent updates
);

INDEXES:
- created_at DESC (retrieve recent logs)
- action (filter by action type)
- initiator_user_id (user's activity history)
- target_user_id (activity affecting user)
- request_id (trace single request)
```

**Purpose**: Tamper-proof audit trail for regulatory compliance

**Why this design?**
- `event_signature`: ECDSA signature proves entry wasn't modified
- `immutable`: Enforce via DB constraints + application logic (no UPDATE allowed)
- `JSONB`: Flexible event data for future event types
- `request_id`: Link multiple log entries to single request (tracing)

---

#### Table 5: `access_permission_audit` (extend existing)
Track permission request lifecycle with timestamps

```sql
ALTER TABLE access_permissions ADD COLUMN (
    cryptographic_verification_token VARCHAR(255),
    -- Token that cryptographically proves this permission grant
    
    approved_at TIMESTAMP WITH TIME ZONE,
    approved_by_signature VARCHAR(1024),
    
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255)
);
```

**Purpose**: Add cryptographic proof to existing permissions table

---

### Summary: Schema Change Map

| New Table | Purpose | TTL | Immutable |
|-----------|---------|-----|-----------|
| `user_keypairs` | Store public keys | None (manual rotation) | Soft yes (revoked flag) |
| `session_keys` | Temporary per-doctor keys | 7 days (auto-expire) | Yes (after expire) |
| `encrypted_record_vaults` | Server-side encrypted backup | None (soft delete) | Yes (no updates) |
| `cryptographic_audit_logs` | Signed audit trail | 7 years (compliance) | Yes (DB constraint) |

---

## Complete Workflows

### Workflow 1: Patient Setup (One-Time)

**Objective**: Patient registers, generates keypair, stores master key locally

**Flow**:

```
Step 1: Patient creates account
User: Taps "Sign Up" in Bionex app
Input: Email, Password, Phone

Step 2: Server validates & creates user
Server receives sign-up request
├── Validate email format
├── Hash password with bcrypt (existing logic)
├── Create Users.id
├── Response: user_id, temp_token
└── Patient status: ACTIVE

Step 3: Patient app generates keypair (Client-Side)
App runs in background (silent):
├── Generate ECDH P-256 keypair
│   private_key = secrets.token_bytes(32)
│   public_key = ECDH_P256.derive_public_key(private_key)
├── Store private_key in device keychain
│   iOS: Keychain Services
│   Android: KeyStore with biometric protection
│   Web: IndexedDB with password encryption
├── Keep public_key in RAM (need to send to server)
└── Never log or display private_key

Step 4: Patient uploads public key to server
App sends:
POST /api/v1/keys/register
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkw...",
  "device_info": "iPhone 14 Pro"
}

Step 5: Server registers public key
Receive public key
├── Parse & validate PEM format
├── Extract curve (must be P-256)
├── Compute fingerprint: SHA256(public_key_pem) = "5a7c9f..."
├── Check if fingerprint already registered (prevent duplicates)
├── Insert into user_keypairs table:
│   user_id = patient_id
│   public_key_pem = received_pem
│   public_key_fingerprint = "5a7c9f..."
│   key_algorithm = "ECDH_P256"
│   created_at = now()
└── Response: success, fingerprint

Step 6: Patient creates master key (Client-Side)
App runs:
├── User enters password: "MySecure@Pass123"
├── Generate salt = SHA256(device_id + user_id)
├── Derive master_key using HKDF:
│   master_key = HKDF(
│     ikm=password,
│     salt=salt[32 bytes],
│     info="bionex_patient_master_key",
│     hash_algo=SHA256,
│     length=32
│   )
│   Result: master_key = b'\x4a\x3f\x9e...' [256 bits]
├── Store master_key in device keychain (protected by biometric/pattern)
├── Clear password from memory
└── Never send master_key to server

Step 7: Patient completes setup
App shows:
├── ✅ Account created
├── ✅ Encryption keys generated
├── ✅ Ready to upload medical records
└── Button: "Next"

---

Result State:
Patient DB:
├── Users: { id: patient_id, email, password_hash, role: PATIENT }
└── user_keypairs: { user_id: patient_id, public_key_pem, fingerprint }

Patient Device (Secure Storage):
├── private_key: [encrypted in keychain]
├── master_key: [encrypted in keychain]
└── public_key: [in app memory]
```

**Error Cases**:
- Network fails during public key upload → Retry, store public_key locally first
- Device doesn't support biometric → Fall back to password-only unlock
- Same patient registers on second device → New keypair generated (different encryption on each device)

---

### Workflow 2: Patient Uploads Medical Record (Recurring)

**Objective**: Patient adds new medical record (locally encrypted, optionally backup to server)

**Flow**:

```
Step 1: Patient creates/receives medical record
User: Taps "Add Record" → Enters data
Input:
├── Type: LAB_REPORT
├── Title: "Blood Test - CBC"
├── Date: 2026-04-18
├── Content: "RBC: 4.5, WBC: 7.2, ..."
├── File: (optional) Blood_Test.pdf

Step 2: App encrypts locally (Client-Side)
App handles:
├── Generate nonce = secrets.token_bytes(12)  [96 bits, random]
├── plaintext_record = serialize(title, content, date, file)
├── Encrypt using ChaCha20-Poly1305:
│   (ciphertext, auth_tag) = ChaCha20.encrypt(
│     key=master_key,
│     nonce=nonce,
│     plaintext=plaintext_record,
│     aad=f"patient:{user_id}"  [authenticated, not encrypted]
│   )
├── local_record = {
│   id: generate_uuid(),
│   ciphertext: base64(ciphertext),
│   auth_tag: base64(auth_tag),
│   nonce: base64(nonce),
│   created_at: now()
│ }
├── Store in app's local database (SQLite with encryption)
└── Show to user: "✅ Saved Locally"

Step 3: Option - Backup encrypted to server (async)
User: Taps "Enable Cloud Backup"
App sends:
POST /api/v1/records/backup
Header: Authorization: Bearer {access_token}
Body:
{
  "medical_record_id": "rec_xyz",
  "encrypted_data": base64(ciphertext),
  "auth_tag": base64(auth_tag),
  "nonce": base64(nonce),
  "record_type": "LAB_REPORT",
  "record_title": "Blood Test - CBC",
  "record_date": "2026-04-18"
}

Step 4: Server stores encrypted backup
Receive backup request
├── Verify Authorization token (existing JWT logic)
├── Extract patient_id from token
├── Generate session_key_fingerprint (current session key being used)
├── Insert into encrypted_record_vaults:
│   patient_id = patient_id
│   encrypted_data = received_ciphertext
│   auth_tag = received_auth_tag
│   nonce = received_nonce
│   record_type = LAB_REPORT
│   record_title = "Blood Test - CBC"
│   record_date = 2026-04-18
│   created_by_action = "PATIENT_UPLOAD"
│   encrypted_with_session_key_fingerprint = current_session_fingerprint
├── Log audit event: "RECORD_BACKED_UP" for patient
└── Response: { backup_id: "backup_abc", status: "stored" }

Step 5: Audit log created
Server logs:
INSERT INTO cryptographic_audit_logs (
  action = "PATIENT_UPLOADED_RECORD",
  resource_type = "MEDICAL_RECORD",
  initiator_user_id = patient_id,
  event_data = { record_id, record_type, backup_id },
  ip_address = request.ip,
  event_signature = ECDSA_Sign(server_private_key, event_json),
  created_at = now()
)

---

Result State:
App Local Storage:
└── SQLite: medical_records[plaintext, encrypted with master_key]

Server Database:
├── encrypted_record_vaults: { encrypted_data, auth_tag, nonce }
├── cryptographic_audit_logs: { action: UPLOADED, event_signature }
└── No plaintext stored anywhere on server
```

**Error Cases**:
- User loses internet → Record saved locally, syncs when online
- Backup fails → App retries with exponential backoff
- File too large (>50MB) → Compress before encryption

---

### Workflow 3: Patient Grants Access to Doctor (Sharing)

**Objective**: Patient approves doctor's access, generates session key, doctor can decrypt records

**Flow**:

```
Step 1: Doctor requests access
Doctor: Clicks "Request Access" to specific patient
Input: Patient ID or Patient Email

Doctor app sends:
POST /api/v1/sharing/request
Header: Authorization: Bearer {doctor_token}
Body:
{
  "patient_id": "pat_xyz",
  "access_scope": "all_records",  # or "lab_only", "prescription_only"
  "reason": "Routine checkup"
}

Step 2: Server creates permission request (PENDING)
Receive doctor request
├── Validate doctor token (extract doctor_id)
├── Verify patient exists
├── Check if doctor already has active permission (prevent duplicates)
├── Create AccessPermission row:
│   patient_id = pat_xyz
│   granted_to_user_id = doctor_id
│   initiated_by = InitiatedBy.DOCTOR
│   request_status = RequestStatus.PENDING
│   access_token = NULL (not issued yet)
│   expires_at = NULL
│   scope = "all_records"
├── Log audit: "DOCTOR_REQUESTED_ACCESS"
└── Response: { permission_id: "perm_abc", status: "PENDING" }

Step 3: Patient receives notification
Patient notification: "Dr. Smith requested access to your records"
├── Shows doctor name, specialty, reason
├── Options: [APPROVE] [REJECT]

Step 4: Patient approves (Patient App)
User: Taps [APPROVE]
App sends:
POST /api/v1/sharing/approve/{permission_id}
Header: Authorization: Bearer {patient_token}
Body: {}

Step 5: Server generates session key (CRITICAL STEP)
Receive approval request
├── Verify permission exists and status = PENDING
├── Verify patient_id matches patient token
├── Fetch doctor's public key:
│   doctor_public_key = SELECT public_key_pem FROM user_keypairs
│                       WHERE user_id = granted_to_user_id
├── Generate ephemeral session key:
│   session_key = secrets.token_bytes(32)  [256 bits]
│   session_key_hash = SHA256(session_key)
├── Encrypt session key with doctor's public key:
│   session_key_encrypted = ChaCha20.encrypt(
│     key=KDF(doctor_public_key),
│     plaintext=session_key,
│     aad=f"session_key_for_doctor:{doctor_id}"
│   )
│   [Note: In practice, use RSA for asymmetric encryption here,
│    or implement ECIES wrapper. For this example, conceptual.]
├── Generate unique sharing token:
│   sharing_token = secrets.token_urlsafe(48)
│   sharing_token_hash = SHA256(sharing_token)
├── Store in session_keys table:
│   patient_id = pat_xyz
│   doctor_id = doctor_id
│   session_key_hash = sharing_token_hash  [for verification]
│   session_key_encrypted = session_key_encrypted
│   expires_at = now() + 7 days
│   status = ACTIVE
│   created_at = now()
├── Update AccessPermission:
│   access_token = sharing_token
│   request_status = RequestStatus.APPROVED
│   expires_at = expires_at
│   approved_at = now()
├── Log audit: "PATIENT_APPROVED_SHARING" [signed]
└── Response: { 
      sharing_token: "eyJ0eXAi...",
      expires_in_seconds: 604800,
      message: "Access granted for 7 days"
    }

Step 6: Patient sends token to doctor (Out-of-band)
Patient can:
├── Option A: NFC tap (Apple Pay, Android Beam)
├── Option B: QR code scan
├── Option C: SMS/Email link
└── Option D: Manual copy-paste

---

Result State:
Patient sees: ✅ Access shared with Dr. Smith (expires in 7 days)
Doctor sees: ⏳ Waiting for access (doesn't have token yet; patient will share)

Server Database:
├── AccessPermission: { status: APPROVED, access_token: sharing_token }
├── session_keys: { doctor_id, session_key_hash, expires: 7 days }
├── cryptographic_audit_logs: { action: APPROVED_SHARING, signature }
└── No plaintext records sent yet
```

**Error Cases**:
- Patient rejects permission → Mark as REJECTED, log reason
- Patient ignores request 15 days → Mark as EXPIRED
- Session key expires → Doctor can't decrypt records, must re-request

---

### Workflow 4: Doctor Accesses Patient Records (The Money Flow)

**Objective**: Doctor decrypts and views patient's medical records

**Flow**:

```
Step 1: Doctor receives sharing token
Patient sends token via NFC/QR/SMS:
Token: "eyJ0eXAi...sharing_token..."

Doctor app stores token locally

Step 2: Doctor requests session key from server
Doctor app sends:
GET /api/v1/sharing/session-key/{sharing_token}
Header: Authorization: Bearer {doctor_token}

Step 3: Server validates & returns encrypted session key
Receive request
├── Extract sharing_token from URL
├── Query AccessPermission:
│   SELECT * FROM access_permissions
│   WHERE access_token = sharing_token
│     AND request_status = APPROVED
├── Verify not expired: expires_at > now()
├── Verify doctor_id matches authorization token
├── Query session_keys:
│   SELECT * FROM session_keys
│   WHERE access_token = sharing_token
│     AND expires_at > now()
│     AND status = ACTIVE
├── Verify doctor row: granted_to_user_id matches

If all valid:
├── Fetch encrypted session key:
│   session_key_encrypted = query.session_key_encrypted
│   encrypted_with_doctor_fingerprint = query.encrypted_for_doctor_public_key
├── Log audit: "DOCTOR_RETRIEVED_SESSION_KEY"
└── Response: {
      "session_key_encrypted": base64(session_key_encrypted),
      "doctor_fingerprint": encrypted_with_doctor_fingerprint,
      "record_ids": [rec_1, rec_2, rec_3],
      "scope": "all_records"
    }

Else (invalid/expired):
└── Return 403 Forbidden + audit log attempt

Step 4: Doctor app decrypts session key (Client-Side)
App handles:
├── Receive session_key_encrypted
├── Load doctor's private_key from device keychain
├── Decrypt using ChaCha20 (or ECIES in production):
│   session_key = ChaCha20.decrypt(
│     key=KDF(doctor_private_key),
│     ciphertext=session_key_encrypted,
│     aad=f"session_key_for_doctor:{doctor_id}"
│   )
├── Verify decryption successful (no errors)
└── Store session_key in app memory (will be cleared after records accessed)

Result: doctor_app now has plaintext session_key [valid for 7 days or current session]

Step 5: Doctor requests encrypted records
Doctor app sends:
GET /api/v1/records/encrypted?record_ids=rec_1,rec_2,rec_3
Header: Authorization: Bearer {doctor_token}
Header: X-Sharing-Token: {sharing_token}
Header: X-Session-Key-Hash: SHA256(session_key)  [not plaintext!]

Step 6: Server verifies and returns encrypted records
Receive request
├── Verify X-Sharing-Token valid (not expired, approved)
├── Verify X-Session-Key-Hash:
│   hash_from_request = X-Session-Key-Hash header
│   hash_in_db = SELECT session_key_hash FROM session_keys
│   IF hash_from_request == hash_in_db:
│     ✅ Session key matches
│   ELSE:
│     ❌ Reject (fake session key or tampering)
├── Verify doctor has permission for these record_ids
├── Query encrypted_record_vaults:
│   SELECT encrypted_data, auth_tag, nonce
│   FROM encrypted_record_vaults
│   WHERE medical_record_id IN (rec_1, rec_2, rec_3)
│     AND patient_id = permission.patient_id
├── Log audit: "DOCTOR_ACCESSED_RECORDS" [with record count, IP, timestamp]
└── Response: {
      "records": [
        {
          "id": "rec_1",
          "encrypted_data": base64(ciphertext1),
          "auth_tag": base64(auth_tag1),
          "nonce": base64(nonce1),
          "record_type": "LAB_REPORT",
          "record_title": "Blood Test"
        },
        ...
      ]
    }

Step 7: Doctor app decrypts records (Client-Side)
App handles (for each record):
├── Receive encrypted_record:
├── Load session_key from memory (kept from Step 4)
├── Decrypt using ChaCha20-Poly1305:
│   (plaintext, is_authentic) = ChaCha20.decrypt(
│     key=session_key,
│     nonce=received_nonce,
│     ciphertext=encrypted_data,
│     auth_tag=auth_tag,
│     aad=f"patient:{patient_id}"
│   )
├── Verify is_authentic:
│   IF authentic:
│     ✅ Record not tampered with
│     Display: plaintext record to doctor
│   ELSE:
│     ❌ Alert: "Record integrity check failed, possible tampering"
│     Don't display
├── Store plaintext in app memory (not cached to disk unless encrypted)
└── Clear session_key from memory after all records accessed

Step 8: Doctor views records in app
App displays:
├── Blood Test - CBC
├── RBC: 4.5, WBC: 7.2, ...
├── Date: 2026-04-18
├── [View Full] [Share Notes]
└── All plaintext, human-readable

Step 9: Background - Audit log signed
Server async process:
├── Fetch audit entry: action="DOCTOR_ACCESSED_RECORDS"
├── Serialize to JSON: { action, doctor_id, record_ids, timestamp, ip }
├── Sign with server's private key:
│   signature = ECDSA_Sign(
│     server_private_key,
│     SHA256(json_entry)
│   )
├── Store signature in audit log:
│   INSERT INTO cryptographic_audit_logs (..., event_signature)

---

Result State:
Doctor sees: 3 plaintext medical records
Server database: encrypted_record_vaults unchanged
Audit trail: "DOCTOR_ACCESSED_RECORDS" signed entry created

Patient could verify at any time:
├── Check audit logs
├── Verify signature (using server's public key)
├── Confirm: "Dr. Smith accessed 3 records on 2026-04-18 at 10:30 AM from 192.168.1.5"
```

**Error Cases**:
- Session key expired (> 7 days) → Doctor must re-request access
- Doctor's private key compromised → Doctor can't request sharing token hash (can't decrypt), patient must revoke
- Network failure mid-download → Retry (idempotent, same encrypted records returned)
- Authentication tag fails → Record was tampered with, don't display
- Doctor tries to access records from different patient → Rejected (permission check)

---

### Workflow 5: Patient Revokes Doctor Access (Emergency)

**Objective**: Patient instantly invalidates doctor's session key (doctor can't access records anymore)

**Flow**:

```
Step 1: Patient decides to revoke
Patient: Opens "Active Sharing" → Sees "Dr. Smith (expires in 5 days)" → Taps [REVOKE]

Step 2: Patient app requests revocation
App sends:
POST /api/v1/sharing/revoke/{permission_id}
Header: Authorization: Bearer {patient_token}
Body: {
  "reason": "Changed my mind / Switched doctors / Data breach suspected"
}

Step 3: Server invalidates session key
Receive revoke request
├── Verify permission_id exists and belongs to patient
├── Update AccessPermission:
│   request_status = RequestStatus.REVOKED
│   revoked_at = now()
├── Update session_keys (find all active for this permission):
│   UPDATE session_keys
│   SET status = REVOKED, revoked_at = now()
│   WHERE permission_id = {permission_id}
├── Fetch session_key_hash to understand what to invalidate
├── Log audit: "PATIENT_REVOKED_ACCESS" [signed]
│   event_data: { doctor_id, permission_id, reason }
└── Response: { status: "revoked", message: "Access removed for Dr. Smith" }

Step 4: Immediate effect
Doctor app has encrypted_session_key in memory
├── Session key now invalid on server
├── If doctor tries to use old session key:
│   Server query: SELECT * FROM session_keys
│                 WHERE session_key_hash = hash_of_old_key
│                   AND status = REVOKED
│   Result: Found but status=REVOKED
│   Response: 403 Forbidden "Access has been revoked"

Step 5: Patient verification
Patient can check:
├── Visit "Audit Log"
├── See entry: "Dr. Smith's access revoked at 10:35 AM"
├── Verify signature: ✅ Event is authentic
├── Confirm: Access is gone, no further access possible

---

Result State:
Patient: ✅ "Access revoked for Dr. Smith"
Doctor: ❌ "Session expired - Request access again"
Server: AccessPermission.status = REVOKED, session_keys.status = REVOKED
Audit: Immutable log entry with signature

Compliance: Can prove to regulator that access was revoked on [timestamp]
```

**Error Cases**:
- Network fails during revocation → Patient retries, with idempotency key (no double-revocation)
- Doctor's device still cached old session key → Doctor can't actually use it (server rejects)

---

### Workflow 6: Session Key Rotation (Automatic)

**Objective**: Every 7 days, invalidate old session key, force doctor to re-request

**Flow**:

```
Step 1: Scheduled job runs daily (e.g., 2 AM UTC)
Backend scheduler (APScheduler or Celery):
├── Query session_keys expiring in next 24 hours:
│   SELECT * FROM session_keys
│   WHERE expires_at BETWEEN now() AND now() + 1 day
│     AND status = ACTIVE
└── For each key:

Step 2: Rotate session key
For each key:
├── Generate new session_key = secrets.token_bytes(32)
├── Encrypt with doctor's current public key
├── Create NEW row in session_keys:
│   doctor_id (same)
│   session_key_encrypted (new, encrypt fresh)
│   status = ACTIVE
│   expires_at = now() + 7 days
│   rotation_at = now()
├── Mark OLD row:
│   status = ROTATED
│   rotated_at = now()
├── Log audit: "SESSION_KEY_ROTATED" [system action]
└── Optionally notify doctor: "Your access key will expire in 1 hour, please reconnect"

Result:
├── Old session key (hash) becomes invalid
├── Doctor still has same access_token (sharing_token)
├── But when requesting session-key, gets NEW encrypted session key
├── Doctor's app decrypts with same private_key (works)
├── Forward secrecy: Old plaintext records couldn't be decrypted even if key stolen

---

Implementation Code Concept:
@scheduler.scheduled_job('cron', hour=2)
def rotate_session_keys():
    expiring_keys = db.query(session_keys).filter(
        session_keys.expires_at < now() + timedelta(days=1),
        session_keys.status == 'ACTIVE'
    ).all()
    
    for old_key in expiring_keys:
        doctor_public_key = get_doctor_public_key(old_key.doctor_id)
        new_session_key = secrets.token_bytes(32)
        new_encrypted = encrypt_symmetric(new_session_key, doctor_public_key)
        
        db.add(session_keys(
            patient_id=old_key.patient_id,
            doctor_id=old_key.doctor_id,
            session_key_encrypted=new_encrypted,
            expires_at=now() + timedelta(days=7),
            status='ACTIVE'
        ))
        
        old_key.status = 'ROTATED'
        db.commit()
        
        log_audit("SESSION_KEY_ROTATED", old_key.id, sign=True)
```

---

## API Endpoints

### Authentication & Key Management

#### 1. Register Public Key (Patient/Doctor First Time)
```http
POST /api/v1/keys/register
Authorization: Bearer {access_token}

Request:
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHK...==\n-----END PUBLIC KEY-----",
  "device_info": "iPhone 14 Pro / Android 14 / Web",
  "device_id": "unique_device_identifier"
}

Response (201 Created):
{
  "public_key_fingerprint": "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f",
  "registered_at": "2026-04-18T10:00:00Z",
  "algorithm": "ECDH_P256",
  "message": "Public key registered successfully"
}

Errors:
- 400: Invalid PEM format or wrong curve (must be P-256)
- 409: Public key already registered by this user
- 401: Unauthorized
```

#### 2. Rotate Public Key (Annual Security Practice)
```http
POST /api/v1/keys/rotate
Authorization: Bearer {access_token}

Request:
{
  "old_public_key_fingerprint": "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f",
  "new_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "reason": "Annual rotation / Compromised / Device replacement"
}

Response (200 OK):
{
  "old_fingerprint": "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f",
  "new_fingerprint": "a1c2e3f4b5d6a7c8e9f0...",
  "rotated_at": "2026-04-18T10:30:00Z",
  "active_sessions_invalidated": 5,
  "message": "All active sessions invalidated. Doctors must re-request access."
}

Behavior:
- Mark old key as revoked
- All active session_keys for this user become invalid
- Doctors see "Session expired, please reconnect"
```

#### 3. List Public Keys (for device management)
```http
GET /api/v1/keys/my-keys
Authorization: Bearer {access_token}

Response (200 OK):
[
  {
    "fingerprint": "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f",
    "device_info": "iPhone 14 Pro",
    "created_at": "2026-01-15T08:00:00Z",
    "rotated_at": "2026-04-15T08:00:00Z",
    "status": "ACTIVE",
    "active_sessions": 3
  },
  {
    "fingerprint": "b2d3e4f5a6b7c8d9e0f1...",
    "device_info": "Android Phone",
    "created_at": "2026-02-20T10:00:00Z",
    "rotated_at": null,
    "status": "REVOKED",
    "revoked_at": "2026-04-10T12:00:00Z",
    "revocation_reason": "Device lost"
  }
]
```

---

### Record Management (New Endpoints)

#### 4. Upload Encrypted Record Backup
```http
POST /api/v1/records/backup
Authorization: Bearer {patient_access_token}

Request:
{
  "encrypted_data": "base64_encoded_ciphertext",
  "auth_tag": "base64_encoded_poly1305_tag",
  "nonce": "base64_encoded_96bit_nonce",
  "record_type": "LAB_REPORT",
  "record_title": "Blood Test - Complete Blood Count",
  "record_date": "2026-04-18",
  "file_name": "blood_test.pdf"
}

Response (201 Created):
{
  "backup_id": "vault_abc123",
  "patient_id": "pat_xyz",
  "stored_at": "2026-04-18T10:00:00Z",
  "checksum": "sha256_hash_for_verification",
  "message": "Encrypted record backed up successfully"
}

Errors:
- 400: Invalid encryption format (wrong nonce size, missing tag)
- 413: File too large (>50MB)
- 401: Unauthorized
```

#### 5. Download Encrypted Records (Doctor)
```http
GET /api/v1/records/encrypted
Authorization: Bearer {doctor_access_token}
X-Sharing-Token: {sharing_token}
X-Session-Key-Hash: {sha256_hash_of_session_key}

Query Parameters:
- record_ids: comma-separated list of record IDs
- filter_type: optional (LAB_REPORT, PRESCRIPTION, etc)
- filter_date_from: optional (YYYY-MM-DD)
- filter_date_to: optional (YYYY-MM-DD)

Response (200 OK):
{
  "records": [
    {
      "id": "rec_001",
      "patient_id": "pat_xyz",
      "encrypted_data": "base64_encrypted",
      "auth_tag": "base64_auth_tag",
      "nonce": "base64_nonce",
      "record_type": "LAB_REPORT",
      "record_title": "Blood Test",
      "record_date": "2026-04-18",
      "created_by": "patient_id",
      "version": 1
    },
    ...
  ],
  "total_count": 5,
  "returned_count": 3
}

Errors:
- 403: Session key invalid or expired
- 403: No permission to access these records
- 401: Unauthorized
- 410: Sharing token has been revoked by patient
```

#### 6. Get Record Metadata (Search-Friendly)
```http
GET /api/v1/records/metadata
Authorization: Bearer {doctor_access_token}
X-Sharing-Token: {sharing_token}

Query Parameters:
- search_type: optional search filter
- date_range: optional date filter
- patient_id: optional (for doctors who see multiple patients)

Response (200 OK):
{
  "patient_id": "pat_xyz",
  "records": [
    {
      "id": "rec_001",
      "record_type": "LAB_REPORT",
      "record_title": "Blood Test - CBC",
      "record_date": "2026-04-18",
      "created_at": "2026-04-18T09:30:00Z",
      "is_encrypted": true,
      "size_bytes": 2048
    },
    ...
  ]
}

Note: Metadata is NOT encrypted (allows search without decrypting every record)
```

---

### Sharing & Access Control

#### 7. Initiate Sharing (Patient → Doctor)
```http
POST /api/v1/sharing/initiate
Authorization: Bearer {patient_access_token}

Request:
{
  "doctor_user_id": "doc_123",
  "access_scope": "all_records",  # or specific scopes
  "expires_in_days": 7,
  "reason": "Routine consultation"
}

Response (201 Created):
{
  "permission_id": "perm_abc",
  "doctor_id": "doc_123",
  "sharing_token": "eyJ0eXAiOiJKV1QiLC...",
  "expires_at": "2026-04-25T10:00:00Z",
  "access_scope": "all_records",
  "status": "APPROVED",
  "message": "Access granted immediately"
}

Note: Patient-initiated = immediate approval (no doctor request needed)
```

#### 8. Doctor Request Access (Doctor → Patient)
```http
POST /api/v1/sharing/request
Authorization: Bearer {doctor_access_token}

Request:
{
  "patient_id": "pat_xyz",
  "access_scope": "all_records",
  "reason": "Follow-up appointment scheduled",
  "expires_in_days": 3
}

Response (201 Created):
{
  "permission_id": "perm_xyz",
  "status": "PENDING",
  "patient_id": "pat_xyz",
  "requested_at": "2026-04-18T10:00:00Z",
  "message": "Request sent to patient"
}

Note: Doctor request = patient must approve ()
```

#### 9. Approve Permission (Patient Approves Doctor Request)
```http
POST /api/v1/sharing/approve/{permission_id}
Authorization: Bearer {patient_access_token}

Request: {} (empty body)

Response (200 OK):
{
  "permission_id": "perm_xyz",
  "status": "APPROVED",
  "sharing_token": "eyJ0eXAi...",
  "doctor_id": "doc_123",
  "expires_at": "2026-04-25T10:00:00Z",
  "message": "Access granted. Share this code with doctor"
}

Process:
- Server generates session_key
- Encrypts with doctor's public key
- Returns sharing_token to patient
- Patient sends token to doctor (NFC/QR/SMS)
```

#### 10. Retrieve Session Key (Doctor Gets Encrypted Key)
```http
GET /api/v1/sharing/session-key/{sharing_token}
Authorization: Bearer {doctor_access_token}

Response (200 OK):
{
  "session_key_encrypted": "base64_encrypted_key",
  "doctor_fingerprint": "a1c2e3f4b5d6a7c8e9f0...",
  "expires_at": "2026-04-25T10:00:00Z",
  "access_scope": "all_records",
  "note": "Decrypt using your private key"
}

Process:
- Doctor decrypts using their private_key (on-device)
- Gets plaintext session_key
- Uses session_key to decrypt medical records
```

#### 11. Revoke Access (Patient Revokes Doctor)
```http
POST /api/v1/sharing/revoke/{permission_id}
Authorization: Bearer {patient_access_token}

Request:
{
  "reason": "Changed doctors / Data breach / No longer needed"
}

Response (200 OK):
{
  "permission_id": "perm_xyz",
  "status": "REVOKED",
  "doctor_id": "doc_123",
  "revoked_at": "2026-04-18T10:30:00Z",
  "message": "Access revoked. Doctor can no longer access your records."
}

Immediate Effect:
- Session key marked as REVOKED
- All doctor's requests with this token → 403 Forbidden
```

#### 12. List Active Sharing (Patient Sees Who Has Access)
```http
GET /api/v1/sharing/sessions
Authorization: Bearer {patient_access_token}

Response (200 OK):
{
  "active_sessions": [
    {
      "permission_id": "perm_abc",
      "doctor_id": "doc_123",
      "doctor_name": "Dr. Smith",
      "access_scope": "all_records",
      "shared_at": "2026-04-15T08:00:00Z",
      "expires_at": "2026-04-25T08:00:00Z",
      "records_accessed": 3,
      "last_accessed_at": "2026-04-18T09:00:00Z",
      "status": "ACTIVE",
      "initiated_by": "PATIENT"
    },
    ...
  ],
  "total": 5,
  "expiring_in_3_days": 1
}
```

---

### Audit & Verification

#### 13. Get Audit Log (Patient/Auditor Reviews)
```http
GET /api/v1/audit/logs
Authorization: Bearer {patient_access_token}

Query Parameters:
- action: optional (DOCTOR_ACCESSED_RECORD, PATIENT_SHARED, etc)
- date_from: optional (YYYY-MM-DD)
- date_to: optional (YYYY-MM-DD)
- initiator_type: optional (DOCTOR, PATIENT, ADMIN, SYSTEM)
- page: optional (pagination)

Response (200 OK):
{
  "logs": [
    {
      "id": "log_001",
      "action": "DOCTOR_ACCESSED_RECORD",
      "initiator": "Dr. Smith (doc_123)",
      "resource": "rec_001 (Blood Test - CBC)",
      "timestamp": "2026-04-18T10:00:00Z",
      "ip_address": "192.168.1.5",
      "status": "SUCCESS",
      "event_signature": "MEUCIBcX...",  # ECDSA signature
      "verified": true,  # Signature verification status
      "event_data": {
        "records_accessed": 1,
        "duration_seconds": 30
      }
    },
    ...
  ],
  "total": 150,
  "verified_count": 150,
  "tampered_count": 0
}
```

#### 14. Verify Audit Entry (Patient Checks Integrity)
```http
POST /api/v1/audit/verify/{log_id}
Authorization: Bearer {patient_access_token}

Response (200 OK):
{
  "log_id": "log_001",
  "verified": true,
  "signature_valid": true,
  "message": "Event is authentic and unmodified",
  "server_public_key_used": "5a7c9f3e...",
  "event": {
    "action": "DOCTOR_ACCESSED_RECORD",
    ...
  }
}

Or:

Response (400 Bad Request):
{
  "verified": false,
  "signature_valid": false,
  "message": "Signature verification FAILED - event may have been tampered with!",
  "alert_level": "HIGH"
}
```

---

## Implementation Phases

### Phase 0: Foundation (Already Complete) ✅
- FastAPI + PostgreSQL setup
- JWT authentication + 2FA
- Audit logging (basic)
- Field-level encryption (Fernet)
- Role-based access control

### Phase 1: Cryptographic Infrastructure (Week 1-4)

**Deliverables**:
- ECDH keypair generation
- ChaCha20-Poly1305 encryption/decryption utilities
- HKDF key derivation
- ECDSA signing module
- Add `cryptography` library to requirements.txt

**Tasks**:
1. Create `app/security/crypto.py` module:
   - `generate_ecdh_keypair()` - Generate P-256 keypair
   - `encrypt_chacha20(key, plaintext, aad)` - Encrypt with AEAD
   - `decrypt_chacha20(key, ciphertext, nonce, auth_tag, aad)` - Decrypt
   - `derive_key_hkdf(password, salt, info)` - Key derivation
   - `sign_event(private_key, event_json)` - Sign audit events
   - `verify_signature(public_key, event_json, signature)` - Verify

2. Create `app/models/user_keypairs.py` (ORM model)
3. Create database migration for `user_keypairs` table
4. Write unit tests for each crypto function
5. Document key formats (PEM for storage, bytes for operations)

**Estimated Effort**: 60-80 hours

---

### Phase 2: Database & API Foundation (Week 5-8)

**Deliverables**:
- New database tables
- API endpoints (endpoints #1-6, 13-14)
- Middleware for session key validation

**Tasks**:
1. Create database migrations:
   - `user_keypairs` table
   - `session_keys` table
   - Add columns to `cryptographic_audit_logs`

2. Create ORM models:
   - `app/models/session_key.py`
   - `app/models/encrypted_record_vault.py`
   - Update `app/models/cryptographic_audit_log.py`

3. Implement endpoints:
   - POST /keys/register (Endpoint #1)
   - GET /records/backup (Endpoint #4)
   - GET /records/encrypted (Endpoint #5)
   - GET /records/metadata (Endpoint #6)
   - GET /audit/logs (Endpoint #13)
   - POST /audit/verify/{log_id} (Endpoint #14)

4. Create middleware:
   - Validate session key before accessing records
   - Extract and verify X-Sharing-Token header
   - Log access with IP + user agent

5. Integration tests with Pytest

**Estimated Effort**: 100-120 hours

---

### Phase 3: Sharing Workflows (Week 9-12)

**Deliverables**:
- Complete sharing flow (endpoints #7-12)
- Session key generation + encryption
- Revocation logic

**Tasks**:
1. Implement endpoints:
   - POST /sharing/initiate (Endpoint #7)
   - POST /sharing/request (Endpoint #8)
   - POST /sharing/approve/{perm_id} (Endpoint #9)
   - GET /sharing/session-key/{token} (Endpoint #10)
   - POST /sharing/revoke/{perm_id} (Endpoint #11)
   - GET /sharing/sessions (Endpoint #12)

2. Session key management:
   - Generate ephemeral session keys
   - Encrypt with doctor's public key
   - TTL-based expiration (default 7 days)
   - Rotation logic (auto-generate new key every 7 days)

3. Revocation:
   - Mark session keys as REVOKED
   - Reject doctor requests immediately
   - Log irrevocation events

4. Notifications:
   - Patient gets notification when doctor requests
   - Doctor gets notification when access approved/revoked
   - Email + push notifications

5. Integration tests

**Estimated Effort**: 120-150 hours

---

### Phase 4: Client Applications (Week 13-20)

**Out of Scope for Backend** (Frontend Teams):

**Patient App (iOS + Android)**:
- Keypair generation on device
- Master key derivation from password
- Local record storage (encrypted)
- Sharing UI (approve/reject doctor requests)
- NFC/QR code generation for sharing
- Audit log viewer
- Screenshot detection (prevent data leaks)

**Doctor App (iOS + Android + Web)**:
- Receive sharing tokens
- Decrypt session keys using private key
- View patient records
- Offline caching (encrypted records)
- Search/filter records
- Export records (with patient approval)

---

### Timeline Summary

| Phase | Duration | Cumulative | Status |
|-------|----------|-----------|--------|
| Phase 0 | Complete | Complete | ✅ Done |
| Phase 1 | 4 weeks | 4 weeks | Ready to start |
| Phase 2 | 4 weeks | 8 weeks | After Phase 1 |
| Phase 3 | 4 weeks | 12 weeks | After Phase 2 |
| Phase 4 | 6-8 weeks | 18-20 weeks | After Phase 3 |

---

## Security Considerations

### 1. Key Compromise Scenarios

#### Scenario A: Doctor's Private Key Stolen
**Today**: Hacker can decrypt all records doctor has ever accessed (lifetime compromise)

**With this system**: 
- Hacker can decrypt records from last 7 days only (session key TTL)
- Records older than 7 days are unreadable (old session key expired)
- Patient immediately revokes access → remaining keys become invalid
- Audit shows "Session key compromised on [date]"

**Mitigation**:
- Encourage doctors to store private key in hardware security module (HSM) or Secure Enclave
- Implement key rotation on device (generate new keypair monthly)
- Revocation API allows patient to instantly invalidate access

---

#### Scenario B: Patient's Master Key Stolen
**Today**: Hacker can read patient's personal records offline (unlimited)

**With this system**:
- Hacker can only read records on patient's device (local encryption)
- Can't decrypt records on server (different encryption layer)
- Can't decrypt records on doctor's device (different session keys)

**Mitigation**:
- Use device-level encryption (iOS Keychain, Android KeyStore biometric)
- Implement account recovery via email + SMS 2FA
- Patient can rotate master key (re-encrypt all records)
- Require online verification for sensitive operations

---

#### Scenario C: Server Database Compromised
**Today**: Hacker gets all plaintext medical records (catastrophic)

**With this system**:
- Hacker gets encrypted records (useless without session keys)
- Encrypted session keys are encrypted AGAIN with doctor's public keys (Hacker can't use even if in DB)
- Audit logs signed with server's private key (can prove what happened)

**Mitigation**:
- Store database encryption key in separate HSM
- Implement database encryption at rest (PostgreSQL pgcrypto or transparent encryption)
- Breach detection: monitor access patterns for anomalies
- Immediate revocation of all session keys if breach detected

---

### 2. Network Security

#### TLS 1.3 (Already Have)
- Encrypt data in transit
- Certificate pinning (optional, for high-security deployments)
- Prevent man-in-the-middle attacks

#### RECOMMENDED: Certificate Pinning
```python
# In doctor/patient apps
# Pin server's certificate SHA256 hash
PINNED_CERTS = [
  "5a7c9f3e2b1d4a8c6e9f2b5d3a1c7e4f",  # Primary cert
  "b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",  # Backup cert
]

# Verify during TLS handshake
# Reject if server cert doesn't match pinned hash
```

---

### 3. Audit Log Integrity

#### Cryptographic Signatures
Every audit event is signed with server's ECDSA private key. This proves:
- Event wasn't modified after creation
- Event came from authorized server
- Timestamp is accurate

#### Verification by Patient
Patient can download public key and verify signatures:
```python
# Patient runs this to verify audit logs
for audit_entry in patient_audit_logs:
  sig_valid = verify_ecdsa_signature(
    server_public_key,
    audit_entry.event,
    audit_entry.signature
  )
  if not sig_valid:
    print(f"⚠️ TAMPERING DETECTED in entry {audit_entry.id}")
```

---

### 4. GDPR Compliance

| Requirement | How This System Addresses |
|-------------|---------------------------|
| **Article 32 - Encryption** | ChaCha20-Poly1305 + AES at rest |
| **Article 28 - Processor Contract** | Doctor signs contract: "Won't retain copies beyond session" |
| **Article 17 - Right to Delete** | Patient can revoke access, server can delete encrypted records |
| **Article 7 - Proof of Consent** | Audit log signed, proves patient approved sharing |
| **Article 33 - Breach Notification** | Audit trail helps identify scope + timeline |

---

### 5. Common Attacks Prevented

| Attack | Traditional System | This System |
|--------|-------------------|------------|
| SQL Injection | Input validation | Query parameterization (unchanged) |
| Man-in-the-Middle | TLS, Cert pinning | TLS 1.3 + certificate pinning |
| Insider Threat | Access logs | Cryptographically signed logs (can't modify) |
| Replay Attack | Token expiration | Session key expires after 7 days |
| Key Reuse Across Patients | N/A | Each doctor gets unique session key per patient |
| Historical Data Breach | All records exposed | Only current 7-day records at risk |

---

## Code Structure

### Directory Layout
```
app/
├── __init__.py
├── main.py (existing)
├── config.py (existing, add new settings)
├── database.py (existing)
├── dependencies.py (existing, extend with sharing validation)
│
├── security/  [NEW]
│   ├── __init__.py
│   ├── crypto.py
│   │   ├── generate_ecdh_keypair()
│   │   ├── encrypt_chacha20()
│   │   ├── decrypt_chacha20()
│   │   ├── derive_key_hkdf()
│   │   ├── sign_event()
│   │   └── verify_signature()
│   └── key_management.py
│       ├── generate_session_key()
│       ├── rotate_session_key_job()
│       ├── revoke_session_key()
│       └── validate_session_key()
│
├── models/
│   ├── __init__.py (existing)
│   ├── user.py (existing)
│   ├── medical_record.py (existing)
│   ├── access_permission.py (existing)
│   ├── audit_log.py (existing)
│   ├── user_keypairs.py  [NEW]
│   ├── session_key.py  [NEW]
│   ├── encrypted_record_vault.py  [NEW]
│   └── cryptographic_audit_log.py  [NEW]
│
├── schemas/
│   ├── __init__.py (existing)
│   ├── user.py (existing)
│   └── encryption.py  [NEW]
│       ├── PublicKeyRegister
│       ├── SessionKeyResponse
│       ├── EncryptedRecordResponse
│       └── AuditLogResponse
│
├── services/
│   ├── __init__.py (existing)
│   ├── auth_service.py (existing)
│   ├── audit_service.py  [EXTEND]
│   ├── sharing_service.py  [EXTEND]
│   ├── encryption_service.py  [NEW]
│   │   ├── register_keypair()
│   │   ├── rotate_keypair()
│   │   └── get_doctor_public_key()
│   ├── session_key_service.py  [NEW]
│   │   ├── generate_session_key()
│   │   ├── encrypt_session_key()
│   │   ├── validate_session_key()
│   │   └── revoke_session_key()
│   └── record_vault_service.py  [NEW]
│       ├── backup_encrypted_record()
│       ├── retrieve_encrypted_records()
│       └── delete_record_vault()
│
├── routers/
│   ├── __init__.py (existing)
│   ├── encryption.py  [NEW]
│   │   ├── POST /keys/register
│   │   ├── POST /keys/rotate
│   │   └── GET /keys/my-keys
│   ├── records_encrypted.py  [NEW]
│   │   ├── POST /records/backup
│   │   ├── GET /records/encrypted
│   │   ├── GET /records/metadata
│   │   └── DELETE /records/{id}
│   ├── sharing.py  [EXTEND]
│   │   ├── POST /sharing/initiate
│   │   ├── POST /sharing/request
│   │   ├── POST /sharing/approve/{perm_id}
│   │   ├── GET /sharing/session-key/{token}
│   │   ├── POST /sharing/revoke/{perm_id}
│   │   └── GET /sharing/sessions
│   └── audit_crypto.py  [NEW]
│       ├── GET /audit/logs
│       └── POST /audit/verify/{log_id}
│
├── middleware/
│   ├── security.py (existing)
│   └── encryption_middleware.py  [NEW]
│       ├── Validate X-Sharing-Token
│       ├── Validate X-Session-Key-Hash
│       └── Check session key TTL
│
├── tasks/  [NEW - Background Jobs]
│   ├── session_key_rotation.py
│   │   └── rotate_expiring_session_keys()
│   └── audit_cleanup.py
│       └── cleanup_old_audit_logs()
│
├── tests/
│   ├── test_crypto.py  [NEW]
│   ├── test_encryption.py  [NEW]
│   ├── test_sharing_workflow.py  [NEW]
│   └── test_audit_logs.py  [NEW]
│
└── alembic/versions/
    ├── [existing migrations]
    ├── _add_user_keypairs_table.py  [NEW]
    ├── _add_session_keys_table.py  [NEW]
    ├── _add_encrypted_record_vaults_table.py  [NEW]
    └── _extend_audit_logs_crypto.py  [NEW]

requirements.txt [UPDATED]
├── cryptography==46.0.6  (already present)
├── APScheduler==3.10.0  (for scheduled jobs)
└── pydantic==2.5.0  (already present)
```

---

## Testing Strategy

### Unit Tests (Per Module)

#### 1. crypto.py Tests
```python
test_generate_ecdh_keypair()
  ✓ Generate valid P-256 keypair
  ✓ Public key can be exported as PEM
  ✓ Different calls produce different keys

test_encrypt_decrypt_chacha20()
  ✓ Encrypt plaintext → ciphertext
  ✓ Decrypt with correct key → original plaintext
  ✓ Decrypt with wrong key → fails
  ✓ Tampered ciphertext → authentication fails
  ✓ Reused nonce with same key → security warning

test_derive_key_hkdf()
  ✓ Same password + salt → same key
  ✓ Different password → different key
  ✓ Different salt → different key
  ✓ Output key has correct length (256-bit)

test_sign_verify_ecdsa()
  ✓ Sign event → signature generated
  ✓ Verify with correct key → valid
  ✓ Verify with wrong key → invalid
  ✓ Modified event → signature fails verification
```

#### 2. Session Key Service Tests
```python
test_generate_session_key()
  ✓ New session key created
  ✓ Each call produces unique key
  ✓ TTL set correctly (7 days default)

test_encrypt_session_key_with_doctor_public_key()
  ✓ Session key encrypted successfully
  ✓ Doctor can decrypt with their private key
  ✓ Other doctors can't decrypt

test_revoke_session_key()
  ✓ Mark session key as REVOKED
  ✓ Future requests with revoked key → rejected
  ✓ Old requests still work (until TTL expires)

test_session_key_rotation()
  ✓ After 7 days, new session key generated
  ✓ Old key becomes ROTATED
  ✓ Doctor still has access (new key decryptable)
```

---

### Integration Tests (Full Workflows)

#### 3. Sharing Workflow Test
```python
test_complete_sharing_workflow()
  ✓ Step 1: Patient setup (register public key)
  ✓ Step 2: Patient uploads encrypted record
  ✓ Step 3: Doctor requests access
  ✓ Step 4: Patient approves
  ✓ Step 5: Doctor retrieves session key
  ✓ Step 6: Doctor decrypts records
  ✓ Step 7: Audit logged with signature
  ✓ Step 8: Patient verifies audit entry
```

#### 4. Revocation Test
```python
test_revoke_access_workflow()
  ✓ Patient grants access (session key active)
  ✓ Doctor accesses 3 records successfully
  ✓ Patient revokes access
  ✓ Doctor's next request → 403 Forbidden
  ✓ Audit shows revocation event
  ✓ Doctor sees "Access revoked" message
```

#### 5. Session Key Expiration Test
```python
test_session_key_expiration()
  ✓ Session key valid for 7 days
  ✓ On day 6: Doctor can access records
  ✓ On day 7 at 23:59: Doctor can access records
  ✓ On day 8 at 00:00: Doctor gets "Session expired"
  ✓ Doctor re-requests access (new 7-day key)
```

---

### Security Tests

#### 6. Tamper Detection Test
```python
test_audit_log_tamper_detection()
  ✓ Modify audit log event → signature fails
  ✓ Attempt to forge signature → fails
  ✓ Replace with different event → detection fails
  ✓ System alerts when tampering detected
```

#### 7. Access Control Test
```python
test_access_control_boundaries()
  ✓ Doctor A can't access Doctor B's session keys
  ✓ Doctor can't access patient records without valid token
  ✓ Patient can't access other patients' records
  ✓ Admin can audit but not decrypt
```

---

### Performance Tests

#### 8. Load Test
```python
test_high_volume_record_access()
  ✓ 100 concurrent doctors accessed records
  ✓ Response time < 500ms per doctor
  ✓ No session key collisions
  ✓ Audit logs still written consistently
```

---

### Compliance Tests

#### 9. GDPR Compliance Test
```python
test_gdpr_article_32_encryption()
  ✓ All PII encrypted at rest
  ✓ All data encrypted in transit (TLS)
  ✓ Encryption keys stored securely (not in source)

test_gdpr_article_17_right_to_delete()
  ✓ Patient can delete records
  ✓ Soft delete with timestamp preserved
  ✓ Audit shows deletion event + reason

test_gdpr_article_33_breach_notification()
  ✓ Audit trail shows access timeline
  ✓ Compromised records identified
  ✓ Notification sent to affected patients
```

---

### Test Coverage Target
- **crypto.py**: 100% coverage (security-critical)
- **session_key_service.py**: 95%+ coverage
- **sharing_service.py**: 90%+ coverage
- **Overall**: 85%+ coverage

---

## Appendix: Glossary

| Term | Definition |
|------|-----------|
| **ECDH** | Elliptic Curve Diffie-Hellman - key exchange algorithm |
| **ChaCha20-Poly1305** | AEAD cipher (Authenticated Encryption with Associated Data) |
| **Nonce** | Number used once - random value for each encryption (never reused with same key) |
| **Session Key** | Temporary encryption key valid for server per doctor per patient (typically 7 days) |
| **Fingerprint** | SHA-256 hash of public key (short identifier) |
| **HKDF** | HMAC-based Key Derivation Function |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm |
| **Audit Log** | Immutable record of all system events with signatures |
| **Forward Secrecy** | Compromise of today's key doesn't expose past records |
| **AAD** | Additional Authenticated Data - metadata authenticated but not encrypted |
| **Poly1305** | AEAD authentication tag (proves integrity) |
| **TTL** | Time-To-Live - expiration duration |

---

## References

- **ECDH**: RFC 6090 - Fundamentals of ECC
- **ChaCha20-Poly1305**: RFC 7539 - ChaCha20 and Poly1305 AEAD
- **HKDF**: RFC 5869 - HMAC-based Extract-and-Expand KDF
- **ECDSA**: FIPS 186-4 - Digital Signature Standard
- **GDPR**: Article 32 - Security of Processing
- **NHS Data Security**: Data Security and Protection Toolkit

---

**Document End**

Next step: Developer team reviews this architecture and provides feedback before Phase 1 implementation begins.
