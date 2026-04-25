# Bionex Hybrid Encryption: Complete Manual Testing Guide

**Version:** 1.0  
**Date:** April 25, 2026  
**Purpose:** Manual step-by-step testing of the complete hybrid encryption model including key generation, session management, expiry, and access control

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites & Setup](#prerequisites--setup)
3. [Key Generation Testing](#key-generation-testing)
4. [Session Key Management Testing](#session-key-management-testing)
5. [Hybrid Model Complete Workflow](#hybrid-model-complete-workflow)
6. [Permission Scoping & Access Control](#permission-scoping--access-control)
7. [Session Expiry & Rotation Testing](#session-expiry--rotation-testing)
8. [Access Revocation Testing](#access-revocation-testing)
9. [Audit Logging Verification](#audit-logging-verification)
10. [End-to-End Scenario](#end-to-end-scenario)

---

## Architecture Overview

### The Hybrid Model (3-Layer Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Patient Vault (Client Device)                          │
│ ┌──────────────────────────────────────────────────────────┐    │
│ │ • Master Key (derived from password + device_id)         │    │
│ │ • Encrypted Medical Records (AES/ChaCha20-Poly1305)      │    │
│ │ • Private Key (for decrypting session keys from server)   │    │
│ └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS + TLS
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Server (Key Authority + Access Control)                │
│ ┌──────────────────────────────────────────────────────────┐    │
│ │ Session Keys Table:                                      │    │
│ │ ├─ doctor_1_patient_1: {key, TTL: 7d, scope: read}      │    │
│ │ ├─ doctor_2_patient_1: {key, TTL: 3d, scope: read_write}│    │
│ │ └─ doctor_3_patient_1: {key, TTL: 30m, scope: read}      │    │
│ │                                                          │    │
│ │ Access Permissions Table:                                │    │
│ │ ├─ doctor_1→patient_1: APPROVED (all records)           │    │
│ │ ├─ doctor_2→patient_1: APPROVED (lab reports only)      │    │
│ │ └─ doctor_3→patient_1: PENDING                          │    │
│ │                                                          │    │
│ │ Audit Log (Immutable, ECDSA Signed):                    │    │
│ │ ├─ Dr. A accessed 5 records [signature] [timestamp]     │    │
│ │ ├─ Patient X updated scope to read_write [sig]          │    │
│ │ └─ Patient X revoked Dr. C [signature] [timestamp]      │    │
│ └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Encrypted Session Key
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Doctor's App (Access Layer)                            │
│ ┌──────────────────────────────────────────────────────────┐    │
│ │ • Receive encrypted session key                          │    │
│ │ • Decrypt using private key                              │    │
│ │ • Use session key to fetch encrypted records             │    │
│ │ • Decrypt records locally                                │    │
│ │ • Display plaintext to doctor                            │    │
│ └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Key Technologies Used

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Key Generation | ECDH (P-256) | Generate shared session keys |
| Symmetric Encryption | ChaCha20-Poly1305 | Encrypt records & session keys |
| Public Key Crypto | ECDSA (P-256) | Digital signatures for audit logs |
| Key Derivation | HKDF-SHA256 | Derive master key from password |
| Hash Function | SHA-256 | Data integrity verification |
| Storage | PostgreSQL | Session keys, permissions, audit logs |
| Caching | Redis | Session validation & invalidation |
| Message Signing | ECDSA | Audit log signatures |

---

## Prerequisites & Setup

### Step 1: Environment Setup

```bash
# 1. Navigate to project directory
cd c:\Myprojects\Bionex\ life\Bionex-Backend-Python

# 2. Activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install dependencies (if not done)
pip install -r requirements.txt

# 4. Start PostgreSQL (ensure it's running)
# On Windows with PostgreSQL installed:
# Services → PostgreSQL → Start (or use pgAdmin)

# 5. Start Redis (if using local Redis)
# For local development, you can use:
# a. Docker: docker run -d -p 6379:6379 redis:latest
# b. Or connect to existing Redis instance

# 6. Start the FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 2: Prepare Test Data

```bash
# Create test users in database
python -c "
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models.user import User, UserRole
from app.models.patient import Patient, Gender
from app.security.crypto import CryptoManager
from datetime import datetime, timezone, timedelta
import uuid

db = SessionLocal()

# Create Patient
patient_user = User(
    id=uuid.uuid4(),
    name='Test Patient',
    email='testpatient@bionex.com',
    phone='+15551234567',
    hashed_password=CryptoManager.hash_data(b'password123'),
    role=UserRole.PATIENT,
    is_active=True
)
db.add(patient_user)
db.flush()

patient = Patient(
    id=uuid.uuid4(),
    user_id=patient_user.id,
    blood_group='O+',
    gender=Gender.MALE
)
db.add(patient)
db.commit()
print(f'Patient created: {patient_user.id}')

# Create Doctor
doctor_user = User(
    id=uuid.uuid4(),
    name='Dr. Test Doctor',
    email='testdoctor@bionex.com',
    phone='+15559876543',
    hashed_password=CryptoManager.hash_data(b'password123'),
    role=UserRole.DOCTOR,
    is_active=True
)
db.add(doctor_user)
db.commit()
print(f'Doctor created: {doctor_user.id}')
"
```

---

## Key Generation Testing

### Test Case 1: Generate ECDH Keypair for User

**Purpose**: Verify that each user (patient/doctor) can generate a unique ECDH keypair

**Expected**: 
- Public key stored in database
- Private key never leaves the application

**API Endpoint**: `POST /crypto/generate-keypair`

**Manual Test Steps**:

#### Step 1.1: Generate Keypair via API

```bash
# Using curl or Postman
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"user_id": "patient_user_id"}'
```

**Expected Response**:
```json
{
  "user_id": "patient_user_id",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
  "created_at": "2026-04-25T10:30:00Z",
  "algorithm": "ECDH_P256"
}
```

#### Step 1.2: Verify in Database

```sql
-- Connect to PostgreSQL
psql -U postgres -d bionex_db -c "
SELECT id, user_id, algorithm, public_key, created_at 
FROM user_keypairs 
WHERE user_id = 'patient_user_id' 
ORDER BY created_at DESC;
"
```

**Expected Output**:
```
                  id                  |             user_id              | algorithm | public_key | created_at
--------------------------------------+----------------------------------+-----------+------------+------------------------
 uuid-xxxxxxxx-xxxx-xxxx-xxxx | patient_user_id            | ECDH_P256 | -----BEGIN... | 2026-04-25 10:30:00
(1 row)
```

#### Step 1.3: Verify Public Key Format

```python
# In Python terminal
from cryptography.hazmat.primitives import serialization
from app.security.crypto import CryptoManager

# Get the public key from database
# Verify it can be loaded
public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"

public_key = serialization.load_pem_public_key(
    public_key_pem.encode(),
    backend=CryptoManager.BACKEND
)

print(f"✓ Public key loaded successfully")
print(f"  Curve: {public_key.curve.name}")
print(f"  Key size: {public_key.curve.key_size} bits")
```

**Expected Output**:
```
✓ Public key loaded successfully
  Curve: secp256r1
  Key size: 256 bits
```

#### Step 1.4: Test Key Rotation

```bash
# Generate a second keypair (should replace the old one)
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"user_id": "patient_user_id"}'
```

**Database Check**:
```sql
-- Should see 2 keypairs for same user
SELECT COUNT(*), user_id FROM user_keypairs 
WHERE user_id = 'patient_user_id' 
GROUP BY user_id;
```

**Expected**: New keypair created, old one archived

---

### Test Case 2: Verify ECDH Shared Secret Generation

**Purpose**: Verify that ECDH can derive a shared secret between two parties

**Expected**: Same secret on both sides, never transmitted

**Manual Steps**:

#### Step 2.1: Generate Keypairs for Both Parties

```bash
# Patient keypair
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"user_id": "<patient_id>"}'

# Doctor keypair
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"user_id": "<doctor_id>"}'
```

#### Step 2.2: Compute Shared Secret (Server-Side)

```python
# Test script to verify ECDH computation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
import hashlib

# Simulate Doctor requesting access
# Server computes: shared_secret = ECDH(Server_Private, Doctor_Public)

# 1. Load doctor's public key from database
doctor_public_key_pem = "..."  # from user_keypairs table

# 2. Server has its own private key (in Vault)
server_private_key_pem = "..."  # from secure storage

# 3. Compute shared secret
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as h

shared_secret = ec.ECDH().exchange(ec.ECDH(), server_private_key, doctor_public_key)

# 4. Derive session key using HKDF
hkdf = HKDF(
    algorithm=h.SHA256(),
    length=32,  # 256-bit key
    salt=None,
    info=b'bionex_session_key',
    backend=backend
)

session_key = hkdf.derive(shared_secret)

print(f"✓ Shared secret computed")
print(f"  Shared secret: {shared_secret.hex()}")
print(f"  Session key: {session_key.hex()}")
```

**Expected Output**:
```
✓ Shared secret computed
  Shared secret: a1b2c3d4e5f6...
  Session key: f6e5d4c3b2a1...
```

---

## Session Key Management Testing

### Test Case 3: Create Session Key for Doctor Access

**Purpose**: Verify session key creation with specific TTL and scope

**Expected**: 
- Unique session key generated
- Stored in database with TTL
- Encrypted for doctor's public key

**API Endpoint**: `POST /doctor/request-patient-access`

**Manual Steps**:

#### Step 3.1: Doctor Requests Access

```bash
curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{
    "patient_id": "<patient_id>",
    "reason": "Regular checkup and medication review"
  }'
```

**Expected Response**:
```json
{
  "sharing_request_id": "uuid-xxxxx",
  "patient_id": "<patient_id>",
  "doctor_id": "<doctor_id>",
  "status": "PENDING",
  "scope": "read",
  "created_at": "2026-04-25T10:35:00Z",
  "expires_at": "2026-05-02T10:35:00Z"
}
```

#### Step 3.2: Patient Approves Request

```bash
curl -X POST http://localhost:8000/patient/sharing-requests/<sharing_request_id>/approve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

**Expected Response**:
```json
{
  "sharing_request_id": "uuid-xxxxx",
  "status": "APPROVED",
  "approved_at": "2026-04-25T10:36:00Z",
  "session_key_created": true
}
```

#### Step 3.3: Verify Session Key in Database

```sql
SELECT 
  id,
  doctor_id,
  patient_id,
  session_key_hash,
  status,
  scope,
  created_at,
  expires_at,
  last_accessed_at
FROM session_keys
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>'
ORDER BY created_at DESC;
```

**Expected Output**:
```
                  id                  |       doctor_id        |       patient_id       |     session_key_hash     |   status   | scope |         created_at         |         expires_at         | last_accessed_at
--------------------------------------+------------------------+------------------------+-------------------------+------------+-------+----------------------------+----------------------------+------------------
 uuid-xxxxxxxx-xxxx-xxxx-xxxx | <doctor_id>            | <patient_id>           | a1b2c3d4e5f6g7h8... | ACTIVE     | read  | 2026-04-25 10:36:00    | 2026-05-02 10:36:00    | NULL
(1 row)
```

#### Step 3.4: Verify Encryption for Doctor

```python
# Doctor's app receives encrypted session key
# Step 1: Doctor decrypts using their private key

encrypted_session_key = "base64_encoded_ciphertext"
doctor_private_key_pem = "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import base64

# Load doctor's private key
doctor_private_key = serialization.load_pem_private_key(
    doctor_private_key_pem.encode(),
    password=None,
    backend=default_backend()
)

# Decrypt session key (using ECIES - hybrid encryption)
decrypted_session_key = decrypt_with_private_key(
    encrypted_session_key,
    doctor_private_key
)

print(f"✓ Session key decrypted by doctor")
print(f"  Decrypted session key: {decrypted_session_key.hex()}")
```

**Expected Output**:
```
✓ Session key decrypted by doctor
  Decrypted session key: f6e5d4c3b2a1...
```

---

### Test Case 4: Session Key Validation

**Purpose**: Verify that session key is validated before granting access

**Expected**: 
- Valid session key → Access granted
- Invalid/expired session key → Access denied

**Manual Steps**:

#### Step 4.1: Access Records with Valid Session Key

```bash
# Doctor requests encrypted records
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <decrypted_session_key_hex>"
```

**Expected Response** (encrypted):
```json
{
  "records": [
    {
      "id": "record_uuid_1",
      "encrypted_data": "base64_encrypted_content",
      "nonce": "base64_nonce",
      "auth_tag": "base64_tag",
      "created_at": "2026-04-20T08:00:00Z"
    }
  ],
  "total_count": 3
}
```

#### Step 4.2: Access Records with Invalid Session Key

```bash
# Use wrong session key
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: invalid_session_key_hex"
```

**Expected Response** (403 Forbidden):
```json
{
  "detail": "Invalid or expired session key",
  "error_code": "INVALID_SESSION_KEY"
}
```

#### Step 4.3: Verify Audit Log Entry

```sql
SELECT 
  id,
  actor_id,
  actor_type,
  action,
  status,
  reason,
  created_at
FROM crypto_audit_logs
WHERE actor_id = '<doctor_id>' 
AND patient_id = '<patient_id>'
ORDER BY created_at DESC
LIMIT 5;
```

**Expected Output**:
```
                  id                  |      actor_id      | actor_type | action             | status    |               reason                | created_at
--------------------------------------+--------------------+------------+--------------------+-----------+-------------------------------------+------------------------
 uuid-xxxxxxxx-xxxx-xxxx-xxxx | <doctor_id>      | DOCTOR     | ACCESS_ATTEMPTED   | SUCCESS   | NULL                                | 2026-04-25 10:38:00
 uuid-xxxxxxxx-xxxx-xxxx-xxxx | <doctor_id>      | DOCTOR     | ACCESS_ATTEMPTED   | FAILED    | Invalid or expired session key      | 2026-04-25 10:37:59
```

---

## Hybrid Model Complete Workflow

### Test Case 5: End-to-End Data Flow

**Purpose**: Test complete data flow from patient storage to doctor decryption

**Scenario**: Patient stores encrypted medical record, doctor requests access and decrypts

**Manual Steps**:

#### Step 5.1: Patient Creates Medical Record (Encrypted Locally)

```bash
# Patient's app encrypts record locally, sends encrypted data to server
curl -X POST http://localhost:8000/patient/medical-records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <patient_token>" \
  -d '{
    "record_type": "lab_report",
    "encrypted_data": "base64_encrypted_content",
    "nonce": "base64_nonce",
    "auth_tag": "base64_authentication_tag",
    "aad": "lab_report_metadata"
  }'
```

**What happens on server**:
1. Server receives encrypted data (can't decrypt - doesn't have key)
2. Validates authentication tag
3. Stores encrypted blob in `encrypted_record_vault` table
4. Never stores plaintext

**Response**:
```json
{
  "record_id": "uuid-xxxxx",
  "patient_id": "<patient_id>",
  "record_type": "lab_report",
  "stored_at": "2026-04-25T10:40:00Z",
  "encryption": {
    "algorithm": "ChaCha20-Poly1305",
    "nonce": "base64_nonce",
    "auth_tag": "base64_authentication_tag"
  }
}
```

#### Step 5.2: Verify Encrypted Storage in Database

```sql
-- Record is stored encrypted
SELECT 
  id,
  patient_id,
  record_type,
  encrypted_data_hash,
  nonce,
  auth_tag,
  created_at
FROM encrypted_record_vault
WHERE id = 'uuid-xxxxx';
```

**Note**: `encrypted_data` column contains unreadable binary blob

**Output**:
```
                  id                  |       patient_id       | record_type | encrypted_data_hash | nonce | auth_tag |         created_at
--------------------------------------+------------------------+-------------+---------------------+-------+----------+----------------------------
 uuid-xxxxxxxx-xxxx-xxxx-xxxx | <patient_id>           | lab_report  | a1b2c3d4e5f6g7h8... | ...   | ...      | 2026-04-25 10:40:00
```

#### Step 5.3: Doctor Requests Access (Sharing Workflow)

```bash
# Doctor requests access
curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"patient_id": "<patient_id>", "reason": "Lab report review"}'
```

#### Step 5.4: Patient Approves Sharing

```bash
curl -X POST http://localhost:8000/patient/sharing-requests/<sharing_request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

**What happens**:
1. Server creates session key
2. Encrypts session key using doctor's public key
3. Stores encrypted session key in database
4. Returns to doctor (doctor decrypts using their private key)

#### Step 5.5: Doctor Decrypts Session Key (On Doctor's Device)

```python
# Doctor's app code
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# 1. Receive encrypted session key from server
encrypted_session_key_from_server = "base64_encrypted_data"

# 2. Load doctor's private key (stored securely on device)
doctor_private_key_pem = "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
doctor_private_key = serialization.load_pem_private_key(
    doctor_private_key_pem.encode(),
    password=None,
    backend=default_backend()
)

# 3. Decrypt session key using ECIES
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

encrypted_bytes = base64.b64decode(encrypted_session_key_from_server)
nonce = encrypted_bytes[:12]
ciphertext = encrypted_bytes[12:-16]
tag = encrypted_bytes[-16:]

# Derive decryption key from ECDH
shared_secret = doctor_private_key.exchange(ec.ECDH(), server_public_key)
cipher = ChaCha20Poly1305(shared_secret)

session_key = cipher.decrypt(nonce, ciphertext + tag, None)

print(f"✓ Session key decrypted: {session_key.hex()}")
```

#### Step 5.6: Doctor Fetches Encrypted Records

```bash
# Doctor sends request with decrypted session key
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records?type=lab_report \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <decrypted_session_key_hex>"
```

**Response**:
```json
{
  "records": [
    {
      "id": "uuid-xxxxx",
      "encrypted_data": "base64_encrypted_blob",
      "nonce": "base64_nonce",
      "auth_tag": "base64_auth_tag",
      "created_at": "2026-04-25T10:40:00Z"
    }
  ]
}
```

#### Step 5.7: Doctor Decrypts Records Locally

```python
# Doctor's app decrypts the encrypted record
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64

# Data from server response
encrypted_data = base64.b64decode(record['encrypted_data'])
nonce = base64.b64decode(record['nonce'])
auth_tag = base64.b64decode(record['auth_tag'])

# Use session key to decrypt
cipher = ChaCha20Poly1305(bytes.fromhex(session_key))

plaintext = cipher.decrypt(nonce, encrypted_data + auth_tag, None)

print(f"✓ Record decrypted on doctor's device")
print(f"  Plaintext: {plaintext.decode()}")
```

**Expected Output**:
```
✓ Record decrypted on doctor's device
  Plaintext: Lab results: Blood pressure 120/80, Cholesterol 180
```

#### Step 5.8: Verify Complete Data Flow

```bash
# Check that server NEVER decrypted anything
# Query database for audit logs
curl -X GET http://localhost:8000/admin/audit-logs?event_type=DATA_DECRYPTION \
  -H "Authorization: Bearer <admin_token>"
```

**Expected Result**: No `DATA_DECRYPTION` events for doctors (only patients decrypt their own data)

---

## Permission Scoping & Access Control

### Test Case 6: Permission Scopes (Read vs Read-Write)

**Purpose**: Verify granular access control with different permission levels

**Expected**: 
- `read` scope → only fetch records
- `read_write` scope → fetch + modify records

**Manual Steps**:

#### Step 6.1: Create Sharing with Read-Only Scope

```bash
# Doctor requests access
curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"patient_id": "<patient_id>"}'

# Patient approves with read-only scope (default)
curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"scope": "read"}'
```

**Database State**:
```sql
SELECT id, doctor_id, patient_id, scope, status FROM session_keys 
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>';
```

**Expected Output**:
```
   scope   
──────────
 read
```

#### Step 6.2: Test Read Permission (Should Work)

```bash
# Doctor reads records
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>"
```

**Expected**: 200 OK - Records returned

#### Step 6.3: Test Write Permission (Should Fail)

```bash
# Doctor tries to modify record
curl -X PUT http://localhost:8000/patient/<patient_id>/medical-records/<record_id> \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>" \
  -d '{"notes": "Updated findings"}'
```

**Expected Response** (403 Forbidden):
```json
{
  "detail": "Write permission denied. Current scope: read",
  "error_code": "INSUFFICIENT_PERMISSION"
}
```

#### Step 6.4: Create Sharing with Read-Write Scope

```bash
# Patient changes scope
curl -X PUT http://localhost:8000/patient/access-control/session/<session_key_id>/scope \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"new_scope": "read_write"}'
```

**Response**:
```json
{
  "session_key_id": "<session_key_id>",
  "scope_updated": "read_write",
  "updated_at": "2026-04-25T10:45:00Z"
}
```

#### Step 6.5: Test Write Permission (Should Now Work)

```bash
# Doctor now can modify record
curl -X PUT http://localhost:8000/patient/<patient_id>/medical-records/<record_id> \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>" \
  -d '{"notes": "Updated findings from review"}'
```

**Expected**: 200 OK - Record updated

#### Step 6.6: Verify Audit Log

```sql
SELECT actor_type, action, scope, reason, created_at 
FROM crypto_audit_logs
WHERE patient_id = '<patient_id>'
ORDER BY created_at DESC
LIMIT 5;
```

**Expected Output**:
```
 actor_type | action            | scope       | reason                  | created_at
────────────┼───────────────────┼─────────────┼─────────────────────────┼────────────
 PATIENT    | SCOPE_UPDATED     | read_write  | Patient updated scope   | 2026-04-25 10:45:00
 DOCTOR     | WRITE_ATTEMPTED   | read_write  | Record modified         | 2026-04-25 10:44:30
 DOCTOR     | WRITE_DENIED      | read        | Insufficient permission | 2026-04-25 10:44:00
```

---

## Session Expiry & Rotation Testing

### Test Case 7: Session Key TTL (Time-To-Live)

**Purpose**: Verify session keys expire automatically

**Expected**: 
- Session key valid until TTL expires
- After expiry, access denied automatically

**Manual Steps**:

#### Step 7.1: Create Session with Short TTL (for testing)

```bash
# Create sharing request with custom TTL
curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{
    "patient_id": "<patient_id>",
    "ttl_hours": 1
  }'

# Patient approves
curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

#### Step 7.2: Verify Expiry Time in Database

```sql
SELECT 
  id,
  doctor_id,
  created_at,
  expires_at,
  (expires_at - now()::timestamp) AS time_remaining
FROM session_keys
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>'
ORDER BY created_at DESC
LIMIT 1;
```

**Expected Output** (with TTL of 1 hour):
```
             id              |       doctor_id        |         created_at         |         expires_at         | time_remaining
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 uuid-xxxxx | <doctor_id>            | 2026-04-25 10:50:00    | 2026-04-25 11:50:00    | 01:00:00
```

#### Step 7.3: Access Records Before Expiry

```bash
# Should work
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>"
```

**Expected**: 200 OK - Access granted

#### Step 7.4: Simulate Expiry (For Testing)

```python
# Use database to manually set expiry to past
from app.database import SessionLocal
from app.models.encryption_models import SessionKey
from datetime import datetime, timezone, timedelta

db = SessionLocal()
session = db.query(SessionKey).filter_by(id='<session_key_id>').first()
session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)  # 5 minutes ago
db.commit()
```

#### Step 7.5: Try to Access After Expiry

```bash
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>"
```

**Expected Response** (403 Forbidden):
```json
{
  "detail": "Session key has expired",
  "error_code": "SESSION_EXPIRED",
  "expired_at": "2026-04-25 10:45:00"
}
```

#### Step 7.6: Verify Expiry in Audit Log

```sql
SELECT actor_type, action, reason, created_at 
FROM crypto_audit_logs
WHERE session_key_id = '<session_key_id>'
ORDER BY created_at DESC;
```

**Expected Output**:
```
 actor_type | action        | reason                 | created_at
────────────┼───────────────┼────────────────────────┼────────────
 SYSTEM     | SESSION_EXPIRED | Session key expired    | 2026-04-25 10:55:00
```

---

### Test Case 8: Session Key Rotation (Daily Automatic + Manual)

**Purpose**: Verify automatic daily rotation and manual rotation

**Expected**: 
- New session key generated daily
- Old key archived but can still be used briefly
- Doctor seamlessly gets new key

**Manual Steps**:

#### Step 8.1: Create Session with Known Timestamp

```bash
# Create session
curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"patient_id": "<patient_id>"}'

curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

**Note time**: `2026-04-25 11:00:00`

#### Step 8.2: Check Session Key Version

```sql
SELECT 
  id,
  doctor_id,
  patient_id,
  status,
  key_version,
  created_at,
  rotated_at
FROM session_keys
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>'
ORDER BY created_at DESC
LIMIT 1;
```

**Expected Output** (initial version):
```
 key_version | status | created_at         | rotated_at
─────────────────────────────────────────────────────────
      1      | ACTIVE | 2026-04-25 11:00   | NULL
```

#### Step 8.3: Trigger Manual Rotation

```bash
# Patient manually rotates the key
curl -X POST http://localhost:8000/patient/access-control/session/<session_key_id>/rotate \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"reason": "Manual rotation for security"}'
```

**Response**:
```json
{
  "session_key_id": "<session_key_id>",
  "old_key_version": 1,
  "new_key_version": 2,
  "new_key_expires_at": "2026-05-02T11:00:00Z",
  "rotated_at": "2026-04-25T11:05:00Z"
}
```

#### Step 8.4: Verify Database After Rotation

```sql
SELECT 
  id,
  doctor_id,
  status,
  key_version,
  created_at,
  rotated_at
FROM session_keys
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>'
ORDER BY created_at DESC
LIMIT 2;
```

**Expected Output** (2 rows - old archived, new active):
```
                  id                  | status   | key_version | created_at         | rotated_at
──────────────────────────────────────┼──────────┼─────────────┼────────────────────┼────────────
 uuid-new-version-2-xxxx | ACTIVE   |      2     | 2026-04-25 11:00   | 2026-04-25 11:05
 uuid-old-version-1-xxxx | ARCHIVED |      1     | 2026-04-25 11:00   | 2026-04-25 11:05
```

#### Step 8.5: Doctor Uses New Key

```bash
# Doctor receives notification about new key
# Requests new session key
curl -X GET http://localhost:8000/doctor/session/<patient_id>/key \
  -H "Authorization: Bearer <doctor_token>"
```

**Response**:
```json
{
  "session_key": "base64_encrypted_new_session_key",
  "key_version": 2,
  "expires_at": "2026-05-02T11:00:00Z",
  "rotation_performed_at": "2026-04-25T11:05:00Z"
}
```

#### Step 8.6: Access Still Works with New Key

```bash
# Doctor accesses records with new key
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <new_session_key>"
```

**Expected**: 200 OK - Seamless access

#### Step 8.7: Verify Rotation in Audit Log

```sql
SELECT actor_type, action, reason, created_at 
FROM crypto_audit_logs
WHERE session_key_id = '<session_key_id>'
AND action = 'SESSION_ROTATED'
ORDER BY created_at DESC;
```

**Expected Output**:
```
 actor_type | action           | reason                             | created_at
────────────┼──────────────────┼────────────────────────────────────┼────────────
 PATIENT    | SESSION_ROTATED  | Manual rotation for security       | 2026-04-25 11:05:00
 SYSTEM     | SESSION_ROTATED  | Automatic daily rotation           | 2026-04-24 11:00:00
```

---

## Access Revocation Testing

### Test Case 9: Immediate Access Revocation

**Purpose**: Verify patient can instantly revoke doctor's access

**Expected**: 
- Revocation takes effect immediately
- Doctor can no longer access records
- Cache invalidated instantly
- Audit logged

**Manual Steps**:

#### Step 9.1: Doctor Access Before Revocation

```bash
# Doctor successfully accesses records
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>"
```

**Expected**: 200 OK

#### Step 9.2: Patient Revokes Access

```bash
# Patient immediately revokes doctor's access
curl -X POST http://localhost:8000/patient/access-control/session/<session_key_id>/revoke \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"reason": "No longer need doctor access"}'
```

**Response**:
```json
{
  "session_key_id": "<session_key_id>",
  "status": "REVOKED",
  "revoked_at": "2026-04-25T11:10:00Z",
  "revocation_reason": "No longer need doctor access"
}
```

#### Step 9.3: Doctor Access Immediately After Revocation

```bash
# Doctor tries to access within seconds
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: <session_key>"
```

**Expected Response** (403 Forbidden):
```json
{
  "detail": "Session has been revoked by patient",
  "error_code": "SESSION_REVOKED",
  "revoked_at": "2026-04-25T11:10:00Z",
  "revocation_reason": "No longer need doctor access"
}
```

#### Step 9.4: Verify Cache Invalidation

```python
# Check Redis cache - should be empty
import redis

r = redis.Redis(host='localhost', port=6379, db=0)
session_key_id = "<session_key_id>"

# Try to get from cache
cached_key = r.get(f"session:{session_key_id}")

print(f"Cached key: {cached_key}")  # Should be None
```

**Expected Output**:
```
Cached key: None
```

#### Step 9.5: Verify Database Status

```sql
SELECT 
  id,
  doctor_id,
  patient_id,
  status,
  revoked_at,
  revocation_reason
FROM session_keys
WHERE id = '<session_key_id>';
```

**Expected Output**:
```
 status  |        revoked_at        |         revocation_reason
─────────┼──────────────────────────┼───────────────────────────
 REVOKED | 2026-04-25 11:10:00    | No longer need doctor access
```

#### Step 9.6: Verify Audit Log

```sql
SELECT actor_type, action, reason, created_at 
FROM crypto_audit_logs
WHERE session_key_id = '<session_key_id>'
ORDER BY created_at DESC
LIMIT 1;
```

**Expected Output**:
```
 actor_type | action             | reason                         | created_at
────────────┼────────────────────┼────────────────────────────────┼────────────
 PATIENT    | SESSION_REVOKED    | No longer need doctor access   | 2026-04-25 11:10:00
```

---

### Test Case 10: Revoke All Sessions for Patient

**Purpose**: Patient revokes ALL doctors' access at once

**Manual Steps**:

#### Step 10.1: Create Multiple Sessions

```bash
# Create sessions with Doctor 1, 2, 3
for doctor_email in "doctor1@hospital.com" "doctor2@hospital.com" "doctor3@hospital.com"
do
  # Each doctor requests access
  curl -X POST http://localhost:8000/doctor/request-patient-access \
    -H "Authorization: Bearer <doctor_token>" \
    -d "{\"patient_id\": \"<patient_id>\"}"
  
  # Patient approves
  curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
    -H "Authorization: Bearer <patient_token>" \
    -d '{}'
done
```

#### Step 10.2: Verify Multiple Active Sessions

```sql
SELECT COUNT(*), status 
FROM session_keys
WHERE patient_id = '<patient_id>'
GROUP BY status;
```

**Expected Output**:
```
 count | status
───────────────
   3   | ACTIVE
```

#### Step 10.3: Revoke All Sessions

```bash
# Patient revokes all doctors
curl -X POST http://localhost:8000/patient/access-control/revoke-all-sessions \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"reason": "Patient requested data deletion"}'
```

**Response**:
```json
{
  "total_sessions_revoked": 3,
  "revoked_at": "2026-04-25T11:15:00Z",
  "revocation_reason": "Patient requested data deletion"
}
```

#### Step 10.4: Verify All Sessions Revoked

```sql
SELECT COUNT(*), status 
FROM session_keys
WHERE patient_id = '<patient_id>'
GROUP BY status;
```

**Expected Output**:
```
 count | status
───────────────
   3   | REVOKED
```

#### Step 10.5: All Doctors Access Denied

```bash
# Try to access with each doctor's key
for doctor_id in "doctor1_id" "doctor2_id" "doctor3_id"
do
  curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
    -H "Authorization: Bearer <doctor_token>" \
    -H "X-Session-Key: <session_key>"
done
```

**Expected**: All return 403 Forbidden

---

## Audit Logging Verification

### Test Case 11: Cryptographic Audit Log Signing

**Purpose**: Verify audit logs are cryptographically signed with ECDSA

**Expected**: 
- Each audit entry has ECDSA signature
- Signature verifiable using server's public key
- Tampered entries detected

**Manual Steps**:

#### Step 11.1: Generate Server ECDSA Keypair

```bash
# Verify server has ECDSA keypair for signing
curl -X GET http://localhost:8000/admin/crypto/server-public-key \
  -H "Authorization: Bearer <admin_token>"
```

**Response**:
```json
{
  "algorithm": "ECDSA_P256",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
  "key_id": "server_audit_key_001",
  "rotated_at": "2026-04-01T00:00:00Z"
}
```

#### Step 11.2: Perform Action and Generate Audit Log

```bash
# Patient approves sharing (generates audit log)
curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

#### Step 11.3: Retrieve Audit Log Entry

```bash
# Get the audit logs
curl -X GET http://localhost:8000/admin/audit-logs?limit=1 \
  -H "Authorization: Bearer <admin_token>"
```

**Response**:
```json
{
  "audit_logs": [
    {
      "id": "log_uuid_xxxxx",
      "actor_id": "<patient_id>",
      "actor_type": "PATIENT",
      "action": "SHARING_APPROVED",
      "patient_id": "<patient_id>",
      "doctor_id": "<doctor_id>",
      "reason": null,
      "status": "SUCCESS",
      "created_at": "2026-04-25T11:20:00Z",
      "signature": "MEYCIQDa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p...",
      "signature_algorithm": "ECDSA_SHA256",
      "signature_verified": true
    }
  ]
}
```

#### Step 11.4: Verify Signature

```python
# Verify ECDSA signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import base64
import json

# Get the audit log
audit_log = {...}  # from API response

# Get server's public key
server_public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# Load public key
public_key = serialization.load_pem_public_key(
    server_public_key_pem.encode(),
    backend=default_backend()
)

# Create message to verify (all fields except signature)
message_data = {
    "id": audit_log["id"],
    "actor_id": audit_log["actor_id"],
    "actor_type": audit_log["actor_type"],
    "action": audit_log["action"],
    "created_at": audit_log["created_at"],
    "status": audit_log["status"]
}
message = json.dumps(message_data, sort_keys=True).encode()

# Get signature
signature_bytes = base64.b64decode(audit_log["signature"])

# Verify signature
try:
    public_key.verify(
        signature_bytes,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("✓ Audit log signature verified")
except:
    print("✗ Audit log signature verification FAILED")
```

**Expected Output**:
```
✓ Audit log signature verified
```

#### Step 11.5: Test Tampered Log Detection

```python
# Tamper with audit log
tampered_log = audit_log.copy()
tampered_log["action"] = "UNAUTHORIZED_ACTION"

# Try to verify - should fail
try:
    public_key.verify(
        signature_bytes,
        json.dumps(tampered_log, sort_keys=True).encode(),
        ec.ECDSA(hashes.SHA256())
    )
    print("✗ Tampered log incorrectly verified!")
except Exception as e:
    print(f"✓ Tampered log detected: {str(e)}")
```

**Expected Output**:
```
✓ Tampered log detected: Bad signature
```

#### Step 11.6: Query Audit Logs with Filtering

```bash
# Get all access attempts
curl -X GET "http://localhost:8000/admin/audit-logs?action=ACCESS_ATTEMPTED&limit=10" \
  -H "Authorization: Bearer <admin_token>"

# Get all revocation events
curl -X GET "http://localhost:8000/admin/audit-logs?action=SESSION_REVOKED&limit=10" \
  -H "Authorization: Bearer <admin_token>"

# Get all audit logs for specific patient
curl -X GET "http://localhost:8000/admin/audit-logs?patient_id=<patient_id>&limit=20" \
  -H "Authorization: Bearer <admin_token>"
```

---

## End-to-End Scenario

### Complete Workflow: From Encryption to Decryption with Full Security

**Scenario**: Patient with medical records shares with doctor, doctor accesses and modifies with audit trail

**Duration**: ~15 minutes

**Steps**:

#### Phase 1: Setup (2 min)

```bash
# 1. Start server
cd c:\Myprojects\Bionex\ life\Bionex-Backend-Python
uvicorn app.main:app --reload

# 2. Ensure database and Redis running
# Check PostgreSQL and Redis connectivity

# 3. Create test users
python -c "from test_phase4_manual import setup_test_users; setup_test_users()"
```

#### Phase 2: Patient Data Encryption (3 min)

```bash
# 1. Patient generates keypair
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"user_id": "<patient_id>"}'

# 2. Patient creates encrypted medical record
curl -X POST http://localhost:8000/patient/medical-records \
  -H "Authorization: Bearer <patient_token>" \
  -d '{
    "record_type": "lab_report",
    "encrypted_data": "base64_encrypted",
    "nonce": "base64_nonce",
    "auth_tag": "base64_tag"
  }'

# 3. Verify in database (encrypted)
psql -U postgres -d bionex_db -c "
SELECT id, patient_id, record_type, created_at 
FROM encrypted_record_vault 
WHERE patient_id = '<patient_id>';"
```

#### Phase 3: Doctor Access Request & Approval (3 min)

```bash
# 1. Doctor generates keypair
curl -X POST http://localhost:8000/crypto/generate-keypair \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"user_id": "<doctor_id>"}'

# 2. Doctor requests patient access
RESPONSE=$(curl -X POST http://localhost:8000/doctor/request-patient-access \
  -H "Authorization: Bearer <doctor_token>" \
  -d '{"patient_id": "<patient_id>"}')
REQUEST_ID=$(echo $RESPONSE | jq -r '.sharing_request_id')

# 3. Patient approves
curl -X POST http://localhost:8000/patient/sharing-requests/$REQUEST_ID/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"scope": "read_write"}'

# 4. Verify session created
psql -U postgres -d bionex_db -c "
SELECT id, doctor_id, patient_id, scope, status, expires_at 
FROM session_keys 
WHERE doctor_id = '<doctor_id>' AND patient_id = '<patient_id>';"
```

#### Phase 4: Doctor Decrypts Session Key (3 min)

```bash
# 1. Get encrypted session key from server
ENCRYPTED_SESSION=$(curl -X GET http://localhost:8000/doctor/session/<patient_id>/key \
  -H "Authorization: Bearer <doctor_token>" \
  | jq -r '.session_key')

# 2. Doctor's app decrypts using private key (simulated)
python -c "
from cryptography.hazmat.primitives import serialization
# [Implementation to decrypt encrypted session key]
print('✓ Session key decrypted')
"

# 3. Use decrypted session key
SESSION_KEY="decrypted_session_key_hex"
```

#### Phase 5: Doctor Accesses & Reads Records (2 min)

```bash
# 1. Doctor fetches encrypted records
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: $SESSION_KEY"

# 2. Records received encrypted
# 3. Doctor's app decrypts locally
python -c "
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# [Implementation to decrypt records]
print('✓ Records decrypted on doctor device')
"
```

#### Phase 6: Doctor Modifies Record (2 min)

```bash
# 1. Doctor updates record (write_permission check)
curl -X PUT http://localhost:8000/patient/<patient_id>/medical-records/<record_id> \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: $SESSION_KEY" \
  -d '{"notes": "Diagnosis confirmed, start treatment"}'

# 2. Server receives encrypted update, stores without decrypting

# 3. Verify in audit log
psql -U postgres -d bionex_db -c "
SELECT actor_type, action, scope, created_at 
FROM crypto_audit_logs 
WHERE actor_id = '<doctor_id>' AND patient_id = '<patient_id>' 
ORDER BY created_at DESC LIMIT 5;"
```

#### Phase 7: Patient Revokes Access (1 min)

```bash
# 1. Patient revokes doctor
curl -X POST http://localhost:8000/patient/access-control/session/<session_key_id>/revoke \
  -H "Authorization: Bearer <patient_token>" \
  -d '{"reason": "Consultation complete"}'

# 2. Doctor tries to access again
curl -X GET http://localhost:8000/patient/<patient_id>/medical-records \
  -H "Authorization: Bearer <doctor_token>" \
  -H "X-Session-Key: $SESSION_KEY"

# Expected: 403 Forbidden
```

#### Phase 8: Verify Complete Audit Trail (1 min)

```bash
# Get all events for this patient
curl -X GET http://localhost:8000/admin/audit-logs?patient_id=<patient_id> \
  -H "Authorization: Bearer <admin_token>" \
  | jq '.audit_logs[] | {action, actor_type, created_at}'
```

**Expected Output**:
```
{
  "action": "SESSION_REVOKED",
  "actor_type": "PATIENT",
  "created_at": "2026-04-25T11:35:00Z"
}
{
  "action": "WRITE_ATTEMPTED",
  "actor_type": "DOCTOR",
  "created_at": "2026-04-25T11:34:15Z"
}
{
  "action": "READ_ATTEMPTED",
  "actor_type": "DOCTOR",
  "created_at": "2026-04-25T11:33:45Z"
}
{
  "action": "SHARING_APPROVED",
  "actor_type": "PATIENT",
  "created_at": "2026-04-25T11:32:00Z"
}
{
  "action": "KEYPAIR_GENERATED",
  "actor_type": "PATIENT",
  "created_at": "2026-04-25T11:30:00Z"
}
```

---

## Troubleshooting & Common Issues

### Issue 1: "Session key not found" Error

**Cause**: Session key not properly created or cached cleared

**Fix**:
```sql
-- Check if session key exists
SELECT * FROM session_keys 
WHERE doctor_id = '<doctor_id>' 
AND patient_id = '<patient_id>'
AND status = 'ACTIVE';

-- If empty, re-approve sharing request
curl -X POST http://localhost:8000/patient/sharing-requests/<request_id>/approve \
  -H "Authorization: Bearer <patient_token>" \
  -d '{}'
```

### Issue 2: "Invalid signature" During Decryption

**Cause**: Data tampered or wrong nonce used

**Fix**:
```python
# Verify auth tag matches
auth_tag_calculated = cipher.decrypt(nonce, ciphertext, associated_data)
if auth_tag != auth_tag_calculated:
    print("Auth tag mismatch - data tampered")
```

### Issue 3: "Session expired" But Should Be Valid

**Cause**: Database timestamp timezone mismatch

**Fix**:
```sql
-- Check server time
SELECT now();
-- Check session expiry
SELECT expires_at FROM session_keys LIMIT 1;
-- Should be in future
```

### Issue 4: Cache Invalidation Not Working

**Cause**: Redis connection issue or wrong cache key

**Fix**:
```bash
# Check Redis connection
redis-cli ping
# Should return: PONG

# Manually clear cache
redis-cli DEL "session:*"
```

---

## Summary Checklist

After completing all tests, verify:

- [ ] ✓ ECDH keypairs generated correctly
- [ ] ✓ Shared secret computed without transmission
- [ ] ✓ Session keys created with proper TTL
- [ ] ✓ ChaCha20-Poly1305 encryption works
- [ ] ✓ Patient records stored encrypted
- [ ] ✓ Doctor session key decryption works
- [ ] ✓ Permission scopes enforced (read vs read_write)
- [ ] ✓ Session expiry blocks access automatically
- [ ] ✓ Manual rotation works seamlessly
- [ ] ✓ Revocation takes effect immediately
- [ ] ✓ Audit logs cryptographically signed
- [ ] ✓ Server never decrypts patient data
- [ ] ✓ All audit events logged with signatures
- [ ] ✓ Cache invalidation works properly
- [ ] ✓ Complete end-to-end workflow verified

---

## Database Connection Verification

```bash
# Test all database queries
psql -U postgres -d bionex_db -c "
SELECT 
  'users' AS table_name, COUNT(*) AS row_count FROM users
UNION ALL
SELECT 'user_keypairs', COUNT(*) FROM user_keypairs
UNION ALL
SELECT 'session_keys', COUNT(*) FROM session_keys
UNION ALL
SELECT 'encrypted_record_vault', COUNT(*) FROM encrypted_record_vault
UNION ALL
SELECT 'crypto_audit_logs', COUNT(*) FROM crypto_audit_logs
UNION ALL
SELECT 'sharing_requests', COUNT(*) FROM sharing_requests;
"
```

---

## Next Steps

1. **Performance Testing**: Measure key generation, encryption/decryption times
2. **Load Testing**: Test with multiple concurrent doctors accessing records
3. **Security Testing**: Penetration testing and vulnerability scanning
4. **Integration Testing**: Test with actual mobile app clients
5. **Production Deployment**: Deploy to Azure with monitoring

---

**Questions?** Refer to [ENCRYPTION_ARCHITECTURE.md](ENCRYPTION_ARCHITECTURE.md) or [Phase5_AccessControl.md](Phase5_AccessControl.md) for detailed component documentation.
