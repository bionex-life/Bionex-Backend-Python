"""
Security Module Documentation

This module provides production-grade cryptographic operations for the Bionex healthcare platform.

## Overview

### Components

1. **CryptoManager** (app/security/crypto.py)
   - ECDH P-256 keypair generation
   - ChaCha20-Poly1305 authenticated encryption
   - ECDSA-SHA256 signatures
   - HKDF-SHA256 key derivation
   - SHA-256 hashing
   - Session key generation

2. **CacheManager** (app/security/cache.py)
   - Redis connection pooling
   - Public key caching (90 days)
   - Session key validation (7 days)
   - Permission caching (1 hour)
   - Cache invalidation on key rotation/revocation

3. **VaultManager** (app/security/vault.py)
   - HashiCorp Vault integration
   - Private key storage (never in DB)
   - Encryption key management
   - Secret rotation tracking
   - Graceful fallback if Vault unavailable

## Installation

### Prerequisites

- Python 3.9+
- PostgreSQL 14+ (already configured)
- Redis 7.0+ (already configured)
- HashiCorp Vault 1.12+ (for production)

### Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. Start services locally:
   ```bash
   # Terminal 1: Redis (for development)
   redis-server

   # Terminal 2: Vault (for development)
   vault server -dev
   # Copy Vault token to .env VAULT_TOKEN

   # Terminal 3: Application
   uvicorn app.main:app --reload
   ```

## Usage Examples

### 1. Keypair Generation

```python
from app.security.crypto import CryptoManager

# Generate new keypair for user
private_pem, public_pem = CryptoManager.generate_keypair()

# Store private key in Vault (NEVER in code/DB)
vault_manager.store_private_key(user_id, private_pem)

# Cache public key in Redis
cache_manager.cache_public_key(user_id, public_pem)
```

### 2. Encrypt Medical Record

```python
from app.security.crypto import CryptoManager

# Get session key for doctor-patient pair
session_key = bytes.fromhex(session_key_from_client)

# Encrypt medical record with ChaCha20-Poly1305
plaintext = b"Patient diagnosis and treatment plan..."
encrypted = CryptoManager.encrypt_chacha20(
    plaintext=plaintext,
    key=session_key,
    associated_data=b"patient_id:doctor_id:record_type"
)

# Store in database:
# - ciphertext: encrypted data (searchable with hash)
# - nonce: IV for decryption
# - auth_tag: authentication (detects tampering)
```

### 3. Decrypt Record with Validation

```python
from app.security.cache import CacheManager
from app.security.crypto import CryptoManager

# Check if doctor's session is valid (fast Redis lookup)
cache_manager = CacheManager()
session_valid = cache_manager.get_session_key_doctor(session_key_hash)

if session_valid:
    # Decrypt
    plaintext = CryptoManager.decrypt_chacha20(
        ciphertext_b64=encrypted['ciphertext'],
        nonce_b64=encrypted['nonce'],
        auth_tag_b64=encrypted['auth_tag'],
        key=session_key
    )
```

### 4. Sign Audit Log Entry

```python
from app.security.crypto import CryptoManager
from app.security.vault import VaultManager

# Get server's private key from Vault
vault_manager = VaultManager()
server_private_key = vault_manager.retrieve_private_key("SERVER")

# Create audit entry
import json
event = {
    "action": "RECORD_ACCESSED",
    "doctor_id": "...",
    "patient_id": "...",
    "timestamp": "2026-04-19T10:30:00Z"
}
event_json = json.dumps(event, sort_keys=True)

# Sign
signature = CryptoManager.sign_data(server_private_key, event_json.encode())

# Store signature with audit log
audit_log = CryptographicAuditLog(
    event_data=event,
    signature=signature,
    signature_timestamp=datetime.utcnow()
)
```

### 5. Verify Audit Log (Tamper Detection)

```python
from app.security.crypto import CryptoManager

# Retrieve server's public key
server_public_key = vault_manager.retrieve_secret("SERVER_PUBLIC_KEY_PEM")

# Recreate event JSON in same order
event_json = json.dumps(audit_log.event_data, sort_keys=True)

# Verify signature
is_valid = CryptoManager.verify_signature(
    public_key_pem=server_public_key,
    data=event_json.encode(),
    signature_b64=audit_log.signature
)

if not is_valid:
    raise SecurityError("Audit log has been tampered with!")
```

## Best Practices

### DO ✅

1. **Store private keys in Vault, NOT in database**
   ```python
   vault_manager.store_private_key(user_id, private_pem)  # ✅
   db.add(UserKeypair(private_key=private_pem))  # ❌ WRONG!
   ```

2. **Use base64 encoding for transport**
   ```python
   encrypted = CryptoManager.encrypt_chacha20(data, key)
   # Output is already base64 encoded for JSON/HTTP
   json.dumps(encrypted)  # ✅
   ```

3. **Validate session keys from cache first**
   ```python
   # Fast check (Redis)
   doctor_id = cache_manager.get_session_key_doctor(hash)
   if doctor_id:
       return  # ✅ 99% cache hit rate
   # Fallback to DB if needed
   ```

4. **Pass associated data for authenticated encryption**
   ```python
   aad = f"{patient_id}:{doctor_id}:{record_type}".encode()
   encrypted = CryptoManager.encrypt_chacha20(data, key, aad)  # ✅
   ```

5. **Log all cryptographic operations**
   ```python
   try:
       plaintext = CryptoManager.decrypt_chacha20(...)
   except CryptoEncryptionError as e:
       logger.error(f"Decryption failed: {e}")  # ✅
   ```

### DON'T ❌

1. **Hardcode keys or crypto parameters**
   ```python
   key = b"fixed_key_123"  # ❌ NEVER!
   ```

2. **Store plaintext secrets in environment variables**
   ```python
   SECRET = os.getenv("SECRET_KEY")  # ❌ Exposed in process memory
   secret = vault_manager.retrieve_secret("secret_key")  # ✅
   ```

3. **Reuse session keys across patients**
   ```python
   # ❌ Doctor's session key reused for multiple patients
   # ✅ Each patient-doctor pair gets unique 7-day session key
   ```

4. **Log plaintext encryption keys**
   ```python
   logger.info(f"Session key: {session_key}")  # ❌
   logger.info("Established session key")  # ✅
   ```

5. **Skip TTL on cached keys**
   ```python
   cache_manager.redis_client.set(key, value)  # ❌ No TTL!
   cache_manager.cache_public_key(user_id, value)  # ✅ 90-day TTL
   ```

## Testing

### Run Unit Tests

```bash
# All crypto tests
pytest tests/test_crypto.py -v

# Specific test class
pytest tests/test_crypto.py::TestCryptoManagerEncryption -v

# With coverage
pytest tests/test_crypto.py --cov=app.security --cov-report=html
```

### Test Scenarios Covered

- ✅ Keypair generation uniqueness
- ✅ Encryption/decryption roundtrips
- ✅ Authentication tag verification
- ✅ Session key isolation (different keys for different users)
- ✅ Signature generation and verification
- ✅ Hash consistency
- ✅ Cache hits and misses
- ✅ TTL expiration
- ✅ Error handling and edge cases

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Keypair generation | 20-30ms | Once per user, cached |
| Session key generation | 1-2ms | Per access approval |
| ChaCha20 encryption | 0.5ms per KB | Fast symmetric cipher |
| ECDSA signature | 10-25ms | Done async, doesn't block |
| Cache lookup | <1ms | 99% hit rate |
| Vault retrieval | 50-100ms | Cached in Redis after first access |

## Production Checklist

- [ ] Set strong SECRET_KEY (32+ chars)
- [ ] Generate and store FIELD_ENCRYPTION_KEY
- [ ] Deploy Redis cluster (not single instance)
- [ ] Deploy Vault HA cluster with proper auth
- [ ] Enable TLS/HTTPS everywhere
- [ ] Configure rate limiting in load balancer
- [ ] Set up monitoring/alerting for failed decryptions
- [ ] Enable audit logging in Vault
- [ ] Implement key rotation scheduler (Celery)
- [ ] Configure backup/restore for Vault
- [ ] Review and restrict admin access
- [ ] Enable database encryption at rest
- [ ] Set up log aggregation (ELK/CloudWatch)

## Troubleshooting

### "Redis health check failed"

```bash
# Check if Redis is running
redis-cli ping
# Should output: PONG

# Start Redis if needed
redis-server
```

### "Vault client not initialized"

```bash
# Check if Vault is running
vault status
# Should show: Sealed: false

# Start Vault (dev mode)
vault server -dev
```

### "Failed to decrypt: authentication failed"

- Session key might be wrong
- Associated data might not match encryption
- Key might have expired (check TTL)
- Check audit logs for tampering

### "Cache miss for public key"

- Cache TTL expired after 90 days
- Fallback to database lookup (automatic)
- Key might have been rotated

## Further Reading

- [ECDH RFC 5116](https://tools.ietf.org/html/rfc5116)
- [ChaCha20-Poly1305 RFC 7539](https://tools.ietf.org/html/rfc7539)
- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
- [ECDSA RFC 6090](https://tools.ietf.org/html/rfc6090)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Redis Best Practices](https://redis.io/docs/management/admin/backups/)
"""
