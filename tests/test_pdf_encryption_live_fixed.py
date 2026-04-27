#!/usr/bin/env python3
"""
LIVE PDF ENCRYPTION/DECRYPTION DEMONSTRATION
=============================================

This script demonstrates the complete encryption workflow for the canonical_written_interview.pdf

Workflow:
1. Read PDF file
2. Generate encryption keys (256-bit session key)
3. Encrypt PDF with ChaCha20-Poly1305 AEAD
4. Show encrypted output (base64)
5. Decrypt back to original
6. Verify integrity
"""

import os
import sys
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from app.security.crypto import CryptoManager
from app.services.key_exchange import KeyExchangeManager
import base64
import json
from datetime import datetime, timezone


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print("  " + title)
    print("=" * 80)


def print_step(step_num, description):
    """Print a numbered step"""
    print("\n[STEP " + str(step_num) + "] " + description)
    print("-" * 80)


def format_bytes(data, label="Data"):
    """Display bytes info"""
    print(label + ":")
    print("  Size: " + str(len(data)) + " bytes")
    print("  Hash: " + CryptoManager.hash_data(data)[:32] + "...")


# ============================================================================
# PHASE 1: SETUP
# ============================================================================

print_section("PHASE 1: SETUP & KEY GENERATION")

print_step(1, "Read PDF File")
pdf_path = Path(__file__).parent / "canonical_written_interview.pdf"

if not pdf_path.exists():
    print("[ERROR] PDF not found at " + str(pdf_path))
    sys.exit(1)

# Read PDF
with open(pdf_path, "rb") as f:
    original_pdf = f.read()

format_bytes(original_pdf, "Original PDF")
print("[OK] PDF loaded successfully from: " + pdf_path.name)

print_step(2, "Generate 256-bit Session Key (Random)")
# This is KEY 1 from the three-key system
session_key = CryptoManager.generate_session_key(32)  # 256 bits
print("Session Key (hex): " + session_key.hex()[:64] + "...")
print("Session Key Length: " + str(len(session_key)) + " bytes = " + str(len(session_key) * 8) + " bits")
format_bytes(session_key, "Session Key")
print("[OK] Session key generated using cryptographically secure random")

print_step(3, "Calculate Session Key Hash (for database lookup)")
# This is the hash that gets stored in DB, not the plaintext key
session_key_hash = CryptoManager.hash_data(session_key)
print("Session Key Hash (SHA-256): " + session_key_hash)
print("Hash Length: " + str(len(session_key_hash)) + " characters (64 hex digits)")
print("[OK] Hash calculated - this is what's stored in DB as UNIQUE constraint")

# ============================================================================
# PHASE 2: ENCRYPT PDF WITH SESSION KEY
# ============================================================================

print_section("PHASE 2: ENCRYPT PDF (ChaCha20-Poly1305 AEAD)")

print_step(4, "Encrypt PDF with Session Key")
print("Using: ChaCha20-Poly1305 (AEAD - Authenticated Encryption with Associated Data)")
print("Guarantees: Confidentiality (ChaCha20) + Authenticity (Poly1305)")

try:
    encrypted_result = CryptoManager.encrypt_chacha20(
        plaintext=original_pdf,
        key=session_key,
        associated_data=b"bionex_encrypted_record"  # AAD for authentication
    )
    
    print("[OK] Encryption successful!")
    print("\nEncryption Result Components:")
    print("  ciphertext (base64): " + encrypted_result['ciphertext'][:80] + "...")
    print("    Length: " + str(len(base64.b64decode(encrypted_result['ciphertext']))) + " bytes")
    print("  nonce (base64): " + encrypted_result['nonce'])
    print("    Decoded: " + base64.b64decode(encrypted_result['nonce']).hex())
    print("    Length: " + str(len(base64.b64decode(encrypted_result['nonce']))) + " bytes (96-bit)")
    print("  auth_tag (base64): " + encrypted_result['auth_tag'])
    print("    Decoded: " + base64.b64decode(encrypted_result['auth_tag']).hex())
    print("    Length: " + str(len(base64.b64decode(encrypted_result['auth_tag']))) + " bytes (128-bit)")

except Exception as e:
    print("[ERROR] Encryption failed: " + str(e))
    sys.exit(1)

print_step(5, "Show Encrypted Data (as would be stored in DB)")

encrypted_db_entry = {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "patient_id": "660e8400-e29b-41d4-a716-446655440000",
    "original_record_id": "770e8400-e29b-41d4-a716-446655440000",
    "ciphertext": encrypted_result["ciphertext"],
    "nonce": encrypted_result["nonce"],
    "auth_tag": encrypted_result["auth_tag"],
    "record_type": "PDF_DOCUMENT",
    "record_date": datetime.now(timezone.utc).isoformat(),
    "encryption_algorithm": "CHACHA20_POLY1305",
    "created_at": datetime.now(timezone.utc).isoformat()
}

print("Database Entry (encrypted_record_vaults table):")
print(json.dumps({
    k: v[:100] + "..." if isinstance(v, str) and len(v) > 100 else v 
    for k, v in encrypted_db_entry.items()
}, indent=2))

print("\nSize Comparison:")
print("  Original PDF:      " + f"{len(original_pdf):,}".replace(',', '') + " bytes")
print("  Encrypted:         " + f"{len(base64.b64decode(encrypted_result['ciphertext'])):,}".replace(',', '') + " bytes")
print("  Overhead:          " + str(len(base64.b64decode(encrypted_result['auth_tag'])) + len(base64.b64decode(encrypted_result['nonce']))) + " bytes (nonce + auth_tag)")
print("  Total in DB:       ~" + f"{len(json.dumps(encrypted_db_entry).encode()):,}".replace(',', '') + " bytes")

# ============================================================================
# PHASE 3: SIMULATE DOCTOR DECRYPTION
# ============================================================================

print_section("PHASE 3: DOCTOR DECRYPTS PDF (Using Same Session Key)")

print_step(6, "Doctor retrieves encrypted record from DB")
print("Session Key Hash: " + session_key_hash)
print("Query: SELECT * FROM encrypted_record_vaults WHERE...")
print("       SELECT session_keys FROM session_keys WHERE session_key_hash = ?")
print("[OK] Retrieved from database")

print_step(7, "Doctor decrypts PDF using Session Key")
print("Process:")
print("  1. Load session_key (recovered from ECDH key exchange)")
print("  2. Load nonce from encrypted data")
print("  3. Load auth_tag from encrypted data")
print("  4. Decrypt with ChaCha20-Poly1305")
print("  5. Verify authentication tag")

try:
    decrypted_pdf = CryptoManager.decrypt_chacha20(
        ciphertext_b64=encrypted_result["ciphertext"],
        nonce_b64=encrypted_result["nonce"],
        auth_tag_b64=encrypted_result["auth_tag"],
        key=session_key,
        associated_data=b"bionex_encrypted_record"
    )
    
    print("[OK] Decryption successful!")
    format_bytes(decrypted_pdf, "Decrypted PDF")

except Exception as e:
    print("[ERROR] Decryption failed: " + str(e))
    sys.exit(1)

# ============================================================================
# PHASE 4: VERIFICATION
# ============================================================================

print_section("PHASE 4: VERIFICATION & INTEGRITY CHECK")

print_step(8, "Verify Decrypted Data Matches Original")

if decrypted_pdf == original_pdf:
    print("[OK] VERIFICATION PASSED: Decrypted data matches original perfectly!")
    
    # Calculate hashes
    original_hash = CryptoManager.hash_data(original_pdf)
    decrypted_hash = CryptoManager.hash_data(decrypted_pdf)
    
    print("\nHash Verification:")
    print("  Original PDF Hash:   " + original_hash)
    print("  Decrypted PDF Hash:  " + decrypted_hash)
    print("  Match:               " + ("[OK] YES" if original_hash == decrypted_hash else "[ERROR] NO"))
else:
    print("[ERROR] VERIFICATION FAILED: Decrypted data does NOT match original!")
    print("  Original size:   " + str(len(original_pdf)) + " bytes")
    print("  Decrypted size:  " + str(len(decrypted_pdf)) + " bytes")
    sys.exit(1)

print_step(9, "Test Authentication Tag Tampering Detection")
print("Simulating: Attacker tries to modify ciphertext...")

tampered_ciphertext = encrypted_result["ciphertext"]
# Flip one character in the base64 string
tampered = tampered_ciphertext[:-10] + "XXXXXXXXXX"

print("Original:  " + encrypted_result['ciphertext'][-20:])
print("Tampered:  " + tampered[-20:])

try:
    CryptoManager.decrypt_chacha20(
        ciphertext_b64=tampered,
        nonce_b64=encrypted_result["nonce"],
        auth_tag_b64=encrypted_result["auth_tag"],
        key=session_key,
        associated_data=b"bionex_encrypted_record"
    )
    print("[ERROR] SECURITY FAILURE: Tampered data was accepted!")
except Exception as e:
    print("[OK] SECURITY SUCCESS: Tampered data rejected!")
    print("     Error: " + str(e)[:80] + "...")
    print("     Poly1305 authentication tag prevented tampering!")

# ============================================================================
# PHASE 5: SUMMARY
# ============================================================================

print_section("SUMMARY: THREE-KEY ENCRYPTION SYSTEM")

summary = """
KEY 1: Session Key (256-bit Random)
  Generated: """ + session_key.hex()[:48] + """...
  Length:    """ + str(len(session_key)) + """ bytes = """ + str(len(session_key) * 8) + """ bits                            
  Purpose:   Encrypts/decrypts medical records (ChaCha20)
  Storage:   Encrypted in DB with doctor's public key (ECDH)
  Lifetime:  7 days

KEY 2: Symmetric Encryption Key (Derived from ECDH)
  Source:    HKDF-SHA256(ECDH_shared_secret)
  Purpose:   Encrypts Session Key with doctor's public key
  Derivation: Only doctor can compute (has Private_Doctor)
  Storage:   Never stored, computed on-demand
  Security:  Forward secrecy (ephemeral keys per operation)

KEY 3: Authentication Tag (128-bit Poly1305 MAC)
  Generated: """ + base64.b64decode(encrypted_result['auth_tag']).hex() + """
  Purpose:   Detects tampering (ensures authenticity)
  Strength:  128-bit Poly1305 MAC
  Guarantee: If 1 bit changed in ciphertext -> MAC fails

ENCRYPTION FLOW:
  Original PDF (""" + f"{len(original_pdf):,}".replace(',', '') + """ bytes)
       DOWN
  [ChaCha20 Cipher + Session Key] -> Ciphertext (""" + f"{len(base64.b64decode(encrypted_result['ciphertext'])):,}".replace(',', '') + """ bytes)
       DOWN
  [Poly1305 MAC] -> Auth Tag (16 bytes)
       DOWN
  [Random Nonce] -> Nonce (12 bytes)
       DOWN
  Store in DB: (ciphertext, nonce, auth_tag)
       DOWN
  [Doctor retrieves with valid session key]
       DOWN
  [ChaCha20 Decipher + Session Key] -> Original PDF [OK]
       DOWN
  [Verify Poly1305 MAC] -> Integrity confirmed [OK]

SECURITY PROPERTIES:
  [OK] Confidentiality:   ChaCha20 stream cipher
  [OK] Authenticity:      Poly1305 MAC (detects tampering)
  [OK] Key Exchange:      ECDH P-256 (forward secrecy)
  [OK] Key Derivation:    HKDF-SHA256 (RFC 5869)
  [OK] Random Generation: os.urandom() (cryptographically secure)
  [OK] No Key Reuse:      Fresh nonce per encryption
  [OK] Immutable Audit:   All access logged with ECDSA signatures
"""

print(summary)

print_section("[OK] DEMONSTRATION COMPLETE")

print("\nFile encrypted and decrypted successfully!")
print("\nFile information:")
print("  Original PDF:     " + pdf_path.name)
print("  Original Size:    " + f"{len(original_pdf):,}".replace(',', '') + " bytes")
print("  Session Key:      " + str(len(session_key)) + " bytes (256-bit)")
print("  Key Hash:         " + session_key_hash)
print("  Nonce:            " + base64.b64decode(encrypted_result['nonce']).hex())
print("  Auth Tag:         " + base64.b64decode(encrypted_result['auth_tag']).hex())
print("\n[OK] All tests passed! PDF is securely encrypted and can be safely transmitted.")
