#!/usr/bin/env python
"""
Comprehensive test script for Phase 2 & Enhanced Security features.
Tests all new endpoints and security validations.
"""

import json
import sys
import time
import random
from datetime import datetime

import httpx

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

BASE_URL = "http://localhost:8000/api/v1"
HEALTH_URL = "http://localhost:8000/health"

# Generate unique phone numbers for each test run to avoid conflicts
RANDOM_SUFFIX = random.randint(10000, 99999)
TEST_PHONE = f"+9198765432{RANDOM_SUFFIX % 100:02d}"  # +91987654321X (changes each run)
TEST_PHONE_LOCKOUT = f"+9198765433{RANDOM_SUFFIX % 100:02d}"  # Different phone for lockout test
TEST_EMAIL = f"phase2test{RANDOM_SUFFIX}@bionex.com"
TEST_PASSWORD = "InitialPass@123"  # Meets basic requirements
TEST_NEW_PASSWORD = "SecureNewPassword@99!"  # Meets strong requirements

test_results = {
    "passed": 0,
    "failed": 0,
    "tests": []
}


# ─────────────────────────────────────────────────────────────────────────────
# Test Utilities
# ─────────────────────────────────────────────────────────────────────────────

def log_test(name: str, passed: bool, details: str = ""):
    """Log test result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} | {name}")
    if details:
        print(f"   └─ {details}")
    
    test_results["tests"].append({
        "name": name,
        "passed": passed,
        "details": details,
    })
    
    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1


def test_endpoint(method: str, url: str, expected_status: int | list, headers=None, json_data=None, name: str = ""):
    """Test an API endpoint."""
    try:
        if method == "POST":
            response = httpx.post(url, headers=headers, json=json_data, timeout=10)
        elif method == "GET":
            response = httpx.get(url, headers=headers, timeout=10)
        elif method == "PUT":
            response = httpx.put(url, headers=headers, json=json_data, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        # Check status
        expected_statuses = [expected_status] if isinstance(expected_status, int) else expected_status
        passed = response.status_code in expected_statuses
        
        details = f"{method} {url.replace(BASE_URL, '')} → {response.status_code}"
        if not passed:
            details += f" (expected {expected_statuses})"
            if response.text:
                details += f" | Response: {response.text[:100]}"
        
        log_test(name or f"{method} {url}", passed, details)
        return response if passed else None
    except Exception as e:
        log_test(name or f"{method} {url}", False, f"Exception: {str(e)}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Basic Connectivity Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_phase_1_connectivity():
    print("\n" + "="*70)
    print("PHASE 1: CONNECTIVITY & CORE FUNCTIONALITY")
    print("="*70)
    
    # Health check
    test_endpoint("GET", HEALTH_URL, 200, name="1.1 Health Check")
    
    # Swagger docs
    test_endpoint("GET", f"{BASE_URL.replace('/api/v1', '')}/docs", [200, 404], name="1.2 Swagger Docs Available")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Part 1: Input Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_phase_2_input_validation():
    print("\n" + "="*70)
    print("PHASE 2: INPUT VALIDATION & REGISTRATION")
    print("="*70)
    
    # Test invalid phone format
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/register",
        400,
        json_data={
            "name": "Test User",
            "phone": "9876543210",  # Missing + prefix
            "email": "test@bionex.com",
            "password": "ValidPass@123",
            "role": "PATIENT",
        },
        name="2.1 Invalid Phone Format (No +)"
    )
    
    # Test valid phone
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/register",
        201,
        json_data={
            "name": "Phase 2 Test User",
            "phone": TEST_PHONE,
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "role": "PATIENT",
        },
        name="2.2 Valid Registration"
    )
    
    return response.json() if response else None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Part 2: Account Lockout Tests (Enhanced Security #1)
# ─────────────────────────────────────────────────────────────────────────────

def test_phase_2_account_lockout(user_data):
    print("\n" + "="*70)
    print("PHASE 2 & ENHANCED #1: ACCOUNT LOCKOUT")
    print("="*70)
    
    if not user_data:
        print("   ⚠️  Skipped - No valid user")
        return None
    
    # First register a separate user for lockout testing
    print("   → Registering user for lockout testing...")
    reg_response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/register",
        201,
        json_data={
            "name": "Lockout Test User",
            "phone": TEST_PHONE_LOCKOUT,
            "email": f"lockout{RANDOM_SUFFIX}@bionex.com",
            "password": TEST_PASSWORD,
            "role": "PATIENT",
        },
        name="2.3.0 Register Lockout Test User (Internal)"
    )
    
    if not reg_response:
        print("   ⚠️  Could not create lockout test user")
        return None
    
    phone = TEST_PHONE_LOCKOUT
    
    # Attempt multiple failed logins
    for attempt in range(1, 6):
        response = test_endpoint(
            "POST",
            f"{BASE_URL}/auth/login",
            [401, 429],
            json_data={"phone": phone, "password": "WrongPassword123!"},
            name=f"2.3.{attempt} Failed Login Attempt {attempt}"
        )
        
        if attempt == 5:
            # 5th attempt should lock account (return 429)
            if response and response.status_code == 429:
                log_test("2.3.6 Account Locked After 5 Failed Attempts", True, "Received 429 Too Many Requests")
            else:
                log_test("2.3.6 Account Locked After 5 Failed Attempts", False, f"Expected 429, got {response.status_code if response else 'No response'}")
    
    return phone


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Part 3: Password Validation Tests (Enhanced Security #3)
# ─────────────────────────────────────────────────────────────────────────────

def test_phase_2_password_strength():
    print("\n" + "="*70)
    print("PHASE 2 & ENHANCED #3: PASSWORD STRENGTH VALIDATION")
    print("="*70)
    
    # Test weak password (too short)
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/register",
        400,
        json_data={
            "name": "Weak Pass Test",
            "phone": "+919876543212",
            "email": "weakpass@bionex.com",
            "password": "Short1!",
            "role": "PATIENT",
        },
        name="2.4 Weak Password - Too Short"
    )
    
    # Test password without uppercase
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/register",
        400,
        json_data={
            "name": "No Upper Test",
            "phone": "+919876543213",
            "email": "noupper@bionex.com",
            "password": "nouppercase123!",
            "role": "PATIENT",
        },
        name="2.5 Weak Password - No Uppercase"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Part 4: Password Change Endpoint (Phase 2 Security)
# ─────────────────────────────────────────────────────────────────────────────

def test_phase_2_password_change():
    print("\n" + "="*70)
    print("PHASE 2: PASSWORD CHANGE ENDPOINT")
    print("="*70)
    
    # First login with valid credentials
    print("   → Getting access token...")
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/login",
        200,
        json_data={"phone": TEST_PHONE, "password": TEST_PASSWORD},
        name="2.6 Login Before Password Change"
    )
    
    if not response:
        print("   ⚠️  Skipped password change tests - Login failed")
        return None
    
    data = response.json()
    access_token = data.get("access_token")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Attempt password change with weak new password
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/change-password",
        400,
        headers=headers,
        json_data={
            "old_password": TEST_PASSWORD,
            "new_password": "weak123",  # Too short
        },
        name="2.7 Password Change - Weak New Password Rejected"
    )
    
    # Successful password change
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/change-password",
        200,
        headers=headers,
        json_data={
            "old_password": TEST_PASSWORD,
            "new_password": TEST_NEW_PASSWORD,
        },
        name="2.8 Password Change - Success"
    )
    
    if response:
        # Try to login with old password (should fail)
        test_endpoint(
            "POST",
            f"{BASE_URL}/auth/login",
            401,
            json_data={"phone": TEST_PHONE, "password": TEST_PASSWORD},
            name="2.9 Old Password Rejected After Change"
        )
        
        # Try to login with new password (should succeed)
        test_endpoint(
            "POST",
            f"{BASE_URL}/auth/login",
            200,
            json_data={"phone": TEST_PHONE, "password": TEST_NEW_PASSWORD},
            name="2.10 New Password Works After Change"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Enhanced Security Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_enhanced_security_headers():
    print("\n" + "="*70)
    print("ENHANCED #9: SECURITY HEADERS")
    print("="*70)
    
    try:
        response = httpx.get(HEALTH_URL)
        headers = response.headers
        
        security_headers = {
            "Content-Security-Policy": headers.get("content-security-policy"),
            "X-Content-Type-Options": headers.get("x-content-type-options"),
            "X-Frame-Options": headers.get("x-frame-options"),
            "X-XSS-Protection": headers.get("x-xss-protection"),
        }
        
        all_present = all(v for v in security_headers.values())
        log_test(
            "3.1 Security Headers Present",
            all_present,
            f"Headers: {json.dumps({k: v for k, v in security_headers.items() if v}, indent=2)}"
        )
        
        # Check X-Request-ID
        request_id = headers.get("x-request-id")
        log_test(
            "3.2 Request ID Tracking",
            bool(request_id),
            f"Request-ID: {request_id}"
        )
    except Exception as e:
        log_test("3.1 Security Headers Present", False, str(e))
        log_test("3.2 Request ID Tracking", False, str(e))


def test_enhanced_2fa_endpoints():
    print("\n" + "="*70)
    print("ENHANCED #2: TWO-FACTOR AUTHENTICATION (2FA)")
    print("="*70)
    
    # Login to get token
    response = httpx.post(
        f"{BASE_URL}/auth/login",
        json={"phone": TEST_PHONE, "password": TEST_NEW_PASSWORD},
        timeout=10
    )
    
    if response.status_code != 200:
        print("   ⚠️  Skipped 2FA tests - Login failed")
        return
    
    data = response.json()
    access_token = data.get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Setup 2FA
    response = test_endpoint(
        "POST",
        f"{BASE_URL}/auth/2fa/setup",
        200,
        headers=headers,
        name="3.3 2FA Setup - Generate Secret"
    )
    
    if response:
        data = response.json()
        secret = data.get("secret")
        backup_codes = data.get("backup_codes")
        log_test(
            "3.4 2FA Setup Response Contains Secret & Backup Codes",
            bool(secret and backup_codes and len(backup_codes) >= 8),
            f"Secret present: {bool(secret)}, Backup codes: {len(backup_codes) if backup_codes else 0}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiting Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_rate_limiting():
    print("\n" + "="*70)
    print("RATE LIMITING")
    print("="*70)
    
    # Rapidly attempt multiple logins to trigger rate limit
    print("   → Testing rate limit on /login (10/minute)...")
    limited = False
    
    for i in range(12):
        response = httpx.post(
            f"{BASE_URL}/auth/login",
            json={"phone": "+919999999999", "password": "test"},
            timeout=10
        )
        
        if response.status_code == 429:
            limited = True
            log_test(
                f"4.1 Rate Limiting Enforced",
                True,
                f"Received 429 on attempt {i + 1}"
            )
            break
    
    if not limited:
        log_test(
            "4.1 Rate Limiting Enforced",
            False,
            "Did not receive 429 after 12 attempts"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main Test Runner
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "BIONEX SECURITY TEST SUITE" + " "*27 + "║")
    print("║" + " "*10 + "Phase 2 Fixes + Enhanced Security Features" + " "*16 + "║")
    print("╚" + "="*68 + "╝")
    
    try:
        # Phase 1: Connectivity
        test_phase_1_connectivity()
        
        # Phase 2: Input Validation & Registration
        user_data = test_phase_2_input_validation()
        
        # Phase 2: Account Lockout
        test_phase_2_account_lockout(user_data)
        
        # Phase 2: Password Strength
        test_phase_2_password_strength()
        
        # Phase 2: Password Change
        test_phase_2_password_change()
        
        # Enhanced Security: Headers
        test_enhanced_security_headers()
        
        # Enhanced Security: 2FA
        test_enhanced_2fa_endpoints()
        
        # Rate Limiting
        test_rate_limiting()
        
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    print(f"📊 Total:  {test_results['passed'] + test_results['failed']}")
    print(f"📈 Success Rate: {(test_results['passed'] / (test_results['passed'] + test_results['failed']) * 100):.1f}%")
    
    # Save results
    summary = {
        "timestamp": datetime.now().isoformat(),
        "passed": test_results["passed"],
        "failed": test_results["failed"],
        "total": test_results["passed"] + test_results["failed"],
        "success_rate": (test_results["passed"] / (test_results["passed"] + test_results["failed"]) * 100) if (test_results["passed"] + test_results["failed"]) > 0 else 0,
        "tests": test_results["tests"],
    }
    
    with open("TEST_RESULTS.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n📄 Full results saved to TEST_RESULTS.json")
    
    return 0 if test_results["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
