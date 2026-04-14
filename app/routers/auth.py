from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.patient import Patient
from app.models.user import User, UserRole
from app.schemas.user import (
    ChangePasswordRequest,
    TwoFASetupRequest,
    TwoFAVerifyRequest,
    TokenRefresh,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.services.audit_service import log_event
from app.services.auth_service import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.services.mfa_service import (
    generate_backup_codes,
    generate_totp_secret,
    verify_backup_code,
    verify_totp_token,
)
from app.services.security_service import (
    is_account_locked,
    is_password_reused,
    record_failed_login,
    record_password_change,
    record_successful_login,
    unlock_account,
    validate_password_strength,
    invalidate_all_user_sessions,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
settings = get_settings()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)):
    """Register a new user. Rate limited to 5/minute."""
    existing = (
        db.query(User)
        .filter((User.phone == payload.phone) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Phone or email is already registered",
        )

    try:
        user = User(
            name=payload.name,
            phone=payload.phone,
            email=payload.email,
            hashed_password=hash_password(payload.password),
            role=payload.role,
        )
        db.add(user)
        db.flush()

        # Create patient profile if registering as patient (Phase 2: Transaction handling)
        if user.role == UserRole.PATIENT:
            db.add(Patient(user_id=user.id))

        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration failed - data integrity error",
        )

    ip = request.client.host if request.client else None
    log_event(db, "REGISTER", "User", str(user.id), user.id, ip_address=ip)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, payload: UserLogin, db: Session = Depends(get_db)):
    """
    Login endpoint with account lockout after failed attempts (Enhanced Security #1).
    Returns requires_2fa=true if 2FA is enabled.
    """
    ip_address = request.client.host if request.client else None
    
    user = db.query(User).filter(User.phone == payload.phone, User.is_active == True).first()
    
    # Check if account is locked (Enhanced Security #1)
    if user and is_account_locked(user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked due to multiple failed attempts. Try again after {user.locked_until.strftime('%H:%M') if user.locked_until else '15 minutes'}",
        )
    
    # Verify credentials
    if not user or not verify_password(payload.password, user.hashed_password):
        if user:
            record_failed_login(db, str(user.id), payload.phone, ip_address)
            # Refresh user from DB to get updated is_locked status
            db.refresh(user)
            if is_account_locked(user):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account locked due to multiple failed attempts. Try again after {user.locked_until.strftime('%H:%M') if user.locked_until else '15 minutes'}",
                )
        else:
            record_failed_login(db, None, payload.phone, ip_address)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    # Record successful login and reset attempts
    record_successful_login(db, str(user.id), ip_address)
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    
    log_event(db, "LOGIN", "User", str(user.id), user.id, ip_address=ip_address)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": user.role,
        "requires_2fa": user.is_2fa_enabled,  # Enhanced Security #2
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: TokenRefresh, request: Request, db: Session = Depends(get_db)):
    """Refresh access token using refresh token."""
    try:
        data = decode_token(payload.refresh_token)
        if data.get("type") != "refresh":
            raise JWTError()
        user_id = data.get("sub")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found or inactive",
        )
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    ip = request.client.host if request.client else None
    log_event(db, "REFRESH_TOKEN", "User", str(user.id), user.id, ip_address=ip)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": user.role,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 & Enhanced Security Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/change-password", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change user password (Phase 2 Security).
    Validates old password, enforces strong new password, prevents reuse.
    Invalidates all active sessions on successful change.
    """
    # Verify old password
    if not verify_password(payload.old_password, current_user.hashed_password):
        ip = request.client.host if request.client else None
        log_event(
            db,
            "PASSWORD_CHANGE_FAILED",
            "User",
            str(current_user.id),
            current_user.id,
            ip_address=ip,
            reason="Invalid old password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid current password",
        )
    
    # Validate new password strength (Enhanced Security #3)
    is_strong, error_msg = validate_password_strength(payload.new_password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)
    
    # Check if password was reused (Enhanced Security #3)
    hashed_new = hash_password(payload.new_password)
    if is_password_reused(db, str(current_user.id), hashed_new):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reuse last 5 passwords",
        )
    
    # Record old password in history (Enhanced Security #3)
    record_password_change(db, str(current_user.id), current_user.hashed_password)
    
    # Update password and mark as changed
    current_user.hashed_password = hashed_new
    current_user.last_password_change = datetime.now(timezone.utc)
    current_user.password_expires_at = datetime.now(timezone.utc) + __import__("datetime").timedelta(
        days=90
    )
    db.commit()
    
    # Invalidate all sessions (Enhanced Security #7)
    invalidate_all_user_sessions(db, str(current_user.id))
    
    ip = request.client.host if request.client else None
    log_event(
        db,
        "PASSWORD_CHANGED",
        "User",
        str(current_user.id),
        current_user.id,
        ip_address=ip,
    )
    
    return {"message": "Password changed successfully. Please login again."}


@router.post("/2fa/setup", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
def setup_2fa(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate TOTP secret for 2FA setup (Enhanced Security #2).
    Returns secret and provisioning_uri for QR code generation.
    User must verify with /2fa/setup/verify before enabling.
    """
    from app.models.login_attempt import TOTPSecret
    
    # Generate new secret
    secret, provisioning_uri = generate_totp_secret()
    backup_codes = generate_backup_codes()
    
    # Store unverified secret
    totp_record = TOTPSecret(
        user_id=current_user.id,
        secret=secret,
        backup_codes=__import__("json").dumps(backup_codes),
        is_verified=False,
    )
    db.add(totp_record)
    db.commit()
    
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "backup_codes": backup_codes,
        "message": "Scan the QR code or enter the secret in your authenticator app. Verify with /2fa/setup/verify before enabling.",
    }


@router.post("/2fa/setup/verify", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
def verify_2fa_setup(
    request: Request,
    payload: TwoFASetupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify 2FA setup by validating TOTP token. Enables 2FA on success."""
    from app.models.login_attempt import TOTPSecret
    
    totp_record = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == current_user.id,
        TOTPSecret.is_verified == False,
    ).first()
    
    if not totp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup found",
        )
    
    # Verify TOTP token
    if not verify_totp_token(totp_record.secret, payload.token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP token",
        )
    
    # Mark as verified and enable 2FA
    totp_record.is_verified = True
    totp_record.verified_at = datetime.now(timezone.utc)
    current_user.is_2fa_enabled = True
    db.commit()
    
    log_event(db, "2FA_ENABLED", "User", str(current_user.id), current_user.id)
    
    return {
        "message": "2FA enabled successfully",
        "remaining_backup_codes": len(__import__("json").loads(totp_record.backup_codes)),
    }


@router.post("/2fa/disable", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
def disable_2fa(
    request: Request,
    payload: TwoFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable 2FA by verifying current TOTP or backup code."""
    from app.models.login_attempt import TOTPSecret
    
    if not current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled",
        )
    
    totp_record = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == current_user.id,
        TOTPSecret.is_verified == True,
    ).first()
    
    if not totp_record:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="2FA record not found",
        )
    
    # Try TOTP token first
    if verify_totp_token(totp_record.secret, payload.token):
        current_user.is_2fa_enabled = False
        db.delete(totp_record)
        db.commit()
        log_event(db, "2FA_DISABLED", "User", str(current_user.id), current_user.id)
        return {"message": "2FA disabled successfully"}
    
    # Try backup code
    is_valid, updated_codes = verify_backup_code(totp_record.backup_codes, payload.token)
    if is_valid:
        if updated_codes == "[]":  # Last backup code used
            current_user.is_2fa_enabled = False
            db.delete(totp_record)
        else:
            totp_record.backup_codes = updated_codes
        db.commit()
        log_event(db, "2FA_DISABLED_VIA_BACKUP", "User", str(current_user.id), current_user.id)
        return {"message": "2FA disabled successfully using backup code"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid TOTP token or backup code",
    )


@router.post("/unlock-account", status_code=status.HTTP_200_OK)
@limiter.limit("3/minute")
def unlock_account_admin(
    request: Request,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Unlock a locked account (Enhanced Security #1).
    Only admins can unlock accounts.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can unlock accounts",
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    unlock_account(db, user)
    log_event(db, "ACCOUNT_UNLOCKED", "User", str(user.id), current_user.id)
    
    return {"message": f"User {user.phone} unlocked successfully"}

