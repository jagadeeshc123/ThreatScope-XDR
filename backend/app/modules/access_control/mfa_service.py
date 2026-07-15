import hashlib
import hmac
import re
import secrets
from datetime import timedelta, timezone

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import get_config
from .models import MfaDevice, MfaLoginChallenge, MfaRecoveryCode, UserAccount
from .session_service import hash_value, utcnow


TOTP_ISSUER = "ThreatScope XDR"
TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_VALID_WINDOW = 1
ENROLLMENT_TTL_MINUTES = 10
MAX_ENROLLMENT_ATTEMPTS = 5
RECOVERY_CODE_COUNT = 10


class EnrollmentExpiredError(ValueError):
    pass


class EnrollmentRateLimitError(ValueError):
    pass


class InvalidEnrollmentCodeError(ValueError):
    pass


def _fernet() -> Fernet:
    key = get_config().mfa_encryption_key
    if not key:
        raise ValueError("MFA enrollment is unavailable until THREATSCOPE_MFA_ENCRYPTION_KEY is configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ValueError("MFA encryption key is invalid") from exc


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(protected: str) -> str:
    try:
        return _fernet().decrypt(protected.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise ValueError("MFA secret cannot be decrypted") from exc


def account_label(user: UserAccount) -> str:
    return (user.email_normalized or user.username)[:254]


def provisioning_uri(secret: str, user: UserAccount) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS).provisioning_uri(
        name=account_label(user), issuer_name=TOTP_ISSUER
    )


def begin_enrollment(
    db: Session, user: UserAccount, label: str, restart: bool = False
) -> tuple[MfaDevice, str, str, str]:
    now = utcnow()
    pending = (
        db.query(MfaDevice)
        .filter_by(user_id=user.id, enabled=False)
        .order_by(MfaDevice.created_at.desc())
        .first()
    )
    if pending and pending.enrollment_expires_at and pending.enrollment_expires_at > now and not restart:
        secret = decrypt_secret(pending.secret_encrypted_or_protected)
        return pending, secret, provisioning_uri(secret, user), "resumed"

    operation = "restarted" if pending else "started"
    if pending is not None and pending in db:
        db.expunge(pending)
    db.query(MfaDevice).filter_by(user_id=user.id, enabled=False).delete(synchronize_session=False)
    secret = pyotp.random_base32()
    device = MfaDevice(
        user_id=user.id,
        label=(label.strip()[:100] or "Authenticator"),
        secret_encrypted_or_protected=encrypt_secret(secret),
        enrollment_expires_at=now + timedelta(minutes=ENROLLMENT_TTL_MINUTES),
        failed_attempts=0,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device, secret, provisioning_uri(secret, user), operation


def _totp_counter() -> int:
    # utcnow() is intentionally stored as naive UTC throughout the project.
    # Attach UTC before converting so the host's local timezone cannot shift a TOTP window.
    return int(utcnow().replace(tzinfo=timezone.utc).timestamp()) // TOTP_PERIOD_SECONDS


def verify_totp(device: MfaDevice, code: str) -> bool:
    normalized = code.strip()
    if not re.fullmatch(r"\d{6}", normalized):
        return False
    secret = decrypt_secret(device.secret_encrypted_or_protected)
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS)
    current = _totp_counter()
    matched_counter = None
    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        candidate_counter = current + offset
        expected = totp.generate_otp(candidate_counter)
        if hmac.compare_digest(expected, normalized):
            matched_counter = candidate_counter
            break
    if matched_counter is None:
        return False
    if device.last_used_counter is not None and matched_counter <= device.last_used_counter:
        return False
    device.last_used_counter = matched_counter
    device.last_used_at = utcnow()
    return True


def _format_code() -> str:
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def recovery_hash(code: str) -> str:
    return hash_value(f"recovery:{code.replace('-', '').strip().upper()}")


def generate_recovery_codes(
    db: Session, user_id: int, count: int = RECOVERY_CODE_COUNT, *, commit: bool = True
) -> list[str]:
    db.query(MfaRecoveryCode).filter_by(user_id=user_id).delete(synchronize_session=False)
    codes = [_format_code() for _ in range(count)]
    for code in codes:
        db.add(MfaRecoveryCode(user_id=user_id, code_hash=recovery_hash(code)))
    if commit:
        db.commit()
    return codes


def confirm_enrollment(
    db: Session, user: UserAccount, code: str, device_id: int | None = None
) -> tuple[MfaDevice, list[str]]:
    query = db.query(MfaDevice).filter_by(user_id=user.id, enabled=False)
    if device_id is not None:
        query = query.filter_by(id=device_id)
    device = query.order_by(MfaDevice.created_at.desc()).first()
    if not device:
        raise ValueError("No pending MFA setup was found")
    if not device.enrollment_expires_at or device.enrollment_expires_at <= utcnow():
        db.delete(device)
        db.commit()
        raise EnrollmentExpiredError("MFA setup has expired")
    if device.failed_attempts >= MAX_ENROLLMENT_ATTEMPTS:
        raise EnrollmentRateLimitError("Too many verification attempts. Restart setup to continue")
    try:
        if not verify_totp(device, code):
            device.failed_attempts += 1
            db.commit()
            if device.failed_attempts >= MAX_ENROLLMENT_ATTEMPTS:
                raise EnrollmentRateLimitError("Too many verification attempts. Restart setup to continue")
            raise InvalidEnrollmentCodeError("The verification code is invalid")
        device.enabled = True
        device.confirmed_at = utcnow()
        device.enrollment_expires_at = None
        device.failed_attempts = 0
        user.mfa_enabled = True
        codes = generate_recovery_codes(db, user.id, commit=False)
        db.commit()
        db.refresh(device)
        return device, codes
    except (InvalidEnrollmentCodeError, EnrollmentRateLimitError):
        raise
    except Exception:
        db.rollback()
        raise


def cancel_enrollment(db: Session, user_id: int) -> int:
    deleted = db.query(MfaDevice).filter_by(user_id=user_id, enabled=False).delete(synchronize_session=False)
    db.commit()
    return deleted


def mfa_status(db: Session, user: UserAccount) -> dict:
    enabled = (
        db.query(MfaDevice)
        .filter_by(user_id=user.id, enabled=True)
        .order_by(MfaDevice.confirmed_at.desc())
        .first()
    )
    pending = (
        db.query(MfaDevice)
        .filter_by(user_id=user.id, enabled=False)
        .order_by(MfaDevice.created_at.desc())
        .first()
    )
    if pending and (not pending.enrollment_expires_at or pending.enrollment_expires_at <= utcnow()):
        db.delete(pending)
        db.commit()
        pending = None
    remaining = db.query(MfaRecoveryCode).filter_by(user_id=user.id, used_at=None).count() if enabled else 0
    return {
        "enabled": bool(enabled and user.mfa_enabled),
        "setup_incomplete": bool(pending and not enabled),
        "method": "Authenticator app (TOTP)" if enabled else None,
        "label": enabled.label if enabled else (pending.label if pending else None),
        "enrolled_at": enabled.confirmed_at if enabled else None,
        "last_used_at": enabled.last_used_at if enabled else None,
        "recovery_codes_remaining": remaining,
        "pending_expires_at": pending.enrollment_expires_at if pending and not enabled else None,
        "issuer": TOTP_ISSUER,
        "account_label": account_label(user),
    }


def consume_recovery_code(db: Session, user_id: int, code: str) -> bool:
    digest = recovery_hash(code)
    item = db.query(MfaRecoveryCode).filter_by(user_id=user_id, code_hash=digest, used_at=None).first()
    if not item or not hmac.compare_digest(item.code_hash, digest):
        return False
    item.used_at = utcnow()
    db.commit()
    return True


def create_challenge(db: Session, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db.add(MfaLoginChallenge(
        user_id=user_id,
        challenge_token_hash=hash_value(token),
        expires_at=utcnow() + timedelta(minutes=5),
    ))
    db.commit()
    return token


def get_challenge(db: Session, token: str) -> MfaLoginChallenge | None:
    challenge = db.query(MfaLoginChallenge).filter_by(challenge_token_hash=hash_value(token)).first()
    if not challenge or challenge.used_at or challenge.expires_at <= utcnow() or challenge.failed_attempts >= 5:
        return None
    return challenge


def verify_user_factor(db: Session, user: UserAccount, value: str, recovery: bool = False) -> bool:
    if recovery:
        return consume_recovery_code(db, user.id, value)
    device = db.query(MfaDevice).filter_by(user_id=user.id, enabled=True).first()
    if not device or not verify_totp(device, value):
        return False
    db.commit()
    return True
