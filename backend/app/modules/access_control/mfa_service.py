import hashlib
import hmac
import secrets
from datetime import timedelta

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import get_config
from .models import MfaDevice, MfaLoginChallenge, MfaRecoveryCode, UserAccount
from .session_service import hash_value, utcnow


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


def begin_enrollment(db: Session, user: UserAccount, label: str) -> tuple[MfaDevice, str, str]:
    db.query(MfaDevice).filter_by(user_id=user.id, enabled=False).delete(synchronize_session=False)
    secret = pyotp.random_base32()
    device = MfaDevice(user_id=user.id, label=label[:100] or "Authenticator", secret_encrypted_or_protected=encrypt_secret(secret))
    db.add(device)
    db.commit()
    db.refresh(device)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="ThreatScope XDR")
    return device, secret, uri


def _totp_counter() -> int:
    return int(utcnow().timestamp()) // 30


def verify_totp(device: MfaDevice, code: str) -> bool:
    secret = decrypt_secret(device.secret_encrypted_or_protected)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code.strip(), valid_window=1):
        return False
    counter = _totp_counter()
    if device.last_used_counter is not None and counter <= device.last_used_counter:
        return False
    device.last_used_counter = counter
    return True


def _format_code() -> str:
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def recovery_hash(code: str) -> str:
    return hash_value(f"recovery:{code.replace('-', '').strip().upper()}")


def generate_recovery_codes(db: Session, user_id: int, count: int = 10) -> list[str]:
    db.query(MfaRecoveryCode).filter_by(user_id=user_id).delete(synchronize_session=False)
    codes = [_format_code() for _ in range(count)]
    for code in codes:
        db.add(MfaRecoveryCode(user_id=user_id, code_hash=recovery_hash(code)))
    db.commit()
    return codes


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

