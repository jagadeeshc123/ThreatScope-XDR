import json
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError


_RULES_DIR = Path(__file__).with_name("rules")
_POLICY = json.loads((_RULES_DIR / "password_policy.json").read_text(encoding="utf-8"))
_COMMON = {
    line.strip().casefold()
    for line in (_RULES_DIR / "common_passwords.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
}
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_HASH = _HASHER.hash("timing-only-unusable-password-value")


class PasswordPolicyError(ValueError):
    pass


def validate_password(password: str, username: str, prohibited_terms: tuple[str, ...] = ()) -> None:
    if not isinstance(password, str):
        raise PasswordPolicyError("Password is required")
    if len(password) < _POLICY["minimum_length"]:
        raise PasswordPolicyError(f"Password must contain at least {_POLICY['minimum_length']} characters")
    if len(password) > _POLICY["maximum_length"]:
        raise PasswordPolicyError(f"Password must contain no more than {_POLICY['maximum_length']} characters")
    if not password.strip():
        raise PasswordPolicyError("Password cannot contain only whitespace")
    normalized_username = username.strip().casefold()
    normalized_password = password.casefold()
    if normalized_username and normalized_username in normalized_password:
        raise PasswordPolicyError("Password must not contain the username")
    for term in prohibited_terms:
        normalized_term = term.strip().casefold()
        if len(normalized_term) >= 3 and normalized_term in normalized_password:
            raise PasswordPolicyError("Password must not contain the email identifier")
    if normalized_password in _COMMON:
        raise PasswordPolicyError("Password is too commonly used")


def hash_password(password: str, username: str, prohibited_terms: tuple[str, ...] = ()) -> str:
    validate_password(password, username, prohibited_terms)
    return _HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    candidate = password_hash or _DUMMY_HASH
    try:
        return bool(_HASHER.verify(candidate, password)) if password_hash else False
    except (VerifyMismatchError, InvalidHashError, TypeError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
