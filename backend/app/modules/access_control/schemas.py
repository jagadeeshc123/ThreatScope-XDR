from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    identifier: str = Field(min_length=1, max_length=254, validation_alias=AliasChoices("identifier", "username"))
    password: str = Field(min_length=1, max_length=128)


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    username: str | None = Field(default=None, min_length=3, max_length=64)
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)
    password_confirmation: str = Field(min_length=12, max_length=128)
    terms_accepted: bool
    privacy_notice_version: str = Field(min_length=1, max_length=64)


class RegistrationApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_keys: list[str] = Field(default_factory=lambda: ["registered_user"], min_length=1, max_length=20)
    confirm_administrator: bool = False


class RegistrationRejectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


class MfaLoginRequest(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=200)
    code: str = Field(min_length=4, max_length=64)
    recovery_code: bool = False


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=2, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    temporary_password: str | None = Field(default=None, min_length=12, max_length=128)
    role_keys: list[str] = Field(default_factory=list, max_length=20)
    is_system_admin: bool = False


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=2, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    must_change_password: bool | None = None


class ResetPasswordRequest(BaseModel):
    temporary_password: str | None = Field(default=None, min_length=12, max_length=128)


class RoleCreate(BaseModel):
    role_key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)
    enabled: bool = True
    permission_keys: list[str] = Field(default_factory=list, max_length=100)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class RoleAssignments(BaseModel):
    role_keys: list[str] = Field(default_factory=list, max_length=20)


class PermissionAssignments(BaseModel):
    permission_keys: list[str] = Field(default_factory=list, max_length=100)


class LogoutAllRequest(BaseModel):
    preserve_current: bool = True


class MfaEnrollRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    label: str = Field(default="Authenticator", min_length=1, max_length=100)
    restart: bool = False


class MfaConfirmRequest(BaseModel):
    device_id: int | None = None
    code: str = Field(pattern=r"^\d{6}$")


class MfaDisableRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=4, max_length=64)
    recovery_code: bool = False
    confirm_disable: bool = False


class MfaRecoveryRegenerateRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=4, max_length=64)
    recovery_code: bool = False


class AuditFilter(BaseModel):
    actor: str | None = None
    event_type: str | None = None
    action: str | None = None
    outcome: str | None = None
    resource_type: str | None = None
    status_code: int | None = None
    request_id: str | None = None
    q: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
