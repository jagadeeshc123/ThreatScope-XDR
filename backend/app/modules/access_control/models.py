from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UserAccount(Base):
    __tablename__ = "user_accounts"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False)
    username_normalized = Column(String(64), nullable=False, unique=True, index=True)
    display_name = Column(String(120), nullable=False)
    email = Column(String(254))
    email_normalized = Column(String(254), unique=True, index=True)
    password_hash = Column(String(512), nullable=False)
    status = Column(String(32), nullable=False, default="active", index=True)
    is_system_admin = Column(Boolean, nullable=False, default=False)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime)
    password_changed_at = Column(DateTime, nullable=False, default=utcnow)
    must_change_password = Column(Boolean, nullable=False, default=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    last_login_at = Column(DateTime)
    last_login_ip_hash = Column(String(64))
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    disabled_at = Column(DateTime)
    registration_source = Column(String(32), nullable=False, default="administrator", index=True)
    approved_at = Column(DateTime)
    approved_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    rejected_at = Column(DateTime)
    rejected_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    rejection_reason = Column(String(500))
    terms_accepted_at = Column(DateTime)
    privacy_notice_version = Column(String(64))
    email_verified = Column(Boolean, nullable=False, default=False)
    onboarding_completed_at = Column(DateTime)
    is_demo_account = Column(Boolean, nullable=False, default=False)

    roles = relationship("UserRoleAssignment", foreign_keys="UserRoleAssignment.user_id", cascade="all, delete-orphan")
    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")


class AccessRole(Base):
    __tablename__ = "access_roles"
    id = Column(Integer, primary_key=True)
    role_key = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False, default="")
    system_role = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    permissions = relationship("RolePermissionAssignment", cascade="all, delete-orphan")


class AccessPermission(Base):
    __tablename__ = "access_permissions"
    id = Column(Integer, primary_key=True)
    permission_key = Column(String(100), nullable=False, unique=True, index=True)
    name = Column(String(120), nullable=False)
    description = Column(String(500), nullable=False, default="")
    category = Column(String(80), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class UserRoleAssignment(Base):
    __tablename__ = "user_role_assignments"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("access_roles.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    assigned_at = Column(DateTime, nullable=False, default=utcnow)
    role = relationship("AccessRole")


class RolePermissionAssignment(Base):
    __tablename__ = "role_permission_assignments"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),)
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("access_roles.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("access_permissions.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_at = Column(DateTime, nullable=False, default=utcnow)
    permission = relationship("AccessPermission")


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    csrf_token_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    idle_expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, index=True)
    revoke_reason = Column(String(120))
    user_agent_summary = Column(String(200))
    client_ip_hash = Column(String(64))
    mfa_verified = Column(Boolean, nullable=False, default=False)
    created_from_login = Column(Boolean, nullable=False, default=True)
    session_version = Column(Integer, nullable=False, default=1)
    user = relationship("UserAccount", back_populates="sessions")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True)
    username_hash = Column(String(64), nullable=False, index=True)
    client_ip_hash = Column(String(64), index=True)
    success = Column(Boolean, nullable=False)
    failure_reason_code = Column(String(64))
    attempted_at = Column(DateTime, nullable=False, default=utcnow, index=True)

    __table_args__ = (Index("ix_login_attempt_identity_time", "username_hash", "attempted_at"),)


class MfaDevice(Base):
    __tablename__ = "mfa_devices"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    device_type = Column(String(20), nullable=False, default="totp")
    label = Column(String(100), nullable=False, default="Authenticator")
    secret_encrypted_or_protected = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=False)
    confirmed_at = Column(DateTime)
    last_used_counter = Column(Integer)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    disabled_at = Column(DateTime)


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False, unique=True)
    used_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class MfaLoginChallenge(Base):
    __tablename__ = "mfa_login_challenges"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    challenge_token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime)
    failed_attempts = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"
    id = Column(Integer, primary_key=True)
    sequence_number = Column(Integer, nullable=False, unique=True, index=True)
    event_type = Column(String(80), nullable=False, index=True)
    actor_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    actor_username_snapshot = Column(String(64))
    actor_role_keys_json = Column(Text, nullable=False, default="[]")
    action = Column(String(120), nullable=False, index=True)
    resource_type = Column(String(80), index=True)
    resource_id = Column(String(100))
    route_template = Column(String(250))
    request_method = Column(String(10))
    request_id = Column(String(64), nullable=False, index=True)
    outcome = Column(String(20), nullable=False, index=True)
    status_code = Column(Integer, index=True)
    reason_code = Column(String(80))
    metadata_json = Column(Text, nullable=False, default="{}")
    client_ip_hash = Column(String(64))
    user_agent_summary = Column(String(200))
    occurred_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    previous_event_hash = Column(String(64))
    event_hash = Column(String(64), nullable=False, unique=True)
