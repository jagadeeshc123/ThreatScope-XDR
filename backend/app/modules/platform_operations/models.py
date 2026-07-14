from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class OperationalJob(Base):
    __tablename__ = "operational_jobs"
    id = Column(Integer, primary_key=True)
    job_key = Column(String(80), nullable=False, unique=True, index=True)
    job_type = Column(String(40), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="queued", index=True)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    progress_percent = Column(Integer, nullable=False, default=0)
    result_summary = Column(String(1000), nullable=False, default="")
    error_code = Column(String(80))
    error_summary = Column(String(500))
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    __table_args__ = (Index("ix_operational_job_type_created", "job_type", "created_at"),)


class BackupRecord(Base):
    __tablename__ = "backup_records"
    id = Column(Integer, primary_key=True)
    backup_key = Column(String(80), nullable=False, unique=True, index=True)
    filename = Column(String(180), nullable=False, unique=True)
    relative_path = Column(String(240), nullable=False, unique=True)
    backup_type = Column(String(40), nullable=False, default="database", index=True)
    status = Column(String(20), nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, default="")
    manifest_sha256 = Column(String(64), nullable=False, default="")
    schema_version = Column(String(40), nullable=False, default="")
    application_version = Column(String(40), nullable=False, default="")
    record_counts_json = Column(Text, nullable=False, default="{}")
    encrypted = Column(Boolean, nullable=False, default=False)
    protected = Column(Boolean, nullable=False, default=False, index=True)
    policy_origin = Column(String(20), nullable=False, default="manual")
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    verified_at = Column(DateTime)
    verification_status = Column(String(20), nullable=False, default="pending", index=True)
    deleted_at = Column(DateTime, index=True)
    creator = relationship("UserAccount", foreign_keys=[created_by_user_id])
    __table_args__ = (Index("ix_backup_status_created", "status", "created_at"),)


class RestoreRecord(Base):
    __tablename__ = "restore_records"
    id = Column(Integer, primary_key=True)
    restore_key = Column(String(80), nullable=False, unique=True, index=True)
    backup_id = Column(Integer, ForeignKey("backup_records.id", ondelete="SET NULL"), index=True)
    source_filename = Column(String(180), nullable=False)
    mode = Column(String(30), nullable=False, default="validate_only", index=True)
    status = Column(String(30), nullable=False, index=True)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    confirmed_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    pre_restore_backup_id = Column(Integer, ForeignKey("backup_records.id", ondelete="SET NULL"))
    validation_summary = Column(Text, nullable=False, default="{}")
    restored_record_counts_json = Column(Text, nullable=False, default="{}")
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    backup = relationship("BackupRecord", foreign_keys=[backup_id])
    pre_restore_backup = relationship("BackupRecord", foreign_keys=[pre_restore_backup_id])
    __table_args__ = (Index("ix_restore_status_created", "status", "created_at"),)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    id = Column(Integer, primary_key=True)
    policy_key = Column(String(80), nullable=False, unique=True, index=True)
    name = Column(String(120), nullable=False)
    entity_type = Column(String(80), nullable=False, index=True)
    retention_days = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    dry_run_only = Column(Boolean, nullable=False, default=True)
    minimum_keep_count = Column(Integer, nullable=False, default=10)
    last_preview_at = Column(DateTime)
    last_applied_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class RetentionRun(Base):
    __tablename__ = "retention_runs"
    id = Column(Integer, primary_key=True)
    run_key = Column(String(80), nullable=False, unique=True, index=True)
    policy_id = Column(Integer, ForeignKey("retention_policies.id", ondelete="RESTRICT"), nullable=False, index=True)
    mode = Column(String(20), nullable=False, index=True)
    candidate_count = Column(Integer, nullable=False, default=0)
    deleted_count = Column(Integer, nullable=False, default=0)
    preserved_count = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, index=True)
    summary_json = Column(Text, nullable=False, default="{}")
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    completed_at = Column(DateTime)
    policy = relationship("RetentionPolicy")


class ExportPackage(Base):
    __tablename__ = "export_packages"
    id = Column(Integer, primary_key=True)
    package_key = Column(String(80), nullable=False, unique=True, index=True)
    filename = Column(String(180), nullable=False, unique=True)
    relative_path = Column(String(240), nullable=False, unique=True)
    package_type = Column(String(40), nullable=False, default="safe_json", index=True)
    status = Column(String(20), nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, default="")
    manifest_sha256 = Column(String(64), nullable=False, default="")
    included_modules_json = Column(Text, nullable=False, default="[]")
    record_counts_json = Column(Text, nullable=False, default="{}")
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    verified_at = Column(DateTime)
    verification_status = Column(String(20), nullable=False, default="pending", index=True)
    deleted_at = Column(DateTime, index=True)
    __table_args__ = (Index("ix_export_status_created", "status", "created_at"),)


class ReleaseArtifact(Base):
    __tablename__ = "release_artifacts"
    id = Column(Integer, primary_key=True)
    release_key = Column(String(80), nullable=False, unique=True, index=True)
    version = Column(String(40), nullable=False, index=True)
    commit_hash = Column(String(64), nullable=False)
    filename = Column(String(180), nullable=False, unique=True)
    relative_path = Column(String(240), nullable=False, unique=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, default="")
    manifest_sha256 = Column(String(64), nullable=False, default="")
    status = Column(String(20), nullable=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
    deleted_at = Column(DateTime, index=True)
    __table_args__ = (Index("ix_release_version_created", "version", "created_at"),)
