from typing import Any, Literal

from pydantic import BaseModel, Field


class BackupCreate(BaseModel):
    backup_type: Literal["database"] = "database"


class RestoreValidate(BaseModel):
    backup_id: int = Field(gt=0)


class RestoreExecute(BaseModel):
    confirmation_phrase: str = Field(max_length=80)
    current_password: str = Field(min_length=1, max_length=1024)
    mfa_code: str | None = Field(default=None, max_length=32)
    recovery_code: str | None = Field(default=None, max_length=64)


class ExportCreate(BaseModel):
    modules: list[str] = Field(min_length=1, max_length=12)


class ImportValidate(BaseModel):
    export_id: int = Field(gt=0)


class RetentionPolicyUpdate(BaseModel):
    enabled: bool | None = None
    dry_run_only: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    minimum_keep_count: int | None = Field(default=None, ge=0, le=10000)


class RetentionPreviewRequest(BaseModel):
    policy_id: int = Field(gt=0)


class RetentionApplyRequest(BaseModel):
    run_id: int = Field(gt=0)
    confirmation_phrase: str = Field(max_length=80)


class ConfirmationRequest(BaseModel):
    confirmation_phrase: str = Field(max_length=80)


class BackupRetentionUpdate(BaseModel):
    maximum_count: int = Field(ge=1, le=1000)
    maximum_age_days: int = Field(ge=1, le=3650)
    minimum_keep_count: int = Field(ge=1, le=100)


class BackupRetentionApply(BaseModel):
    candidate_ids: list[int] = Field(max_length=1000)
    preview_token: str = Field(min_length=1, max_length=100)
    confirmation_phrase: str = Field(max_length=80)


class ReleaseBuildRequest(BaseModel):
    allow_dirty: bool = False


class SafeResponse(BaseModel):
    status: str
    detail: str
    metadata: dict[str, Any] = {}
