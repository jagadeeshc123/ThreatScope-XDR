from typing import Literal

from pydantic import BaseModel


class PreflightCheckResponse(BaseModel):
    name: str
    state: Literal["pass", "warning", "failure"]
    summary: str
    remediation_code: str


class PreflightResponse(BaseModel):
    ready: bool
    status: str
    failure_count: int
    warning_count: int
    checks: list[PreflightCheckResponse]
