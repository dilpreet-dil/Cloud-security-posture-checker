from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanRequest(BaseModel):
    provider: Literal["mock", "aws"] = "mock"
    region: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    profile: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,32}$")  # demo account name (mock only)


class ProwlerImport(BaseModel):
    findings: list[dict]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    provider: str
    source: str
    account: str
    region: str
    score: float
    started_at: datetime
    summary: dict

    @field_validator("started_at")
    @classmethod
    def _utc(cls, v):
        from .models import utc
        return utc(v)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    title: str
    severity: str
    service: str
    resource: str
    status: str
    detail: str
    remediation: str
    compliance: str
    source: str
