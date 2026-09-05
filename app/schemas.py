"""
Pydantic Schemas
================
Request / response models for the FastAPI layer.
All UUIDs and datetimes are serialised to strings automatically.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ── Request ──────────────────────────────────────────────────────────────────

class ConfigParseRequest(BaseModel):
    """Body sent to POST /api/v1/parse."""
    config_text: str = Field(
        ...,
        min_length=10,
        description="Raw Cisco IOS configuration text to parse and evaluate",
        examples=[
            "hostname Router1\nservice password-encryption\nip ssh version 2\n"
            "ntp server 10.0.0.1\naaa new-model\n"
            "banner motd ^Authorised access only^"
        ],
    )
    device_name: str | None = Field(
        None,
        max_length=255,
        description="Optional friendly name for the device",
    )


# ── Response ─────────────────────────────────────────────────────────────────

class RuleResultSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    rule_id: str
    description: str
    severity: str
    status: str
    detail: str


class ComplianceReportSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    device_config_id: uuid.UUID
    score: float
    total_rules: int
    passed_rules: int
    failed_rules: int
    is_compliant: bool
    result_data: dict[str, Any]
    evaluated_at: datetime


class DeviceConfigSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    device_name: str | None
    raw_lines: int
    created_at: datetime
    updated_at: datetime


class ParseResponse(BaseModel):
    """Returned from POST /api/v1/parse."""
    model_config = ConfigDict(from_attributes=True)
    config: DeviceConfigSchema
    report: ComplianceReportSchema
    parsed_data: dict[str, Any]


class ConfigListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    device_name: str | None
    raw_lines: int
    created_at: datetime
    has_report: bool = False


class ConfigDetailSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    device_name: str | None
    raw_config: str
    parsed_data: dict[str, Any]
    raw_lines: int
    created_at: datetime
    updated_at: datetime


class ReportListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    device_config_id: uuid.UUID
    score: float
    is_compliant: bool
    passed_rules: int
    failed_rules: int
    total_rules: int
    evaluated_at: datetime
