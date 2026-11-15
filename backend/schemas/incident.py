"""Pydantic schemas for incident management serialization and validation."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from .event import LoginEventResponse


IncidentStatus = Literal["open", "investigating", "resolved", "false_positive"]
IncidentSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    description: str | None = None
    user_id: str
    incident_type: str
    risk_score: int
    severity: IncidentSeverity
    status: IncidentStatus
    start_time: datetime
    end_time: datetime
    signals: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    scorer_version: str | None = None
    created_at: datetime
    updated_at: datetime


class IncidentDetailResponse(IncidentResponse):
    events: list[LoginEventResponse] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    description: str | None = None


class PaginatedIncidentListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IncidentResponse]

