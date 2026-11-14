"""Pydantic schemas for alert management serialization and validation."""

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict

from .incident import IncidentResponse


AlertSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    incident_id: str
    alert_type: str
    severity: AlertSeverity
    message: str
    is_acknowledged: bool
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AlertDetailResponse(AlertResponse):
    incident: IncidentResponse | None = None


class AlertUpdate(BaseModel):
    is_acknowledged: bool = True
    acknowledged_by: str | None = None


class PaginatedAlertListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AlertResponse]

