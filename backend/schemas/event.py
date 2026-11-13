"""Pydantic schemas for event ingestion and retrieval conforming to EVENT_SCHEMA.md."""

from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_UTC_TIMESTAMP_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)


class ErrorDetail(BaseModel):
    field: str
    code: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: ErrorBody


class EventIngestPayload(BaseModel):
    """Strict v1 event ingestion schema according to docs/EVENT_SCHEMA.md."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=False,
    )

    schema_version: Literal["1.0"]
    event_id: str
    user_id: str
    event_type: Literal["LOGIN_SUCCESS", "LOGIN_FAILURE"]
    timestamp: str
    source: str
    ip_address: str | None = None
    device_id: str | None = None
    failure_reason: str | None = None

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        if not (1 <= len(v) <= 128) or v != v.strip():
            raise ValueError("invalid event_id")
        return v

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not (1 <= len(v) <= 256) or v != v.strip():
            raise ValueError("invalid user_id")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        if not (1 <= len(v) <= 64) or v != v.strip():
            raise ValueError("invalid source")
        return v

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, v: str | None) -> str | None:
        if v is not None:
            if not (1 <= len(v) <= 256) or v != v.strip():
                raise ValueError("invalid device_id")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not _UTC_TIMESTAMP_REGEX.match(v):
            raise ValueError("invalid_utc_timestamp")
        try:
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_utc_timestamp") from None
        if parsed.tzinfo is None:
            raise ValueError("invalid_utc_timestamp")
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str | None) -> str | None:
        if v is not None:
            if "%" in v or v != v.strip():
                raise ValueError("invalid_ip_address")
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("invalid_ip_address") from None
        return v

    def parsed_datetime(self) -> datetime:
        return datetime.fromisoformat(self.timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)

    def canonical_hash(self) -> str:
        """Compute stable hash for idempotency and conflict comparison."""
        import hashlib
        # Normalize timestamp to UTC instant
        utc_ts = self.parsed_datetime().isoformat().replace("+00:00", "Z")
        canonical_obj = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "timestamp": utc_ts,
            "source": self.source,
        }
        if self.ip_address is not None:
            canonical_obj["ip_address"] = self.ip_address
        if self.device_id is not None:
            canonical_obj["device_id"] = self.device_id
        if self.failure_reason is not None:
            canonical_obj["failure_reason"] = self.failure_reason

        serialized = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class EventIngestResponse(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    status: Literal["accepted", "duplicate"]
    detection_result: dict[str, Any] | None = None


class LoginEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    user_id: str
    timestamp: datetime
    event_type: str
    source: str
    ip_address: str | None = None
    device_id: str | None = None
    failure_reason: str | None = None
    detection_status: str
    detection_result: dict[str, Any] | None = None
    created_at: datetime


class PaginatedEventListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[LoginEventResponse]

