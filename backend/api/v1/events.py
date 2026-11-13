"""Event ingestion and retrieval API routes."""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ...database import get_db
from ...schemas.event import (
    ErrorBody,
    ErrorDetail,
    ErrorResponse,
    EventIngestPayload,
    EventIngestResponse,
    LoginEventResponse,
    PaginatedEventListResponse,
)
from ...services.event_service import (
    EventConflictError,
    get_event_by_id,
    ingest_event,
    list_events,
)

router = APIRouter(tags=["Events"])


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"model": EventIngestResponse, "description": "Duplicate identical event replayed"},
        201: {"model": EventIngestResponse, "description": "Event accepted and persisted"},
        400: {"model": ErrorResponse, "description": "Invalid JSON"},
        409: {"model": ErrorResponse, "description": "Conflicting event ID"},
        415: {"model": ErrorResponse, "description": "Unsupported media type"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
async def post_event(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Ingest a single authentication event adhering to v1 event schema and API contracts."""
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={
                "error": {
                    "code": "UNSUPPORTED_MEDIA_TYPE",
                    "message": "Content-Type must be application/json",
                    "details": [{"field": "$", "code": "unsupported_media_type"}],
                }
            },
        )

    try:
        raw_body = await request.body()
        if not raw_body:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "INVALID_JSON",
                        "message": "Malformed JSON body",
                        "details": [{"field": "$", "code": "empty_body"}],
                    }
                },
            )
        data = json.loads(raw_body)
        if not isinstance(data, dict):
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Request body must be a JSON object",
                        "details": [{"field": "$", "code": "invalid_type"}],
                    }
                },
            )
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": {
                    "code": "INVALID_JSON",
                    "message": "Malformed JSON body",
                    "details": [{"field": "$", "code": "invalid_json"}],
                }
            },
        )

    # Validate against EventIngestPayload
    try:
        payload = EventIngestPayload.model_validate(data)
    except Exception as exc:
        details = []
        # Extract validation errors
        if hasattr(exc, "errors"):
            for err in exc.errors():
                loc = ".".join(str(p) for p in err.get("loc", [])) or "$"
                msg = err.get("msg", "")
                err_type = err.get("type", "")
                if "invalid_utc_timestamp" in msg:
                    code = "invalid_utc_timestamp"
                elif "invalid_ip_address" in msg:
                    code = "invalid_ip_address"
                elif "extra_forbidden" in err_type or "unknown" in msg.lower():
                    code = "unknown_field"
                elif "missing" in err_type:
                    code = "required"
                elif "type" in err_type:
                    code = "invalid_type"
                else:
                    code = "invalid_value"
                details.append({"field": loc, "code": code})
        else:
            details.append({"field": "$", "code": "invalid_value"})

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Event validation failed",
                    "details": details,
                }
            },
        )

    try:
        status_code, result_status = ingest_event(db, payload)
        return JSONResponse(
            status_code=status_code,
            content={
                "schema_version": "1.0",
                "event_id": payload.event_id,
                "status": result_status,
                "detection_result": None,
            },
        )
    except EventConflictError:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "EVENT_ID_CONFLICT",
                    "message": "event_id already exists with different content",
                    "details": [{"field": "event_id", "code": "conflict"}],
                }
            },
        )


@router.post(
    "/events/login",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def post_login_event(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Convenience endpoint accepting either canonical v1 events or flexible login formats."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": {
                    "code": "INVALID_JSON",
                    "message": "Malformed JSON body",
                    "details": [{"field": "$", "code": "invalid_json"}],
                }
            },
        )

    # Normalize alternate field names if present
    normalized = dict(body)
    if "schema_version" not in normalized:
        normalized["schema_version"] = "1.0"
    if "event_id" not in normalized:
        # Generate reproducible ID based on user_id and timestamp if possible
        identity_blob = f"{normalized.get('user_id')}-{normalized.get('timestamp')}-{uuid4().hex[:8]}"
        normalized["event_id"] = "evt-" + hashlib.sha256(identity_blob.encode()).hexdigest()[:16]

    # Map status to event_type
    if "status" in normalized and "event_type" not in normalized:
        raw_status = str(normalized.pop("status")).lower()
        normalized["event_type"] = "LOGIN_SUCCESS" if raw_status in ("success", "successful") else "LOGIN_FAILURE"

    # Map source_ip to ip_address
    if "source_ip" in normalized and "ip_address" not in normalized:
        normalized["ip_address"] = normalized.pop("source_ip")

    # Map device to device_id
    if "device" in normalized and "device_id" not in normalized:
        normalized["device_id"] = normalized.pop("device")

    # Map application to source
    if "application" in normalized and "source" not in normalized:
        normalized["source"] = normalized.pop("application")
    elif "source" not in normalized:
        normalized["source"] = "api-login-endpoint"

    # Validate normalized payload
    try:
        payload = EventIngestPayload.model_validate(normalized)
    except Exception as exc:
        details = []
        if hasattr(exc, "errors"):
            for err in exc.errors():
                loc = ".".join(str(p) for p in err.get("loc", [])) or "$"
                details.append({"field": loc, "code": "invalid_value"})
        else:
            details.append({"field": "$", "code": "invalid_value"})
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Event validation failed",
                    "details": details,
                }
            },
        )

    try:
        status_code, result_status = ingest_event(db, payload)
        return JSONResponse(
            status_code=status_code,
            content={
                "schema_version": "1.0",
                "event_id": payload.event_id,
                "status": result_status,
                "detection_result": None,
            },
        )
    except EventConflictError:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "EVENT_ID_CONFLICT",
                    "message": "event_id already exists with different content",
                    "details": [{"field": "event_id", "code": "conflict"}],
                }
            },
        )


@router.get(
    "/events",
    response_model=PaginatedEventListResponse,
)
def get_events(
    user_id: str | None = Query(None, description="Filter by user identity"),
    start_time: datetime | None = Query(None, description="Filter events after or at UTC timestamp"),
    end_time: datetime | None = Query(None, description="Filter events before or at UTC timestamp"),
    event_type: str | None = Query(None, description="LOGIN_SUCCESS or LOGIN_FAILURE"),
    ip_address: str | None = Query(None, description="Filter by source IP address"),
    source: str | None = Query(None, description="Filter by source producer"),
    limit: int = Query(50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> PaginatedEventListResponse:
    """Retrieve stored authentication events with optional filters and pagination."""
    total, items = list_events(
        db,
        user_id=user_id,
        start_time=start_time,
        end_time=end_time,
        event_type=event_type,
        ip_address=ip_address,
        source=source,
        limit=limit,
        offset=offset,
    )
    return PaginatedEventListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[LoginEventResponse.model_validate(item) for item in items],
    )


@router.get(
    "/events/{event_id}",
    response_model=LoginEventResponse,
    responses={404: {"model": ErrorResponse, "description": "Event not found"}},
)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
) -> LoginEventResponse:
    """Retrieve a single stored authentication event by ID."""
    event = get_event_by_id(db, event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event not found: {event_id}",
        )
    return LoginEventResponse.model_validate(event)

