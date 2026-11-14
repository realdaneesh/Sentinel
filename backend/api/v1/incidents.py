"""Incident management API endpoints."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database import get_db
from ...models.user import User
from ...schemas.incident import (
    IncidentDetailResponse,
    IncidentResponse,
    IncidentUpdate,
    PaginatedIncidentListResponse,
)
from ...security.dependencies import get_current_user, require_role
from ...services.incident_service import (
    get_incident_by_id,
    list_incidents,
    update_incident,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get(
    "",
    response_model=PaginatedIncidentListResponse,
    dependencies=[Depends(require_role(["viewer", "analyst"]))],
)
def get_incidents(
    user_id: str | None = Query(None, description="Filter incidents by associated user identity"),
    severity: str | None = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status: open, investigating, resolved, false_positive"),
    min_risk_score: int | None = Query(None, ge=0, le=100, description="Minimum risk score"),
    max_risk_score: int | None = Query(None, ge=0, le=100, description="Maximum risk score"),
    start_time: datetime | None = Query(None, description="Filter incidents starting on or after timestamp"),
    end_time: datetime | None = Query(None, description="Filter incidents ending on or before timestamp"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> PaginatedIncidentListResponse:
    """Retrieve security incidents with comprehensive filtering and pagination."""
    total, items = list_incidents(
        db,
        user_id=user_id,
        severity=severity,
        status=status_filter,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return PaginatedIncidentListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[IncidentResponse.model_validate(inc) for inc in items],
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    dependencies=[Depends(require_role(["viewer", "analyst"]))],
    responses={404: {"description": "Incident not found"}},
)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Retrieve detailed incident record including linked contributing authentication events."""
    incident = get_incident_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    return IncidentDetailResponse.model_validate(incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    responses={404: {"description": "Incident not found"}},
)
def patch_incident(
    incident_id: str,
    payload: IncidentUpdate,
    current_user: User = Depends(require_role(["analyst"])),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Update incident investigation status (restricted to Analyst and Administrator)."""
    updated = update_incident(
        db,
        incident_id,
        status=payload.status,
        description=payload.description,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )
    return IncidentDetailResponse.model_validate(updated)

