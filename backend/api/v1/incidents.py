"""Incident management API endpoints."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from ...database import get_db
from ...models.user import User
from ...models.incident import Incident
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
from ...services.coordination import lock_administrators, lock_identity
from ...services.audit_service import record_audit_log

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
    include_historical: bool = Query(False, description="Include superseded or unsupported incidents"),
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
        include_historical=include_historical,
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
    try:
        actor_id = current_user.id
        lock_administrators(db)
        actor = db.get(User, actor_id, populate_existing=True)
        if actor is None or actor.account_status != "active" or actor.role not in ("admin", "analyst"):
            raise HTTPException(status_code=403, detail="Analyst access required")
        existing = db.get(Incident, incident_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
        lock_identity(db, existing.user_id)
        db.expire_all()
        updated = update_incident(db, incident_id, status=payload.status,
                                  description=payload.description, commit=False)
        record_audit_log(db, actor=actor.username, action="UPDATE_INCIDENT_STATUS",
                         resource_type="incident", resource_id=incident_id,
                         details={"status": payload.status, "description": payload.description},
                         commit=False)
        db.commit()
        return IncidentDetailResponse.model_validate(updated)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=503, detail="Storage unavailable")

