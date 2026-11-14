"""Alert management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database import get_db
from ...models.user import User
from ...schemas.alert import (
    AlertDetailResponse,
    AlertResponse,
    AlertUpdate,
    PaginatedAlertListResponse,
)
from ...security.dependencies import get_current_user, require_role
from ...services.alert_service import (
    acknowledge_alert,
    get_alert_by_id,
    list_alerts,
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get(
    "",
    response_model=PaginatedAlertListResponse,
    dependencies=[Depends(require_role(["viewer", "analyst"]))],
)
def get_alerts(
    severity: str | None = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    is_acknowledged: bool | None = Query(None, description="Filter by acknowledgement state"),
    incident_id: str | None = Query(None, description="Filter alerts by associated incident"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> PaginatedAlertListResponse:
    """Retrieve security alerts ordered by acknowledgement priority and severity."""
    total, items = list_alerts(
        db,
        severity=severity,
        is_acknowledged=is_acknowledged,
        incident_id=incident_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedAlertListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[AlertResponse.model_validate(alert) for alert in items],
    )


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    dependencies=[Depends(require_role(["viewer", "analyst"]))],
    responses={404: {"description": "Alert not found"}},
)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Retrieve alert details including linked security incident."""
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert not found: {alert_id}",
        )
    return AlertDetailResponse.model_validate(alert)


@router.patch(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    responses={404: {"description": "Alert not found"}},
)
def patch_alert(
    alert_id: str,
    payload: AlertUpdate,
    current_user: User = Depends(require_role(["analyst"])),
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Acknowledge or update status of an alert (restricted to Analyst and Administrator)."""
    if not payload.is_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot unacknowledge an alert once created",
        )

    updated = acknowledge_alert(
        db,
        alert_id,
        acknowledged_by=payload.acknowledged_by or current_user.username,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert not found: {alert_id}",
        )
    return AlertDetailResponse.model_validate(updated)

