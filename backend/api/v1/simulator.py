"""API route for generating synthetic authentication events using Daneesh's simulator."""

from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...database import get_db
from ...schemas.event import EventIngestPayload
from ...services.event_service import ingest_event
from services.simulator.generator import (
    DEFAULT_REFERENCE_TIME,
    SCENARIOS,
    generate_events,
)

router = APIRouter(prefix="/simulator", tags=["Simulator"])


class SimulatorGenerateRequest(BaseModel):
    scenario: Literal["normal_activity", "failed_login_burst", "unfamiliar_device", "unfamiliar_ip"]
    seed: int = 42
    count: int | None = None
    reference_time: str | None = None
    ingest: bool = Field(False, description="Whether to automatically store generated events in the database")


class SimulatorGenerateResponse(BaseModel):
    scenario: str
    seed: int
    count: int
    ingested: bool
    events: list[dict[str, str]]


@router.post(
    "/generate",
    response_model=SimulatorGenerateResponse,
    status_code=status.HTTP_200_OK,
)
def generate_synthetic_events(
    request: SimulatorGenerateRequest,
    db: Session = Depends(get_db),
) -> SimulatorGenerateResponse:
    """Generate reproducible test authentication events and optionally persist them."""
    if request.reference_time:
        ref_time = datetime.fromisoformat(request.reference_time.replace("Z", "+00:00")).astimezone(timezone.utc)
    else:
        ref_time = datetime.now(timezone.utc)

    raw_events = generate_events(
        scenario=request.scenario,
        seed=request.seed,
        reference_time=ref_time,
        count=request.count,
    )

    if request.ingest:
        for evt in raw_events:
            payload = EventIngestPayload.model_validate(evt)
            ingest_event(db, payload)

    return SimulatorGenerateResponse(
        scenario=request.scenario,
        seed=request.seed,
        count=len(raw_events),
        ingested=request.ingest,
        events=raw_events,
    )

