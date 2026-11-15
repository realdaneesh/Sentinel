"""Recompute eligible identity history and reconcile persistent incidents."""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..logging import logger
from ..models.alert import Alert
from ..models.base import utc_now
from ..models.event import LoginEvent
from ..models.incident import Incident
from services.detection.incident_correlation import INCIDENT_TYPE, correlate_incidents
from services.detection.risk_scoring import score_risk
from services.detection.rules import detect_failed_login_burst, detect_unfamiliar_login_event


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        # SQLite discards timezone data. Ingested event timestamps are validated UTC.
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _evaluation_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evaluation_time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _wire(event: LoginEvent) -> dict[str, str]:
    record = {
        "schema_version": "1.0", "event_id": event.event_id, "user_id": event.user_id,
        "event_type": event.event_type,
        "timestamp": _utc(event.timestamp).isoformat().replace("+00:00", "Z"),
        "source": event.source,
    }
    if event.device_id is not None:
        record["device_id"] = event.device_id
    if event.ip_address is not None:
        record["ip_address"] = event.ip_address
    return record


def _adapt(event: LoginEvent) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": event.event_id, "identity": event.user_id,
        "event_type": event.event_type, "timestamp": _utc(event.timestamp),
    }
    if event.device_id is not None:
        record["device_id"] = event.device_id
    if event.ip_address is not None:
        record["ip_address"] = event.ip_address
    return record


def _result(event: LoginEvent, eligible: list[LoginEvent]) -> dict[str, Any]:
    event_time = _utc(event.timestamp)
    window = [_adapt(row) for row in eligible if
              event_time - timedelta(minutes=settings.BURST_WINDOW_MINUTES)
              <= _utc(row.timestamp) <= event_time]
    burst = detect_failed_login_burst(window, event.user_id, now=event_time)
    signals: list[str] = []
    reasons: list[str] = []
    if burst["triggered"]:
        signals.append(burst["rule_id"])
        reasons.append(burst["reason"])
    if event.event_type == "LOGIN_SUCCESS":
        history = [_adapt(row) for row in eligible if row.event_type == "LOGIN_SUCCESS"
                   and _utc(row.timestamp) < event_time]
        novelty = detect_unfamiliar_login_event(
            history, _adapt(event), event.user_id, now=event_time,
            min_history=settings.MIN_HISTORY_FOR_NOVELTY,
        )
        signals.extend(novelty["triggered_signals"])
        reasons.extend(novelty["explanations"])
    if signals:
        scored = score_risk(signals)
        reasons.extend(scored["reasons"])
        risk_score, severity = scored["risk_score"], scored["severity"]
    else:
        risk_score, severity = 0, "LOW"
        reasons.append(burst["reason"])
    return {
        "schema_version": "1.0", "event_id": event.event_id,
        "risk_score": risk_score, "severity": severity, "reasons": reasons,
        "detector_version": settings.DETECTOR_VERSION,
    }


def _snapshot(incident: Incident) -> dict[str, Any]:
    return {
        "fingerprint": incident.evidence_fingerprint,
        "event_ids": sorted(event.event_id for event in incident.events),
        "risk_score": incident.risk_score, "severity": incident.severity,
        "start_time": _utc(incident.start_time).isoformat().replace("+00:00", "Z"),
        "end_time": _utc(incident.end_time).isoformat().replace("+00:00", "Z"),
    }


def _refresh_alerts(db: Session, incident: Incident) -> None:
    current = sorted((alert for alert in incident.alerts if alert.is_current), key=lambda a: a.alert_id)
    for duplicate in current[1:]:
        duplicate.is_current = False
    if incident.severity not in ("HIGH", "CRITICAL"):
        for alert in current:
            alert.is_current = False
        return
    message = (f"Threat detected for identity {incident.user_id}: {incident.title} "
               f"(Severity: {incident.severity}, Score: {incident.risk_score})")
    if current:
        alert = current[0]
        if alert.severity != incident.severity or alert.message != message:
            alert.severity = incident.severity
            alert.message = message
            alert.updated_at = utc_now()
    else:
        db.add(Alert(
            alert_id=f"alt-{uuid4().hex[:16]}", incident=incident,
            alert_type="THREAT_INCIDENT_CORRELATED", severity=incident.severity,
            message=message, is_acknowledged=False, is_current=True,
        ))


def _reconcile_incidents(db: Session, identity: str, results: list[dict[str, Any]],
                         eligible: list[LoginEvent]) -> None:
    by_id = {event.event_id: event for event in eligible}
    old = list(db.execute(
        select(Incident).options(selectinload(Incident.events), selectinload(Incident.alerts))
        .where(Incident.user_id == identity, Incident.incident_type == INCIDENT_TYPE,
               Incident.is_current.is_(True))
        .order_by(Incident.created_at, Incident.incident_id)
    ).scalars().all())
    # Evidence overlap survives changed first timestamps and added/removed contributors.
    pairs: list[tuple[int, int, int]] = []
    for new_index, result in enumerate(results):
        ids = set(result["contributing_event_ids"])
        for old_index, incident in enumerate(old):
            overlap = len(ids & {event.event_id for event in incident.events})
            if overlap:
                pairs.append((overlap, old_index, new_index))
    pairs.sort(key=lambda pair: (-pair[0], old[pair[1]].created_at,
                                 old[pair[1]].incident_id, results[pair[2]]["incident_id"]))
    assignments: dict[int, int] = {}
    used_old: set[int] = set()
    for _, old_index, new_index in pairs:
        if old_index not in used_old and new_index not in assignments:
            assignments[new_index] = old_index
            used_old.add(old_index)

    current_by_new: dict[int, Incident] = {}
    for new_index, result in enumerate(results):
        previous = old[assignments[new_index]] if new_index in assignments else None
        if previous is None:
            split_sources = [pair for pair in pairs if pair[2] == new_index]
            incident = Incident(
                incident_id=f"inc-{uuid4().hex}",
                title="Failed Login Burst Followed By Unfamiliar Login",
                description=(f"Identity {identity} experienced a burst of failed logins "
                             "followed by an unfamiliar successful authentication."),
                user_id=identity, incident_type=result["incident_type"], status="open",
                split_from_id=old[split_sources[0][1]].incident_id if split_sources else None,
            )
            db.add(incident)
        else:
            incident = previous
            if incident.evidence_fingerprint != result["incident_id"]:
                incident.evidence_history = [*(incident.evidence_history or []), _snapshot(incident)]
        new_fields = {
            "evidence_fingerprint": result["incident_id"],
            "risk_score": result["risk_score"], "severity": result["severity"],
            "start_time": datetime.fromisoformat(result["start_time"].replace("Z", "+00:00")),
            "end_time": datetime.fromisoformat(result["end_time"].replace("Z", "+00:00")),
            "signals": result["signals"], "explanations": result["explanations"],
            "scorer_version": result["scorer_version"],
        }
        changed = previous is None
        for field, value in new_fields.items():
            existing = getattr(incident, field, None)
            if isinstance(value, datetime) and existing is not None:
                same = _utc(existing) == _utc(value)
            else:
                same = existing == value
            if not same:
                setattr(incident, field, value)
                changed = True
        if {event.event_id for event in incident.events} != set(result["contributing_event_ids"]):
            incident.events = [by_id[event_id] for event_id in result["contributing_event_ids"]]
            changed = True
        if changed and previous is not None:
            incident.updated_at = utc_now()
        _refresh_alerts(db, incident)
        current_by_new[new_index] = incident

    for old_index, incident in enumerate(old):
        if old_index in used_old:
            continue
        overlaps = [pair for pair in pairs if pair[1] == old_index]
        winner = current_by_new.get(overlaps[0][2]) if overlaps else None
        incident.is_current = False
        incident.superseded_by_id = winner.incident_id if winner is not None else None
        incident.updated_at = utc_now()
        for alert in incident.alerts:
            alert.is_current = False


def reconcile_identity(db: Session, identity: str, *, evaluation_time: datetime) -> None:
    """Correctness-first full-history recomputation for one exact identity."""
    now = _evaluation_time(evaluation_time)
    events = list(db.execute(
        select(LoginEvent).where(LoginEvent.user_id == identity)
        .order_by(LoginEvent.timestamp, LoginEvent.event_id)
    ).scalars().all())
    eligible = [event for event in events if _utc(event.timestamp) <= now]
    eligible_ids = {event.event_id for event in eligible}
    for event in events:
        if event.event_id not in eligible_ids:
            if event.detection_status != "pending" or event.detection_result is not None:
                event.detection_status, event.detection_result = "pending", None
            continue
        result = _result(event, eligible)
        if event.detection_status != "evaluated" or event.detection_result != result:
            event.detection_status, event.detection_result = "evaluated", result
    correlated = correlate_incidents(
        [_wire(event) for event in eligible], evaluation_time=now,
        correlation_window=timedelta(minutes=settings.DEFAULT_CORRELATION_WINDOW_MINUTES),
        min_history=settings.MIN_HISTORY_FOR_NOVELTY,
    )
    _reconcile_incidents(db, identity, correlated, eligible)
    db.commit()


def process_event_detection(db: Session, event: LoginEvent,
                            *, evaluation_time: datetime | None = None) -> dict[str, Any] | None:
    """Evaluate at processing time; future events remain pending until reevaluation."""
    now = _evaluation_time(evaluation_time or datetime.now(timezone.utc))
    if _utc(event.timestamp) > now:
        return None
    try:
        reconcile_identity(db, event.user_id, evaluation_time=now)
        db.refresh(event)
        return event.detection_result
    except Exception:
        db.rollback()
        logger.exception("Detection reconciliation failed for event %s", event.event_id)
        event.detection_status = "failed"
        db.commit()
        return None
