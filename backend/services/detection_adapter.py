"""Integration adapter connecting persisted login events with Daneesh's detection suite."""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..logging import logger
from ..models.alert import Alert
from ..models.event import LoginEvent
from ..models.incident import Incident
from services.detection.incident_correlation import correlate_incidents
from services.detection.risk_scoring import score_risk
from services.detection.rules import (
    detect_failed_login_burst,
    detect_unfamiliar_login_event,
)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.utcoffset() is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def process_event_detection(db: Session, event: LoginEvent) -> dict[str, Any]:
    """Execute Daneesh's detection pipeline and incident correlation for an accepted event.

    Args:
        db: SQLAlchemy transactional database session.
        event: Persisted LoginEvent model instance.

    Returns:
        Structured detection result envelope conforming to docs/EVENT_SCHEMA.md.
    """
    eval_time = _ensure_utc(event.timestamp)

    try:
        # 1. Burst Detection: Query rolling 15-minute history for this identity
        window_start = eval_time - timedelta(minutes=settings.BURST_WINDOW_MINUTES)
        stmt_window = (
            select(LoginEvent)
            .where(LoginEvent.user_id == event.user_id)
            .where(LoginEvent.timestamp >= window_start)
            .where(LoginEvent.timestamp <= eval_time)
            .order_by(LoginEvent.timestamp.asc(), LoginEvent.event_id.asc())
        )
        window_events = list(db.execute(stmt_window).scalars().all())

        burst_history = [
            {
                "identity": e.user_id,
                "event_type": e.event_type,
                "timestamp": _ensure_utc(e.timestamp),
            }
            for e in window_events
        ]
        burst_result = detect_failed_login_burst(burst_history, event.user_id, now=eval_time)

        # 2. Novelty Detection: If LOGIN_SUCCESS, compare with strictly earlier successes
        novelty_result = None
        if event.event_type == "LOGIN_SUCCESS":
            stmt_prior_success = (
                select(LoginEvent)
                .where(LoginEvent.user_id == event.user_id)
                .where(LoginEvent.event_type == "LOGIN_SUCCESS")
                .where(LoginEvent.timestamp < eval_time)
                .order_by(LoginEvent.timestamp.asc(), LoginEvent.event_id.asc())
            )
            prior_successes = list(db.execute(stmt_prior_success).scalars().all())

            adapted_prior = [
                {
                    "event_id": e.event_id,
                    "identity": e.user_id,
                    "event_type": e.event_type,
                    "timestamp": _ensure_utc(e.timestamp),
                    **({"device_id": e.device_id} if e.device_id else {}),
                    **({"ip_address": e.ip_address} if e.ip_address else {}),
                }
                for e in prior_successes
            ]

            adapted_current = {
                "event_id": event.event_id,
                "identity": event.user_id,
                "event_type": event.event_type,
                "timestamp": eval_time,
                **({"device_id": event.device_id} if event.device_id else {}),
                **({"ip_address": event.ip_address} if event.ip_address else {}),
            }

            novelty_result = detect_unfamiliar_login_event(
                adapted_prior,
                adapted_current,
                event.user_id,
                now=eval_time,
                min_history=settings.MIN_HISTORY_FOR_NOVELTY,
            )

        # 3. Risk Scoring: Combine triggered signals and compute explainable score
        triggered_signals: list[str] = []
        explanations: list[str] = []

        if burst_result["triggered"]:
            triggered_signals.append(burst_result["rule_id"])
            explanations.append(burst_result["reason"])

        if novelty_result and novelty_result["triggered_signals"]:
            triggered_signals.extend(novelty_result["triggered_signals"])
            explanations.extend(novelty_result["explanations"])

        if triggered_signals:
            scored = score_risk(triggered_signals)
            risk_score = scored["risk_score"]
            severity = scored["severity"]
            explanations.extend(scored["reasons"])
        else:
            risk_score = 0
            severity = "LOW"
            explanations.append(burst_result["reason"])

        # 4. Construct Detection Result Envelope conforming to v1 schema
        detection_envelope = {
            "schema_version": "1.0",
            "event_id": event.event_id,
            "risk_score": risk_score,
            "severity": severity,
            "reasons": explanations,
            "detector_version": settings.DETECTOR_VERSION,
        }

        # 5. Incident Correlation: Fetch recent history and evaluate correlation episodes
        corr_window_start = eval_time - timedelta(minutes=60)
        stmt_corr = (
            select(LoginEvent)
            .where(LoginEvent.user_id == event.user_id)
            .where(LoginEvent.timestamp >= corr_window_start)
            .where(LoginEvent.timestamp <= eval_time)
            .order_by(LoginEvent.timestamp.asc(), LoginEvent.event_id.asc())
        )
        recent_events = list(db.execute(stmt_corr).scalars().all())

        raw_corr_events = []
        for e in recent_events:
            rec = {
                "schema_version": "1.0",
                "event_id": e.event_id,
                "user_id": e.user_id,
                "event_type": e.event_type,
                "timestamp": _ensure_utc(e.timestamp).isoformat().replace("+00:00", "Z"),
                "source": e.source,
            }
            if e.device_id:
                rec["device_id"] = e.device_id
            if e.ip_address:
                rec["ip_address"] = e.ip_address
            raw_corr_events.append(rec)

        correlated_incidents = correlate_incidents(
            raw_corr_events,
            evaluation_time=eval_time,
            correlation_window=timedelta(minutes=settings.DEFAULT_CORRELATION_WINDOW_MINUTES),
            min_history=settings.MIN_HISTORY_FOR_NOVELTY,
        )

        for inc_dict in correlated_incidents:
            existing_inc = db.get(Incident, inc_dict["incident_id"])
            if existing_inc is None:
                title = f"Failed Login Burst Followed By Unfamiliar Login"
                desc = (
                    f"Identity {inc_dict['identity']} experienced a burst of failed logins "
                    f"followed by an unfamiliar successful authentication."
                )
                new_inc = Incident(
                    incident_id=inc_dict["incident_id"],
                    title=title,
                    description=desc,
                    user_id=inc_dict["identity"],
                    incident_type=inc_dict["incident_type"],
                    risk_score=inc_dict["risk_score"],
                    severity=inc_dict["severity"],
                    status="open",
                    start_time=datetime.fromisoformat(inc_dict["start_time"].replace("Z", "+00:00")),
                    end_time=datetime.fromisoformat(inc_dict["end_time"].replace("Z", "+00:00")),
                    signals=inc_dict["signals"],
                    explanations=inc_dict["explanations"],
                    scorer_version=inc_dict["scorer_version"],
                )

                # Link contributing events
                stmt_contrib = select(LoginEvent).where(
                    LoginEvent.event_id.in_(inc_dict["contributing_event_ids"])
                )
                contrib_evts = list(db.execute(stmt_contrib).scalars().all())
                new_inc.events.extend(contrib_evts)
                db.add(new_inc)

                # Auto-generate alert if HIGH or CRITICAL
                if new_inc.severity in ("HIGH", "CRITICAL"):
                    alert = Alert(
                        alert_id=f"alt-{uuid4().hex[:16]}",
                        incident_id=new_inc.incident_id,
                        alert_type="THREAT_INCIDENT_CORRELATED",
                        severity=new_inc.severity,
                        message=f"Threat detected for {new_inc.user_id}: {title} (Risk: {new_inc.risk_score})",
                    )
                    db.add(alert)
                    logger.warning(
                        "Alert generated for incident %s (User: %s, Score: %d)",
                        new_inc.incident_id,
                        new_inc.user_id,
                        new_inc.risk_score,
                    )

        # 6. Mark event as evaluated and store detection result
        event.detection_status = "evaluated"
        event.detection_result = detection_envelope
        db.commit()
        db.refresh(event)
        return detection_envelope

    except Exception as exc:
        logger.error("Detection engine execution failed for event %s: %s", event.event_id, exc, exc_info=True)
        event.detection_status = "failed"
        db.commit()
        return {
            "schema_version": "1.0",
            "event_id": event.event_id,
            "risk_score": None,
            "severity": "UNKNOWN",
            "reasons": [f"Detection evaluation failed: {str(exc)}"],
            "detector_version": settings.DETECTOR_VERSION,
        }
