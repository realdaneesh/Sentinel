"""Pure offline correlation of failed-login bursts and unfamiliar successes."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import TypedDict

from .pipeline import _unique_events
from .risk_scoring import score_risk
from .rules import (
    WINDOW, NoveltyResult, detect_failed_login_burst, detect_unfamiliar_login_event,
)


INCIDENT_TYPE = "failed_login_burst_followed_by_unfamiliar_login"
DEFAULT_CORRELATION_WINDOW = timedelta(minutes=15)


class Incident(TypedDict):
    incident_id: str
    identity: str
    incident_type: str
    start_time: str
    end_time: str
    contributing_event_ids: list[str]
    signals: list[str]
    risk_score: int
    severity: str
    explanations: list[str]
    scorer_version: str


@dataclass
class _Episode:
    failure_ids: set[str] = field(default_factory=set)
    successes: list[tuple[dict[str, object], NoveltyResult]] = field(default_factory=list)
    burst_reason: str = ""


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def correlate_incidents(
    events: Iterable[Mapping[str, object]],
    *,
    evaluation_time: datetime,
    correlation_window: timedelta = DEFAULT_CORRELATION_WINDOW,
    min_history: int = 1,
) -> list[Incident]:
    """Return deterministic incidents for a validated, deduplicated v1 batch.

    A burst is a threshold crossing of the existing rolling rule. Continued
    above-threshold failures remain in that episode. A novel success attaches to
    the most recent qualifying burst observation strictly before its timestamp.
    """
    if not isinstance(evaluation_time, datetime):
        raise TypeError("evaluation_time must be a timezone-aware datetime")
    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise ValueError("evaluation_time must be timezone-aware")
    if not isinstance(correlation_window, timedelta):
        raise TypeError("correlation_window must be a timedelta")
    if correlation_window < timedelta(0):
        raise ValueError("correlation_window must be non-negative")
    if type(min_history) is not int:
        raise TypeError("min_history must be an integer")
    if min_history < 1:
        raise ValueError("min_history must be at least 1")

    now = evaluation_time.astimezone(timezone.utc)
    unique = _unique_events(events)
    by_identity: dict[str, list[dict[str, object]]] = {}
    for event_id, (record, timestamp) in unique.items():
        if timestamp > now:
            continue
        adapted = {
            "event_id": event_id,
            "identity": record["user_id"],
            "event_type": record["event_type"],
            "timestamp": timestamp,
        }
        for field_name in ("device_id", "ip_address"):
            if field_name in record:
                adapted[field_name] = record[field_name]
        by_identity.setdefault(record["user_id"], []).append(adapted)

    incidents: list[Incident] = []
    for identity in sorted(by_identity):
        records = sorted(by_identity[identity], key=lambda row: (row["timestamp"], row["event_id"]))
        failures = [row for row in records if row["event_type"] == "LOGIN_FAILURE"]
        successes = [row for row in records if row["event_type"] == "LOGIN_SUCCESS"]
        episodes: list[_Episode] = []
        observations: list[tuple[datetime, _Episode, frozenset[str], str]] = []
        active: _Episode | None = None
        for failure_time in sorted({row["timestamp"] for row in failures}):
            # The rolling count can fall below threshold between observed
            # timestamps. Check just before this group so a new batch of
            # same-time failures cannot silently extend a stale episode.
            if active is not None:
                earlier = [row for row in failures if row["timestamp"] < failure_time]
                if not detect_failed_login_burst(
                    earlier, identity, now=failure_time,
                )["triggered"]:
                    active = None
            eligible = [row for row in failures if row["timestamp"] <= failure_time]
            rule = detect_failed_login_burst(eligible, identity, now=failure_time)
            if not rule["triggered"]:
                active = None
                continue
            if active is None:
                active = _Episode()
                episodes.append(active)
            evidence = frozenset(
                row["event_id"] for row in eligible
                if failure_time - row["timestamp"] <= WINDOW
            )
            observations.append((failure_time, active, evidence, rule["reason"]))

        for success in successes:
            novelty = detect_unfamiliar_login_event(
                records, success, identity, now=now, min_history=min_history,
            )
            if not novelty["triggered_signals"]:
                continue
            eligible_observations = [
                observation for observation in observations
                if observation[0] < success["timestamp"]
                and success["timestamp"] - observation[0] <= correlation_window
            ]
            if not eligible_observations:
                continue
            _, episode, evidence, reason = eligible_observations[-1]
            episode.failure_ids.update(evidence)
            episode.successes.append((success, novelty))
            episode.burst_reason = reason

        by_id = {row["event_id"]: row for row in records}
        for episode in episodes:
            if not episode.successes:
                continue
            contribution_ids = episode.failure_ids | {
                success["event_id"] for success, _ in episode.successes
            }
            ordered_ids = sorted(contribution_ids, key=lambda event_id: (
                by_id[event_id]["timestamp"], event_id,
            ))
            signals = {"failed_login_burst"}
            for _, novelty in episode.successes:
                signals.update(novelty["triggered_signals"])
            scored = score_risk(signals)
            start_time = _utc_text(by_id[ordered_ids[0]]["timestamp"])
            end_time = _utc_text(by_id[ordered_ids[-1]]["timestamp"])
            canonical = json.dumps(
                [INCIDENT_TYPE, identity, start_time, end_time, ordered_ids,
                 scored["triggered_signals"]],
                ensure_ascii=False, separators=(",", ":"),
            )
            incident_id = "inc-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            success_reasons = [
                f"Successful login {success['event_id']!r} at {_utc_text(success['timestamp'])} "
                f"followed a failed-login burst; {'; '.join(novelty['explanations'])}"
                for success, novelty in episode.successes
            ]
            incidents.append({
                "incident_id": incident_id,
                "identity": identity,
                "incident_type": INCIDENT_TYPE,
                "start_time": start_time,
                "end_time": end_time,
                "contributing_event_ids": ordered_ids,
                "signals": scored["triggered_signals"],
                "risk_score": scored["risk_score"],
                "severity": scored["severity"],
                "explanations": [
                    f"{len(episode.failure_ids)} failed-login event(s) formed a burst "
                    f"before {len(episode.successes)} unfamiliar successful login(s).",
                    episode.burst_reason,
                    *success_reasons,
                    *scored["reasons"],
                ],
                "scorer_version": scored["scorer_version"],
            })
    return sorted(incidents, key=lambda item: (
        item["identity"],
        datetime.fromisoformat(item["start_time"].replace("Z", "+00:00")),
        datetime.fromisoformat(item["end_time"].replace("Z", "+00:00")),
        item["incident_id"],
    ))
