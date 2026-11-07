"""Offline v1 authentication event validation and identity-level detection."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import ipaddress
import re
from typing import TypedDict

from .risk_scoring import score_risk
from .rules import detect_failed_login_burst, detect_unfamiliar_login_signals


_UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
)
_REQUIRED = frozenset({
    "schema_version", "event_id", "user_id", "event_type", "timestamp", "source",
})
_OPTIONAL = frozenset({"ip_address", "device_id"})
_TEXT_LIMITS = {"event_id": 128, "user_id": 256, "source": 64, "device_id": 256}


class PipelineResult(TypedDict):
    identity: str
    triggered_signals: list[str]
    risk_score: int
    severity: str
    explanations: list[str]
    failed_attempts: int
    scorer_version: str


def _valid_text(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()


def _validate_event(event: object, index: int) -> tuple[dict[str, object], datetime]:
    if not isinstance(event, Mapping):
        raise TypeError(f"events[{index}] must be a v1 event mapping")
    record = dict(event)
    missing = _REQUIRED - record.keys()
    unknown = record.keys() - _REQUIRED - _OPTIONAL
    if missing:
        raise ValueError(f"events[{index}] missing field: {sorted(missing)[0]}")
    if unknown:
        raise ValueError(f"events[{index}] unknown field: {sorted(unknown, key=str)[0]}")
    if record["schema_version"] != "1.0":
        raise ValueError(f"events[{index}] unsupported schema_version")
    for field, limit in _TEXT_LIMITS.items():
        if field in record and not _valid_text(record[field], limit):
            raise ValueError(f"events[{index}] invalid {field}")
    if record["event_type"] not in ("LOGIN_SUCCESS", "LOGIN_FAILURE"):
        raise ValueError(f"events[{index}] invalid event_type")
    stamp = record["timestamp"]
    if not isinstance(stamp, str) or not _UTC_TIMESTAMP.fullmatch(stamp):
        raise ValueError(f"events[{index}] invalid UTC timestamp")
    try:
        timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"events[{index}] invalid UTC timestamp") from None
    if "ip_address" in record:
        address = record["ip_address"]
        if not isinstance(address, str) or not _valid_text(address, len(address)) or "%" in address:
            raise ValueError(f"events[{index}] invalid ip_address")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError(f"events[{index}] invalid ip_address") from None
    return record, timestamp.astimezone(timezone.utc)


def evaluate_events(
    events: Iterable[Mapping[str, object]], *, evaluation_time: datetime,
    min_history: int = 1,
) -> list[PipelineResult]:
    """Validate and evaluate a batch, returning summaries sorted by identity.

    Identical event IDs are counted once. An ID reused with different validated
    content raises ValueError. All events are validated before any result returns.
    """
    if not isinstance(evaluation_time, datetime):
        raise TypeError("evaluation_time must be a timezone-aware datetime")
    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise ValueError("evaluation_time must be timezone-aware")
    if type(min_history) is not int:
        raise TypeError("min_history must be an integer")
    if min_history < 1:
        raise ValueError("min_history must be at least 1")
    now = evaluation_time.astimezone(timezone.utc)
    if isinstance(events, (str, bytes, bytearray, Mapping)):
        raise TypeError("events must be an iterable of v1 event mappings")
    try:
        iterator = iter(events)
    except TypeError:
        raise TypeError("events must be an iterable of v1 event mappings") from None

    unique: dict[str, tuple[dict[str, object], datetime]] = {}
    for index, event in enumerate(iterator):
        record, timestamp = _validate_event(event, index)
        event_id = record["event_id"]
        previous = unique.get(event_id)
        if previous is not None:
            previous_record, previous_timestamp = previous
            # Presence of optional fields is significant; only timestamp syntax
            # is normalized when comparing validated replay payloads.
            if previous_timestamp != timestamp or {
                key: value for key, value in previous_record.items() if key != "timestamp"
            } != {key: value for key, value in record.items() if key != "timestamp"}:
                raise ValueError(f"events[{index}] conflicting event_id: {event_id}")
            continue
        unique[event_id] = record, timestamp

    by_identity: dict[str, list[dict[str, object]]] = {}
    for record, timestamp in unique.values():
        identity = record["user_id"]
        adapted = {
            "identity": identity, "event_type": record["event_type"], "timestamp": timestamp,
        }
        for field in ("device_id", "ip_address"):
            if field in record:
                adapted[field] = record[field]
        by_identity.setdefault(identity, []).append(adapted)

    results: list[PipelineResult] = []
    for identity in sorted(by_identity):
        rule = detect_failed_login_burst(by_identity[identity], identity, now=now)
        signals = [rule["rule_id"]] if rule["triggered"] else []
        novelty = detect_unfamiliar_login_signals(
            by_identity[identity], identity, now=now, min_history=min_history,
        )
        signals.extend(novelty["triggered_signals"])
        scored = score_risk(signals)
        results.append({
            "identity": identity,
            "triggered_signals": scored["triggered_signals"],
            "risk_score": scored["risk_score"],
            "severity": scored["severity"],
            "explanations": [rule["reason"], *novelty["explanations"], *scored["reasons"]],
            "failed_attempts": rule["failed_attempts"],
            "scorer_version": scored["scorer_version"],
        })
    return results
