"""Identity-specific authentication detection rules."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import ipaddress
from typing import TypedDict


RULE_ID = "failed_login_burst"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=15)


class RuleResult(TypedDict):
    rule_id: str
    triggered: bool
    failed_attempts: int
    reason: str


class NoveltyResult(TypedDict):
    triggered_signals: list[str]
    explanations: list[str]


def _as_utc(timestamp: datetime) -> datetime:
    if not isinstance(timestamp, datetime):
        raise TypeError("Timestamps must be datetime objects")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def detect_failed_login_burst(
    events: Iterable[Mapping[str, object]],
    identity: str,
    *,
    now: datetime | None = None,
) -> RuleResult:
    """Count one identity's failures in the rolling interval [now - 15m, now].

    Events use ``identity``, ``event_type``, and ``timestamp`` fields. Timestamps
    must be aware datetime objects; UTC offsets are normalized to UTC. Unrelated
    events are ignored. The optional evaluation time makes replay deterministic;
    by default the rule evaluates against the current UTC time. Future failures
    never count, and successful logins do not reset the rolling failure count.
    """
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError("identity must be a non-empty string")

    evaluation_time = _as_utc(now if now is not None else datetime.now(timezone.utc))
    window_start = evaluation_time - WINDOW
    failed_attempts = 0
    for event in events:
        if event.get("identity") != identity or event.get("event_type") != "LOGIN_FAILURE":
            continue
        timestamp = _as_utc(event["timestamp"])
        if window_start <= timestamp <= evaluation_time:
            failed_attempts += 1

    triggered = failed_attempts >= FAILURE_THRESHOLD
    return {
        "rule_id": RULE_ID,
        "triggered": triggered,
        "failed_attempts": failed_attempts,
        "reason": (
            f"{failed_attempts} LOGIN_FAILURE events for identity {identity!r} "
            f"in the last 15 minutes; threshold of {FAILURE_THRESHOLD} "
            f"{'met' if triggered else 'not met'}."
        ),
    }


def detect_unfamiliar_login_signals(
    events: Iterable[Mapping[str, object]],
    identity: str,
    *,
    now: datetime,
    min_history: int = 1,
) -> NoveltyResult:
    """Compare the latest successful-login cohort with strictly earlier successes.

    The caller supplies unique, validated records with aware datetime timestamps.
    Each optional identifier needs ``min_history`` earlier successes containing
    that identifier. Events at the latest timestamp cannot establish its baseline.
    """
    _validate_novelty_inputs(identity, min_history)
    evaluation_time = _as_utc(now)
    successes = [
        (event, timestamp)
        for event in events
        if event.get("identity") == identity
        and event.get("event_type") == "LOGIN_SUCCESS"
        and (timestamp := _as_utc(event["timestamp"])) <= evaluation_time
    ]
    if not successes:
        return {"triggered_signals": [], "explanations": []}

    latest = max(timestamp for _, timestamp in successes)
    current = [event for event, timestamp in successes if timestamp == latest]
    history = [event for event, timestamp in successes if timestamp < latest]
    return _compare_identifiers(current, history, identity, min_history)


def detect_unfamiliar_login_event(
    events: Iterable[Mapping[str, object]],
    current_event: Mapping[str, object],
    identity: str,
    *,
    now: datetime,
    min_history: int = 1,
) -> NoveltyResult:
    """Evaluate one successful login against strictly earlier same-identity successes.

    ``events`` and ``current_event`` are unique, validated adapted records. This
    helper leaves the latest-login identity summary rule unchanged. Same-time
    successes cannot establish one another's baseline.
    """
    _validate_novelty_inputs(identity, min_history)
    evaluation_time = _as_utc(now)
    if current_event.get("identity") != identity or current_event.get("event_type") != "LOGIN_SUCCESS":
        raise ValueError("current_event must be a successful login for identity")
    current_time = _as_utc(current_event["timestamp"])
    if current_time > evaluation_time:
        return {"triggered_signals": [], "explanations": []}
    history = [
        event for event in events
        if event.get("identity") == identity
        and event.get("event_type") == "LOGIN_SUCCESS"
        and _as_utc(event["timestamp"]) < current_time
    ]
    return _compare_identifiers(
        [current_event], history, identity, min_history, current_label="evaluated",
    )


def _validate_novelty_inputs(identity: str, min_history: int) -> None:
    if not isinstance(identity, str) or not identity.strip():
        raise ValueError("identity must be a non-empty string")
    if type(min_history) is not int:
        raise TypeError("min_history must be an integer")
    if min_history < 1:
        raise ValueError("min_history must be at least 1")


def _compare_identifiers(
    current: list[Mapping[str, object]],
    history: list[Mapping[str, object]],
    identity: str,
    min_history: int,
    *,
    current_label: str = "latest",
) -> NoveltyResult:
    signals: list[str] = []
    explanations: list[str] = []
    for field, signal in (("device_id", "unfamiliar_device"),
                          ("ip_address", "unfamiliar_ip")):
        prior = [event[field] for event in history if field in event]
        if len(prior) < min_history:
            continue
        if field == "ip_address":
            known = {ipaddress.ip_address(value) for value in prior}
            novel = sum(
                ipaddress.ip_address(event[field]) not in known
                for event in current if field in event
            )
        else:
            known = set(prior)
            novel = sum(event[field] not in known for event in current if field in event)
        if novel:
            signals.append(signal)
            explanations.append(
                f"{signal}: {novel} of {len(current)} {current_label} successful login(s) "
                f"used a {field} unseen in {len(prior)} earlier successful "
                f"login(s) for identity {identity!r}."
            )
    return {"triggered_signals": signals, "explanations": explanations}
