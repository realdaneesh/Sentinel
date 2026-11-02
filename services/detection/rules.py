"""Identity-specific authentication detection rules."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import TypedDict


RULE_ID = "failed_login_burst"
FAILURE_THRESHOLD = 5
WINDOW = timedelta(minutes=15)


class RuleResult(TypedDict):
    rule_id: str
    triggered: bool
    failed_attempts: int
    reason: str


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
