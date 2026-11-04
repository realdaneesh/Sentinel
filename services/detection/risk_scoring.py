"""Deterministic scoring of normalized signals, independent of event ingestion."""

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Literal, TypedDict


SCORER_VERSION = "1.0.0"
DEFAULT_WEIGHTS: Mapping[str, int] = MappingProxyType({
    "failed_login_burst": 35,
    "unfamiliar_device": 20,
    "unusual_login_hour": 15,
    "unfamiliar_ip": 20,
})

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ScoringResult(TypedDict):
    """Internal score summary, not the event-level detection-result envelope."""

    risk_score: int
    severity: Severity
    reasons: list[str]
    triggered_signals: list[str]
    scorer_version: str


def _validate_signal(signal: str) -> None:
    if not isinstance(signal, str):
        raise TypeError("signal identifiers must be strings")
    if signal not in DEFAULT_WEIGHTS:
        raise ValueError(f"unknown signal identifier: {signal!r}")


def score_risk(
    signals: Iterable[str],
    *,
    weights: Mapping[str, int] | None = None,
) -> ScoringResult:
    """Score unique signals with optional partial overrides of default weights.

    Identifiers are exact and case-sensitive. Strings, bytes, and mappings are
    not signal collections. Weights must be integers in [0, 100], excluding
    booleans; every override is validated even if its signal is absent.
    Contributions and identifiers are ordered lexicographically. Reasons report
    pre-cap contributions, followed by a cap explanation when needed.
    Inputs and defaults are never mutated; each call returns fresh lists.
    """
    if isinstance(signals, (str, bytes, bytearray, Mapping)):
        raise TypeError("signals must be an iterable of identifiers, not text or a mapping")
    try:
        signal_iterator = iter(signals)
    except TypeError:
        raise TypeError("signals must be an iterable of identifiers") from None

    effective_weights = dict(DEFAULT_WEIGHTS)
    if weights is not None:
        if not isinstance(weights, Mapping):
            raise TypeError("weights must be a mapping or None")
        for signal, weight in weights.items():
            _validate_signal(signal)
            if type(weight) is not int:
                raise TypeError("weights must be integers, excluding booleans")
            if not 0 <= weight <= 100:
                raise ValueError("weights must be between 0 and 100 inclusive")
            effective_weights[signal] = weight

    unique_signals: set[str] = set()
    for signal in signal_iterator:
        _validate_signal(signal)
        unique_signals.add(signal)
    triggered_signals = sorted(unique_signals)
    total = sum(effective_weights[signal] for signal in triggered_signals)
    risk_score = min(total, 100)
    severity: Severity
    if risk_score < 25:
        severity = "LOW"
    elif risk_score < 50:
        severity = "MEDIUM"
    elif risk_score < 75:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    reasons = [
        f"{signal}: +{effective_weights[signal]} risk points."
        for signal in triggered_signals
    ]
    if total > 100:
        reasons.append(f"Total of {total} risk points capped at 100.")
    return {
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons,
        "triggered_signals": triggered_signals,
        "scorer_version": SCORER_VERSION,
    }
