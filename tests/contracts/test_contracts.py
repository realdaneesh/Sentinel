"""Test-only reference validation; no runtime API or scoring implementation."""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from services.detection.rules import detect_failed_login_burst
from services.simulator import SCENARIOS, generate_events


FIXTURES = Path(__file__).parents[1] / "fixtures" / "contracts"
UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
)


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()


def validate(payload, kind):
    """Return invalid field names for the documented v1 contract."""
    if not isinstance(payload, dict):
        return {"$"}
    limits = {"event_id": 128}
    if kind == "events":
        limits.update(user_id=256, source=64)
        required = set(limits) | {"schema_version", "event_type", "timestamp"}
        optional = {"ip_address", "device_id"}
    else:
        limits.update(detector_version=128)
        required = set(limits) | {"schema_version", "risk_score", "severity", "reasons"}
        optional = set()
    errors = (required - payload.keys()) | (payload.keys() - required - optional)
    errors.update(key for key, limit in limits.items() if not text(payload.get(key), limit))
    if payload.get("schema_version") != "1.0":
        errors.add("schema_version")
    if kind == "events":
        if payload.get("event_type") not in ("LOGIN_SUCCESS", "LOGIN_FAILURE"):
            errors.add("event_type")
        stamp = payload.get("timestamp")
        try:
            if not isinstance(stamp, str) or not UTC_TIMESTAMP.fullmatch(stamp):
                raise ValueError
            datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            errors.add("timestamp")
        if "device_id" in payload and not text(payload["device_id"], 256):
            errors.add("device_id")
        if "ip_address" in payload:
            address = payload["ip_address"]
            try:
                if not isinstance(address, str) or "%" in address:
                    raise ValueError
                ipaddress.ip_address(address)
            except ValueError:
                errors.add("ip_address")
    else:
        score = payload.get("risk_score")
        if score is not None and (type(score) is not int or not 0 <= score <= 100):
            errors.add("risk_score")
        allowed = ("UNKNOWN",) if score is None else ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        if payload.get("severity") not in allowed:
            errors.add("severity")
        reasons = payload.get("reasons")
        if not isinstance(reasons, list) or any(not text(item, 1024) for item in reasons):
            errors.add("reasons")
    return errors


@pytest.mark.parametrize("kind", ["events", "results"])
def test_valid_fixtures(kind):
    for payload in load(kind)["valid"]:
        assert validate(payload, kind) == set()


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("seed", [0, 42, -7])
def test_simulator_events_follow_shared_contract(scenario, seed):
    for payload in generate_events(scenario, seed=seed):
        assert validate(payload, "events") == set()


INVALID_CASES = [
    pytest.param(kind, case, id=f"{kind}-{case['name']}")
    for kind in ("events", "results")
    for case in load(kind)["invalid"]
]


@pytest.mark.parametrize("kind,case", INVALID_CASES)
def test_invalid_fixtures(kind, case):
    payload = dict(load(kind)["valid"][0])
    payload.update(case["patch"])
    for field in case.get("remove", []):
        payload.pop(field)
    assert case["field"] in validate(payload, kind)


@pytest.mark.parametrize("kind", ["events", "results"])
@pytest.mark.parametrize("payload", [None, [], "event", 1])
def test_non_object_payloads(kind, payload):
    assert validate(payload, kind) == {"$"}


def test_documented_adapter_matches_current_detector():
    now = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
    base = load("events")["valid"][0]
    history = [
        dict(base, event_id=f"evt-{i}", timestamp=(now - timedelta(minutes=i)).isoformat())
        for i in range(5)
    ]
    history += [dict(base, event_id="other-user", user_id="bob")]
    history += [dict(base, event_id="future", timestamp=(now + timedelta(seconds=1)).isoformat())]
    assert all(not validate(record, "events") for record in history)
    adapted = [
        {"identity": record["user_id"], "event_type": record["event_type"],
         "timestamp": datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))}
        for record in history
    ]
    result = detect_failed_login_burst(adapted, base["user_id"], now=now)
    assert result["triggered"] is True
    assert result["failed_attempts"] == 5
    assert set(result) == {"rule_id", "triggered", "failed_attempts", "reason"}
