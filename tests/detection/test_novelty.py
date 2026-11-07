"""Successful-login novelty in the offline identity pipeline."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from services.detection.pipeline import evaluate_events
from services.detection.risk_scoring import score_risk
from services.simulator import generate_events


NOW = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)


def login(index, minutes, *, user="alice", device="known", ip="192.0.2.1", kind="LOGIN_SUCCESS"):
    record = {
        "schema_version": "1.0",
        "event_id": f"evt-{index}",
        "user_id": user,
        "event_type": kind,
        "timestamp": (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
        "source": "test",
    }
    if device is not None:
        record["device_id"] = device
    if ip is not None:
        record["ip_address"] = ip
    return record


def signals(events, **kwargs):
    return evaluate_events(events, evaluation_time=NOW, **kwargs)[0]["triggered_signals"]


@pytest.mark.parametrize("device,ip,expected", [
    ("known", "192.0.2.1", []),
    ("new", "192.0.2.1", ["unfamiliar_device"]),
    ("known", "192.0.2.2", ["unfamiliar_ip"]),
    ("new", "192.0.2.2", ["unfamiliar_device", "unfamiliar_ip"]),
])
def test_independent_identifiers_and_scoring(device, ip, expected):
    result = evaluate_events([login(0, -5), login(1, 0, device=device, ip=ip)],
                             evaluation_time=NOW)[0]
    scored = score_risk(expected)
    assert result["triggered_signals"] == expected
    assert (result["risk_score"], result["severity"]) == (
        scored["risk_score"], scored["severity"]
    )
    if expected:
        assert result["explanations"][-len(scored["reasons"]):] == scored["reasons"]
    else:
        assert len(result["explanations"]) == 1
    for signal in expected:
        assert any(reason.startswith(signal + ":") and "earlier successful" in reason
                   for reason in result["explanations"])


def test_first_login_and_configurable_minimum_history():
    first = login(0, -10)
    changed = login(1, 0, device="new", ip="192.0.2.2")
    assert signals([changed]) == []
    assert signals([first, changed], min_history=2) == []
    assert signals([first, login(2, -5), changed], min_history=2) == [
        "unfamiliar_device", "unfamiliar_ip"
    ]


@pytest.mark.parametrize("bad,error", [(0, ValueError), (-1, ValueError), (True, TypeError), (1.5, TypeError)])
def test_invalid_minimum_history(bad, error):
    with pytest.raises(error, match="min_history"):
        evaluate_events([], evaluation_time=NOW, min_history=bad)


def test_missing_device_does_not_establish_or_trigger_device_novelty():
    assert signals([login(0, -5, device=None), login(1, 0, device="new")]) == []
    assert signals([login(0, -5), login(1, 0, device=None)]) == []
    assert signals([login(0, -5, device=None, ip="192.0.2.1"),
                    login(1, 0, device="new", ip="192.0.2.2")]) == ["unfamiliar_ip"]


def test_missing_ip_does_not_establish_or_trigger_ip_novelty():
    assert signals([login(0, -5, ip=None), login(1, 0, ip="192.0.2.2")]) == []
    assert signals([login(0, -5), login(1, 0, ip=None)]) == []


def test_ip_literals_compare_by_address_not_spelling():
    assert signals([login(0, -5, ip="2001:0db8:0:0:0:0:0:1"),
                    login(1, 0, ip="2001:db8::1")]) == []


def test_success_only_and_exact_identity_scope():
    events = [login(0, -10, user="bob"),
              login(1, -5, kind="LOGIN_FAILURE"),
              login(2, 0, device="new", ip="192.0.2.2")]
    results = evaluate_events(events, evaluation_time=NOW)
    assert [item["identity"] for item in results] == ["alice", "bob"]
    assert all(item["triggered_signals"] == [] for item in results)


def test_latest_cohort_strict_time_boundary_future_and_order():
    events = [login(0, -5), login(1, 0, device="new", ip="192.0.2.2"),
              login(2, 0, device="known", ip="192.0.2.1"),
              login(3, 1, device="future", ip="192.0.2.3")]
    original = deepcopy(events)
    expected = evaluate_events(events, evaluation_time=NOW)
    assert expected == evaluate_events(reversed(events), evaluation_time=NOW)
    assert expected == evaluate_events(events + [events[0], events[1]], evaluation_time=NOW)
    assert events == original
    assert expected[0]["triggered_signals"] == ["unfamiliar_device", "unfamiliar_ip"]
    assert "1 of 2 latest" in expected[0]["explanations"][1]
    assert signals(events[:1] + events[1:3]) == expected[0]["triggered_signals"]
    assert signals([login(4, 0, device="new", ip="192.0.2.2"),
                    login(5, 0, device="known", ip="192.0.2.1")]) == []
    assert signals(events, min_history=2) == []


def test_future_success_is_excluded_even_if_it_looks_like_baseline():
    assert signals([login(0, 1), login(1, 2, device="new", ip="192.0.2.2")]) == []
    assert signals([login(0, -5), login(1, 0),
                    login(2, 1, device="new", ip="192.0.2.2")]) == []


def test_only_latest_success_is_evaluated_against_all_earlier_successes():
    events = [login(0, -10), login(1, -5, device="temporary", ip="192.0.2.2"),
              login(2, 0)]
    assert signals(events) == []
    assert signals(events[:2]) == ["unfamiliar_device", "unfamiliar_ip"]


def test_duplicate_replay_cannot_satisfy_minimum_history_and_conflicts_raise():
    baseline = login(0, -5)
    changed = login(1, 0, device="new", ip="192.0.2.2")
    replay = dict(baseline, timestamp=baseline["timestamp"].replace("Z", "+00:00"))
    assert signals([baseline, baseline, replay, changed], min_history=2) == []
    for conflict in (dict(baseline, device_id="other"),
                     dict(baseline, ip_address="192.0.2.3"),
                     dict(baseline, user_id="bob")):
        with pytest.raises(ValueError, match="conflicting event_id"):
            evaluate_events([baseline, conflict, changed], evaluation_time=NOW)


def test_burst_combines_with_both_novelty_signals_through_scorer():
    events = [login(0, -20), login(1, 0, device="new", ip="192.0.2.2")]
    events += [login(index, -index, kind="LOGIN_FAILURE") for index in range(2, 7)]
    result = evaluate_events(events, evaluation_time=NOW)[0]
    scored = score_risk(["failed_login_burst", "unfamiliar_device", "unfamiliar_ip"])
    assert result["failed_attempts"] == 5
    assert result["triggered_signals"] == scored["triggered_signals"]
    assert (result["risk_score"], result["severity"]) == (75, "CRITICAL")
    assert result["explanations"][-3:] == scored["reasons"]


@pytest.mark.parametrize("scenario,expected", [
    ("unfamiliar_device", ["unfamiliar_device"]),
    ("unfamiliar_ip", ["unfamiliar_ip"]),
])
def test_simulator_pairs(scenario, expected):
    events = generate_events(scenario, seed=42, reference_time=NOW)
    assert signals(events) == expected
    assert signals(reversed(events)) == expected
    assert signals(events, min_history=2) == []
