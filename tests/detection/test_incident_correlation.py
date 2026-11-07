"""Offline incident correlation and event-specific novelty regression tests."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from services.detection.incident_correlation import correlate_incidents
from services.detection.pipeline import evaluate_events
from services.detection.risk_scoring import score_risk
from services.detection.rules import detect_unfamiliar_login_event
from services.simulator import generate_events


NOW = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)


def event(index, minutes, *, user="alice", kind="LOGIN_FAILURE", device="known", ip="192.0.2.1"):
    record = {
        "schema_version": "1.0", "event_id": f"evt-{index}", "user_id": user,
        "event_type": kind,
        "timestamp": (NOW + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
        "source": "test",
    }
    if device is not None:
        record["device_id"] = device
    if ip is not None:
        record["ip_address"] = ip
    return record


def burst(*, user="alice", first=-14, count=5, offset=0):
    return [event(offset + index, first + index, user=user) for index in range(count)]


def sample(*, user="alice", device="new", ip="192.0.2.1", success_minute=0):
    return [event(90, -30, user=user, kind="LOGIN_SUCCESS"),
            *burst(user=user),
            event(91, success_minute, user=user, kind="LOGIN_SUCCESS", device=device, ip=ip)]


def correlate(events, **kwargs):
    return correlate_incidents(events, evaluation_time=NOW, **kwargs)


@pytest.mark.parametrize("device,ip,expected", [
    ("new", "192.0.2.1", ["failed_login_burst", "unfamiliar_device"]),
    ("known", "192.0.2.2", ["failed_login_burst", "unfamiliar_ip"]),
    ("new", "192.0.2.2", ["failed_login_burst", "unfamiliar_device", "unfamiliar_ip"]),
])
def test_positive_incident_fields_and_scoring(device, ip, expected):
    incident, = correlate(sample(device=device, ip=ip))
    scored = score_risk(expected)
    assert incident["incident_id"].startswith("inc-")
    assert len(incident["incident_id"]) == 68
    assert incident["identity"] == "alice"
    assert incident["incident_type"] == "failed_login_burst_followed_by_unfamiliar_login"
    assert incident["start_time"] == "2026-11-04T11:46:00Z"
    assert incident["end_time"] == "2026-11-04T12:00:00Z"
    assert incident["contributing_event_ids"] == [*(f"evt-{index}" for index in range(5)), "evt-91"]
    assert incident["signals"] == expected
    assert (incident["risk_score"], incident["severity"]) == (
        scored["risk_score"], scored["severity"]
    )
    assert incident["explanations"][-len(scored["reasons"]):] == scored["reasons"]
    assert "threshold of 5 met" in incident["explanations"][1]


def test_latest_identity_summary_limitation_and_event_level_helper():
    records = sample(device="new")
    records.append(event(92, 0, kind="LOGIN_SUCCESS", device="known"))
    # The summary sees the entire latest-timestamp cohort. Add a later known
    # login to demonstrate why correlation must evaluate the earlier success.
    records[-1]["timestamp"] = (NOW + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    assert evaluate_events(records, evaluation_time=NOW + timedelta(minutes=1))[0]["triggered_signals"] == [
        "failed_login_burst"
    ]
    assert correlate_incidents(records, evaluation_time=NOW + timedelta(minutes=1))[0]["signals"] == [
        "failed_login_burst", "unfamiliar_device"
    ]
    adapted = [
        {"identity": row["user_id"], "event_type": row["event_type"],
         "timestamp": datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")),
         **{key: row[key] for key in ("device_id", "ip_address") if key in row}}
        for row in records
    ]
    event_novelty = detect_unfamiliar_login_event(adapted, adapted[-2], "alice", now=NOW)
    assert event_novelty["triggered_signals"] == ["unfamiliar_device"]
    assert "evaluated successful login" in event_novelty["explanations"][0]
    assert "latest successful login" not in event_novelty["explanations"][0]
    assert detect_unfamiliar_login_event(adapted, adapted[-1], "alice", now=NOW)[
        "triggered_signals"
    ] == []


def test_unrelated_events_and_identity_isolation():
    assert correlate(burst()) == []
    assert correlate(sample(device="known")) == []
    assert correlate([event(90, -30, kind="LOGIN_SUCCESS"), *burst(user="bob"),
                      event(91, 0, kind="LOGIN_SUCCESS", device="new")]) == []
    alice = sample()
    bob = [dict(row, user_id="bob", event_id="bob-" + row["event_id"])
           for row in sample(user="bob", ip="192.0.2.2")]
    result = correlate(bob + alice)
    assert [item["identity"] for item in result] == ["alice", "bob"]
    assert all(all(event_id.startswith("bob-") == (item["identity"] == "bob")
                   for event_id in item["contributing_event_ids"])
               for item in result)


def test_time_boundaries_before_burst_same_timestamp_and_future():
    base = event(90, -30, kind="LOGIN_SUCCESS")
    failures = burst(first=-19)
    assert len(correlate([base, *failures, event(91, 0, kind="LOGIN_SUCCESS", device="new")])) == 1
    assert correlate([base, *failures, event(91, 0, kind="LOGIN_SUCCESS", device="new")],
                     correlation_window=timedelta(minutes=14, seconds=59)) == []
    assert correlate([base, *failures, event(91, -15, kind="LOGIN_SUCCESS", device="new")]) == []
    assert correlate([base, *failures, event(91, -20, kind="LOGIN_SUCCESS", device="new")]) == []
    assert correlate([base, *failures, event(91, 0, kind="LOGIN_SUCCESS", device="new")],
                     correlation_window=timedelta(0)) == []
    assert correlate(sample(success_minute=1)) == []
    future = sample()
    assert correlate_incidents(future, evaluation_time=NOW - timedelta(minutes=1)) == []


def test_same_timestamp_failures_count_together_and_success_does_not_follow():
    base = event(90, -30, kind="LOGIN_SUCCESS")
    failures = [event(index, -5) for index in range(5)]
    assert correlate([base, *failures, event(91, -5, kind="LOGIN_SUCCESS", device="new")]) == []
    incident, = correlate([base, *failures, event(91, -4, kind="LOGIN_SUCCESS", device="new")])
    assert incident["contributing_event_ids"] == [*(f"evt-{index}" for index in range(5)), "evt-91"]


def test_success_at_new_failure_timestamp_uses_only_earlier_burst_observation():
    records = sample(device="new")
    records[-1]["timestamp"] = (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    records.append(event(92, -5))
    incident, = correlate(records)
    assert "evt-91" in incident["contributing_event_ids"]
    assert "evt-92" not in incident["contributing_event_ids"]


def test_latest_qualifying_observation_extends_window_and_evidence_is_qualified():
    failures = [event(index, minute) for index, minute in enumerate(
        (-30, -29, -28, -27, -26, -25, -20, -16, -12)
    )]
    records = [event(90, -40, kind="LOGIN_SUCCESS"), *failures,
               event(91, 0, kind="LOGIN_SUCCESS", device="new")]
    incident, = correlate(records)
    assert incident["start_time"] == "2026-11-04T11:33:00Z"
    assert incident["contributing_event_ids"] == [
        *(f"evt-{index}" for index in range(3, 9)), "evt-91"
    ]
    assert correlate_incidents(
        [*records[:-1], event(91, 4, kind="LOGIN_SUCCESS", device="new")],
        evaluation_time=NOW + timedelta(minutes=4),
    ) == []


def test_below_threshold_failure_is_not_incident_evidence():
    records = [event(90, -40, kind="LOGIN_SUCCESS"), *burst(first=-20),
               event(10, -1),
               event(91, 0, kind="LOGIN_SUCCESS", device="new")]
    incident, = correlate(records, correlation_window=timedelta(minutes=20))
    assert "evt-10" not in incident["contributing_event_ids"]
    assert incident["contributing_event_ids"] == [
        *(f"evt-{index}" for index in range(5)), "evt-91"
    ]


def test_stale_episode_resets_before_simultaneous_new_threshold():
    records = [event(90, -120, kind="LOGIN_SUCCESS")]
    records += [event(index, -100) for index in range(5)]
    records += [event(91, -99, kind="LOGIN_SUCCESS", device="new")]
    records += [event(index + 10, -10) for index in range(5)]
    records += [event(92, 0, kind="LOGIN_SUCCESS", device="newer")]
    incidents = correlate(records)
    assert len(incidents) == 2
    assert incidents[0]["contributing_event_ids"] == [
        *(f"evt-{index}" for index in range(5)), "evt-91"
    ]
    assert incidents[1]["contributing_event_ids"] == [
        *(f"evt-{index}" for index in range(10, 15)), "evt-92"
    ]
    assert incidents[0]["incident_id"] != incidents[1]["incident_id"]


def test_partial_expiry_before_new_simultaneous_threshold_starts_new_episode():
    records = [event(90, -40, kind="LOGIN_SUCCESS"),
               *burst(first=-20),
               event(91, -15, kind="LOGIN_SUCCESS", device="new"),
               *(event(index + 10, -1) for index in range(5)),
               event(92, 0, kind="LOGIN_SUCCESS", device="newer")]
    incidents = correlate(records)
    assert len(incidents) == 2
    assert "evt-92" in incidents[1]["contributing_event_ids"]
    assert "evt-91" not in incidents[1]["contributing_event_ids"]
    # The old failure at -16 belongs to the new qualifying rolling window.
    assert "evt-4" in incidents[1]["contributing_event_ids"]


def test_same_timestamp_successes_cannot_satisfy_minimum_novelty_history():
    records = [event(90, -30, kind="LOGIN_SUCCESS"), *burst(),
               event(91, 0, kind="LOGIN_SUCCESS", device="known"),
               event(92, 0, kind="LOGIN_SUCCESS", device="new")]
    assert correlate(records, min_history=2) == []
    adapted = [
        {"identity": row["user_id"], "event_type": row["event_type"],
         "timestamp": datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")),
         **{key: row[key] for key in ("device_id", "ip_address") if key in row}}
        for row in records
    ]
    assert detect_unfamiliar_login_event(
        adapted, adapted[-1], "alice", now=NOW, min_history=2,
    )["triggered_signals"] == []
    assert correlate(records)[0]["signals"] == ["failed_login_burst", "unfamiliar_device"]


def test_order_replay_utc_equivalence_and_immutability():
    records = sample(ip="192.0.2.2")
    original = deepcopy(records)
    replay = dict(records[0], timestamp=records[0]["timestamp"].replace("Z", "+00:00"))
    expected = correlate(records)
    assert correlate(reversed(records)) == expected
    assert correlate(records + [records[0], records[-1], replay]) == expected
    alternate_spelling = [
        dict(row, timestamp=row["timestamp"].replace("Z", ".000000+00:00"))
        for row in records
    ]
    assert correlate(reversed(alternate_spelling)) == expected
    assert correlate_incidents(records, evaluation_time=NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))) == expected
    assert records == original
    with pytest.raises(ValueError, match="conflicting event_id"):
        correlate(records + [dict(records[0], device_id="other")])


def test_overlapping_windows_and_multiple_successes_make_one_incident():
    records = [event(90, -30, kind="LOGIN_SUCCESS"), *burst(count=7),
               event(91, -1, kind="LOGIN_SUCCESS", device="new"),
               event(92, 0, kind="LOGIN_SUCCESS", device="known", ip="192.0.2.2")]
    incidents = correlate(records)
    assert len(incidents) == 1
    assert incidents[0]["signals"] == ["failed_login_burst", "unfamiliar_device", "unfamiliar_ip"]
    assert incidents[0]["risk_score"] == 75
    assert incidents[0]["severity"] == "CRITICAL"
    assert set(incidents[0]["contributing_event_ids"]) == {
        *(f"evt-{index}" for index in range(7)), "evt-91", "evt-92"
    }


def test_separate_bursts_make_separate_incidents():
    early = [event(90, -100, kind="LOGIN_SUCCESS"),
             *burst(first=-80),
             event(91, -70, kind="LOGIN_SUCCESS", device="new")]
    later = [*burst(first=-14, offset=10),
             event(92, 0, kind="LOGIN_SUCCESS", device="newer")]
    result = correlate(early + later)
    assert len(result) == 2
    assert result[0]["incident_id"] != result[1]["incident_id"]
    assert result[0]["end_time"] < result[1]["start_time"]


@pytest.mark.parametrize("scenario", ["unfamiliar_device", "unfamiliar_ip"])
def test_simulator_composition(scenario):
    burst_events = generate_events("failed_login_burst", seed=42, reference_time=NOW)
    novelty_events = generate_events(
        scenario, seed=42, reference_time=NOW + timedelta(minutes=5),
    )
    incident, = correlate_incidents(
        burst_events + novelty_events, evaluation_time=NOW + timedelta(minutes=5),
    )
    assert incident["identity"] == burst_events[0]["user_id"]
    assert incident["signals"] == ["failed_login_burst", scenario]
    assert novelty_events[-1]["event_id"] in incident["contributing_event_ids"]
    assert correlate_incidents(
        burst_events + novelty_events, evaluation_time=NOW + timedelta(minutes=5),
        min_history=2,
    ) == []


@pytest.mark.parametrize("bad,error", [
    (None, TypeError), ("15", TypeError), (timedelta(minutes=-1), ValueError),
])
def test_invalid_correlation_window(bad, error):
    with pytest.raises(error, match="correlation_window"):
        correlate([], correlation_window=bad)


@pytest.mark.parametrize("bad,error", [
    (None, TypeError), ("2026-11-04T12:00:00Z", TypeError),
    (NOW.replace(tzinfo=None), ValueError),
])
def test_invalid_evaluation_time(bad, error):
    with pytest.raises(error, match="evaluation_time"):
        correlate_incidents([], evaluation_time=bad)


@pytest.mark.parametrize("bad,error", [(0, ValueError), (True, TypeError), (1.2, TypeError)])
def test_invalid_min_history(bad, error):
    with pytest.raises(error, match="min_history"):
        correlate([], min_history=bad)
