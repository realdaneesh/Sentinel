import ipaddress
import random
from datetime import datetime, timedelta, timezone

import pytest

from services.detection.rules import detect_failed_login_burst
from services.simulator import DEFAULT_REFERENCE_TIME, SCENARIOS, generate_events


NOW = datetime(2026, 11, 4, 12, 0, 0, 123456, tzinfo=timezone.utc)
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
))


def timestamps(events):
    return [datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) for event in events]


def adapt(events):
    return [
        {"identity": event["user_id"], "event_type": event["event_type"], "timestamp": stamp}
        for event, stamp in zip(events, timestamps(events))
    ]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_reproducibility_unique_ids_utc_and_synthetic_values(scenario):
    events = generate_events(scenario, seed=42, reference_time=NOW)
    assert events == generate_events(scenario, seed=42, reference_time=NOW)
    assert len({event["event_id"] for event in events}) == len(events)
    stamps = timestamps(events)
    assert stamps == sorted(stamps)
    assert stamps[-1] == NOW
    for event, stamp in zip(events, stamps):
        assert event["timestamp"].endswith("Z")
        assert stamp.utcoffset() == timedelta(0)
        assert event["user_id"].startswith("synthetic-user-")
        assert event["device_id"].startswith("synthetic-device-")
        assert any(ipaddress.ip_address(event["ip_address"]) in network for network in DOCUMENTATION_NETWORKS)


def test_ids_are_disjoint_across_scenarios_seeds_times_and_counts():
    seen = set()
    for scenario in SCENARIOS:
        for seed in (0, 1, -7):
            for now in (NOW, NOW + timedelta(seconds=1)):
                counts = (5, 10) if scenario == "failed_login_burst" else (
                    (2, 12) if scenario == "normal_activity" else (2,)
                )
                for count in counts:
                    ids = {event["event_id"] for event in generate_events(
                        scenario, seed=seed, reference_time=now, count=count,
                    )}
                    assert seen.isdisjoint(ids)
                    seen.update(ids)


def test_defaults_and_equivalent_timezones_reproduce_same_payloads():
    expected = generate_events("normal_activity", seed=1)
    offset = timezone(timedelta(hours=5, minutes=30))
    assert expected == generate_events(
        "normal_activity", seed=1, count=12,
        reference_time=DEFAULT_REFERENCE_TIME.astimezone(offset),
    )


def test_calls_do_not_change_global_random_state_or_share_mutable_results():
    state = random.getstate()
    events = generate_events("normal_activity", seed=1)
    assert random.getstate() == state
    expected_user = events[0]["user_id"]
    events[0]["user_id"] = "modified"
    assert events[3]["user_id"] == expected_user
    assert generate_events("normal_activity", seed=1)[0]["user_id"] == expected_user


@pytest.mark.parametrize("count", [2, 12, 10000])
def test_normal_activity_contains_multiple_stable_successful_identities(count):
    events = generate_events("normal_activity", seed=0, count=count, reference_time=NOW)
    assert len(events) == count
    assert len({event["user_id"] for event in events}) >= 2
    profiles = {}
    for event in events:
        assert event["event_type"] == "LOGIN_SUCCESS"
        profile = (event["device_id"], event["ip_address"])
        assert profiles.setdefault(event["user_id"], profile) == profile
    for user in profiles:
        assert detect_failed_login_burst(adapt(events), user, now=NOW)["triggered"] is False


@pytest.mark.parametrize("count", [5, 9, 10000])
def test_burst_is_within_window_and_compatible_with_unchanged_detector(count):
    events = generate_events("failed_login_burst", seed=17, reference_time=NOW, count=count)
    assert len(events) == count
    assert len({event["user_id"] for event in events}) == 1
    assert {event["event_type"] for event in events} == {"LOGIN_FAILURE"}
    stamps = timestamps(events)
    assert stamps[0] == NOW - timedelta(minutes=15)
    assert all(NOW - timedelta(minutes=15) <= stamp <= NOW for stamp in stamps)
    result = detect_failed_login_burst(adapt(events), events[0]["user_id"], now=NOW)
    assert result["triggered"] is True
    assert result["failed_attempts"] == count
    assert detect_failed_login_burst(adapt(events), "synthetic-other-user", now=NOW)["triggered"] is False


@pytest.mark.parametrize("scenario,changed", [
    ("unfamiliar_device", "device_id"), ("unfamiliar_ip", "ip_address"),
])
def test_unfamiliar_pair_changes_only_intended_attribute(scenario, changed):
    baseline, event = generate_events(scenario, seed=99, reference_time=NOW)
    assert baseline["event_type"] == event["event_type"] == "LOGIN_SUCCESS"
    assert timestamps([baseline, event]) == [NOW - timedelta(minutes=5), NOW]
    assert {key for key in baseline if baseline[key] != event[key]} == {
        "event_id", "timestamp", changed,
    }
    assert detect_failed_login_burst(adapt([baseline, event]), event["user_id"], now=NOW)["triggered"] is False


@pytest.mark.parametrize("seed", [True, 1.0, "1", None])
def test_invalid_seed_types(seed):
    with pytest.raises(TypeError, match="seed"):
        generate_events("normal_activity", seed=seed)


@pytest.mark.parametrize("count", [True, 2.0, "2"])
def test_invalid_count_types(count):
    with pytest.raises(TypeError, match="count"):
        generate_events("normal_activity", seed=1, count=count)


@pytest.mark.parametrize("scenario,count", [
    ("normal_activity", 0), ("normal_activity", 1), ("normal_activity", -1),
    ("normal_activity", 10001), ("failed_login_burst", 4),
    ("unfamiliar_device", 3), ("unfamiliar_ip", 1), ("unfamiliar_ip", 3),
])
def test_invalid_scenario_counts(scenario, count):
    with pytest.raises(ValueError):
        generate_events(scenario, seed=1, count=count)


@pytest.mark.parametrize("scenario,error", [("unknown", ValueError), ("NORMAL_ACTIVITY", ValueError), ([], TypeError)])
def test_invalid_scenarios(scenario, error):
    with pytest.raises(error):
        generate_events(scenario, seed=1)


@pytest.mark.parametrize("reference_time,error", [
    (None, TypeError), ("2026-11-04T12:00:00Z", TypeError),
    (NOW.replace(tzinfo=None), ValueError),
    (datetime.min.replace(tzinfo=timezone.utc), ValueError),
])
def test_invalid_reference_times(reference_time, error):
    with pytest.raises(error, match="reference_time"):
        generate_events("normal_activity", seed=1, reference_time=reference_time)
