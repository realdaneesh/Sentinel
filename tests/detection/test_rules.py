from datetime import datetime, timedelta, timezone

import pytest

from services.detection.rules import detect_failed_login_burst


NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def event(minutes_ago=1, *, identity="alice", event_type="LOGIN_FAILURE"):
    return {
        "identity": identity,
        "event_type": event_type,
        "timestamp": NOW - timedelta(minutes=minutes_ago),
    }


def evaluate(events):
    return detect_failed_login_burst(events, "alice", now=NOW)


def test_four_failures_do_not_trigger():
    result = evaluate([event(i) for i in range(4)])
    assert result == {
        "rule_id": "failed_login_burst",
        "triggered": False,
        "failed_attempts": 4,
        "reason": (
            "4 LOGIN_FAILURE events for identity 'alice' in the last 15 minutes; "
            "threshold of 5 not met."
        ),
    }


def test_exactly_five_failures_trigger():
    result = evaluate([event(i) for i in range(5)])
    assert result["triggered"] is True
    assert result["failed_attempts"] == 5
    assert "threshold of 5 met" in result["reason"]


def test_more_than_five_failures_returns_full_count():
    result = evaluate([event(i) for i in range(8)])
    assert result["triggered"] is True
    assert result["failed_attempts"] == 8


def test_events_outside_window_are_excluded():
    result = evaluate([event(i) for i in range(4)] + [event(15.001), event(60)])
    assert result["triggered"] is False
    assert result["failed_attempts"] == 4


def test_mixed_identities_are_counted_separately():
    events = [event(i) for i in range(4)] + [event(i, identity="bob") for i in range(5)]
    alice = evaluate(events)
    bob = detect_failed_login_burst(events, "bob", now=NOW)
    assert alice["triggered"] is False
    assert alice["failed_attempts"] == 4
    assert bob["triggered"] is True
    assert bob["failed_attempts"] == 5


def test_successful_logins_are_not_failures():
    result = evaluate([event(i, event_type="LOGIN_SUCCESS") for i in range(5)])
    assert result["triggered"] is False
    assert result["failed_attempts"] == 0


def test_successful_logins_do_not_reset_failure_count():
    events = [event(i) for i in range(1, 6)] + [event(0, event_type="LOGIN_SUCCESS")]
    assert evaluate(events)["failed_attempts"] == 5
    assert evaluate(events)["triggered"] is True


def test_future_events_are_excluded():
    result = evaluate([event(i) for i in range(4)] + [event(-0.001), event(-10)])
    assert result["triggered"] is False
    assert result["failed_attempts"] == 4


def test_window_includes_both_boundaries_with_unsorted_events():
    result = evaluate([event(15), event(3), event(0), event(14), event(7)])
    assert result["failed_attempts"] == 5
    assert result["triggered"] is True


def test_aware_offsets_are_normalized_to_utc():
    offset = timezone(timedelta(hours=5, minutes=30))
    events = [event(i) for i in range(5)]
    for item in events:
        item["timestamp"] = item["timestamp"].astimezone(offset)
    result = detect_failed_login_burst(events, "alice", now=NOW.astimezone(offset))
    assert result["failed_attempts"] == 5
    assert result["triggered"] is True


def test_empty_events():
    assert evaluate([])["failed_attempts"] == 0
    assert evaluate([])["triggered"] is False


def test_naive_evaluation_time_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        detect_failed_login_burst([], "alice", now=NOW.replace(tzinfo=None))


def test_naive_failure_timestamp_is_rejected():
    item = event()
    item["timestamp"] = NOW.replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate([item])


def test_non_datetime_timestamp_is_rejected():
    item = event()
    item["timestamp"] = "2026-11-02T12:00:00Z"
    with pytest.raises(TypeError, match="datetime objects"):
        evaluate([item])


@pytest.mark.parametrize("identity", ["", " ", None])
def test_missing_identity_is_rejected(identity):
    with pytest.raises(ValueError, match="non-empty string"):
        detect_failed_login_burst([], identity, now=NOW)
