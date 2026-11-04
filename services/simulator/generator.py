"""Deterministic, standard-library-only authentication scenario generation."""

import json
import random
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5


DEFAULT_REFERENCE_TIME = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
SCENARIOS = (
    "normal_activity", "failed_login_burst", "unfamiliar_device", "unfamiliar_ip",
)
MAX_EVENT_COUNT = 10_000
_DEFAULT_COUNTS = dict(zip(SCENARIOS, (12, 5, 2, 2)))


def generate_events(
    scenario: str,
    *,
    seed: int,
    reference_time: datetime = DEFAULT_REFERENCE_TIME,
    count: int | None = None,
) -> list[dict[str, str]]:
    """Return fresh v1 wire records in chronological order, ending at reference_time.

    Identical effective inputs reproduce IDs and payloads (intentional replay).
    Pair scenarios contain a baseline at index 0 and changed login at index 1.
    All times are converted to UTC; naive reference times are rejected.
    """
    if not isinstance(scenario, str):
        raise TypeError("scenario must be a string")
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario!r}")
    if type(seed) is not int:
        raise TypeError("seed must be an integer, excluding booleans")
    if not isinstance(reference_time, datetime):
        raise TypeError("reference_time must be a datetime")
    if reference_time.tzinfo is None or reference_time.utcoffset() is None:
        raise ValueError("reference_time must be timezone-aware")
    if count is None:
        count = _DEFAULT_COUNTS[scenario]
    if type(count) is not int:
        raise TypeError("count must be an integer, excluding booleans")
    minimum = 5 if scenario == "failed_login_burst" else 2
    if not minimum <= count <= MAX_EVENT_COUNT:
        raise ValueError(f"count must be between {minimum} and {MAX_EVENT_COUNT}")
    if scenario in ("unfamiliar_device", "unfamiliar_ip") and count != 2:
        raise ValueError("unfamiliar scenarios require exactly 2 events")

    span = timedelta(minutes={
        "normal_activity": 60, "failed_login_burst": 15,
        "unfamiliar_device": 5, "unfamiliar_ip": 5,
    }[scenario])
    try:
        reference_time = reference_time.astimezone(timezone.utc)
        start = reference_time - span
    except OverflowError:
        raise ValueError("reference_time is outside the supported scenario date range") from None

    # A private RNG avoids affecting callers' global random state or reading a clock.
    rng = random.Random(seed)
    profiles = [
        {
            "user_id": f"synthetic-user-{rng.getrandbits(128):032x}",
            "device_id": f"synthetic-device-{rng.getrandbits(128):032x}",
            "ip_address": f"{prefix}.{rng.randint(1, 254)}",
        }
        for prefix in ("192.0.2", "198.51.100", "203.0.113")
    ]
    events = []
    for index in range(count):
        profile = profiles[index % len(profiles) if scenario == "normal_activity" else 0]
        event = {
            "schema_version": "1.0",
            **profile,
            "event_type": "LOGIN_FAILURE" if scenario == "failed_login_burst" else "LOGIN_SUCCESS",
            "timestamp": (start + span * index / (count - 1)).isoformat().replace("+00:00", "Z"),
            "source": "sentinel-simulator",
        }
        if index == 1 and scenario == "unfamiliar_device":
            event["device_id"] = profile["device_id"] + "-changed"
        if index == 1 and scenario == "unfamiliar_ip":
            event["ip_address"] = profiles[1]["ip_address"]
        # Include the full payload and generation configuration so changed content
        # cannot reuse a replay ID. The index also distinguishes repeated payloads.
        identity = json.dumps(
            ["sentinel-simulator-v1", scenario, seed, count, index, event],
            sort_keys=True, separators=(",", ":"),
        )
        event["event_id"] = "sim-" + str(uuid5(NAMESPACE_URL, identity))
        events.append(event)
    return events
