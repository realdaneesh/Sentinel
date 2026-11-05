# Offline detection pipeline

`services.detection.pipeline.evaluate_events(events, *, evaluation_time)` accepts
an in-memory iterable of v1 authentication event mappings and a required aware
`datetime`. It returns a list of identity summaries sorted by exact `user_id`.
An empty batch returns `[]`. The function does not read the clock, mutate inputs,
access the network, or persist records.

```python
from datetime import datetime, timezone
from services.detection.pipeline import evaluate_events
from services.simulator import generate_events

now = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
events = generate_events("failed_login_burst", seed=42, reference_time=now)
results = evaluate_events(events, evaluation_time=now)
```

Each summary has `identity` (the exact `user_id`), `triggered_signals` (sorted
normalized signal names), `risk_score` (integer 0–100), `severity`,
`explanations` (the rule explanation followed by scorer contribution reasons),
`failed_attempts` (the rule's count in the inclusive 15-minute window), and
`scorer_version`. These are batch identity summaries, **not** the v1 per-event
detection-result envelope in `EVENT_SCHEMA.md`: there is no evaluated event ID or
truthful deployment `detector_version` to put in that envelope. A 0/LOW summary
means no implemented signal fired, not that an identity is safe.

All records are validated against the documented v1 field names, values, and UTC
timestamp syntax before evaluation. The adapter converts `user_id` to the rule's
`identity` and parses timestamps to aware UTC datetimes. Identical replays of an
`event_id` count once; `Z` and `+00:00` representations of the same instant are
equivalent. Any other difference for an existing ID, including optional-field
presence, raises `ValueError`. Invalid batches or evaluation times raise
`TypeError` or `ValueError`; no partial results are returned.

Only `failed_login_burst` can trigger. The existing rule handles the inclusive
window and threshold; the existing scorer supplies weights, reasons, and severity.
Successes, future events, and failures outside the window do not contribute to
the burst count. Histories must include all relevant events for each identity;
this offline function cannot fetch missing events. Unfamiliar-device and
unfamiliar-IP signals are not produced here.
