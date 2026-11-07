# Offline detection pipeline

`services.detection.pipeline.evaluate_events(events, *, evaluation_time, min_history=1)` accepts
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

The existing failed-login burst rule still handles its inclusive 15-minute window
and threshold. Successful logins do not contribute to that count; future events
and failures outside the window do not contribute either. The existing scorer
supplies all signal weights, reasons, and severity.

For `unfamiliar_device` and `unfamiliar_ip`, the detector selects each identity's
latest successful-login timestamp at or before `evaluation_time`. Every success at
that timestamp is a current login. Only strictly earlier successful logins for
the **same exact `user_id`** form the baseline. Failures, future events, and other
identities never establish a baseline. An identifier is unfamiliar when at least
one current login's identifier is absent from its earlier baseline. The two
identifiers are compared independently. IP literals are compared as addresses via
Python's `ipaddress` module, so equivalent IPv6 spellings match; the v1 payload
is not changed. Missing optional identifiers neither establish a baseline for
that identifier nor trigger its signal.

By default, each identifier needs **one earlier successful login containing that
identifier**. This lets the simulator's two-login scenarios trigger while keeping
a first observed login unscored for novelty. Set `min_history` to a positive
integer to require more earlier successful logins per identifier; booleans and
non-integers are rejected. The count is of unique events, not distinct identifier
values. The baseline has no age limit. Identical event-ID replays count once;
conflicting IDs reject the whole batch. Same-timestamp logins cannot establish
one another's baseline. If several current logins share the latest timestamp,
their novelty signals are combined in the identity summary. Event ordering has
no effect on the result.

Histories must include all relevant events for each identity; this offline
function cannot fetch missing events. A first-seen device or IP is a change
indicator, not evidence of malicious activity. Device IDs can be absent, rotated,
or unreliable, and IPs can change because of normal networks, proxies, or shared
addresses. The score is heuristic and the identity summary does not identify an
individual malicious event.
