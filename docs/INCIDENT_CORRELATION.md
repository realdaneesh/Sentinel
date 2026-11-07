# Offline incident correlation

`services.detection.incident_correlation.correlate_incidents(events, *,
evaluation_time, correlation_window=timedelta(minutes=15), min_history=1)`
accepts an in-memory iterable of v1 authentication events and returns a list of
incident dictionaries. `evaluation_time` is required and timezone-aware. The
function reads no clock or external state and does not mutate its inputs.

```python
from datetime import datetime, timezone
from services.detection.incident_correlation import correlate_incidents

evaluation_time = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
incidents = correlate_incidents(events, evaluation_time=evaluation_time)
```

The engine uses the pipeline's v1 validation and event-ID replay semantics.
Identical IDs count once, including equivalent `Z` and `+00:00` timestamp
spellings; a conflicting ID rejects the whole batch. Future events are ignored
after validation. All comparisons use UTC instants and exact, case-sensitive
`user_id` values. An empty batch or a batch without a qualifying sequence
returns `[]`.

## Correlation policy

1. For each identity, group failures by timestamp and apply the existing
   `detect_failed_login_burst` rule at each failure timestamp. A burst episode
   begins when its inclusive 15-minute rolling count first reaches five. Later
   above-threshold failure groups stay in that episode. Before each new failure
   timestamp, the rule is also checked without that timestamp's failures: if
   the prior rolling count has fallen below five, the old episode ends. This
   catches quiet gaps and partial expiry even when the next timestamp has five
   failures at once. A new threshold crossing starts another episode.
   Same-timestamp failures count together.
2. Evaluate **each** successful login with
   `detect_unfamiliar_login_event`, using strictly earlier successful logins of
   the same identity as its device and IP baselines. This helper uses the same
   comparison logic and `min_history` requirement as the identity-level rule.
   Missing optional identifiers do not trigger novelty. A first observed login
   has insufficient history. IP literals are compared as addresses.
3. A success with an unfamiliar device or IP matches the latest burst
   observation strictly before its timestamp when the elapsed time is at most
   `correlation_window`. The default is 15 minutes. Equality at the upper
   boundary is included; a success at the *same* timestamp as the burst
   observation does not establish that it followed the failures and is excluded.
   Zero and positive `timedelta` values are accepted; negative values are
   rejected. A later failure cannot support an earlier success.
4. Each success attaches to at most one episode, and each episode produces at
   most one incident. If several unfamiliar successes follow one episode, their
   evidence and distinct signals are combined. The evidence contains the
   rolling failure window for each matched burst observation and the matched
   successful logins. Earlier baseline successes are context, not contributing
   incident events. Incident time range spans the contributing events.

The existing scorer assigns weights and severity to the distinct signals:
`failed_login_burst` plus whichever of `unfamiliar_device` and `unfamiliar_ip`
occurred. The defaults yield 55/HIGH for a burst plus one novelty signal, and
75/CRITICAL for all three. These are heuristic risk scores, not probabilities.

## Incident dictionary

This is an **offline incident summary**, separate from the v1 authentication
event and per-event detection-result contracts. No API or database format is
introduced.

| Field | Meaning |
| --- | --- |
| `incident_id` | `inc-` plus SHA-256 hex digest of canonical incident data |
| `identity` | Exact `user_id` |
| `incident_type` | `failed_login_burst_followed_by_unfamiliar_login` |
| `start_time`, `end_time` | Earliest and latest contributing event timestamps, UTC ISO 8601 with `Z` |
| `contributing_event_ids` | Unique IDs ordered by UTC timestamp, then ID |
| `signals` | Sorted distinct normalized signal names from the scorer |
| `risk_score`, `severity` | Existing scorer's score and severity |
| `explanations` | Burst evidence, matched successful logins, novelty reasons, then scorer reasons |
| `scorer_version` | Existing scorer's implementation version |

The incident ID hashes a compact UTF-8 JSON array containing incident type,
identity, start and end times, ordered contributing IDs, and sorted signals.
The same validated batch, regardless of input order, replay copies, or equivalent
UTC spellings, produces the same IDs and incident order. Adding or removing
contributing evidence can change an incident ID; this offline function does not
maintain persistent incident identity across changing datasets.

## Limits

`evaluate_events()` intentionally keeps its existing identity-level output and
checks novelty only at the latest successful-login timestamp. That summary can
miss an earlier unfamiliar success followed by a later known success. Incident
correlation uses the separately tested event-level helper so it can find the
earlier sequence without changing the summary contract.

The supplied batch must contain the relevant baseline, failures, and successes;
the engine cannot fetch omitted history. Its burst episodes are based on
observed threshold crossings, so incomplete history can change grouping. A
first-seen device or IP may reflect normal device rotation or network changes.
Even a correlated incident is suspicious activity for review, **not confirmed
account compromise**. No geolocation, threat intelligence, or behavioral model
is used.
