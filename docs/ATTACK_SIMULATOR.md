# Offline authentication attack simulator

`services/simulator/` generates **synthetic authentication events only** using
the Python standard library. It does not attempt authentication, collect
credentials, send network requests, or import FastAPI, database, detector, or
scorer modules. It generates data in memory and writes a local file only when
the CLI receives an explicit `--output` path.

Every event follows [EVENT_SCHEMA.md](EVENT_SCHEMA.md) v1 exactly. The source is
`sentinel-simulator`; identities and devices have `synthetic-` prefixes. All IPs
come from `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`, using host
numbers 1 through 254. No actual accounts or identity inventory are consulted.

## Scenarios

| Name | Default count | Behavior |
| --- | --- | --- |
| `normal_activity` | 12 | Successful logins over one hour, cycling through up to three synthetic identities with stable devices and IPs; minimum two events ensures multiple identities. |
| `failed_login_burst` | 5 | Failures for one synthetic identity, evenly spaced across the inclusive 15-minute interval ending at the reference time; minimum five events. |
| `unfamiliar_device` | 2 | A successful baseline login five minutes before the reference time, followed by a successful login for the same identity and IP with a changed device ID. |
| `unfamiliar_ip` | 2 | A successful baseline login five minutes before the reference time, followed by a successful login for the same identity and device with a changed documentation-range IP. |

All outputs are chronological and end at the reference time. Normal and burst
counts are configurable up to 10,000 to bound in-memory generation. Unfamiliar
scenarios always contain exactly two events; `--count 2` is accepted, and other
counts are rejected. Counts include the baseline event.

The v1 wire schema has no baseline relationship fields. For each unfamiliar
scenario, **array index 0 (JSONL line 1) is the baseline; index 1 (line 2) is the
changed login**. This ordering convention is simulator documentation, not a new
wire field. Keep the selected scenario and command alongside exported fixtures
when interpreting them later. The export contains only authentication events,
with no scenario labels, baseline IDs, signals, scores, or result envelopes.

The offline detector in `services/detection/pipeline.py` recognizes each pair
with its default one-login baseline requirement when evaluated at the reference
time. Raising `min_history` above one makes these two-event scenarios
insufficient to trigger novelty. The exported records themselves contain no
signals or scores; a first-seen identifier does not establish malicious activity.
An unfamiliar scenario alone contains no failed-login burst and therefore creates
no correlated incident. To exercise correlation, combine a burst fixture with
an unfamiliar fixture for the same synthetic identity and compatible timestamps;
see [INCIDENT_CORRELATION.md](INCIDENT_CORRELATION.md).

## CLI usage

Run from the repository root. `--scenario`, `--seed`, and `--output` are required.
The fixed default reference time is `2026-11-04T12:00:00Z`, independent of the
machine clock. Use `--reference-time` to select a different fixed UTC instant.

```sh
python -m services.simulator --scenario normal_activity --seed 42 --count 12 --output normal.json
python -m services.simulator --scenario failed_login_burst --seed 42 --count 8 --reference-time 2026-11-04T12:00:00Z --format jsonl --output burst.jsonl
python -m services.simulator --scenario unfamiliar_device --seed 42 --output device.json
python -m services.simulator --scenario unfamiliar_ip --seed 42 --output ip.json
python -m services.simulator --scenario normal_activity --seed 42 --output normal.json --overwrite
python -m services.simulator --help
```

Use a local filesystem location with an existing parent directory. URLs and UNC
paths are rejected; the caller must also avoid network-mounted locations. No
directories are created automatically. Exclusive file creation protects existing
files unless `--overwrite` is explicitly supplied. Validation and serialization
finish before opening the file. An OS failure during writing can leave partial
output; exports are not transactional.

`--format json` (the default) produces an array of event objects; `--format jsonl`
produces one object per line. The extension does not select the format. Both use
UTF-8, stable key ordering, LF newlines, and a final newline. Events are never
printed to stdout. Success exits with status 0; invalid arguments, protected
existing files, and file I/O errors report to stderr and exit with status 2.

CLI reference times accept the contract's UTC ISO 8601 syntax, with `Z` or
`+00:00` and optional 1-6 fractional digits. Invalid dates, naive timestamps,
nonzero offsets, noninteger seeds/counts, and out-of-range counts are rejected.
Seeds may be any integer, including zero and negative values.

## Python usage and determinism

```python
from datetime import datetime, timezone
from services.simulator import generate_events

reference_time = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
events = generate_events(
    "failed_login_burst", seed=42, reference_time=reference_time, count=8,
)
```

The Python API requires an explicit integer seed and accepts an aware datetime;
aware non-UTC offsets are normalized to UTC. The CLI is stricter and requires a
UTC string. Booleans are not accepted as seeds or counts. Date ranges that would
underflow during generation are rejected. Each call returns fresh dictionaries.

A private seeded random generator creates synthetic profiles without changing
global random state. Identical effective scenario, seed, count, and normalized
reference time reproduce identical events and IDs for this implementation and
Python runtime. No current-time reads or nondeterministic UUIDs are used.

Event IDs use namespaced UUID5 values derived from the generator version,
scenario, seed, effective count, event position, and full event content. IDs are
unique within a generated set, and different generation inputs produce distinct
IDs subject to the usual UUID collision limits. Identical runs intentionally
reuse IDs: ingesting them again would be an idempotent replay, not a fresh batch.
Choose a different seed or reference time for a separate dataset. Changes to
generator behavior or Python's pseudorandom implementation may change output;
retain the code/runtime version when archiving reproducible fixtures.

## Detector compatibility and integration assumptions

The CLI does not ingest events or run detection/scoring. A JSON array or JSONL
file is an offline fixture, not a batch request body for the proposed
`POST /events` endpoint, which accepts one event per request. Ingestion,
persistence, deduplication, and result orchestration remain separate work; see
[API_CONTRACTS.md](API_CONTRACTS.md) and [RISK_SCORING.md](RISK_SCORING.md).

For a local burst evaluation, adapt the wire records as documented by the API
contract and explicitly use the generation reference time:

```python
from datetime import datetime
from services.detection.rules import detect_failed_login_burst

# events and reference_time come from the Python example above.
adapted = [
    {
        "identity": event["user_id"],
        "event_type": event["event_type"],
        "timestamp": datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
    }
    for event in events
]
result = detect_failed_login_burst(adapted, events[0]["user_id"], now=reference_time)
assert result["triggered"] is True
assert result["failed_attempts"] == 8
```

The existing detector expects `identity` and aware Python datetimes, not raw
wire events. Using its default current-time evaluation could exclude historical
fixtures or future events. Deduplicate replayed IDs before detection in any
future integration: the existing rule counts every supplied row. No existing
detector or scorer behavior is modified by this simulator.

## Verification

```sh
python -m pytest -q -p no:cacheprovider
git diff --check
```

Tests exercise the existing reference contract validator, unique IDs and replay
stability, UTC timestamps, reserved IPs, scenario invariants, detector adaptation,
CLI subprocess execution, JSON/JSONL byte reproducibility, overwrite protection,
and invalid inputs. They require only the existing pytest dependency.
