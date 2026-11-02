# Authentication event contract v1

Status: proposed shared contract. Ingestion, persistence, result orchestration,
and risk scoring are not implemented by this document. The existing failed-login
rule is implemented separately in `services/detection/rules.py`.

## Event JSON

One JSON object represents one authentication attempt. Field names and enum values
are case-sensitive. Unknown fields are rejected in v1; optional fields must be
omitted when unavailable, not set to null. No string coercion or whitespace trimming
is performed. All strings must have no leading/trailing whitespace.

| Field | Required | Constraints |
| --- | --- | --- |
| schema_version | yes | String, exactly `1.0` |
| event_id | yes | Stable, globally unique, producer-generated opaque string; 1–128 characters |
| user_id | yes | Stable identity string; 1–256 characters; do not use a display name |
| event_type | yes | `LOGIN_SUCCESS` or `LOGIN_FAILURE` |
| timestamp | yes | UTC-aware ISO 8601 string as defined below |
| ip_address | no | IPv4 or IPv6 literal; no hostname, port, CIDR, or zone ID |
| device_id | no | Opaque device identifier; 1–256 characters |
| source | yes | Producer identifier, e.g. `sentinel-simulator`; 1–64 characters |

`user_id` is compared exactly, including case. Producers must agree on the same
stable identity namespace; unrelated accounts must never share a `user_id`.
Identifiers are opaque and are not required to be UUIDs.

Timestamps use `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` or the equivalent `+00:00`
suffix, with 1–6 fractional digits when present. A real calendar date is required.
Naive timestamps, nonzero offsets, lowercase `z`, and leap seconds are rejected.
Consumers parse them into aware UTC `datetime` objects. Storage and responses
should serialize UTC with `Z`. Future timestamps are valid contract input, but
the current detector excludes them until the evaluation time reaches them.
Historical timestamps are also valid; ingestion time is not event time.

## Identity, duplicates, and versioning

Uniqueness is global across sources. The producer must retain the same `event_id`
when retrying. The ingestion layer must atomically enforce uniqueness before
events reach detection; the detector itself does not deduplicate.

Same ID and same validated payload is an idempotent replay. Same ID with any
different field is a conflict, never an update. Compare payloads after normalizing
timestamps to UTC instants (`Z`, `+00:00`, and equivalent fractional precision
compare equal); compare all other fields exactly, including optional-field
presence. JSON key order is irrelevant. Do not expire the uniqueness record while
the associated event is retained; after deletion, replay guarantees end.

Every payload carries `schema_version`. Only `1.0` is supported by this proposal.
Field/validation changes require a new declared version and explicit consumer
support; incompatible semantics require a major version. Do not infer versions or
silently drop unknown fields. Result schema versions are independent of detector
implementation versions.

## Detection result JSON

This is a proposed downstream result envelope, not the current rule return type.
It represents evaluation associated with one accepted event; context can include
other events for that identity. Optional fields are not defined in v1.

| Field | Required | Constraints |
| --- | --- | --- |
| schema_version | yes | String, exactly `1.0` |
| event_id | yes | Same ID as the event evaluated; same string constraints as above |
| risk_score | yes | Integer 0–100 (booleans excluded), or null while scoring is pending |
| severity | yes | `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| reasons | yes | Array of nonempty, trimmed strings, each at most 1024 characters; empty allowed |
| detector_version | yes | Nonempty, trimmed implementation identifier, at most 128 characters |

Risk scoring is a **future component**. Pending scoring must use `risk_score: null`
and `severity: "UNKNOWN"`, never a fabricated zero. A numeric score requires a
non-UNKNOWN severity. Severity bands and score calibration must be agreed before
the future scorer ships; v1 does not infer severity from the burst rule. `reasons`
can contain the actual rule explanation without implying a risk score. Fixtures
with numeric scores illustrate future envelope validation only.

The rule currently returns `rule_id`, `triggered`, `failed_attempts`, and singular
`reason`. It returns no event ID, score, severity, or detector version. A future
orchestrator must retain the triggering event ID, copy `reason` into `reasons`, and
supply a truthful configured implementation version (for example an immutable
release tag or commit identifier). Do not treat `rule_id` as an implementation
version. Until that orchestrator exists, API responses use `detection_result: null`.

See [API contracts](API_CONTRACTS.md) for the proposed HTTP behavior and the exact
adapter required by the existing detector. JSON examples live in
`tests/fixtures/contracts/`; their tests are reference checks, not runtime API
validation or a FastAPI implementation.
