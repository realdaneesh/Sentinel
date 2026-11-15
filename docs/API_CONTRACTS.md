# Proposed ingestion API contract

Status: v1 payload and response contract, now implemented by the backend. Payload
definitions are in [EVENT_SCHEMA.md](EVENT_SCHEMA.md). Task 008B adds producer
authentication to every HTTP ingestion route. `source` is metadata checked against
the authenticated producer's assigned source, never a credential.
Task 008D implements event-ID-targeted concurrent replay and strict duplicate-key
and optional-null validation. See
[database migrations and transactions](DATABASE_MIGRATIONS_AND_TRANSACTIONS.md)
for the transaction and recovery policy.

## Authentication added in Task 008B

`POST /events`, `POST /api/v1/events`, and `POST /api/v1/events/login` require
`X-Sentinel-Producer-Key: <provisioned key>`. These keys are separate from user JWTs.
Missing, invalid, or revoked keys return 401 before ingestion; a valid key for
another `source` returns 403. Neither condition persists an event or runs detection.
See [SECURITY.md](SECURITY.md) for provisioning, rotation, and revocation. The v1
event JSON and authorized replay/conflict behavior are unchanged.

## Processing changes in Task 008C

Task 008C accepts future-dated v1 events but leaves them with
`detection_result: null` and persisted `detection_status: pending` until a later
explicit processing time. Authorized ingestion of late events reevaluates the
affected exact identity. The local `reevaluate-due` command can advance pending
events without an HTTP endpoint. Incident and alert list endpoints now default to
current records and accept `include_historical=true`; detail endpoints can still
retrieve historical records by ID. These are backend orchestration changes, not
changes to the v1 event payload or replay/conflict keys.

## POST /events

Accept `Content-Type: application/json` and exactly one authentication event
object per request (no batches). Require explicit `schema_version: "1.0"`.
Validate the entire event before attempting an insert. Do not coerce numbers to
strings, accept unknown fields, or trust the caller to have deduplicated.

For a new event, respond **201 Created** only after durable persistence:

```json
{"schema_version":"1.0","event_id":"evt-001","status":"accepted","detection_result":null}
```

Acceptance means stored, not scored or proven safe. Eligible events normally
receive the detection envelope specified in EVENT_SCHEMA.md in this response.
Future-dated events retain a null result until reevaluation. A rule execution
failure after storage does not erase the accepted event; the stored event is
`failed` or remains `pending` if failure-status persistence also fails. Local
`reevaluate-due` retries either state. Automatic queue processing is not implemented.
The POST response confirms durable acceptance: a non-null `detection_result`
means detection completed, while null means deferred or failed processing.
An authorized viewer or analyst can query `GET /api/v1/events/{event_id}` and
read `detection_status` (`pending`, `evaluated`, or `failed`) to distinguish those
states. Producer keys alone do not authorize that read.

An identical retry returns **200 OK** with `status: "duplicate"`, the original
`event_id`, response `schema_version: "1.0"`, and the currently stored
`detection_result` (possibly null). Do not insert a second event or dispatch detection again.
The request body's `event_id` is the idempotency key; no separate
`Idempotency-Key` header is defined. Enforce this with a database uniqueness
constraint and event-ID-targeted conflict handling, including concurrent requests. Duplicate
comparison and retention semantics are specified in EVENT_SCHEMA.md.

An existing ID with a different validated payload returns **409 Conflict**:

```json
{"error":{"code":"EVENT_ID_CONFLICT","message":"event_id already exists with different content","details":[{"field":"event_id","code":"conflict"}]}}
```

Errors use the same `error` envelope, with a human-readable `message` and a
`details` array of `{ "field": "...", "code": "..." }` objects. Use `$` for
whole-body errors. Do not echo submitted secrets or full event contents.

| Status | error.code | Behavior |
| --- | --- | --- |
| 400 | INVALID_JSON | Malformed JSON, including duplicate object keys; no persistence |
| 415 | UNSUPPORTED_MEDIA_TYPE | Content type is not application/json; no persistence |
| 422 | VALIDATION_ERROR | Wrong JSON shape, missing/unknown fields, null optional field, invalid value, or unsupported version; no persistence |
| 409 | EVENT_ID_CONFLICT | Existing ID with different valid content; original event remains |
| 503 | STORAGE_UNAVAILABLE | Cannot confirm durable storage; retry with the same ID |

For example, a timestamp without a timezone returns **422**:

```json
{"error":{"code":"VALIDATION_ERROR","message":"Event validation failed","details":[{"field":"timestamp","code":"invalid_utc_timestamp"}]}}
```

Validation detail codes: `required`, `unknown_field`, `invalid_type`,
`invalid_value`, `unsupported_version`, `invalid_utc_timestamp`, and
`invalid_ip_address`. Error detail ordering is unspecified. A non-object body uses
`field: "$"` and `code: "invalid_type"`. Validation takes precedence over
duplicate/conflict lookup. Clients must branch on status/codes, not message text.

## Historical integration guidance

1. Validate and atomically persist the event contract. Keep `user_id`,
   `timestamp`, and source metadata intact. Deduplicate before loading history.
2. Read all eligible events for the exact user at a nondecreasing, aware UTC
   processing time. Build inclusive 15-minute burst windows per event and use
   all strictly earlier successes for novelty. Future events do not enter either
   input. Late events trigger full identity recomputation. Historical what-if
   analysis uses the offline engine and does not mutate persisted current state.
3. Adapt wire records to the existing function; do not pass raw JSON directly:

```python
from datetime import datetime, timezone
from services.detection.rules import detect_failed_login_burst

# validated_history contains parsed, validated event JSON objects for one user.
# accepted_event is the newly persisted event; history includes it at most once.
evaluation_time = datetime.now(timezone.utc)
adapted = [
    {
        "identity": record["user_id"],
        "event_type": record["event_type"],
        "timestamp": datetime.fromisoformat(
            record["timestamp"].replace("Z", "+00:00")
        ).astimezone(timezone.utc),
    }
    for record in validated_history
]
result = detect_failed_login_burst(
    adapted, accepted_event["user_id"], now=evaluation_time
)
```

Capture `evaluation_time` before querying history in a real implementation. The
example assumes timestamps have already passed strict contract validation;
`fromisoformat` alone is more permissive than this contract.

The actual signature is
`detect_failed_login_burst(events: Iterable[Mapping[str, object]], identity: str, *, now: datetime | None = None) -> RuleResult`.
Its default evaluation time is current UTC. It requires `identity` rather than
`user_id`, and aware Python datetime timestamps rather than ISO strings. It
accepts other aware offsets internally, while the wire contract requires UTC.
It ignores unrelated identities and non-LOGIN_FAILURE events. Five or more
failures trigger; both time boundaries are inclusive and successes do not reset
the count. It returns `{rule_id, triggered, failed_attempts, reason}` only.

4. Preserve this rule output as evidence. A future orchestrator can associate it
   with the accepted `event_id` and configured `detector_version`, using
   `reasons: [result["reason"]]`, `risk_score: null`, and `severity: "UNKNOWN"`
   while scoring is pending. The standalone [risk scorer](RISK_SCORING.md) accepts
   `failed_login_burst` only when this rule's `triggered` flag is true; it assigns
   35 points by default. A non-triggered rule supplies no signal. The scorer's
   result is internal and must be explicitly adapted into the event-level
   envelope. The backend now implements envelope generation; this paragraph retains
   the original offline detector integration guidance.
5. Run `python -m pytest -q` from the repository root. Contract fixture validation
   uses only the standard library plus the existing pytest dependency. The adapter
   integration test verifies compatibility with the unchanged detector. Backend
   concurrency, HTTP errors, and storage guarantees still need implementation
   and integration tests in Tanish's work.
