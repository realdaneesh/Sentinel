# Proposed ingestion API contract

Status: design for Tanish's ingestion implementation; no FastAPI routes, database
code, or scoring pipeline are implemented here. Payload definitions are in
[EVENT_SCHEMA.md](EVENT_SCHEMA.md). API authentication/authorization must be agreed
separately before deployment; `source` is producer metadata, not an authorization
claim.

## POST /events

Accept `Content-Type: application/json` and exactly one authentication event
object per request (no batches). Require explicit `schema_version: "1.0"`.
Validate the entire event before attempting an insert. Do not coerce numbers to
strings, accept unknown fields, or trust the caller to have deduplicated.

For a new event, respond **201 Created** only after durable persistence:

```json
{"schema_version":"1.0","event_id":"evt-001","status":"accepted","detection_result":null}
```

Acceptance means stored, not scored or proven safe. Detection may run later.
`detection_result` stays null until result orchestration exists; subsequently it
may hold the envelope specified in EVENT_SCHEMA.md. A rule execution failure after
storage must not erase the accepted event. Future retry/queue behavior is backend
work and is not implemented here.

An identical retry returns **200 OK** with `status: "duplicate"`, the original
`event_id`, response `schema_version: "1.0"`, and `detection_result: null` until
orchestration exists. Do not insert a second event or dispatch detection again.
The request body's `event_id` is the idempotency key; no separate
`Idempotency-Key` header is defined. Enforce this with a database uniqueness
constraint and atomic conflict handling, including concurrent requests. Duplicate
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

## Integration guide for Tanish

1. Implement validation and atomic persistence against the event contract. Keep
   `user_id`, `timestamp`, and source metadata intact. Deduplicate before loading
   history for detection; the current rule counts each supplied row.
2. Fetch unique events for the exact user in the inclusive interval
   `[evaluation_time - 15 minutes, evaluation_time]`. Capture one aware UTC
   evaluation time. Include the newly accepted event once if it lies in that
   interval. Future events must not count. Late events outside this interval do
   not count for a current-time evaluation; historical replay requires an explicit
   historical evaluation time and the corresponding history.
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
   until scoring exists. Neither a triggered burst nor a non-triggered burst
   currently has a defined numerical score. No adapter or envelope generation
   has been added to production code in this change.
5. Run `python -m pytest -q` from the repository root. Contract fixture validation
   uses only the standard library plus the existing pytest dependency. The adapter
   integration test verifies compatibility with the unchanged detector. Backend
   concurrency, HTTP errors, and storage guarantees still need implementation
   and integration tests in Tanish's work.
