# Deterministic risk scoring

`services/detection/risk_scoring.py` provides the standalone, pure-Python
`score_risk(signals, *, weights=None)` function. It accepts normalized signal
identifiers, not authentication events or rule-result dictionaries. It performs
no I/O, detection, clock reads, or persistence and adds no dependencies.

| Signal | Default points | Producer status |
| --- | --- | --- |
| `failed_login_burst` | 35 | Existing rule; orchestration must check `triggered` |
| `unfamiliar_device` | 20 | Future detector |
| `unusual_login_hour` | 15 | Future detector |
| `unfamiliar_ip` | 20 | Future detector |

```python
from services.detection.risk_scoring import score_risk

result = score_risk(["unfamiliar_ip", "failed_login_burst", "unfamiliar_ip"])
# {
#     "risk_score": 55,
#     "severity": "HIGH",
#     "reasons": [
#         "failed_login_burst: +35 risk points.",
#         "unfamiliar_ip: +20 risk points.",
#     ],
#     "triggered_signals": ["failed_login_burst", "unfamiliar_ip"],
#     "scorer_version": "1.0.0",
# }
```

Each distinct signal contributes once. Signals and corresponding contribution
reasons are sorted lexicographically, independent of input order. The integer
score is the sum capped at 100; a final reason explains capping when the sum
exceeds 100. Reasons show contributions before capping. Severity uses the capped
score: **LOW** 0–24, **MEDIUM** 25–49, **HIGH** 50–74, **CRITICAL** 75–100.
Empty input returns 0/LOW with empty reasons and signals. This means no supplied
signals contributed points, not that an event is safe or all detectors ran.

## Configuration and validation

`weights` is an optional mapping of partial overrides. For example,
`score_risk(["failed_login_burst"], weights={"failed_login_burst": 50})`
returns 50/HIGH. Omitted keys retain defaults; `None` or `{}` uses all defaults.
Defaults are exposed as the immutable `DEFAULT_WEIGHTS` mapping. Inputs are not
modified and each result has fresh lists. A supplied iterator is consumed once.

- Accept finite iterables of string identifiers, including lists, tuples, sets,
  and generators. Reject bare strings, bytes, bytearrays, mappings, and
  non-iterables with `TypeError`. Non-string elements also raise `TypeError`.
- Identifiers must match exactly; no trimming, case folding, or coercion occurs.
  Unknown identifiers (including empty strings) raise `ValueError`.
- Overrides must be mappings with known string keys and built-in integer values
  from 0 to 100 inclusive. Booleans, floats (including NaN/infinity), and other
  non-integers raise `TypeError`; out-of-range integers raise `ValueError`.
  Every override is validated, even for signals absent from the input.
- Zero-weight signals remain in `triggered_signals` and have a zero-point reason.
  Configuration cannot introduce new signal identifiers.

## Future event-level integration

`ScoringResult` is an internal summary, **not** the full detection-result
contract in [EVENT_SCHEMA.md](EVENT_SCHEMA.md). It has no `event_id`,
`schema_version`, or `detector_version`. The scorer never invents those values.
An orchestrator must retain the accepted event's ID, scope evidence to that
event/identity, and pass only signals whose producers actually triggered:

```python
# Future orchestration sketch, not an implemented ingestion pipeline.
signals = [rule_result["rule_id"]] if rule_result["triggered"] else []
scored = score_risk(signals)
envelope = {
    "schema_version": "1.0",
    "event_id": accepted_event["event_id"],
    "risk_score": scored["risk_score"],
    "severity": scored["severity"],
    "reasons": scored["reasons"],
    "detector_version": configured_pipeline_version,
}
```

The v1 envelope rejects extra fields, so do not spread the scoring dictionary
into it. Retain `triggered_signals` and `scorer_version` as internal metadata.
`scorer_version` identifies scoring behavior/defaults, not the complete detector
pipeline or custom configuration. Record effective weights alongside that
version for reproducible audits; `detector_version` must truthfully identify the
orchestrated implementation. Preserve rule evidence separately or append its
explanation to envelope reasons. The existing rule remains unchanged.

No ingestion adapter or result orchestration is implemented here. API
`detection_result` remains null until orchestration exists; pending scoring uses
null/UNKNOWN, not an empty-input score. See [API_CONTRACTS.md](API_CONTRACTS.md).
Only the failed-login burst producer currently exists. The other accepted names
reserve inputs for future detectors and do not imply those checks ran.

These additive weights are an explicit heuristic, not a calibrated probability
or an ML model. Scores do not account for signal correlations, frequency beyond
presence, missing evidence, or time decay. Identical signals and effective
weights produce identical results; changing configuration can change severity.
