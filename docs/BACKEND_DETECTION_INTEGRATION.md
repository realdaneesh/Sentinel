# Backend to Detection Engine Integration Contract

**Component:** Person B (Tanish) Backend Integration Adapter  
**Target:** Person A (Daneesh) Threat Detection Engine  
**Contract Version:** 1.0.0  

---

## 1. Overview

This document specifies the interface contract between the Sentinel backend ingestion pipeline and Daneesh's offline threat detection modules (`services/detection/rules.py`, `services/detection/risk_scoring.py`, and `services/detection/incident_correlation.py`).

The detection engine is pure, deterministic, and memory-only. The backend adapter (`backend/services/detection_adapter.py`) manages all state retrieval, context preparation, rule invocation, and result persistence without altering the underlying detection algorithms.

---

## 2. Ingestion to Detection Workflow

Before validation or persistence, each HTTP ingestion route authenticates a
source-bound producer key from `X-Sentinel-Producer-Key`. User JWTs do not
authorize ingestion. See [SECURITY.md](SECURITY.md) for local provisioning and
revocation. The offline detector is independent of HTTP authentication.

```
[Inbound Login Event]
        │
        ▼
1. Validate & Normalize (Pydantic v1 Event Schema)
        │
        ▼
2. Persist to Database (login_events table, status="pending")
        │
        ▼
3. Detection Adapter Invocation
        ├── Load All Eligible Events for Exact Identity
        ├── Build Prior-Success Baselines from Full History
        │
        ├── Step 3A: Invoke detect_failed_login_burst(...)
        │
        ├── Step 3B: (If LOGIN_SUCCESS) Invoke detect_unfamiliar_login_event(...)
        │
        ├── Step 3C: Aggregate Signals & Invoke score_risk(signals)
        │
        └── Step 3D: Correlate Incidents with correlate_incidents(...)
        │
        ▼
4. Persistence & Dispatch
        ├── Update LoginEvent (status="evaluated", detection_result=envelope)
        ├── Persist Correlated Incidents & Associate Contributing Events
        └── Auto-generate Alerts for HIGH/CRITICAL Severities
        │
        ▼
[Return Response / Expose via REST APIs]
```

---

## 3. Interface Specifications

### A. Burst Detection Adapter (`detect_failed_login_burst`)
- **Source Module:** `services.detection.rules`
- **Adapter Function:** Queries all events for `user_id` where `timestamp >= event.timestamp - 15 minutes` and `timestamp <= event.timestamp`.
- **Adapted Input Format:**
  ```python
  {
      "identity": str,        # event.user_id
      "event_type": str,      # "LOGIN_FAILURE" or "LOGIN_SUCCESS"
      "timestamp": datetime,  # timezone-aware UTC datetime
  }
  ```
- **Rule Threshold:** 5 failures within 15 minutes triggers `"failed_login_burst"`.

### B. Unfamiliar Novelty Adapter (`detect_unfamiliar_login_event`)
- **Source Module:** `services.detection.rules`
- **Adapter Function:** If `event_type == "LOGIN_SUCCESS"`, queries prior successful logins for `user_id` with `timestamp < event.timestamp`.
- **Baseline Requirement:** At least `min_history` (default 1) prior successes with `device_id` or `ip_address`.
- **Triggered Signals:** `"unfamiliar_device"`, `"unfamiliar_ip"`.

### C. Signal Risk Scorer (`score_risk`)
- **Source Module:** `services.detection.risk_scoring`
- **Input:** Unique list of triggered signal strings.
- **Output:**
  - `risk_score`: 0 to 100.
  - `severity`: `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"`.
  - `reasons`: Contribution list explaining score breakdown.

### D. Incident Correlation Engine (`correlate_incidents`)
- **Source Module:** `services.detection.incident_correlation`
- **Input:** Wire-format v1 event mappings for the identity across all eligible history.
- **Output:** Offline incident mappings with evidence-dependent SHA-256 fingerprints, contributing event IDs, risk scores, and combined explanations.
- **Persistence:** Matched to stable database incidents, linked through `incident_events`, and recorded as `evidence_fingerprint`.

---

## 4. Error Handling & Reliability

- **Detection Failures:** An unhandled detection exception marks the accepted event as failed.
- **Auditability:** Detection envelopes store the configured detector version and scorer reasons.
- **Chronological Ordering:** Historical events are ordered by `(timestamp, event_id)`.

## 5. Task 008C persistent reconciliation

`backend.services.detection_adapter.reconcile_identity(db, user_id,
evaluation_time=aware_utc_datetime)` recomputes every event at or before that
processing-time reference for one exact, case-sensitive identity. It uses all
earlier successful logins for novelty baselines, without a 60-minute cutoff;
burst windows remain inclusive 15-minute windows. It then invokes the unchanged
offline `correlate_incidents()` over the full eligible identity history.

The offline `incident_id` is stored as `evidence_fingerprint`. A new database
incident receives an independent persistent `incident_id`. New offline episodes
are matched to current incidents of the same identity and type by the number of
shared contributing event IDs. Pairs are assigned greedily by descending overlap,
then existing creation time and ID, then fingerprint. No overlap creates a new
incident; this avoids merging separate episodes solely by identity or time.
Changes in the first failure, start time, or evidence fingerprint do not force a
new persistent ID when evidence still overlaps.

A matched incident receives current event links, score, severity, signals,
explanations, and time range. Its previous fingerprint and evidence snapshot are
appended to `evidence_history`. Investigation `status`, analyst `description`,
and existing alert acknowledgement remain unchanged. At most one alert is current
for an episode; severity and message update on escalation while acknowledgement
remains intact. Identical replay stops before reevaluation.

On merge, the strongest matching old incident retains its ID; displaced records
and alerts become historical (`is_current=false`) with `superseded_by_id` pointing
to the survivor. On split, the strongest matching child keeps the old ID; other
children get new IDs and `split_from_id`. Unmatched old records are marked
historical, retain analyst state and forensic event links, and remain available
by ID or with `include_historical=true` in list APIs. Current lists hide them by
default. A previously unsupported episode is not automatically resurrected as
the same persistent ID if it later reappears without a current overlap.

Event time is distinct from processing time. A newly accepted event after the
processing reference remains `pending` with a null result and cannot trigger an
incident or alert. `python -m backend.manage reevaluate-due --at <aware ISO time>`
is a local management command to process due events deterministically; omitting
`--at` uses current UTC time. `--identity` limits work to an exact identity. There
is no public reevaluation route or background scheduler. Late events trigger a
full recomputation of their identity at the current processing reference, with
no fixed reconciliation horizon. Previously eligible event results can change.

This correctness-first approach reads all events for the identity and runs
per-event windows and full correlation. It can become expensive for long histories
and should be optimized with proven equivalence tests. The database schema adds
incident fingerprint, current-state, lineage, and evidence-history columns plus
an alert current-state column. Existing databases need a reviewed migration and
backfill; `create_all` does not alter existing tables. Concurrent ingestion and
transaction failure paths remain Task 008D work; PostgreSQL is unverified.

