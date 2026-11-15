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
        ├── Query Rolling 15-Min History for Identity
        ├── Query Historical Success Baselines for Identity
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
- **Input:** Wire-format v1 event mappings for the identity within the recent evaluation window.
- **Output:** List of `Incident` records with SHA-256 deterministic IDs, contributing event IDs, risk scores, and combined explanations.
- **Persistence:** Saved to `incidents` table and linked through `incident_events` junction table.

---

## 4. Error Handling & Reliability

- **Detection Failures:** Any unhandled exception during detection sets `event.detection_status = "failed"` without rolling back or deleting the accepted event.
- **Auditability:** Detection envelopes store `detector_version: "1.0.0"` and `scorer_version: "1.0.0"`.
- **Chronological Ordering:** Historical context queries are ordered by `(timestamp, event_id)` to ensure deterministic evaluation.

