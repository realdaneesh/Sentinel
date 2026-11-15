# Sentinel — AI-Powered Identity Threat Detection Platform

Sentinel monitors authentication activity in real time, ingests structured login events, evaluates threats using deterministic rules and explainable heuristic risk scoring, correlates multi-stage attack episodes into security incidents, and dispatches prioritized alerts to security analysts.

## Engineering Collaboration

- **Person A (Daneesh):** Threat Detection Engine, Risk Scoring, Incident Correlation, Attack Simulator.
- **Person B (Tanish):** Backend Application Architecture, Persistent Storage, REST APIs, Detection Adapter, RBAC Security, System Integration.

---

## Architecture & Technology Stack

- **Backend Framework:** FastAPI + Starlette (ASGI)
- **Database & Persistence:** SQLAlchemy 2.0 ORM with SQLite for local development; PostgreSQL requires the optional driver and separate verification
- **Authentication & RBAC:** PyJWT (HS256) + Salted Bcrypt
- **Data Validation:** Pydantic v2 (Strict Schema Contracts)
- **Testing:** Pytest; run the full suite using the pinned development dependencies

---

## Windows PowerShell development setup

From the repository root, use Python 3.14 and the project virtual environment:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -c constraints.lock
.\.venv\Scripts\python.exe -m pip check
```

For a local SQLite instance, copy the example configuration, keep `ENVIRONMENT=development` and `DATABASE_URL=sqlite:///./sentinel.db`, and replace the intentionally invalid `SECRET_KEY` placeholder in `.env` with a stable, randomly generated value. The application creates SQLite tables at startup. Keep `.env` and `sentinel.db` outside version control.

```powershell
Copy-Item .env.example .env
$secret = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
(Get-Content .env) -replace '^SECRET_KEY=.*$', "SECRET_KEY=$secret" | Set-Content .env
Remove-Variable secret
$env:DEBUG = 'true' # Override a conflicting machine-level DEBUG value if present.
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The health endpoint is `http://127.0.0.1:8000/health`; interactive API documentation is at `/docs`. Use only synthetic authentication data and bind development servers to loopback. Before using protected endpoints, create the first administrator locally and provision a source-bound event producer as described in [Security operations](docs/SECURITY.md).

Run tests from the repository root with a writable pytest temporary directory:

```powershell
$env:DEBUG = 'true'
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=.\sentinel-pytest
```

`requirements.txt` contains runtime packages; `requirements-dev.txt` adds test packages; `requirements-postgres.txt` adds the optional PostgreSQL driver. `constraints.lock` pins the resolved development environment. For PostgreSQL installation, use `-r requirements-postgres.txt -c constraints.lock`; this does not create or connect to a database.

---

## API Summary

- **Authentication (`/api/v1/auth`):** viewer-only public registration, login, profile, admin-only user listing and role management
- **Ingestion (`/api/v1/events` & root `/events`):** source-bound producer key required for all POST routes; protected event queries and filtering
- **Incidents (`/api/v1/incidents`):** List incidents, retrieve details with contributing event traces, update investigation status (`open`, `investigating`, `resolved`, `false_positive`)
- **Alerts (`/api/v1/alerts`):** Prioritized security alerts, acknowledgement workflow (`is_acknowledged`, `acknowledged_by`)
- **Simulator (`/api/v1/simulator`):** admin-only `/generate`; API persistence also requires explicit development or testing enablement. The offline CLI needs no API credentials.

## Detection reevaluation

Future-dated events are accepted as pending. A local administrator can process
eligible events at the current UTC time, or supply an explicit aware ISO time for
deterministic replay:

```powershell
.\.venv\Scripts\python.exe -m backend.manage reevaluate-due
.\.venv\Scripts\python.exe -m backend.manage reevaluate-due --at 2026-11-15T12:00:00Z --identity synthetic-user
```

The command is local and has no HTTP route. Late events automatically recompute
their exact identity. Incident and alert lists show current records by default;
`include_historical=true` includes superseded records. Existing databases require
a reviewed schema migration before running Task 008C code. See
[backend detection integration](docs/BACKEND_DETECTION_INTEGRATION.md).

---

## Documentation Links

- [System Architecture & Schema Guide](docs/ARCHITECTURE.md)
- [Backend to Detection Engine Integration Contract](docs/BACKEND_DETECTION_INTEGRATION.md)
- [Final Handover Report](docs/HANDOVER_REPORT.md)
- [Authentication Event Contract v1](docs/EVENT_SCHEMA.md)
- [Proposed Ingestion API Contract](docs/API_CONTRACTS.md)
- [Offline Detection Pipeline](docs/DETECTION_PIPELINE.md)
- [Offline Incident Correlation](docs/INCIDENT_CORRELATION.md)
- [Deterministic Risk Scoring](docs/RISK_SCORING.md)
- [Authentication Attack Simulator](docs/ATTACK_SIMULATOR.md)
