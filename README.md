# Sentinel — AI-Powered Identity Threat Detection Platform

Sentinel monitors authentication activity in real time, ingests structured login events, evaluates threats using deterministic rules and explainable heuristic risk scoring, correlates multi-stage attack episodes into security incidents, and dispatches prioritized alerts to security analysts.

## Engineering Collaboration

- **Person A (Daneesh):** Threat Detection Engine, Risk Scoring, Incident Correlation, Attack Simulator.
- **Person B (Tanish):** Backend Application Architecture, Persistent Storage, REST APIs, Detection Adapter, RBAC Security, System Integration.

---

## Architecture & Technology Stack

- **Backend Framework:** FastAPI 0.115 + Starlette (Asynchronous ASGI)
- **Database & Persistence:** SQLAlchemy 2.0 ORM with SQLite (dev/test) & PostgreSQL (production-ready)
- **Authentication & RBAC:** PyJWT (HS256) + Salted Bcrypt
- **Data Validation:** Pydantic v2 (Strict Schema Contracts)
- **Testing:** Pytest 8.3 (322 tests passing)

---

## Quick Start Guide

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Start API Server
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
- Interactive Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Interactive ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 3. Run Test Suite
```bash
pytest Sentinel -o pythonpath=Sentinel
```

---

## API Summary

- **Authentication (`/api/v1/auth`):** `/register`, `/login`, `/me`, `/users` (admin-only)
- **Ingestion (`/api/v1/events` & root `/events`):** Strict v1 ingestion, `/events/login` convenience endpoint, `/events` query with filters & pagination
- **Incidents (`/api/v1/incidents`):** List incidents, retrieve details with contributing event traces, update investigation status (`open`, `investigating`, `resolved`, `false_positive`)
- **Alerts (`/api/v1/alerts`):** Prioritized security alerts, acknowledgement workflow (`is_acknowledged`, `acknowledged_by`)
- **Simulator (`/api/v1/simulator`):** `/generate` (synthetic offline scenarios: `failed_login_burst`, `normal_activity`, `unfamiliar_device`, `unfamiliar_ip`)

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
