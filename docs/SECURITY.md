# Security operations implemented in Task 008B

These commands operate locally against `DATABASE_URL`. Protect shell and database access. The
`SECRET_KEY` value must be explicitly configured, at least 32 UTF-8 bytes, varied, and stable
across restarts. The previous default and example placeholders are rejected. Only HS256 is
permitted. Set a randomly generated secret in an untracked `.env` or a secure environment
variable. Changing it invalidates existing JWTs. Do not put the key on a command line.
JWTs require `sub`, `iat`, and `exp`; the server verifies the HS256 signature and expiry.

## Accounts and roles

Public `POST /api/v1/auth/register` accepts username, optional email, and password, and
creates a viewer. A submitted `role` field is rejected with 422. Password hashes are stored
using bcrypt and omitted from all user API responses.

After configuring the database and signing key, create the first active administrator:

```powershell
.\.venv\Scripts\python.exe -m backend.manage bootstrap-admin --username sentinel_admin
```

The command prompts twice for the password. It refuses to create another admin while an
active admin exists. An authenticated administrator can promote or demote an existing user
with `PATCH /api/v1/auth/users/{user_id}/role`, JSON `{"role":"analyst"}` (also `viewer`
or `admin`), and `Authorization: Bearer <JWT>`. Viewers and analysts cannot use this route.
The final active administrator cannot be demoted. Changes are recorded in `audit_logs`.
Authorization checks reload the active user and role from the database on each request,
so old JWTs do not preserve revoked roles. Disabled or suspended users are rejected.

The final-admin count check is effective for sequential requests but is not serialized
across concurrent processes. Two administrators demoting each other at the same time
could both observe a count of two. A production migration must enforce this invariant
with a database-level serialized transaction or trigger, and the role update must use
that transaction. The same concurrency concern applies to simultaneous first-admin
bootstrap commands. Until then, perform these operations one at a time.

## Event producers

Producer keys are separate from user JWTs. Provision a key for one exact v1 `source`:

```powershell
.\.venv\Scripts\python.exe -m backend.manage provision-producer --name windows-agent-1 --source windows-agent-1
```

The command prints a producer ID and a random key once. Store the key in a secure secret
store and deliver it to the authorized agent or website backend. The database retains only
its SHA-256 digest; requests compare digests in constant time. Send
`X-Sentinel-Producer-Key: <key>` on `POST /events`, `POST /api/v1/events`, and
`POST /api/v1/events/login`. The JSON `source` must exactly match the source assigned to
the key. Missing, invalid, or revoked keys get 401; a source mismatch gets 403. The event
payload and its replay/conflict semantics remain the same after authentication.

Rotate or revoke by producer ID:

```powershell
.\.venv\Scripts\python.exe -m backend.manage rotate-producer --id <producer-id>
.\.venv\Scripts\python.exe -m backend.manage revoke-producer --id <producer-id>
```

Rotation invalidates the previous key for subsequent checks and prints the replacement
once. Revocation disables subsequent key checks. A request already authorized before a
concurrent rotation or revocation may still finish; ordered transaction handling belongs
to Task 008D. A wildcard test source is accepted only when
`ENVIRONMENT=testing`; normal provisioning requires an exact source.

## Simulator

`POST /api/v1/simulator/generate` requires an administrator JWT. It can generate
responses without persistence in any environment. `ingest=true` additionally requires
`ENVIRONMENT=development` or `testing` and `SIMULATOR_PERSISTENCE_ENABLED=true`.
Production denies API simulator persistence even if the flag is set. The offline
`python -m services.simulator` CLI is independent of API authentication and persistence.

## Existing database migration

Task 008B adds the `event_producers` table. A fresh SQLite database gets it at startup
through `Base.metadata.create_all`. Existing deployments need a reviewed migration that
creates `event_producers` before any producer keys can be provisioned. `create_all` can add
this table but is not a general schema migration mechanism. Existing historical public
ingestion credentials do not exist, so each legitimate producer must be provisioned.
No PostgreSQL migration or deployment has been verified.

## Remaining limits

The role and producer administration commands require secure local OS and database access.
Task 008C will address incident reconciliation. Task 008D will address concurrent replay,
transaction consistency, database failure mapping, and the database-level final-admin
invariant described above. Role changes and their audit rows use one commit, but bootstrap
account creation and its audit row use separate commits. Production readiness and PostgreSQL
compatibility remain unverified.
