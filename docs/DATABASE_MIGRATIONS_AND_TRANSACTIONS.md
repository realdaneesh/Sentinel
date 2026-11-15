# Database migrations and transaction boundaries

## Migration commands

Alembic revision `0001` records the original backend schema. Revision `0002`
adds the source-bound producer table and persistent incident/alert reconciliation
columns. Revision `0003` adds the exact-identity processing watermark and the
administrator guard. These migrations preserve existing primary keys, events,
analyst status and description, alert acknowledgement, users, and audit rows.
Legacy incident IDs are retained and copied into `evidence_fingerprint`; all
legacy incidents start as current with empty evidence history. For repeated
legacy alerts of the same incident and type, the newest by creation time and ID
is current and older rows remain historical, with acknowledgements intact. The
database enforces one current alert per incident/type and one current incident
per identity/type/evidence fingerprint through partial unique indexes. The
watermark for each identity with evaluated events is conservatively backfilled
to its latest evaluated event timestamp, since the old schema did not record
processing time.

For a **new, empty** SQLite database, configure a development-only signing
secret and run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m backend.migrate upgrade --database-url sqlite:///./sentinel.db
```

For an **unversioned original backend** database, first make and verify a
backup, then run:

```powershell
.\.venv\Scripts\python.exe -m backend.migrate adopt-original --database-url sqlite:///./sentinel.db
```

`adopt-original` checks the exact original table and column sets, primary keys,
and incident/alert foreign keys before stamping revision `0001`; it then upgrades
to head. A missing SQLite file is rejected without creating it. An unrecognized
or partially upgraded schema is rejected. Databases
already changed manually or by unversioned Task 008B/008C `create_all` are not a
supported automatic adoption path; review and migrate them separately. The API
refuses to start in development or production unless the revision is `0003` and
the expected tables, columns, and current-incident/alert uniqueness indexes are
present. A missing SQLite file is rejected before opening a connection.
`create_all` is used only for isolated test databases and does not upgrade tables.
Testing-mode API startup does not initialize the default database; tests create
their own isolated database fixtures.
Automatic downgrades are intentionally unsupported because they would discard
investigation or coordination state. PostgreSQL migration execution is unverified.

## Transactions and recovery

An authenticated event insert is Transaction A. An `event_id`-targeted
`ON CONFLICT DO NOTHING` makes concurrent replay race-safe. The winner commits
the accepted event; the loser reads its committed canonical hash and returns
`200 duplicate` or `409 EVENT_ID_CONFLICT`. Unrelated insert failures roll back
and return `503 STORAGE_UNAVAILABLE`. The original event is never overwritten.

Transaction B acquires the exact identity's database guard before reading
authoritative history. It recomputes eligible event results, incident evidence,
lineage, current alert state, and the processing watermark in one commit. A
failure rolls back all of Transaction B. A separate attempt marks the accepted
event `failed`; if that write also fails, the event remains `pending`. Both are
recoverable through local `reevaluate-due`. A `201 accepted` response may contain
a null detection result when processing failed or is deferred. An identical
replay returns stored state without triggering processing.

The guard is a row keyed by exact `user_id`. A targeted insert-if-absent and
version update obtain a SQLite write lock or PostgreSQL row lock before history
is read. Reconciliation and analyst incident/alert updates take that guard in
the same transaction. The administrator guard is a separate singleton row;
bootstrap and role changes take it before checking the active-admin invariant.
Analyst updates take the administrator guard first, recheck the actor's current
database role, then take the identity guard. This ordering prevents a concurrent
role change from invalidating authorization between the check and commit.
Bootstrap and its audit row share one commit, as do role changes, incident
updates, and alert acknowledgements with their audit rows. Application APIs
have no audit edit/delete route; database administrators can still change audit
data because no database-level append-only policy is implemented.

The per-identity watermark never decreases. A late event can still arrive with
an older event timestamp; processing uses the later of the requested evaluation
time and the stored watermark. Future events remain pending. The local
`reevaluate-due --at` command rejects a time later than current UTC and a time
before any selected identity's persisted watermark; it is for mutating due-event
processing. Historical what-if analysis must use the offline detector and must
not write current database state. Reevaluation commits each identity separately,
so a multi-identity command can partially complete and may safely be rerun.

SQLite tests use independent file-backed sessions to verify concurrent replay,
same-identity reconciliation, bootstrap, and final-admin demotion. SQLite
serializes writers broadly. PostgreSQL uses targeted row locking but has not
been exercised against an isolated server. Lock timeouts and persistent storage
outages can leave events pending for operator retry. This design does not provide
automatic background retries, PostgreSQL deployment guarantees, or a
database-level immutable audit log. Direct SQL writes that bypass these
application guards can also bypass the final-admin invariant.
