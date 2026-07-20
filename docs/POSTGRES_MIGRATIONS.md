# PostgreSQL migrations (migration-runner, migration-validity)

Monday Report ships a deterministic, idempotent migration runner
(`backend/app/migrations.py`) that applies the numbered SQL sequence in
`db/migrations/` and records each applied version in a dedicated
`schema_migrations` metadata table. It is enforced by
`scripts/migration_runner_guard.py` (`audit:migration-runner`, in `audit:all`)
and the evidence-driven `ga_migration_runner` / `ga_migration_validity` readiness
probes.

> **Honest status.** This increment delivers the runner, the metadata/immutability
> policy, the concurrency + transaction contract, a supplemental static validator,
> and the decisive **real-PostgreSQL** test harness. It does **not** deliver
> normalized persistence, active RLS, transactional business/audit atomicity, or
> backup/restore — those stay separate BLOCKED controls. **GA remains
> `GA_BLOCKED`.**

## What the runner applies (and what it does not)

The runner applies **`db/migrations/*.sql`** — the executable migration sequence.
It does **not** apply `db/schema.sql`.

`db/schema.sql` is a **divergent, flattened design reference** that uses different
entity names than the sequence (it defines `projects`/`reports`; the sequence's
`0001_foundation.sql` creates `workspaces`/`monday_reports`, matching the running
app's domain — the API's `/workspaces`, `store.py`, and `CLAUDE.md`). `schema.sql`
is **not authoritative** and is not what the runner executes. Treat the numbered
sequence as the source of truth.

## Migration 0003 correction (migration-validity)

`db/migrations/0003_benchmarking.sql` originally declared foreign keys to
`projects(id)` and `reports(id)` — names taken from `schema.sql`, which the
migration **sequence never creates**. In sequence, `0003` was therefore
**un-appliable**: its FK targets do not exist after `0001`+`0002`.

**Applied-migration immutability (proof of unapplied).** `0003` was corrected in
place rather than superseded because it is **provably unapplied**:

1. No migration runner and no `schema_migrations` table have ever existed in this
   repository (this increment introduces both), so nothing ever recorded `0003`
   as applied.
2. The only prior PostgreSQL code path (`PostgresStateStore._ensure_repository_schema`)
   creates **only** the `monday_report_state_snapshots` JSONB table — it never
   applies `db/migrations/`.
3. `0003` as written references `projects`/`reports`, which the sequence does not
   create, so it **cannot have been successfully applied** in-sequence anywhere.
4. The running app persists through the JSONB snapshot, not the normalized
   benchmarking tables (which remain the "normalized repository target").

The correction retargets the FK columns to the tables the sequence actually
creates and aligns their names with the `0001` convention:

| 0003 (before) | 0003 (after) |
|---|---|
| `project_id uuid references projects(id)` (×3) | `workspace_id uuid references workspaces(id)` |
| `report_id uuid references reports(id)` | `report_id uuid references monday_reports(id)` |
| `idx_measurements_tenant_project_metric (…, project_id, …)` | `idx_measurements_tenant_workspace_metric (…, workspace_id, …)` |
| `idx_key_decisions_tenant_project_time (…, project_id, …)` | `idx_key_decisions_tenant_workspace_time (…, workspace_id, …)` |

No non-SQL code reads these columns (they are the not-yet-used normalized target),
so the rename is behavior-neutral for the running app. Because `0003` was never
recorded as applied, no `schema_migrations` checksum is invalidated and **no
misleading history is created**.

## Runner contract

Explicit operator command — **never** run automatically on API startup:

```
python -m backend.app.migrations apply     [--database-url DSN]
python -m backend.app.migrations status    [--database-url DSN]
python -m backend.app.migrations validate
```

The DSN falls back to `MONDAY_REPORT_MIGRATIONS_DATABASE_URL` or `DATABASE_URL`;
its value is **never echoed**.

### Filename + version contract

`NNNN_description.sql` — a zero-padded 4-digit version, lowercase snake
description, unique version, deterministic ascending order, UTF-8, stable
SHA-256 over the raw bytes. Duplicate versions and malformed names are rejected.

### `schema_migrations` metadata

| column | meaning |
|---|---|
| `version` (PK) | integer migration version |
| `filename` | source file name |
| `checksum_sha256` | SHA-256 of the applied file bytes |
| `applied_at` | apply timestamp |
| `execution_ms` | apply duration |
| `runner_version` | runner contract version (`RUNNER_VERSION`) |

A row is inserted **only after** the migration SQL succeeds. An already-applied
migration whose on-disk checksum no longer matches its recorded checksum is
**refused** (checksum drift); the recorded checksum is **never rewritten**. The
table stores **no credentials, DSNs, or absolute paths**.

### Concurrency (advisory lock)

A whole run holds a **session-level** advisory lock
(`pg_advisory_lock(ADVISORY_LOCK_KEY)`) on a stable, app-specific key, released in
`finally`. Two concurrent `apply` runs serialize: one applies pending migrations,
the other observes them applied and no-ops. Correctness does **not** rely on the
primary-key constraint alone.

### Per-migration transactions

Each pending migration runs in its own transaction: `BEGIN` → execute the
migration SQL → insert the metadata row → `COMMIT`. On failure the transaction
`ROLLBACK`s (no schema change, no metadata row) and the run **stops** — later
migrations are not attempted. Statements that cannot run inside a transaction
(e.g. `CREATE INDEX CONCURRENTLY`, `CREATE DATABASE`, some `ALTER TYPE … ADD
VALUE`) are a documented limitation; the current migrations use none.

## Validity: real PostgreSQL is the source of truth

Migration **validity** is decided by a **real PostgreSQL execution** against an
ephemeral, test-marked database — the complete sequence must apply cleanly and
supported partial upgrades must succeed. The runner is exercised by
`scripts/migration_runner_guard.py` across: fresh apply, idempotent rerun,
partial upgrades (empty / metadata-only / first-N / interrupted / current /
unknown-recorded-version), failure rollback, concurrency, and checksum drift.

The **supplemental static validator** (`validate_migration_set`) is a narrow
regex heuristic that confirms every `references <table>(…)` FK target is created
by the same or an earlier migration. It is **supplemental only**, with documented
limitations (it is not a SQL parser; it does not resolve `ALTER TABLE ADD
CONSTRAINT`, schema-qualified targets, column-level correctness, RLS, or
extensions). It can never establish validity on its own.

### Supported upgrade paths

`empty` → head; `metadata-only` (table present, no rows) → head; `first-N`
applied → applies the rest; `interrupted before a migration's metadata` → resumes
at that migration; `current` → no-op. A `schema_migrations` row for a version
**not on disk** is treated as **drift** and the run is refused (unknown deployed
states keep validity honest). When real deployed states are unknown, this is said
plainly and **migration-validity stays BLOCKED**.

## Ephemeral-database safety

The guard refuses destructive setup unless the target database name contains a
`test` marker and resolves to a local host; it **never** prints the DSN or
password. A disposable database/container created solely for a test run is torn
down afterward.

## Evidence + readiness

`output/migrations/migration-evidence.v1.json` records the runner + validity
results with `git_commit`/`git_tree`/`worktree_clean`, `runner_version`,
`postgres_server_version`, `migration_set_sha256`, per-scenario results, `status`,
and a canonical `payload_sha256` (SHA-256 of the canonical UTF-8 JSON excluding
`payload_sha256`, independently recomputed by the guard). It **excludes** any
password, DSN, username, host path, absolute path, or client data.

`ga_migration_runner` and `ga_migration_validity` are **evidence-driven**: they
PASS **only** when the committed evidence has `status == "passed"`, its
`payload_sha256` verifies, it was captured from a clean worktree with a real
`postgres_server_version`, and its `migration_set_sha256` still matches the
on-disk migrations (so editing a migration re-blocks until re-proven). Absent,
stale, or non-passing evidence keeps both controls **BLOCKED** — code presence
alone never flips them.

## Current environmental status

At the time of this increment, no PostgreSQL was reachable in the build
environment (Docker Desktop's Linux engine could not be started non-interactively
— the privileged `com.docker.service` requires administrator elevation that a
headless session cannot grant; WSL2 itself was healthy). The decisive
real-PostgreSQL run therefore **did not execute**, so the committed evidence is
`BLOCKED_NO_POSTGRES` and **`migration-runner` and `migration-validity` remain
BLOCKED**. To resolve: provide a disposable, test-marked PostgreSQL 16 via
`MONDAY_REPORT_TEST_DATABASE_URL` and run
`python scripts/migration_runner_guard.py --emit-evidence`; both controls then
flip on clean evidence. **GA remains `GA_BLOCKED` regardless.**

## What this does NOT claim

Not delivered here: normalized persistence, active PostgreSQL RLS, transactional
business/audit atomicity, cross-process correction atomicity, backup/restore, or
GA/enterprise readiness. Those remain their own BLOCKED controls.
