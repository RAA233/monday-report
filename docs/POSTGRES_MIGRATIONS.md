# PostgreSQL migrations (migration-runner, migration-validity)

Monday Report ships a deterministic, idempotent migration runner
(`backend/app/migrations.py`) that applies a numbered SQL sequence and records
each applied version in a dedicated `schema_migrations` metadata table. It is
enforced by `scripts/migration_runner_guard.py` (`audit:migration-runner`, in
`audit:all`) and the evidence-driven `ga_migration_runner` /
`ga_migration_validity` readiness probes.

> **Honest status.** This delivers the runner, metadata/immutability policy,
> concurrency + transaction contract, a supplemental static validator, a
> corrected fresh-install baseline, and the decisive **real-PostgreSQL** test
> harness. It does **not** deliver normalized persistence, active RLS,
> transactional business/audit atomicity, or backup/restore. **GA remains
> `GA_BLOCKED`.**

## Two migration sets

| Set | Path | Purpose | Validity |
|---|---|---|---|
| **legacy** | `db/migrations/` | The original committed sequence. **Immutable.** | 0003 references `projects(id)`/`reports(id)` that no earlier legacy migration creates → **un-appliable → BLOCKED**. |
| **baseline** | `db/baseline/` | Corrected sequence for **fresh installs**. | FK targets retargeted to `workspaces(id)`/`monday_reports(id)` → applies cleanly. |

```
python -m backend.app.migrations apply    --set baseline   [--database-url DSN]
python -m backend.app.migrations status    --set legacy     [--database-url DSN]
python -m backend.app.migrations validate  --set baseline
```

The runner applies the numbered `.sql` files of the chosen set. It does **not**
apply `db/schema.sql` — a divergent, non-authoritative flattened reference that
uses yet another set of names (`projects`/`reports`); it is not what the runner
executes.

## Migration 0003 and the migration-history decision

`db/migrations/0003_benchmarking.sql` declares foreign keys to `projects(id)` and
`reports(id)` — names the legacy sequence never creates (`0001` creates
`workspaces` and `monday_reports`). In sequence, `0003` is therefore
**un-appliable**.

**History investigated (Part D).** `0003` was added in commit `f7b6635`
(2026-07-14), which is **after** the repository's only release tag
`ga-2026-07-13`; no migration runner or `schema_migrations` table has ever
existed; the only prior PostgreSQL path creates only the JSONB snapshot table;
and the in-repo docs describe these normalized tables as a future "normalized
repository target," with the app running on the JSONB snapshot. This is **strong
evidence** the normalized migrations were never deployed — but it is **not
authoritative proof** that no person or client ever executed or distributed the
SQL manually.

**Decision — restore, do not edit.** Because the "unpublished draft" status
cannot be *proven*, and per the safe policy that an existing migration must not
be edited on the mere inference that it "could not have succeeded",
`0003_benchmarking.sql` is **restored byte-for-byte to its original committed
contents** and kept **immutable**. The earlier attempt to correct it in place is
reverted. No claim is made that the corrected bytes were ever the historical
`0003`.

**Corrected baseline instead.** A separate, corrected **fresh-install baseline**
lives in `db/baseline/` (`0001`/`0002` byte-identical to the immutable legacy
foundation; `0003` with FK targets retargeted to `workspaces`/`monday_reports`).
A fresh install applies the baseline and passes validation; the **legacy upgrade
path stays BLOCKED** because its committed `0003` is invalid and immutable.

| 0003 (legacy, immutable) | 0003 (baseline, corrected) |
|---|---|
| `project_id uuid references projects(id)` (×3) | `workspace_id uuid references workspaces(id)` |
| `report_id uuid references reports(id)` | `report_id uuid references monday_reports(id)` |

## Runner contract

Explicit operator command — **never** run automatically on API startup. Filename
contract `NNNN_description.sql`; unique versions; deterministic ascending order;
UTF-8; stable per-file SHA-256. Duplicate versions and malformed names rejected.

### `schema_migrations` metadata

`version` (PK), `filename`, `checksum_sha256`, `applied_at`, `execution_ms`,
`runner_version`. A row is inserted **only after** the migration SQL succeeds. An
already-applied migration whose on-disk checksum no longer matches its recorded
checksum is **refused** — the recorded checksum is **never rewritten**. A
recorded version not on disk is treated as drift and the run is refused. No
credentials, DSNs, or absolute paths are stored.

### Concurrency + transactions

Whole run holds a **session-level** advisory lock (stable app key, released in
`finally`), so it does not rely on the primary key alone. Each pending migration
runs in its own transaction (BEGIN → SQL → metadata insert → COMMIT); on failure
it ROLLBACKs (no schema change, no metadata) and the run **stops**.
Non-transactional statement types (`CREATE INDEX CONCURRENTLY`, `CREATE
DATABASE`, some `ALTER TYPE … ADD VALUE`) are a documented limitation; the
current migrations use none.

## Validity: real PostgreSQL is the source of truth

Migration **validity** is decided by a **real PostgreSQL** execution against an
ephemeral, test-marked database. The guard proves, on real PG: the immutable
**legacy** sequence FAILS at 0003 (validity gap is real); the corrected
**baseline** applies cleanly with the expected tables + FK targets; idempotent
rerun; supported partial upgrades; failure rollback; concurrency serialization;
and checksum-drift refusal. The **supplemental static validator**
(`validate_migration_set`) is a narrow regex heuristic with documented limits
(not a SQL parser); it detects the legacy 0003 FK gap and confirms the baseline
is clean, but never establishes validity on its own.

### Supported upgrade paths

Baseline: empty → head; metadata-only → head; first-N applied → applies the rest;
interrupted-before-metadata → resumes; current → no-op. A recorded version not on
disk → drift refusal. **Legacy upgrades are unsupported** (the committed legacy
0003 is un-appliable) and stay BLOCKED. When real deployed states are unknown,
this is said plainly and validity stays BLOCKED.

## Ephemeral-database safety

The guard refuses destructive setup unless the target database name contains a
`test` marker **and** the connection string names an explicit loopback host. It
is **fail-closed**: an unparseable DSN, a missing database name, or an
indeterminate host is refused rather than allowed.

Both libpq forms are handled — the URL form (`postgresql://…`) and the
keyword/value form (`host=… dbname=… password=…`). This matters: `urlsplit` does
not understand keyword/value input, so it previously reported no host, and an
empty host satisfied the local-host allow-set — meaning a **remote** database
could have received `drop schema public cascade`. The same parse also put the
whole connection string, password included, into the recorded reason.

The returned reason **never** interpolates the DSN, password, host or username.

## Evidence + readiness

`output/migrations/migration-evidence.v1.json` (gitignored) records the runner +
validity results with `git_commit`/`git_tree`/`worktree_clean`, `runner_version`,
`postgres_server_version`, legacy + baseline set hashes and checksums, the
per-scenario results (incl. `legacy_apply_result` showing legacy fails), `status`,
and a canonical `payload_sha256` (independently recomputed by the guard). It
**excludes** any password, DSN, username, host path, absolute path, or client data.

`ga_migration_runner` is **evidence-driven**: it PASSes only with committed
real-PostgreSQL passing evidence (deterministic order, metadata, advisory lock,
per-migration transactions, idempotent rerun, checksum-drift refusal, failure
rollback, concurrency). `ga_migration_validity` **also** re-runs the supplemental
static validator on the immutable **legacy** set, so it stays **BLOCKED** as long
as the committed legacy 0003 is invalid — a passing baseline does not flip it.
Absent/stale/non-passing evidence keeps both **BLOCKED**.

## Database prerequisites

`db/baseline/0001_foundation.sql` (and the legacy `0001`) declare three
extensions:

```sql
create extension if not exists pgcrypto;
create extension if not exists citext;
create extension if not exists vector;
```

`pgcrypto` and `citext` ship with the standard `postgres` image; **`vector`
(pgvector) does not.** On a stock `postgres:16` the very first migration fails
with `extension "vector" is not available` and nothing applies. Use an image that
bundles pgvector — e.g. `pgvector/pgvector:pg16` — or install the extension on
the server. Verify before running:

```sql
select name from pg_available_extensions
 where name in ('pgcrypto', 'citext', 'vector');
```

### Line endings are part of the checksum

Migration checksums are SHA-256 over **raw file bytes**
(`discover_migrations` → `path.read_bytes()`) and are persisted in
`schema_migrations`, then compared on every later run. Line endings therefore
change the checksum. With `core.autocrlf=true` (the Windows default) a checkout
smudges `LF` → `CRLF`, so a database migrated from Windows records different
checksums than the same commit checked out on Linux/CI, and the next run from the
other platform reports **checksum drift on every applied migration and refuses to
apply anything**. `.gitattributes` pins `*.sql text eol=lf` so the bytes are
identical on every platform. Do not remove it, and do not commit `.sql` files
with CRLF.

## Current environmental status

A decisive real-PostgreSQL run **has executed**, against a disposable,
test-marked **PostgreSQL 16.14** (`pgvector/pgvector:pg16`) on a random loopback
port. The guard completed with **64 checks passed, 0 skipped, 0 failed** — no
PostgreSQL-dependent check was skipped. The run proved, on a real server: fresh
baseline apply, `schema_migrations` metadata, idempotent rerun, supported partial
upgrades, resume after an interrupted run, failure rollback with no orphan
metadata row, concurrency serialization under the session advisory lock, and
checksum-drift refusal without rewriting the stored checksum.

The same run also confirmed the validity gap is real rather than theoretical: the
**immutable legacy sequence fails on real PostgreSQL at `0003`** with
`relation "projects" does not exist`.

Consequently `migration-runner` is PASS-capable from committed real-PostgreSQL
evidence, while **`migration-validity` remains BLOCKED** — the legacy `0003`
still references tables no earlier legacy migration creates, and
`_migration_validity_probe` independently re-runs the static validator over
`db/migrations/`, so a passing *baseline* apply cannot flip it. **GA remains
`GA_BLOCKED`** on other unresolved controls.

To reproduce: provide a disposable, test-marked PostgreSQL 16 **with pgvector**
via `MONDAY_REPORT_TEST_DATABASE_URL` and run
`python scripts/migration_runner_guard.py --emit-evidence`.

## What this does NOT claim

Not delivered: normalized persistence, active PostgreSQL RLS, transactional
business/audit atomicity, cross-process correction atomicity, backup/restore, or
GA/enterprise readiness. Those remain their own BLOCKED controls.
