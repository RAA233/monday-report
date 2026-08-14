---
name: monday-report-database
description: >-
  PostgreSQL persistence, migrations, tenant RLS, and the production-database
  adapter for Monday Report. INVOKE for schema/migration work, disposable-DB
  verification, RLS/runtime-role checks, or production-DB adapter/evidence
  questions. Triggers: "add a migration", "checksum drift", "RLS", "runtime role
  safety", "production DB adapter", "why is production DB NOT_ACCEPTED", "fake DSN".
---

# Monday Report — database, migrations, RLS

Two backends: demo = local JSON store; client mode = `PostgresStateStore`
(RLS-enabled). Normalized tables are authoritative for migrated entities — see
[[monday-report-backend-api]].

## Migration runner (`backend/app/migrations.py`)
- Operator command only: `python -m backend.app.migrations apply|status|validate
  --set legacy|baseline`. **Never runs on API startup.** Guard: `audit:migration-runner`.
- Discovery globs `db/<set>/*.sql`, enforces `^(\d{4})_[a-z0-9_]+\.sql$`, rejects
  duplicate versions, orders ascending.
- **Checksum = SHA-256 over RAW FILE BYTES**, recorded per version in the
  `schema_migrations` table; **never rewritten**. Drift on an already-applied
  migration aborts the whole run before applying anything new.
- Whole-run **session advisory lock**; each pending migration in its **own
  transaction** (rollback + stop on failure); idempotent no-op when up to date.
- The runner applies the numbered set, **not** the flattened `db/schema.sql`.
- **CRLF hazard**: because checksums hash raw bytes, `.gitattributes` pins
  `*.sql text eol=lf`. Never relax it — see [[monday-report-git-pr]].

## `db/migrations/` (legacy, immutable) vs `db/baseline/` (corrected)
- Both hold `0001`–`0007`. `db/migrations/` is **immutable legacy**: its `0003`
  references `projects`/`reports` that no earlier legacy migration creates, so the
  legacy sequence is **un-appliable → `ga_migration_validity` stays BLOCKED**. It
  is NOT rewritten (its never-deployed status cannot be proven).
- `db/baseline/` is the corrected fresh-install set (FK targets retargeted to
  `workspaces`/`monday_reports`) and applies cleanly on real PostgreSQL.

## Disposable-DB verification workflow
- Real-PostgreSQL evidence needs **PostgreSQL 16 with pgvector**
  (`pgvector/pgvector:pg16` — `0001` needs the `vector` extension that stock
  `postgres:16` lacks). `docker-compose.client.yml` brings up a local Postgres +
  Redis for client-mode dev.
- Migration evidence artifact lives under `output/` (gitignored), so a **fresh
  checkout correctly falls back to BLOCKED** — that is fail-closed, not a
  regression. See [[monday-report-evidence-certification]].
- Live DB guards must use an **isolated stack** (state/storage/export roots
  outside the repo, API port ≠ 8000, web ≠ 5173): the
  `audit:restricted-postgres-runtime-*` family, `audit:tenant-rls-enforcement`,
  `audit:report-create-persistence`. Docker-less runs report UNAVAILABLE, never a
  false pass.

## Tenant RLS (`backend/app/tenant_rls.py`)
- `PROTECTED_TABLES` / `NORMALIZED_TABLES`. `assert_runtime_role_safe()` refuses
  to start the protected store (client mode) if the runtime role is **superuser,
  `BYPASSRLS`, owns a protected table, or equals the migration role** — a
  least-privilege, migration-vs-runtime role separation.
- `apply_verified_tenant_scope(cursor, tenant_slug)` sets the transaction-local
  GUC `app.tenant_slug` and **verifies read-back** (fail closed). The trust model
  is honest: it is not a defense against full runtime-principal compromise.
- Resolution requires **Postgres RLS active over the normalized store**; the
  normalized migration currently leaves tenant-isolation policies commented, so
  `tenant-authorization-enforcement` stays a declared blocker even though the
  API layer enforces ownership. Guard: `audit:tenant-rls-enforcement`.

## Production-database adapter — stays NOT_ACCEPTED
- `production_database_adapter.py` is a **behavioral** tier (pooled TLS, RLS
  forced, role separation, business/audit atomicity, bounded pre-mutation retry /
  no post-mutation retry) proven **only** on disposable Docker Postgres.
- `production_database_adapter_evidence.py` requires a real **production target**:
  22 required proof domains (incl. `failover_behavior`, `backup_policy`,
  `restore_test`, `monitoring_and_alerting`, `capacity_and_disk_thresholds`,
  `tls_configuration`), each needing a proving observation class (live target /
  control-plane response / **executed drill** / signed operator attestation).
  **Rejected**: loopback / docker-bridge / unknown endpoints; ephemeral storage;
  `staging`/`test`/`development` environments; `production_parity=false`. A
  disposable Docker Postgres, a loopback DSN, and the restricted-runtime matrix
  are explicitly **non-qualifying**. So `ga_postgres_adapter` remains BLOCKED and
  `PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED` stands. See [[monday-report-release-ga]].

## Non-goals / safety
- **Never fabricate a production DSN, TLS/drill/attestation, or production
  evidence** to flip acceptance. Contract acceptance ≠ adapter acceptance.
- Never point a live/mutating guard at the live API or `.local_data`.
