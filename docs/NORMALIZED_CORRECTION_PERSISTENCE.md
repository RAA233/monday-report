# Normalized Correction Persistence (Phase 04 vertical slice)

Design note for migration `0005_normalized_corrections.sql` and the PostgreSQL
cutover of reports, field corrections, validation tasks/outcomes, reviewer
attribution, idempotency linkage, and audit references. This document is the
single design authority for the slice; implementation must not diverge from it
without updating it in the same change.

## Registry conditions this slice addresses (quoted verbatim)

- `correction-cross-process-atomicity` (`ga_correction_cross_process_atomicity`,
  software/high): *"Correction lineage integrity is guaranteed across processes
  via normalized persistence with row/advisory locking or a uniqueness
  constraint."* — the target of this slice; PASS-capable with evidence.
- `production-database-adapter` (`ga_postgres_adapter`, infrastructure/blocker):
  requested==active==postgres via a live runtime probe. A slice does not satisfy
  a full-adapter runtime condition; the existing delegated evaluation is
  unchanged and the control remains environment-dependent.
- `tenant-authorization-enforcement` (`ga_tenant_authorization`): *"Tenant is
  resolved from the authenticated request and enforced at the API layer (with
  Postgres RLS active for the normalized store)."* This slice ADDS forced RLS
  for its four new tables, but the normalized store is not yet complete, so the
  probe's existing BLOCKED disposition is unchanged and no PASS is claimed.
- `persistence-locking-transactions` (`ga_persistence_locking`): unchanged
  condition; the snapshot transaction implementation changes materially here, so
  its implementation version is bumped and evidence regenerated (stale evidence
  is rejected by the existing probe).
- `audit-keyed-integrity`, `verified-reviewer-identity`: semantics preserved
  exactly (same audit actions/metadata, same reviewer gates); no disposition
  change is claimed.
- `backup-restore-drill`: untouched (manual review; out of scope).

## Entity classification (Part B)

| Entity | Current runtime shape | 0001 normalized table | Classification | Slice action |
|---|---|---|---|---|
| tenants | snapshot `tenant` (single) | `tenants` (usable; has slug) | existing and usable | FK anchor; mirror row upserted (projection) |
| users/credentials | snapshot | `users` (partial) | existing but incompatible | out of slice; app-level only |
| workspaces | snapshot dict | `workspaces` (usable) | existing and usable | FK anchor; mirror row upserted (projection) |
| reports (MondayReport) | snapshot dict | `monday_reports` (incompatible: no revision/report_json split) | existing but incompatible → new table | **migrated**: `monday_report_norm_reports` |
| field corrections | snapshot dict | none | missing | **migrated**: `monday_report_norm_field_corrections` |
| validation tasks | snapshot dict | `validation_tasks` (incompatible: no reviewer attribution/revision) | existing but incompatible → new table | **migrated**: `monday_report_norm_validation_tasks` |
| validation outcomes | implicit in task status | none | missing | **migrated**: `monday_report_norm_validation_outcomes` (append) |
| reviewer attribution | fields on correction/task | none | snapshot-only | columns + full doc on migrated rows |
| audit events | snapshot `audit_logs` (HMAC chain) | `audit_logs` (dead) | snapshot-only BY DESIGN | referenced by `audit_event_id` (no payload duplication, no FK — see below) |
| idempotency records | `monday_report_idempotency_records` (0004) | — | existing and usable | linked via `operation_id` column |
| report exports | snapshot dict | `report_exports` (dead) | snapshot-only | out of slice (reads report state via store) |

`db/schema.sql` is an aspirational reference (never applied; incompatible in
places) and is NOT a source of truth. 0001's `validation_tasks`/`monday_reports`
tables remain untouched dead schema (0001 is immutable); the new tables carry a
distinct `monday_report_norm_` prefix so nothing collides.

## Source of truth (Part C)

**In PostgreSQL mode** the write AND read authority for `monday_reports`,
`field_corrections`, and `validation_tasks` is the normalized tables:

- the snapshot payload **no longer contains** those entities (their keys are
  written as empty lists) and carries a marker
  `normalized_authority = {"version": 1, "entities": [...]}`;
- `refresh()` loads the three collections from normalized rows (via the open
  transaction's connection when this thread owns one, else a read connection);
- there are **no independent dual writes**: nothing writes those entities into
  the snapshot payload in PostgreSQL mode;
- a deterministic **compatibility projection** (`normalized_projection()`)
  reproduces the legacy snapshot list shape from normalized rows for
  import-verify and drift detection; the guard proves projection determinism and
  detects injected drift.

File/local mode keeps full snapshot ownership and is explicitly documented as
lacking normalized cross-process guarantees.

Legacy PostgreSQL snapshots that still hold migrated entities and carry no
marker are an **unsupported historical state**: PostgreSQL startup fails closed
naming the import tool. The import tool (Part H) is the only cutover path.

Authority hardening (added after adversarial review of the slice):

- **Fail-closed startup, no laundering.** The startup gate raises the dedicated
  `NormalizedCutoverRequired` and `create_store()` re-raises it instead of
  falling back to local JSON — a fallback would create a two-live-authorities
  split-brain with the un-imported client data sitting silently in PostgreSQL.
  Ordinary availability failures still fall back so readiness can report them.
- **Per-transaction marker refusal.** The same held-entities-without-marker
  refusal is applied to every transaction's locked payload read, not only at
  bootstrap: a concurrent old-version writer that re-materializes migrated
  entities into the snapshot is never silently overwritten (its committed
  entities would otherwise be blanked and the marker re-stamped).
- **Deletion reconciliation.** Lifecycle paths that REMOVE migrated entities
  from the in-memory dicts — `run_retention(apply=True)` and the demo-seed
  self-wipe — call `_normalized_prune_missing()`, which deletes the
  corresponding normalized rows **in the same protected transaction**
  (FK-safe order: outcomes → tasks → corrections → reports). Without it,
  purged entities resurrect on the next refresh and the audited retention
  counts would be false.
- **Typed back-link on supersede.** `PgFieldCorrectionRepository.create`
  writes the `superseded_by_id` column together with the doc, and the drift
  detector covers the pair, so live-superseded and imported rows share one
  shape.
- **Tenant-filtered import queries.** The import tool's conflict and verify
  queries carry explicit `tenant_slug` filters in addition to the RLS GUC,
  because the tool may run as a superuser/owner role, which bypasses RLS.

## Schema (Part D — migration 0005)

Typed columns carry every field that participates in keys, relationships,
lifecycle, revision, uniqueness, attribution or RLS; the complete canonical
entity (exact Pydantic serialization) is stored in a `doc jsonb` column so
reconstruction is deterministic (`Model.model_validate(doc)`) and cannot drift
from the app schema. Typed-column/doc consistency is guard-verified.

- `monday_report_norm_reports(id PK, tenant_id FK tenants, workspace_id,
  status CHECK draft/review/approved/exported, revision >= 0, doc, audit_event_id,
  operation_id, created_at, updated_at)`; composite FK `(workspace_id, tenant_id)`
  → `workspaces(id, tenant_id)` (unique index added on workspaces) enforces
  tenant/workspace consistency.
- `monday_report_norm_field_corrections(id PK, tenant_id, workspace_id,
  target_type, field_key, status CHECK active/superseded/reverted,
  supersedes_id FK self, superseded_by_id FK self, actor_user_id NOT NULL,
  reviewer_user_id, revision >= 0, doc, audit_event_id, operation_id,
  created_at, reverted_at, updated_at)` + **partial unique index: one ACTIVE
  correction per (tenant_id, workspace_id, target_type, field_key)** — the
  lineage-integrity uniqueness constraint the registry condition names.
- `monday_report_norm_validation_tasks(id PK, tenant_id, target_type, target_id,
  status CHECK open/validated/rejected/conflict, revision >= 0,
  reviewer_user_id, doc, audit_event_id, operation_id, created_at, updated_at)`.
- `monday_report_norm_validation_outcomes(id PK, task_id FK tasks (NO cascade),
  tenant_id, task_revision >= 0, outcome CHECK terminal-only,
  reviewer_user_id NOT NULL, reviewer_verified bool, audit_event_id,
  operation_id, reviewed_at)` + **UNIQUE(task_id, task_revision)** — one
  terminal outcome per task revision, DB-enforced.

No cascading deletes anywhere in the slice (FKs default NO ACTION; deleting a
referenced tenant/workspace/task is blocked, preserving audit-relevant rows).
Lifecycle transition legality is intentionally NOT a DB constraint: the current
route contract permits any→any status transitions (administrative reopening
included) and Part J forbids changing review semantics; structural CHECKs only.

Timestamps: the application supplies entity timestamps (deterministic from the
entity); `now()` defaults exist only as fallback.

**Audit relationship**: rows store `audit_event_id` — the UUID of the
corresponding `AuditLog` event in the snapshot-owned, HMAC-chained audit log.
The payload is never duplicated. A database FK is not compatible with the
current audit design (the chain lives inside the snapshot jsonb and its
integrity is protected by HMAC + linkage, not by relational constraints), so the
reference is a durable UUID; the guard proves every mutated row references a
real committed audit event.

**RLS**: the four new tables get `ENABLE` + `FORCE ROW LEVEL SECURITY` with a
`tenant_isolation` policy `tenant_id = current_setting('app.tenant_id', true)::uuid`
(same pattern as `monday_report_state_snapshots`). The application sets
`app.tenant_id` transaction-locally (`set_config(..., is_local => true)`) inside
every snapshot transaction and on read connections, so pooled-connection reuse
cannot leak context and a missing context denies access. This is enforcement for
the slice's tables only — `tenant-authorization-enforcement`'s overall
disposition is NOT claimed from it.

## Transaction boundaries and lock ordering (Parts E/F)

Every protected mutation runs in ONE PostgreSQL transaction — the existing
thread-owned `snapshot_transaction` — now covering, in order:

1. global snapshot advisory lock (audit chain + non-migrated state authority);
2. snapshot row `SELECT ... FOR UPDATE` + CAS revision read;
3. idempotency replay/conflict decision (0004 table);
4. **normalized row locks** (`SELECT ... FOR UPDATE` on the target correction
   lineage / task / report rows) and row revision checks;
5. domain mutation (in-memory model + normalized INSERT/UPDATE writes);
6. reviewer attribution; audit event construction + HMAC (returns the event so
   rows link `audit_event_id`); outcome row append for terminal validations;
7. idempotency record; snapshot CAS commit (payload EXCLUDES migrated
   entities); single COMMIT.

Any pre-commit failure (domain error, audit/HMAC failure, constraint violation,
process death) rolls back EVERYTHING: normalized rows, audit event, idempotency
record, revision — proven by guard scenarios.

**Lock-order rule (deterministic, documented):** the global snapshot advisory
lock is always acquired FIRST, then normalized row locks (ordered by table,
then id). No mutation in this slice can safely skip the global lock while the
audit chain remains snapshot-owned — every protected mutation appends to the
global HMAC chain, which is a NECESSARY serialization point of the current audit
design. "Independent aggregates mutate concurrently without unnecessary
serialization" therefore means: no cross-aggregate row-lock conflicts, no
false stale-revision aborts, no lock-timeout failures between independent
reports/tasks/tenants — both writers commit (serialized only by the audit
chain), which the guard proves with independent OS processes.

## Repositories (Part E)

`backend/app/repositories.py` defines `ReportRepository`,
`FieldCorrectionRepository`, `ValidationTaskRepository` with: scoped load,
create, transition, revert, revision check, idempotent replay support (via the
store idempotency layer), transaction participation (they execute on the owning
transaction's connection), and deterministic result reconstruction
(`model_validate(doc)`). The store's domain methods call repositories through
narrow persistence hooks (`_normalized_*`); local mode binds no-op hooks. Route
code is unchanged — normalized persistence is not embedded in routes.

## Import and cutover (Part H)

`python -m backend.app.normalized_import <assess|dry-run|execute|verify>` —
explicit operator command, never run at API startup. `assess` reports snapshot
holdings, conflicts, relationship validity; `dry-run` performs the full
transformation without writing; `execute` imports all units in ONE transaction
(global lock: read snapshot → insert normalized rows with the entities' own
UUIDs (deterministic) → upsert tenant/workspace FK anchors → strip migrated
keys + write marker → CAS snapshot → commit); `verify` recomputes the
projection and compares counts/docs. Idempotent rerun (marker present → verify
only). Conflicts (existing divergent rows) are reported and block execute.
Snapshot data is unchanged until execute succeeds; tests never touch live
`.local_data`.

## Rollback plan

The migration is forward-only and additive. Application rollback = deploy the
previous release: it reads the snapshot, whose migrated keys are empty after
cutover — therefore rollback after cutover REQUIRES restoring the pre-cutover
snapshot payload (the import tool prints the pre-cutover revision for operator
records) or re-projecting rows into the snapshot with the compatibility
projection. This limitation is explicit and disclosed; no automatic rollback is
provided.

## Compatibility limitations

- File/local mode: no normalized guarantees (unchanged behavior, documented).
- The audit chain remains snapshot-owned; all protected writers still serialize
  on the global advisory lock (necessary; see lock-order rule).
- `production-database-adapter` remains a runtime condition; this slice does not
  claim it.
- RLS covers only the slice's tables; overall tenant-authorization disposition
  is unchanged.
