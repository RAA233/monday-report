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
reference is a durable UUID. Every APP-created protected mutation (corrections,
validation-task creation, transitions) writes a non-null audit reference in the
same transaction; rows introduced by the one-time import cutover carry a null
per-row reference and are instead recorded by the marker's `normalized.import`
batch reference. The guard proves both (checks 16, 58, the task-audit checks) —
it does not claim database-enforced referential integrity for a snapshot-owned
audit log.

**RLS**: the four new tables get `ENABLE` + `FORCE ROW LEVEL SECURITY` with a
`tenant_isolation` policy `tenant_slug = current_setting('app.tenant_slug', true)`
(same GUC and pattern as `monday_report_state_snapshots`/the idempotency table).
The application sets `app.tenant_slug` transaction-locally
(`set_config(..., is_local => true)`) inside every snapshot transaction and on
read connections, so pooled-connection reuse cannot leak context and a missing
context denies access. RLS enforcement is proven only for a genuine
non-superuser, non-BYPASSRLS role (foreign-key checks and superuser connections
bypass RLS); the guard classifies its own connection role honestly. This is
enforcement for the slice's tables only — `tenant-authorization-enforcement`'s
overall disposition is NOT claimed from it.

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

## Independent-review correction round (migration 0006, evidence v2)

A final independent review confirmed ten defects, all corrected here; evidence
was bumped to v2 so prior artifacts fail closed:

- **Import supersession ordering** is two-phase (NULL self-refs first, validated
  backlinks second); `_lineage_issues` rejects missing/cross-tenant/cross-coordinate/
  self-reference/cycle/branching/non-reciprocal links **in both directions**, and
  an empty `field_key` is refused cleanly rather than hitting the DB CHECK.
- **Reset preserves tenant identity** (no id rotation), prunes under the preserved
  id, and verifies deletion before reseed — no resurrection, no slug collision.
- **`verify` is authoritative**: it compares the marker's per-entity counts AND id
  digests to the live tenant-scoped rows (a stale marker after a mutation → `ok:false`).
- **Conflict accounting** is explicit (no `ON CONFLICT DO NOTHING`); a cross-tenant
  id collision is a hard REFUSED.
- **Migration 0006** adds composite tenant/coordinate FKs, no-self-reference CHECKs,
  no-branching unique indexes, and outcome→task tenant binding (additive over 0005;
  the earlier "database-enforced lineage integrity" claim in 0005's header is
  corrected by 0006's header and this document).
- **Validation-task rows carry a non-null audit reference**; imported rows are
  recorded by the marker's `normalized.import` batch reference (no fabricated events).
- **Refresh/transaction**: a non-owner refresh serializes against the writer's
  in-process lock; a rolled-back mutation reloads committed state so no phantom row
  leaks.

## Store-level transaction isolation (copy-on-write publication)

The earlier disclosed residual — a lock-free reader could observe a writer's
uncommitted state — is now **eliminated**, not documented. Every process-wide
mutable container is a `MANAGED_STATE` context-aware property backed by a
committed **published projection**:

- an **owner** thread inside a protected transaction reads and mutates a
  transaction-private **working projection** (a `copy.deepcopy` of the published
  projection, so mutating any nested entity, list or dict in place never touches
  published — the sole exception is the append-only `audit_logs` hash chain,
  copied as a *shallow* list because its entries are never mutated in place, only
  appended; this avoids deep-copying an unbounded log on every transaction);
- every **non-owner** caller (route, export, authorization lookup, worker) reads
  straight from the live committed published projection — always the current
  committed generation. There is **no** sticky per-thread captured view: an
  earlier read never leaves a snapshot that a pooled worker thread could serve
  stale on a later request;
- on **commit**, the complete new committed projection is published atomically
  under `_publish_lock`, stamped with **this transaction's own committed
  revision** (the value written by the snapshot compare-and-swap), not a value
  re-read on a separate connection; a monotonic revision guard means an older
  refresh/commit can never overwrite a newer published generation;
- on **rollback**, the private working projection is discarded and nothing is
  published; a defensive refresh reload keeps subsequent reads on committed state;
- refresh builds its candidate committed projection off to the side (into a
  per-thread loading buffer) and publishes it atomically — it never mutates the
  published projection in place.

Result: a non-owner reader **never** observes a writer's uncommitted state through
any read surface, and every individual read is a whole committed generation — no
dirty read and no torn projection. (Because each non-owner read is the live
current-committed generation, two reads in one long request could span a commit
boundary; each is a consistent committed generation, never uncommitted.) This is
proven by deterministic two-thread guard checks (route/export/authorization/worker
surfaces, commit-publishes, rollback-publishes-nothing, deep-copy privacy,
generation ordering, no-stale-view, revision binding, audit-log list isolation),
each mutation-tested to fail under a broken implementation.

Every state-reading route calls `store.refresh()` before touching state (verified
by inspection of the full route inventory), so a read handler always observes the
current committed generation rather than whatever a prior request left on its
pooled thread.

Throughput note: the non-owner refresh builds its candidate under `_txn_lock`, so
a reader that must rebuild the committed projection serializes behind an active
writer for the duration of that build. This is a deliberate correctness-over-
throughput choice for the in-process singleton: the lock guarantees the candidate
projection and its revision come from one consistent committed generation. Writer
transactions are short and bounded by the row-lock timeout.

### Whole-operation read coherence (committed read view)

Per-access committed reads (above) prevent dirty reads but not *torn* reads: an
operation that touches several managed fields could observe entities from two
committed generations if a writer commits between accesses (e.g. `store.X.get(id)`
succeeding, then `store.X[id]` raising `KeyError` after a concurrent delete). A
request/task-scoped **committed read view** closes that gap:

- `store.committed_read_view()` is a context manager that pins ONE committed
  projection for the operation. Resolution order is (1) the owner's private
  working projection, else (2) this context's pinned committed view, else (3) the
  live published projection.
- The view is backed by a `contextvars.ContextVar` (`_read_view`), **not**
  `threading.local` — verified to auto-scope per asyncio task and per threadpool
  request copy, so it can never persist across pooled-thread request reuse (the old
  sticky-view leak) and two async tasks on one event-loop thread stay isolated.
- It pins **on the first `refresh()`** inside the view, capturing the freshly
  refreshed generation; a later `refresh()` in the same view is coherence-preserving
  (does not switch generations). An operation that commits its OWN mutation advances
  its pinned view to the new generation, so it observes its own write.
- Applied structurally, not per route: the `coherent_read_view` http middleware
  wraps every request (so identity resolution, authorization/`_tenant_owned`, domain
  reads and serialization share one generation), and the worker wraps its job pass.
  `scripts/read_coherence_guard.py` fails closed if a new state-reading route omits
  `store.refresh()`, if the middleware/worker boundary is removed, or if the view
  reverts to `threading.local`.

Sealed audit entries are `frozen` (`AuditLog`), so the shallow-copied working
`audit_logs` list can safely share published entry objects: an entry present in the
published projection cannot be mutated in place.
- **RLS honesty**: enforcement is proven only with a genuine non-superuser role,
  and the guard proves the superuser-bypass vs non-superuser-enforced contrast;
  `tenant-resource-authorization` stays BLOCKED.
