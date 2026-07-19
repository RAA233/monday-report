# Field-Level Correction & Review-Provenance Foundation

This document specifies the auditable, tenant-scoped field-level correction
foundation. It addresses the enterprise readiness gaps that no correction /
revision-history entity existed (extractions could only be accepted or
rejected, never corrected with a preserved from/to trail).

## What a correction is

A `FieldCorrection` is a **versioned overlay record**. It captures an actor's
correction to a **registered** extracted field **without overwriting** the
source-derived value or its lineage. The original extracted value is preserved
on the record, and the underlying parsed document / `report_profile` is never
mutated. Corrections are surfaced as **review-required overlays**, never as
confirmed source facts.

This is **versioned history stored in the tenant snapshot, not an immutable
append-only event log**: superseding and reverting update the `status`/linkage
of an already-persisted record. A tamper-resistant immutable-event model (and
cross-process atomicity via normalized persistence) is tracked follow-up work.

## Correction contract (Part H fields)

| Field | Meaning |
| --- | --- |
| `source_value` | The original extracted/source value, preserved on the record. |
| `corrected_value` | The replacement value (may be `null`). |
| `correction_reason` | Justification (length-capped; never written to the audit log raw). |
| `actor_user_id` / `actor_email` / `actor_roles` / `actor_source` | The **configured actor context** at record time — `actor_source="configured"`, **not** a verified per-user reviewer (no authenticated per-user identity exists yet). |
| `created_at` | Correction timestamp. |
| `prior value` | Preserved as the superseded record's `corrected_value` (version chain). |
| `status` | `active` \| `superseded` \| `reverted`. |
| `supersedes_id` / `superseded_by_id` | Version-chain linkage. |
| `revert_reason` | Reason recorded when an active correction is reverted. |
| `tenant_id` / `workspace_id` | Tenant and workspace scope, stamped at record time. |

- **Audit event.** Recording emits `field_correction.record`; reverting emits
  `field_correction.revert`. Both are hash-chained and redacted: the audit
  metadata carries attribution and shape only (field key, target type,
  value-present / value-changed booleans, reason length, version linkage) —
  never the raw source value, corrected value, or reason text.
- **Conflict resolution.** Re-correcting the same
  `(workspace, target_type, field_key)` supersedes the prior active record
  (status → `superseded`, `superseded_by_id` set) and the new record is the
  single `active` one. History is never destroyed.
- **Report Draft behavior.** `GET /workspaces/{id}/report-draft` returns the
  active corrections in `field_corrections` as overlays. The source-derived
  scalar/casing/survey/hydraulics values in the same response are unchanged.
- **Final JSON / export behavior.** This foundation slice records, versions,
  surfaces, and audits corrections. It deliberately does **not** apply
  corrected values into the official `MondayReport` JSON or the formatted
  HTML/PDF/XLSX exports — applying corrections into formatted exports (with the
  same per-row provenance the UI shows) is the separate export-provenance
  increment. Deterministic source extraction stays authoritative until that
  reviewed policy lands.

## Correctable-field registry

Only a field listed in the centralized registry
(`backend/app/corrections_registry.py`) may be corrected. The registry declares
per field: target type, value type (`string` / `numeric_text`), nullability,
max length, and whether the value may enter the Report Draft overlay
(`enters_draft`) and the official report JSON (`enters_final_json` — **`False`
for every field in this slice**). The correctable surface is the report-identity
scalar fields (`report_no`, `well`, `rig`, `operator`, `phase`, `hole_size`,
`md_ft`, `tvd_ft`, `mud_weight`).

Free-form field keys and unrestricted JSON paths are rejected. Audit-chain and
hash fields, actor/role/permission fields, tenant/workspace ownership,
recommendation status and `DiagnosticAction` state, Benchmarking metrics and
thresholds, parser method/version, source page/confidence/snippet/hash, FORGE
expectations, validation-gate state, model/prompt provenance, immutable
identifiers, and system timestamps are **not registered** and therefore a
correction targeting them returns a stable `422` (`code: "unknown_field"`).
No object attribute is ever set dynamically from `field_key`. Values are
bounded: corrected values must match the field type (numeric fields reject
NaN/infinity/non-numeric text), strings are length-capped, control characters
are rejected, and reasons are length-capped. `GET /field-corrections/registry`
returns the catalog for operator discovery.

## Concurrency (honest scope)

The full correction route (refresh → checks → record/revert → save) is
serialized in-process by a re-entrant lock, so the single-active-lineage and
no-lost-write invariants hold under Starlette threadpool concurrency (proven by
a 6-way concurrent-correction guard vector). **Cross-process atomicity is not
guaranteed:** the local JSON snapshot is last-writer-wins across separate
processes, so true multi-process correction integrity requires normalized
persistence (Phase 04). That GA blocker stays open.

## Routes

- `POST /workspaces/{workspace_id}/field-corrections` → record a correction
  (permission `record_field_corrections`; readiness-gated in client mode;
  `422` on an unregistered field or invalid value).
- `GET /workspaces/{workspace_id}/field-corrections[?active_only=true]` → list
  history or active overlays (permission `view_field_corrections`).
- `POST /field-corrections/{correction_id}/revert` → revert an active
  correction (HTTP 409 if it is not active).
- `GET /field-corrections/registry` → the correctable-field catalog.

## Boundaries preserved

- **Source evidence is never overwritten.** Corrections are overlay records;
  the parsed document, `report_profile`, chunks, and citation lineage are
  untouched.
- **Deterministic extraction is unchanged.** No parser rule, unit conversion,
  or FORGE expectation is modified; the corpus evaluation remains 65/65.
- **Recommendation / Benchmarking boundary intact.** Recording a correction
  creates no anomaly events, benchmark measurements, failures, or validation
  tasks, and never touches the recommended-only Hydraulics / Torque & Drag
  diagnostics.
- **Tenant isolation.** Every correction is stamped with `tenant_id` and
  `workspace_id` and is only returned within its workspace; both the local-JSON
  and PostgreSQL snapshot backends persist the collection with no migration.

## Security and privacy

- The audit log records **who (actor context) / what field / when / why-length
  / version**, but never the raw corrected or source values or the free-text
  reason. The actor is attributed via the standard `actor_user_id` on every
  audit event; recording persists the correction state and the audit event in
  one `save()`, so they cannot diverge in-process.
- Persistence is additive: old snapshots without the `field_corrections`
  collection load as empty; no migration is required and both backends persist
  the new collection inside the existing tenant snapshot.

## Known limitations (honest scope)

- **Actor identity is the single configured actor, not a verified reviewer.**
  Authenticated per-user identity / RBAC does not yet exist (a separate
  identity-and-access increment); every correction is attributed to the one
  configured actor context (`actor_source="configured"`), with the
  `record_field_corrections` permission establishing the least-privilege write
  hook for when multi-user identity lands. **AUDIT-001 is not closed.**
- **Versioned, not immutable.** Superseding/reverting mutates the `status`/
  linkage of a persisted record; a tamper-resistant immutable-event model is
  follow-up. **AUDIT-004 / DLP-09 are addressed as a foundation, not fully
  closed.**
- **In-process concurrency only.** Cross-process correction atomicity requires
  normalized persistence (Phase 04).
- Corrected values are recorded and surfaced in the draft only; they are not
  yet propagated into official report JSON or formatted exports.

## Not a client-readiness or GA claim

This foundation is a software-owned enterprise-readiness increment. It does not
by itself confer GA, client, or production authorization. Real-client GA
remains blocked by the external-infrastructure (PostgreSQL/Redis),
reviewed-evidence, and organizational-approval gates reported by
`pnpm run ga:readiness`.
