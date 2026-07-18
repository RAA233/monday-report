# Field-Level Correction & Review-Provenance Foundation

This document specifies the auditable, tenant-scoped field-level correction
foundation. It addresses the enterprise readiness gaps that no correction /
revision-history entity existed (extractions could only be accepted or
rejected, never corrected with a preserved from/to trail).

## What a correction is

A `FieldCorrection` is an **append-only overlay record**. It captures a
reviewer's correction to a named extracted field **without overwriting** the
source-derived value or its lineage. The original extracted value is preserved
on the record, and the underlying parsed document / `report_profile` is never
mutated. Corrections are surfaced as **review-required overlays**, never as
confirmed source facts.

## Correction contract (Part H fields)

| Field | Meaning |
| --- | --- |
| `source_value` | The original extracted/source value, preserved on the record. |
| `corrected_value` | The reviewer's replacement value (may be `null`). |
| `correction_reason` | Free-text justification (never written to the audit log raw). |
| `reviewer_user_id` / `reviewer_email` / `reviewer_roles` | Reviewer identity captured from the configured user at record time. |
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

## Routes

- `POST /workspaces/{workspace_id}/field-corrections` → record a correction
  (permission `record_field_corrections`; readiness-gated in client mode).
- `GET /workspaces/{workspace_id}/field-corrections[?active_only=true]` → list
  history or active overlays (permission `view_field_corrections`).
- `POST /field-corrections/{correction_id}/revert` → revert an active
  correction (HTTP 409 if it is not active).

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

- The audit log records **who / what field / when / why-length / version**, but
  never the raw corrected or source values or the free-text reason. Reviewer
  identity is attributed via the standard `actor_user_id` on every audit event.
- Persistence is additive: old snapshots without the `field_corrections`
  collection load as empty; no migration is required and both backends persist
  the new collection inside the existing tenant snapshot.

## Known limitations (honest scope)

- **Reviewer identity is the single configured user.** Per-user
  authentication / RBAC does not yet exist (a separate identity-and-access
  increment); until then every correction is attributed to the one configured
  operator identity, with the `record_field_corrections` permission establishing
  the least-privilege write hook for when multi-user identity lands.
- Corrected values are recorded and surfaced in the draft only; they are not
  yet propagated into official report JSON or formatted exports.

## Not a client-readiness or GA claim

This foundation is a software-owned enterprise-readiness increment. It does not
by itself confer GA, client, or production authorization. Real-client GA
remains blocked by the external-infrastructure (PostgreSQL/Redis),
reviewed-evidence, and organizational-approval gates reported by
`pnpm run ga:readiness`.
