# Verified reviewer attribution (AUDIT-001)

Correction and validation **outcomes** are attributed to a **verified authenticated
human reviewer** — server-derived, permission-eligible — instead of the single
configured actor context. Enforced by `scripts/verified_reviewer_guard.py`
(`audit:verified-reviewer`, in `audit:all`) and the evidence-driven
`ga_verified_reviewer_identity` readiness probe.

## Verified reviewer definition

A reviewer is **verified** only when ALL of the following hold, read entirely from
the request-scoped **server** identity and stored records (never from client input):

- `actor_source == "authenticated"` (a request-scoped per-user credential resolved
  server-side; the demo/local `demo_bootstrap` and the `system`/configured default
  context are **not** verified);
- the user is an **active, non-bootstrap** `User`;
- the credential is **active** and bound to the reviewer and the request tenant;
- the user, credential, and identity are all bound to the **configured request
  tenant**;
- the reviewer is **eligible through the permission policy** (`permissions.py`), not
  a hardcoded role name.

Unknown roles/permissions **deny**. `store.resolve_verified_reviewer(permission,
operation)` performs this check and, in **client mode**, raises `ReviewerNotVerified`
(HTTP **403**) **before** any outcome mutation or audit append.

## Permission-based eligibility

| Workflow | Permission (`permissions.py`) |
|---|---|
| Field-correction record / revert | `record_field_corrections` |
| Validation-task resolution | `resolve_validation` |

Eligibility uses `has_permission(roles, permission)` — the same authority that gates
the routes — so a reviewer who lacks the permission is denied even if authenticated.

## Correction attribution

`record_field_correction` and `revert_field_correction` copy the verified reviewer
from the server identity onto the `FieldCorrection`:

- record → `reviewer_user_id`, `reviewer_credential_id`, `reviewer_credential_fingerprint`,
  `reviewer_roles`, `reviewer_actor_source`, `reviewer_verified_at`;
- revert → `revert_reviewer_user_id`, `revert_reviewer_credential_fingerprint`,
  `revert_reviewer_roles`, `revert_reviewer_actor_source`, `revert_reviewer_verified_at`.

The **reverting** reviewer is kept **distinct** from the original recorder. The
source-derived value and lineage are never mutated — a correction remains a
versioned overlay (see `docs/FIELD_CORRECTIONS.md`).

## Validation attribution — terminal outcomes only

A verified reviewer is required, and `reviewer_*` attribution is recorded, **only for
a TERMINAL review OUTCOME** — a transition to `validated`, `rejected`, or `conflict`
(a human review decision; `update_validation_task` is a human-only route, and
`conflict` is never system-generated). A transition to `open` (**reopen / pending**)
is an **administrative** update: it is **not** reviewer-gated and **clears** the
outcome reviewer fields so a reopened task never claims a verified reviewer — an
administrative update cannot create false reviewer evidence. The audit event records
`review_outcome` (true/false) and the acting actor either way.

## Audit / HMAC relationship

Each outcome writes a **keyed** (HMAC-SHA256) audit event whose actor
(`actor_user_id`/`actor_source`/`actor_roles`/`actor_credential_fingerprint`, from
`current_identity()`) equals the outcome's reviewer, plus explicit
`reviewer_verified`/`reviewer_actor_source` metadata. Outcome attribution and audit
attribution therefore agree by construction. This inherits the versioned-HMAC threat
model (`docs/AUDIT_INTEGRITY.md`); it does **not** add cryptographic non-repudiation
or an external anchor.

## Privacy / redaction

Only **non-secret** attribution is stored: user id, credential id, the one-way
**credential fingerprint**, roles, actor source, and a verify timestamp. The **raw
token** and the **credential hash** are never written to the outcome, the audit log,
or evidence. Client-supplied `reviewer_*`/`tenant`/`email` fields are ignored — the
`FieldCorrectionCreate`/`ValidationTaskUpdate` payloads carry no reviewer fields, and
attribution is copied only from the server identity.

## Demo / bootstrap limitations

Demo/local mode remains compatible: a `demo_bootstrap`/configured/system action is
allowed but is explicitly **labelled unverified** (`reviewer_actor_source =
demo_bootstrap`/`system`, `reviewer_verified_at = null`). A demo action is **never**
described as verified human review and **cannot** satisfy the
`verified-reviewer-identity` control.

## Old-snapshot behavior

The `reviewer_*` fields are additive and optional. Pre-AUDIT-001 snapshots load with
absent reviewer fields (`reviewer_user_id = null`); there is **no startup migration
or backfill** and read routes do not rewrite the snapshot. Local JSON and Postgres
JSONB both preserve the reviewer fields on new outcomes.

## Transaction limitations

Reviewer verification fails closed **before** the outcome mutation. However, this
increment does **not** add transactional business/audit atomicity: a save failure
after the in-memory mutation, whole-snapshot concurrent mutation, and cross-process
consistency remain unresolved (`persistence-locking-transactions`,
`correction-cross-process-atomicity`). The audit chain read→append→save stays
serialized under `audit_lock`, and concurrent reviewer identities remain distinct.

## Attribution consistency verifier

`store.verify_reviewer_attribution_consistency()` re-reads every reviewer-attributed
outcome **and** its matching keyed audit event and confirms they agree on reviewer
user id, actor source, roles, credential fingerprint, and tenant, that the audit
event is keyed, and that it records the reviewer verification — returning any
mismatches. It is exercised by the behavioral guard (and by the readiness probe), so
consistency is **verified behaviorally**, not asserted "by construction."

## Readiness behavior

`ga_verified_reviewer_identity` is **evidence-driven**, and the **decisive** PASS
condition is a **real behavioral run** (`_verified_reviewer_behavioral_evidence`) on
a throwaway, fully isolated client-mode store (tempdir state, env restored, never
touches live state): an eligible authenticated reviewer records a correction whose
verified attribution matches the keyed audit actor; a second reviewer reverts
(reverter distinct); a terminal validation outcome attributes the reviewer; an
administrative reopen creates no verified evidence; a system actor is rejected before
mutation; the consistency verifier is clean; and no credential material leaks.
Source-string wiring + schema-field checks are **supporting parity only** — they can
**never** make the control PASS without the behavioral evidence; when the behavioral
contract cannot be exercised, the control stays **BLOCKED**. The full HTTP client-mode
route stack (auth → permission → tenant → reviewer → store → keyed audit, with only
the client-readiness gate bypassed) is proven by `audit:verified-reviewer`. The
registry is **unchanged**; `audit-keyed-integrity` stays PASS-capable with a key,
`audit-tail-truncation-detection` stays **BLOCKED**, `tenant-authorization-enforcement`
stays **BLOCKED** (normalized RLS pending), the persistence/transaction blockers stay
**BLOCKED**, and **GA stays `GA_BLOCKED`**.

## Remaining gaps (uncovered workflows)

The registry resolution condition is **correction/validation** outcomes — both are
covered. **AI-content approval** (`approve_ai_content`) and **client-report issuance**
(`issue_client_reports`) are outside this control's resolution condition and are
**not** given verified-reviewer attribution here; extending reviewer attribution to
them (and cryptographic non-repudiation / external anchoring) is a separate future
increment. No claim of complete reviewer coverage across all approval workflows is
made.
