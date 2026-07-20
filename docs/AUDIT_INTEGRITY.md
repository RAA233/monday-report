# Audit-chain integrity — versioned HMAC foundation

This increment replaces the forgeable, unkeyed SHA-256 audit chain with a
**versioned, keyed HMAC-SHA256** integrity envelope. It is a bounded foundation:
it adds keyed signing + verification + rotation, but it deliberately does **not**
add an external audit anchor and does **not** detect tail truncation.

> Reviewer-controlled outcomes (field correction / validation) additionally carry
> **verified reviewer attribution** whose keyed-audit actor matches the outcome
> reviewer — see `docs/VERIFIED_REVIEWER_ATTRIBUTION.md`. This inherits the threat
> model here (authenticity of recorded keyed events); it adds no non-repudiation.

## Threat model

**Protects against** (with a configured, managed audit secret):

- accidental snapshot corruption;
- unauthorized **offline modification** of a snapshot by an actor who can alter the
  state file but does **not** possess the audit secret;
- modification of any signed field or of the chain linkage without the key;
- forged events created only with the **publicly known SHA-256** algorithm.

**Does NOT protect against** (documented, out of scope):

- a **compromised application process** that can read the HMAC key. The process
  that signs an event necessarily reads the active key, so keyed HMAC protects the
  snapshot-at-rest against an actor *without* the secret — it is **not** a claim
  that the key is unreadable by the signing process;
- a **malicious administrator** with access to both the state and the secret;
- **tail truncation** — deleting the most recent N events (see below);
- deletion of the **entire keyed suffix**, which can leave a valid legacy prefix;
- **rollback** to an older complete snapshot;
- **external** audit-log destruction.

## HMAC envelope (v2)

- **Algorithm:** `HMAC-SHA256` over a canonical payload, keyed by a managed
  secret. `integrity_version = 2`, `integrity_algorithm = "HMAC-SHA256"`.
- **Canonical payload** (`store._canonical_v2_audit_payload`): UTF-8, `sort_keys`,
  compact separators `(",", ":")`, explicit JSON `null`s, deterministic and
  byte-identical across repeated canonicalization. It includes every
  security-relevant field: the integrity envelope (version / algorithm / key id /
  key version), the event id, the timestamp, the tenant id, the actor (user id,
  source, roles), the action, the resource type/id, the **redacted** metadata, and
  the **previous hash**. Chain linkage/position is carried by `previous_hash`;
  audit metadata is already redacted by `audit_safety.sanitize_audit_metadata`, so
  the payload carries no machine-specific paths or secret material.
- **Linkage:** each v2 event's `previous_hash` is the prior event's `entry_hash`,
  so reordering, insertion, or middle-deletion breaks verification.

## Key provider (`backend/app/audit_keys.py`)

A bounded provider contract — **not** a key-management service and **no** automatic
rotation scheduler:

- `active_key()` — the current signing key (id + version + secret), or `None`.
- `key_for(key_id, key_version)` — resolve any known key for **verification**.
- `available_versions()` / `provider_type()`.
- The environment provider reads `MONDAY_REPORT_AUDIT_HMAC_KEY` (base64 or UTF-8,
  **≥ 32 bytes**), `MONDAY_REPORT_AUDIT_HMAC_KEY_ID`, `MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION`,
  and optional verification-only `MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS`
  (`[{key_id, key_version, secret}]`).
- **Rejected:** a missing key for a client request mutation, a short key, malformed
  encoding, a non-integer/`<1` version, and a duplicate key id/version with a
  different secret. An **unknown historical key version** at verification time is
  reported as `key_unavailable`.
- **Only non-secret metadata** is ever exposed: key id, key version, provider type,
  and a one-way truncated-SHA-256 **fingerprint**. Key material is never written to
  the snapshot, audit events, source control, generated evidence, logs, or errors.

### Rotation

One active version signs new events; zero or more retained versions verify older
events. Verification selects the key by **each event's stored key id/version** —
there is no "verify everything with the latest key" behavior. Rotating without
retaining a still-referenced version makes those events `key_unavailable`.

**Snapshot consistency (per-append).** The provider reads the environment on every
`active_key()` call, and `audit()` resolves the active key **exactly once per
event** under `audit_lock` — so a single event is always sealed under one key
id/version and can never be split across a rotation. A rotation takes effect at the
**next event boundary**. There is no per-process snapshot; a multi-event logical
operation may span a rotation, which is acceptable because each event self-describes
its key and this store provides no multi-event transactional atomicity.

## Demo vs client behavior

- **Demo/local, no key configured:** new events are written under clearly-labelled
  **legacy** integrity (unkeyed SHA-256, `integrity_version = None`); the status is
  never reported as keyed. No prior events are rewritten.
- **Any mode, key configured:** new events use v2 HMAC; old events stay legacy; the
  chain may report a **mixed** legacy/keyed state.
- **Client mode, key unavailable/invalid — fail closed for EVERY actor.** Client
  mode **never** writes a new unkeyed event and **never** persists a keyless
  business mutation, for any actor — authenticated request, system/bootstrap,
  worker, CLI, startup, or denial. There is no `actor_source == "system"` carve-out
  and no silent SHA-256 fallback. This is enforced at four layers:
  - **Edge preflight (`main.py`):** in client mode, if no valid active key, EVERY
    non-public HTTP request returns a stable **503** *before* authentication,
    authorization, routing, or any business/audit attempt — protected GET/HEAD,
    invalid-credential requests, permission/tenant denials, docs, readiness detail,
    and signed-capability issuance/redemption. Only a narrow public allow-list
    (minimal `/health` + CORS preflight) stays available. No denial event is
    written and no protected data is disclosed.
  - **Mutation preflight (`store.require_audit_write_capability`):** every
    business-mutation entry point (see the table below) calls it FIRST, so a
    keyless client-mode mutation raises `AuditIntegrityUnavailable` **before**
    touching in-memory state — no orphan business record, no audit event, no
    snapshot write. The worker (`process_queued_jobs`) and the `identity_admin`
    CLI fail closed the same way with a key-material-free error.
  - **Audit backstop (`store.audit`):** a business-mutation audit raises; a
    rejection/denial audit skips (never written unkeyed).
  - **Diagnostic startup:** when a client-mode process starts with no valid active
    key, the store starts **read-only / diagnostic** — it does **not** seed demo
    records, initialize benchmarking defaults, reset the bootstrap, append any audit
    event, or write the snapshot (no partial mutable initialization). Existing state
    is loaded read-only. Readiness reports the missing/invalid key as BLOCKED
    (without exposing key material); all mutations fail closed.

## Legacy → v2 transition

Historical events are **never re-signed**. Verification checks each legacy event
with the legacy SHA-256 algorithm and each v2 event with its recorded key
id/version. The first v2 event references the current legacy head hash; subsequent
v2 events use HMAC. There is **no startup migration or backfill**, and read routes
do not rewrite the snapshot.

**Forward-only keying (`legacy* keyed+`).** Once **any** keyed v2 event exists in
the chain, every later event must be keyed:

- `audit()` refuses to append a legacy event behind a keyed suffix (raises), so a
  demo-mode key disappearance after keying, or a client-mode keyless write, cannot
  extend a keyed chain with an unkeyed event.
- The **verifier** classifies a legacy (or pre-seal) event appearing *after* the
  keyed suffix begins as **`broken`** — never `legacy_valid`, `mixed_valid`, or
  `sealed`. Allowed shapes: empty, legacy-only, keyed-only, or a legacy prefix
  followed by a keyed suffix. Forbidden: `keyed → legacy` and `legacy → keyed →
  legacy`.

`audit_integrity_status()` reports both a backward-compatible `status`
(`empty`/`sealed`/`legacy`/`broken`, where `sealed` means the hash chain is
intact — **not** a claim of keying) and a precise `integrity_state`:

| `integrity_state` | meaning |
|---|---|
| `empty` | no events |
| `legacy_valid` | chain intact, all events legacy (unkeyed) — **not keyed** |
| `mixed_valid` | chain intact, some legacy + some keyed — **not fully keyed** |
| `keyed_valid` | chain intact, all events keyed (HMAC-SHA256) |
| `key_unavailable` | a keyed event's verification key is unavailable |
| `broken` | a verification or linkage failure |

`legacy_valid` and `mixed_valid` are **not** described as fully keyed.

## Mutation-writability preflight (every client-mode entry point)

`require_audit_write_capability(operation)` is called **before any business
mutation** at every non-demo client-mode mutation entry point. In client mode with
no valid key it raises `AuditIntegrityUnavailable` *before* the method touches
in-memory state → no orphan business record, no audit event, no snapshot write.

| Entry point | Actor source | Business mutation | Audit action | Preflight | Guard |
|---|---|---|---|---|---|
| `create_user` / `set_user_status` | request / CLI | users | `auth.user.*` | `require_audit_write_capability` | `audit-keyed-integrity` 77, `identity-rbac`, `api-auth` |
| `create_credential` / `revoke_credential` | request / CLI | api_credentials | `auth.credential.*` | preflight | `identity-rbac`, `api-auth` |
| `create_workspace` | request | workspaces | `workspace.create` | preflight | edge 60/61, `route-rbac` |
| `create_upload` / `create_uploaded_file` / `complete_upload` | request | uploads/files/jobs | `upload.*` | preflight | `signed-url`, `malware`, e2e |
| `process_queued_jobs` (worker) | worker | jobs/docs/chunks/failures | `document.*`/`processing_job.*` | preflight | `audit-keyed-integrity` 78 |
| `update_validation_task` | request | tasks/failures | `validation_task.update` | preflight | e2e |
| `record_field_correction` / `revert_field_correction` | request | field_corrections | `field_correction.*` | preflight | `field-corrections` |
| `create_monday_report` / `export_monday_report` | request | reports/exports | `monday_report.*` | preflight | e2e, `report-draft` |
| `update_benchmark_value` / `record_benchmark_measurement` | request | benchmarks/anomalies | `benchmark_*` | preflight | `benchmarking` |
| `dismiss_diagnostic_action` | request | anomaly events | `diagnostic_action.dismiss` | preflight | `benchmarking` |
| `run_retention` (apply) | request/admin | 9 collections + disk | `retention.run` | preflight (apply only) | `retention` |
| signed-URL issuance / redemption | request | audit + expiring URL | `*.signed_url`/`*.download` | edge 503 + audit backstop | `signed-url` 63 |
| startup seed / benchmarking-default init | system | workspace/benchmarks | `state.bootstrap`/`benchmark_config.seed` | diagnostic-startup gate | `audit-keyed-integrity` 72-75 |
| HTTP denials (permission/tenant/auth) | request/system | none | `*_denied`/`*_blocked` | edge 503 (client no-key) | `route-rbac`, `tenant-authorization` |

## Atomicity — scope and honest limitations

`audit()` serializes read-previous → build → HMAC → append → save under
`audit_lock`, so concurrent appends chain linearly and key versions never cross
events. The **no-key** path is prevented *before* mutation by the preflight above.
This increment does **not** implement a store-wide transactional refactor; the
following are **known non-atomic paths** and remain declared blockers
(persistence-locking / normalized persistence / transaction safety):

- **Key-unavailable failure is pre-mutation and fail-closed** (the preflight),
  so a keyless client-mode operation leaves no in-memory business mutation, no
  audit append, and no snapshot save.
- **HMAC** authenticates the *recorded keyed events* — it proves authenticity, not
  transactional business/audit consistency.
- **Save failure after a business mutation may remain non-atomic.** A store method
  applies its business mutation to the shared in-memory singleton *before*
  `audit()`; `audit()` rolls back only its own append on a snapshot-write failure,
  not the caller's business mutation. A concurrent whole-snapshot `save()` can also
  persist an already-applied business mutation before its audit append.
- **Cross-thread whole-snapshot mutation remains last-writer-risk**, and
  **cross-process transactional consistency is not provided** — the local JSON
  snapshot is last-writer-wins.

The `audit-keyed-integrity` readiness control is scoped to **HMAC authenticity +
forgery rejection + client fail-closed** only; it does **not** assert
transactional business/audit consistency.

## No external anchor / no tail-truncation detection (this PR)

Deleting the entire v2 suffix can leave a valid legacy prefix that still verifies;
deleting a keyed tail leaves an internally consistent keyed prefix. **Neither is
detectable without an externally persisted checkpoint**, which this increment does
**not** implement. There is deliberately no local sidecar, same-directory file,
same-process checkpoint, or ACL approximation presented as an anchor.
`audit-tail-truncation-detection` remains **BLOCKED**.

A future increment must design a genuinely external append-only checkpoint or
service with a defined event/anchor **atomic-delivery** protocol, append
acknowledgement, failure recovery, idempotency, rollback behavior, outage policy,
reconciliation, and operational ownership.

## Readiness behavior

- `audit-keyed-integrity` is **evidence-driven** (`ga_readiness._audit_keyed_integrity_probe`):
  PASS-capable **only** when an active managed key exists **and** a fresh v2 event
  round-trips under HMAC while a public-SHA forgery of the same payload is
  rejected, the client fail-closed wiring is present, and no key material is
  exposed. With no active key (or only legacy events) it stays **BLOCKED** — it
  never flips to PASS on code presence alone. The blocker registry is unchanged.
- The generic `audit_hash_chain` client-data readiness check confirms internal
  hash **linkage** only; it is **not** evidence for the keyed-integrity blocker and
  must not be read as a keying claim. The `audit-keyed-integrity` blocker uses
  **only** v2/HMAC runtime evidence (above).
- The backward-compatible `status` field is a linkage-verification result only. No
  UI, report, readiness display, screenshot, or doc infers keyed protection from
  `status == "sealed"`; `integrity_state` is the display authority (`legacy_valid`
  = warning/unkeyed, `mixed_valid` = keyed suffix over unkeyed history, `keyed_valid`
  = positive, `key_unavailable`/`broken` = error, `empty` = neutral).
- `audit-tail-truncation-detection` stays **BLOCKED**.
- **GA remains `GA_BLOCKED`.**

## Operational key requirements

Provision `MONDAY_REPORT_AUDIT_HMAC_KEY` (≥ 32 random bytes) from a managed secret
the state-file writer does not control; set a stable `KEY_ID`/`KEY_VERSION`; on
rotation, move the new key to active and add the previous key to
`RETAINED_KEYS` until all events signed by it are aged out. Client mode requires
an active key; without one, request mutations fail closed and readiness is BLOCKED.

## Verification

`scripts/audit_keyed_integrity_guard.py` (`pnpm run audit:audit-keyed-integrity`,
chained into `audit:all`) proves all of the above across 58 vectors, including the
reproduced baseline forgeability + tail-truncation, HMAC/tamper/forgery rejection,
canonicalization stability, legacy transition with no rewrite, rotation, client
fail-closed, atomicity/concurrency, no key leakage, and the readiness dispositions.
