# Audit-chain integrity — versioned HMAC foundation

This increment replaces the forgeable, unkeyed SHA-256 audit chain with a
**versioned, keyed HMAC-SHA256** integrity envelope. It is a bounded foundation:
it adds keyed signing + verification + rotation, but it deliberately does **not**
add an external audit anchor and does **not** detect tail truncation.

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

## Demo vs client behavior

- **Demo/local, no key configured:** new events are written under clearly-labelled
  **legacy** integrity (unkeyed SHA-256, `integrity_version = None`); the status is
  never reported as keyed. No prior events are rewritten.
- **Any mode, key configured:** new events use v2 HMAC; old events stay legacy; the
  chain may report a **mixed** legacy/keyed state.
- **Client mode, request write, key unavailable/invalid:** the write **fails
  closed** — `audit()` raises `AuditIntegrityUnavailable` **before** any append or
  save, so neither the audit event nor the in-flight business mutation is
  persisted, and the API returns a stable **503**. Client mode never writes a new
  unkeyed request event; there is no silent SHA-256 fallback. (System/bootstrap
  writes, which run before any request and only when the key is absent — a
  not-ready misconfiguration — fall back to labelled legacy rather than crash
  startup; readiness reports the missing key.)

## Legacy → v2 transition

Historical events are **never re-signed**. Verification checks each legacy event
with the legacy SHA-256 algorithm and each v2 event with its recorded key
id/version. The first v2 event references the current legacy head hash; subsequent
v2 events use HMAC. There is **no startup migration or backfill**, and read routes
do not rewrite the snapshot.

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

## Atomicity limitations

`audit()` serializes read-previous → build → HMAC → append → save under
`audit_lock`, so concurrent appends chain linearly and key versions do not cross
requests. On a key/HMAC failure it persists neither the event nor the business
mutation; on a snapshot-write failure it rolls back the in-memory append and
re-raises rather than claim success. This is **in-process** integrity only — the
local JSON snapshot remains last-writer-wins across processes, so
**cross-process** transactional and persistence-locking guarantees are unchanged
and remain declared blockers.

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
