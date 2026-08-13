# Monday Report — Offline Edition (Windows-first)

The commercial offline package: fully functional without Internet access, no
Docker, no external PostgreSQL, no external Redis, localhost-only, signed
offline licensing with machine binding, expiration/renewal, local
backup/restore, and a SaaS-compatible licensing abstraction.

This document records the Part-D runtime audit, every packaging/licensing
decision, and the honest limitations. Nothing here claims production
database/queue target acceptance, SaaS acceptance, or GA.

## 1. Runtime audit (Part D) and deployment model

| Aspect | Finding | Offline Edition decision |
| --- | --- | --- |
| Frontend build | Vite SPA; `VITE_API_BASE_URL` baked at build time (default `http://127.0.0.1:8000`) | Build with `VITE_API_BASE_URL=""` → same-origin; the backend serves `dist/` itself. No CORS surface, any port works |
| Backend startup | `uvicorn backend.app.main:app` on 127.0.0.1 | Wrapped by `backend/app/offline_runtime.py`; `main.py` is byte-unmodified |
| State | `LocalStateStore` durable JSON (atomicity remediation accepted); paths via `MONDAY_REPORT_STATE_PATH` etc. | Local JSON backend (`local_json` + `inline_worker`); paths under the installation data dir |
| Queue | Inline enqueue + `worker.run_once()`; Redis optional | In-process worker thread (2s cadence), gated by the license decision |
| Auth | Demo/local mode does not enforce API keys; client mode requires per-user credentials + readiness | Offline-local mode (single user, loopback trust boundary). LAN mode is OFF by default and ENFORCES client mode + a configured API key before it will start |
| Python deps | FastAPI/uvicorn/pydantic/PyMuPDF/reportlab (+psycopg/redis lazily imported, PG-path only) | Packaged with PyInstaller; `psycopg`/`redis` excluded (verified lazy) |
| Node | Build-time only | **Not required at runtime** |
| Elevation | none required | Per-user install under `%LOCALAPPDATA%\Programs`; HKCU uninstall entry; **no administrator step exists** |

**Selected model:** PyInstaller one-folder app (`MondayReportOffline.exe`) with
prebuilt `dist/` bundled, per-user PowerShell installer (reviewed:
`packaging/installer/install.ps1` / `uninstall.ps1`), plus an Inno Setup script
(`packaging/innosetup/monday-report-offline.iss`) for the release pipeline that
owns code signing (Inno Setup is not part of this repository's toolchain).

## 2. Application data layout (Part L)

```
%LOCALAPPDATA%\Programs\MondayReportOffline\   application binaries (replaced on upgrade)
%LOCALAPPDATA%\MondayReportOffline\            mutable customer data (never touched by installer)
  config\      installation.json, license_state.bin (copy 1), runtime.lock.json, public key
  data\        monday_report_state.json, storage\, exports\, .license_state.bin (copy 2)
  licenses\    monday-report-license.json
  logs\        runtime logs
  backups\     monday-report-backup-*.zip
  tmp\         staged restores, scratch
```

Binaries and customer data are fully separated. Uninstall preserves customer
data by default; `uninstall.ps1 -RemoveData` is the explicit separate option.

## 3. Licensing abstraction (Part E)

`backend/app/licensing/contract.py` defines `LicenseProvider` with three
editions: `OfflineSignedLicenseProvider` (fully implemented),
`SaaSSubscriptionProvider` and `HybridOfflineLeaseProvider` (explicit
fail-closed placeholders returning `PROVIDER_NOT_IMPLEMENTED`). Business logic
consumes only the normalized `LicenseDecision` (state, edition, feature flags,
times, machine-binding result, product-version eligibility, renewal sequence,
read-only flag, typed `ReasonCode`, support code). SaaS support later means
implementing a provider — not rewriting enforcement.

## 4. License format (Part F)

`monday-report-license.v1`: canonical JSON (sorted keys, compact separators),
**Ed25519** via the audited `cryptography` library, signature over the document
minus `signature`. Strict field policy: unknown fields rejected, missing fields
rejected, wrong schema/product/algorithm rejected, `machine_fingerprint_hash`
must commit to `machine_binding`. The application embeds ONLY the public
verification key (`licensing_public_key.txt`, installed at package build). The
private key is generated and stored exclusively by the operator CLI
(`scripts/license_issuer_cli.py`) at an operator-chosen protected path or a
process-local environment reference; it is never committed, packaged, logged,
tested-in, evidenced, printed, or generated inside a customer installation.

## 5. Machine fingerprint (Part G)

`mr-machine-fingerprint.v1` — components (Windows): `machine_guid` (registry),
`smbios_uuid`, `board_serial`, `system_volume_serial`, and ONE aggregated
`physical_adapters` component (permanent addresses of physical adapters only;
VPN/TAP/loopback/virtual/WSL/Docker/Bluetooth adapters excluded). Placeholder
vendor values are excluded rather than bound. Raw values never leave
`fingerprint.py`: each is normalized deterministically and hashed
(SHA-256, domain-separated by version + component name).

- **MAC is one optional component, never sufficient**: a match requires at
  least one strong component (`machine_guid` or `smbios_uuid`).
- **Tolerance (documented threshold)**: `min(n, max(2, n-1))` of the issued
  components must match (the cap keeps a degraded single-component machine able
  to match itself; a strong component is still mandatory, so cross-machine
  rejection is unaffected) — one approved hardware change (adapter swap, re-serialized board)
  keeps a legitimate install working; a different machine fails.
- **Virtual machines**: detected via SMBIOS manufacturer/model markers and
  reported explicitly as `reduced_virtual_machine` confidence. A fully cloned
  VM shares every fact; clone resistance comes from the protected state/clock
  lineage, and this limitation is stated, not hidden.
- Missing optional facts degrade the component count; activation never crashes.
- The ONLY diagnostic ever surfaced: fingerprint version, eligible component
  count, confidence class, match/mismatch.
- Collection cost: the runtime collects the fingerprint ONCE per process
  (PowerShell CIM queries are expensive); every license evaluation reuses the
  hashes, and a hardware change is observed on the next application start.

## 6. Air-gapped activation and renewal (Part H)

`monday-report-activation-request.v1` carries: schema, installation id, hashed
machine binding + commitment hash, product version, requested edition, nonce,
timestamp — **no raw hardware identifiers** (operator-side validation rejects
raw component names/values). Flow: export request file → operator combines with
commercial terms (outside the repository) + private key → signed license file →
manual import. No Internet anywhere. Renewal = import a newer license;
`issue_sequence` is strictly monotonic per installation lineage: older or
same-sequence-different-id imports are rejected, and swapping an older license
file back on disk is detected at evaluation (`LICENSE_ROLLBACK_REJECTED`).

## 7. Clock rollback and tamper resistance (Part I)

`mr-license-state.v1`: non-sensitive facts only (license id, issue sequence,
highest trusted wall-clock epoch, last validation epoch, write counter,
integrity value). Stored as TWO copies (config dir + data dir), DPAPI-protected
on Windows (`CryptProtectData`, UI-forbidden, app entropy); the executable test
mode must be selected explicitly via env and never silently replaces DPAPI.
Backward movement beyond 48h tolerance ⇒ `CLOCK_ROLLBACK_DETECTED` (read-only).
UTC epochs make timezone changes and sleep irrelevant. Deleting ONE copy does
not reset the lineage (surviving copy wins by write counter); corrupted copies
fail closed (`STATE_INTEGRITY_FAILURE`).

**Expiry uses the monotonic trusted clock, not the system clock.** Both
evaluation and import compare against `max(system_clock, highest_trusted_epoch)`.
The 48h tolerance exists ONLY to avoid declaring hard rollback on legitimate
drift/NTP correction — it never hands licensed operation back. Without this, a
clock parked just inside the tolerance below an already-passed `grace_until`
would look like ordinary drift on every evaluation and restore full operation
indefinitely. Regression coverage: `LG29a`/`LG29b`, and mutation cycle `MUT05`
proves the gate is load-bearing.

**Recovery when protected state cannot be read.** DPAPI blobs are user-scoped,
so an admin-forced password reset, profile recreation, or moving the data
directory between accounts can leave both copies undecryptable — the
installation then reports `STATE_TAMPERED` / `STATE_INTEGRITY_FAILURE` and stays
read-only (data readable, backups still available). Recovery: take a backup,
delete both licensing-state files (`config\license_state.bin` and
`data\.license_state.bin` — the second is hidden), restart, and re-import the
current license. This re-anchors the clock lineage to the license issue time,
which is the same bounded limitation documented above.

**Honest limitation:** deleting every state copy in one pass re-anchors the
lineage to the license's own issue time. Offline licensing DETERS unauthorized
copying; it cannot make client-controlled hardware impossible to modify. No
perfect anti-tamper claim is made.

## 8. Expiration behavior (Part J)

| State | Behavior |
| --- | --- |
| valid | full operation |
| expiring soon (≤14d) | full operation + visible renewal warning |
| grace (`grace_until`) | full operation + renewal warning |
| expired | READ-ONLY: reads allowed, backups allowed, restore allowed (it cannot create licensed business operations); new mutations, report drafts, exports, signed-URL redemption, and worker business processing blocked with HTTP 423 |

Every blocked action returns: typed `reason_code`, license state, expiry/grace
dates, renewal action, `/license` page, `/offline/license/import` action, and a
support code — never a silent no-op. Customer data is never deleted, encrypted,
corrupted, or hidden by expiry, and backups always remain possible.

**Backups exclude the license file and licensing state** (documented): licenses
are machine-bound, so a backup restored on another machine requires that
machine's own license.

## 9. Offline update format (Part M)

`monday-report-update.v1`: signed manifest (product, version, minimum
compatible data version, prohibition floor, payload SHA-256, Ed25519).
`update_format.verify_update_manifest` rejects unsigned, tampered,
below-floor, older-than-installed, data-incompatible, wrong-product, and
wrong-key updates. No automatic Internet update checks exist.

## 10. Network posture

Default binding is `127.0.0.1` with a dynamically selected port (47613–47630,
then ephemeral). LAN mode requires BOTH `MONDAY_REPORT_OFFLINE_LAN=1` and
`MONDAY_REPORT_OFFLINE_LAN_ACK=I_UNDERSTAND_LAN_EXPOSURE`, and is not reachable
from any packaged UI. It is additionally **enforced** (not merely documented):
the runtime REFUSES to start in LAN mode unless
`MONDAY_REPORT_CLIENT_DATA_MODE=client` and a `MONDAY_REPORT_API_KEY` are
configured — the loopback boundary is what makes unauthenticated local mode
safe, so an unauthenticated API is never published to a network. A runtime lock file + live-port probe prevents two instances from
mutating the same state; stale locks are recovered after crashes.

## 11. Establishing the trust root (v2.1 — the design that governs C1–C4)

v2 removed the author's `.git` from every integrity decision. An independent
review then found the remaining, deeper hole: **v2 never established the trust
root itself.** `-ExportSource` ran the author's own just-copied
`scripts/offline_export_manifest.py`, through a `PATH`-resolved `python`,
elevated, and accepted the result on self-consistency alone (no
`-ExpectedRootHash`). Author-controlled code running as the operator minted the
very pin that the reviewer later treats as authority, and the "provenance" it
recorded was whatever the author's tree said. The C4 claim
"provenance is operator-recorded" was false, and #30's trusted-source-copy
constraint had been dropped entirely.

This section is the governing design. It is written **before** the fixes it
mandates, and every control below is verified by EFFECT (an executed call, a
computed hash, an applied ACL, a launched binary's identity) — never by the
presence of a string in a file.

### The eight invariants

1. **No author-controlled executable runs before source trust is established.**
   No repository Python helper, no `PATH`-resolved interpreter, no elevated
   repository script that mints its own manifest or root hash. Trust cannot be
   bootstrapped by the thing being trusted.

2. **The operator supplies OUT-OF-BAND pins from an independent pristine
   channel**: the exact expected export root hash, the exact SHA-256 of the
   bootstrap script, and the expected source commit/provenance. These arrive as
   parameters or from the operator-owned trust directory. They are **never**
   read from the author workspace or repository.

3. **The bootstrap script's own bytes are verified before it executes**, using
   trusted OS facilities only (`Get-FileHash`/.NET, and any native resolved
   from the verified System directory — never `PATH`), compared against the
   operator-supplied SHA-256. This is an operator step performed on a pristine
   copy; only a byte-matching bootstrap may run.

4. **Source acceptance is pinned, never self-consistent.** Author bytes are
   exported without consulting `.git`; the byte manifest and root hash are
   computed by a **non-author-controlled implementation** (the PowerShell side,
   using trusted natives and .NET only — no repository Python); the result is
   compared against the operator pin. Self-consistency-only acceptance is
   forbidden. Any `.git`/`.GIT`/`gitdir`/reparse point/case-collision refuses.

5. **C2 path identity is ordinal and collision-hostile.** No PowerShell
   hashtable ever carries file identity (they are case-insensitive and collapse
   slots). Canonical sorted paths, explicit ordinal comparison, Windows
   case-collisions rejected outright, and any PowerShell/Python twin
   disagreement is a FAILURE rather than a preference.

6. **C1 ACL evaluation is fail-closed and twin-identical.** A NULL DACL fails.
   An unknown or uninterpretable relevant ACE fails. An unsafe inherited or
   write-capable ACE fails. Owner and DACL are read through Windows ACL APIs.
   Both twins enforce the *same* semantics — parity is asserted on the
   predicate, not merely on the allowlist.

7. **Privileged natives are never `PATH`- or environment-derived.** Every
   privileged native — `icacls` included — resolves from the verified OS System
   directory through C1. `$env:USERNAME` is never an authorization operand: the
   intended operator/reviewer **SID** is derived and verified explicitly, and
   every native's exit code is checked. A bare-name native anywhere inside the
   boundary is a door around C1 and is therefore a defect, not a style issue.

8. **A trusted/pristine-source handover contract is explicit in the operator
   procedure.** The author workspace alone can *never* establish provenance.

### What this changes for the operator

The operator now supplies three out-of-band values, obtained from a channel
independent of the author's workspace, and runs the bootstrap from a **pristine
copy** whose hash they verified first. See §14 for the exact invocation.

### Honest scope of the v2.1 remediation

These invariants close the *establishment* of the trust root. They do not
change the protocol's standing residual (§17): the reviewer still executes code
the author wrote, and that is closed only by human review of the exact attested
commit. Nor do they claim resistance to a host administrator.

## 12. The terminating trust boundary (Offline Edition v2)

The earlier package established the reviewer's trust in the source by having the
reviewer operate on the author's own Git checkout. Six independent review rounds
each found one more way an author-controlled `.git` could steer an integrity
decision (config includes, `attributesFile`, gitdir pointers, alternates,
submodule `.git/modules` configs, `refs/replace`, the commit-graph,
per-directory `.gitignore`) — an unbounded class that enumeration cannot close.
v2 removes the class by construction, expressed as one governing sentence:

> **The reviewer executes only from a git-free, manifest-verified tree that the
> reviewer principal itself created; no author `.git`, environment variable, or
> pre-existing directory ever participates in an integrity decision.**

Four small designs implement it, each proving closure by EFFECT (a
fault-injected, fail-closed guard), never by enumerating what it forbids.

**C1 — trusted native resolution.** `packaging/hyperv/lib/trusted_natives.ps1`
and its Python twin `scripts/offline_trusted_natives.py` are the ONLY way
boundary code invokes a native binary. The system directory comes from
`[Environment]::GetFolderPath(System)` / `GetSystemDirectoryW` — never
`$env:SystemRoot`, never `PATH`, never a relative path. A fixed allowlist
(icacls, takeown, robocopy, schtasks, …) deliberately **omits git**, so git is
structurally uninvokable inside the boundary. Before first use, each binary's
owner must be TrustedInstaller/SYSTEM and no non-admin principal may hold a
write-capable right on it; an unreadable descriptor refuses. The decision
consumes zero author-controllable operands, so there is nothing left to
enumerate. Guard: `audit:offline-natives-trust` (poisoned SystemRoot/PATH →
mimic System32 ignored; user-owned ACL-defective plant refused; both twins).

**C2 — git-free export + manifest.** Source crosses the boundary as a flat byte
export plus a per-file SHA-256 manifest whose Merkle-style root hash the operator
pins into the reviewer trust root (`scripts/offline_export_manifest.py`,
`packaging/hyperv/lib/export_verify.ps1`). The manifest is computed from FILE
BYTES ON DISK — never `git archive`, never `hash-object`, nothing that reads a
repository. The reviewer re-hashes the actual bytes of its OWN fresh copy and
compares against the pin before any file is loaded. ANY `.git` component, any
`gitdir:` file head, or any reparse point anywhere in the export is an O(1)
refusal — a shape check, not a content scan. A missing or unreadable manifest or
pin is a refusal, never a skip. Guard: `audit:offline-export-integrity` (the
six-round `.git` corpus as fixtures — submodule config, refs/replace,
commit-graph, junctioned `.git`, gitdir pointer — each refused; byte flip;
missing manifest; pin mismatch; both twins).

**C3 — fresh, protected task root.** The task root is never adopted or reclaimed
(`packaging/hyperv/lib/task_root.ps1`). The reviewer creates it at a path
verified nonexistent, applies a restrictive DACL with inheritance broken BEFORE
any content, and copies content only file-by-file from the verified export
(never a move/rename of an author-owned tree). Every directory it creates is
opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked for the reparse
attribute; identity is confirmed by comparing the file ID of the handle used for
the ACL write against the file ID reached by path. There is no pre-existing tree
to scan for junctions — the adopted-directory class is removed by construction.
Guard: `audit:offline-taskroot-integrity` (pre-planted junction refused;
mid-copy junction race refused both on a colliding path and via the final
handle sweep; DACL read back through the creation handle).

**C4 — git-free code-execution boundary.** Git is absent from the C1 allowlist,
so boundary code cannot invoke it. Provenance (the source head) is carried as a
data string inside the C2 manifest — recorded by the operator OUTSIDE the
boundary, never queried from a repository inside it. All executed code comes only
from C2-verified files, and interpreters run isolated and site-less
(`python -I -S` on the dedicated runtime whose `._pth` omits `import site`, the
one earlier concept retained and rewritten). The repository-shape rule is O(1):
the author workspace has exactly one repository at its root and the export has
none. Guard: `audit:offline-boundary-shape` (git absent + uninvokable;
nested/no-repo refused; a seeded `sitecustomize`/PYTHONPATH does NOT load under
`-I -S`, and the SAME seed DOES load unisolated — proving the flag, not an inert
fixture).

## 13. Environment 2 — a task-owned clean Hyper-V virtual machine

Environment 2 remains a genuine Generation 2 Hyper-V VM installed from official
Microsoft evaluation media with Secure Boot (Windows template) and a virtual
TPM, driven one bounded stage at a time over PowerShell Direct. **No requirement
is bypassed** (no `BypassNRO`, no registry injection, no TPM/Secure Boot/CPU/
activation bypass); the host's `bcdboot` is resolved through C1. Zero network
adapters during certification; transport is `Copy-VMFile` host→guest and
PowerShell Direct guest→host. The operator private key never enters the VM, the
guest disk, the package, the transfer set, or the evidence. Both request phases
run before either resume, so each environment can be issued a genuine licence
bound to the OTHER environment's fingerprint and prove rejection in both
directions.

**This task does not execute Environment 2.** The two-environment matrix and the
commercial-evidence artifact require a built package AND a real Hyper-V run;
absent that record the package and commercial verdicts stay **NOT_ACCEPTED**,
and the generators/guards report the honest "package not built" / not-accepted
state rather than passing vacuously.

## 14. Operator procedure (v2 deltas from the earlier package)

The architectural fix changes operator steps. Flagged deltas:

- **CHANGED — source handover.** The operator produces the git-free export and
  manifest and pins the root hash into the reviewer trust root; the reviewer
  never touches the author's checkout or `.git`.
  `reviewer_bootstrap.ps1 -ExportSource -SourceWorkspace <author checkout>
  -SourceCommit <hex> -SourceTree <hex> -AuthorAccount <name>` enforces the O(1)
  repository-shape rule, copies bytes file-by-file, generates the manifest from
  disk bytes, and pins the root hash.
- **CHANGED — no pre-staged task root.** The operator must NOT pre-create or
  stage the reviewer task root; the session creates a fresh copy per run and
  bootstrap refuses any pre-existing path (no adopt/reclaim).
- **CHANGED — provenance recorded, not discovered.** The source head is a
  manifest field the operator records outside the boundary, never queried from a
  repo inside it.
- **UNCHANGED — dual-principal protocol.** operator ≠ author account (bootstrap
  refuses `OFFLINE_OPERATOR_IS_AUTHOR` when they resolve to the same SID); the
  reviewer key is generated AFTER the operator sets the password (by
  construction — key generation happens only inside the reviewer session the
  stored password enables); the live-reviewer-credential red line
  (`OFFLINE_OPERATOR_HANDOFF_REVIEWER_STATE_UNSAFE` /
  `OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE` — never create-or-reset over live
  DPAPI state); licence-issuance brokering (the reviewer never holds the issuer
  key).

Operator order: `reviewer_bootstrap.ps1 -RegisterTask -AuthorAccount <name>`
(creates the non-administrative reviewer, installs the session scripts into an
operator-owned protected bin, registers the scheduled task), then
`-ProvisionPaths`, then `-ExportSource`. The reviewer is driven with
`schtasks /Run` (stored credential, no password). `-Verify` reports the current
bootstrap facts.

## 15. Verification map

| Concern | Guard |
| --- | --- |
| C1 trusted natives (poison + ACL plant, both twins) | `pnpm run audit:offline-natives-trust` |
| C2 export manifest (six-round `.git` corpus, byte flip, missing manifest, pin) | `pnpm run audit:offline-export-integrity` |
| C3 fresh task root (pre-plant + mid-copy junction race, handle identity) | `pnpm run audit:offline-taskroot-integrity` |
| C4 git-free boundary (git uninvokable, repo shape, isolated interpreter) | `pnpm run audit:offline-boundary-shape` |
| Dedicated site-less reviewer runtime | `pnpm run audit:offline-reviewer-runtime` |
| audit:all offline-membership pin | `pnpm run audit:offline-audit-membership` |
| License format, binding, expiry, rollback, updates, key hygiene | `pnpm run audit:offline-license` |
| Runtime enforcement, read-only mode, backup/restore, localhost, single instance, **SPA deep-route serving** | `pnpm run audit:offline-runtime` |
| Air-gapped signing boundary | `pnpm run audit:offline-airgap` |
| Secret/privacy scan (seeded self-test) | `pnpm run audit:offline-secret-scan` |
| E2 guest-runner handshake (explicit head binding, fail-closed) | `pnpm run audit:offline-e2-handshake` |
| Brokered issuance + witness anti-replay | `pnpm run audit:offline-broker-issuance` |
| Authoritative evidence contract (hermetic validator, in `audit:all` membership) | `pnpm run audit:offline-evidence-contract` |
| Two-environment combiner refusals | `pnpm run audit:offline-combiner-faults` |
| Built-package execution matrix (needs a package build) | `pnpm run audit:offline-package` |
| Commercial evidence artifact / generation (needs package + Hyper-V E2) | `pnpm run audit:offline-commercial-evidence` / `pnpm run ga:offline-commercial-evidence` |

The four C1–C4 guards run in `audit:all` immediately after the harness guard;
membership is pinned in `scripts/offline_audit_membership_manifest.py` and
asserted redundantly from `audit_harness_guard` (not an offline guard).

## 16. The dual-principal acceptance protocol

The authoritative acceptance anchor is a fact the authoring process cannot
manufacture: an Ed25519 signature from a key held by a SEPARATE Windows
principal (`MR-OFFLINE-REVIEWER`) whose DPAPI-sealed credential the author never
learned (`backend/app/offline_review_attestation.py`). The author holds the
worktree, the package build, the licence-issuer key and the evidence body; the
reviewer holds the review key, both matrix executions and the attestation. The
reviewer is `Users` + `Hyper-V Administrators`, never `Administrators`.

Source integrity is established UPSTREAM of the signature by C2 (the export
manifest + operator pin), reconciled in
`scripts/offline_reviewer_execute.py::_head_binding_reasons`; the attestation's
`source_commit`/`source_tree` are the operator-recorded provenance the manifest
carries. The verdict is DERIVED: `accepted`, `verdict`, `checks_passed` and
`environment_count` are untrusted inputs, and the author-side validator can only
downgrade — acceptance requires both the reviewer's signed verdict and the
locally derived one. What the validator refuses: legacy v1 acceptance; missing,
unsigned or replaced attestation; a review key supplied only by the artifact;
author and reviewer sharing a key or principal; a copied `ENVIRONMENT_1`
masquerading as `ENVIRONMENT_2` even when re-sealed and re-signed; different
package hashes; a different commit or tree; an attestation reused for a new
package or transcripts; a modified transcript; a hand-edited `accepted` field
(`audit:offline-evidence-contract`, hermetic, 29 checks).

## 17. What this protocol does NOT claim

Stated plainly, because each of these was at some point claimed and was wrong.

1. **It does not resist a host administrator** who takes ownership of the
   reviewer account. Declared non-goal.
2. **A signature does not prove the matrices executed.** It proves the review
   key signed a set of values.
3. **The reviewer executes code the author wrote.** A runner committed by the
   author that emitted an all-PASS list without executing anything would produce
   genuine hashes and a genuine signature over fabricated facts. Tool hashes
   record *which* binary ran, never that it was honest. **This is the protocol's
   real residual, closed only by human review of the exact attested commit.**
4. **Validator integrity rests on human review** of that same commit. A program
   cannot authenticate itself to itself.
5. **The C1–C4 designs terminate a class, they do not make tampering
   impossible.** They remove the author-controllable operands from each integrity
   decision, so the specific unbounded `.git`-internals class cannot recur; they
   do not defend against a principal who can act AS the reviewer, which is the
   boundary the whole protocol rests on.
6. **Audit membership is deterrence, not impossibility.** Removing offline
   validation requires coordinated edits to `package.json`, the frozen manifest,
   and `audit_harness_guard`.
7. **DPAPI here is a process guard,** not cryptographic separation between
   humans: it prevents the authoring tooling and any accidental cross-account
   read from decrypting the review key on the ordinary path.

Bootstrap: `.\packaging\hyperv\reviewer_bootstrap.ps1` — **run by the operator.**
