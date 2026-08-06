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

## 11. Environment 2 — a task-owned clean Hyper-V virtual machine

The Part-O minimum (`REQUIRED_ENVIRONMENT_MINIMUM = 2`,
`backend/app/offline_commercial_evidence.py`) needs a second clean Windows
environment. The first attempt used Windows Sandbox; it stopped executing its
logon command after a few launches on the certification host, so that
implementation is **retired** — the orchestrator, the `.wsb` template, the
session driver and the `audit:offline-sandbox` command are all removed, and the
Hyper-V route is the only supported Environment 2. The shared licensing,
activation, issuer, package-builder, evidence and combiner components are
unchanged.

**Installation.** Official Windows 11 Enterprise Evaluation media from the
Microsoft Evaluation Center, verified by full SHA-256, successful mount, an
Enterprise Evaluation image index, x64 confirmation, `Get-WindowsImage` metadata
and Microsoft signature posture. The image is applied with DISM
(`Expand-WindowsImage`) to a GPT/EFI VHDX, made bootable with BCDBoot, and
answered with a supported unattend file. **No requirement is bypassed** — no
`BypassNRO`, no registry injection, no offline hive edit, no TPM/Secure
Boot/CPU/activation/licensing bypass. If supported setup cannot complete, the
run stops with `HYPERV_WINDOWS_SETUP_NOT_ACCEPTED`.

**Mandatory security posture**, re-queried rather than assumed: Generation 2,
Secure Boot **On** with the **`MicrosoftWindows`** template (not a third-party
UEFI CA template), a local key protector, and a virtual TPM — verified host-side
via `Get-VMFirmware`/`Get-VMSecurity` and in-guest via `Confirm-SecureBootUEFI`
and `Get-Tpm`. Failure stops with
`HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED` and the matrix does not run.

**Isolation.** Zero network adapters during certification. A temporary adapter
bound to *no* virtual switch is permitted during installation only and is removed
before the clean baseline; the guest then proves no default route, no configured
DNS server and no external reachability. Transport is non-network throughout:
`Copy-VMFile` host→guest, PowerShell Direct guest→host.

**Guest credential.** Generated per VM, never reused, protected at rest by BOTH
DPAPI (bound to the elevated host user) and a filesystem ACL restricted to that
user and SYSTEM. Decrypted in memory only, immediately before a bounded
PowerShell Direct call. Never printed, logged, committed, packaged or evidenced;
a corrupted or absent blob fails closed with no blank/prompted fallback.

**Key isolation.** The operator private key never enters the VM, the guest disk,
the guest registry, the package, the transfer set, the guest result, the logs or
the evidence. The guest exports only a privacy-validated activation request; the
host signs outside the product and outside the VM; only signed licenses return.

**Cross-environment proof.** Both request phases run before either resume, so
the operator can issue each environment a *genuine* license bound to the **other**
environment's fingerprint. `PK19` then proves rejection in both directions, and
the combiner requires it of both environments.

## 12. Verification map

| Concern | Guard |
| --- | --- |
| License format, binding, expiry, rollback, updates, key hygiene, **mutation cycles** | `pnpm run audit:offline-license` |
| Runtime enforcement, read-only mode, backup/restore, localhost, single instance | `pnpm run audit:offline-runtime` |
| Built-package execution matrix (fresh install → uninstall), one environment | `pnpm run audit:offline-package` |
| Air-gapped signing boundary | `pnpm run audit:offline-airgap` |
| Environment 2 matrix inside the clean Hyper-V VM | `pnpm run audit:offline-hyperv` |
| Hyper-V isolation, security posture, credential protection, cross-environment rejection, **mutation cycles** | `pnpm run audit:offline-hyperv-isolation` |
| Two-environment combiner refusals, **mutation cycles** | `pnpm run audit:offline-combiner-faults` |
| Both matrices + the two-environment record | `pnpm run offline:two-environment-matrix` |
| Secret/privacy scan (seeded self-test) | `pnpm run audit:offline-secret-scan` |
| Evidence artifact + fault mutations | `pnpm run audit:offline-commercial-evidence` |
| Evidence generation | `pnpm run ga:offline-commercial-evidence` |

**Reproducing the evidence.** `ga:offline-commercial-evidence` executes the
secret scan, whose `OS04` compares the shipped package against the operator's
private key and FAILS CLOSED when it cannot. Regenerating the artifact therefore
requires `MONDAY_REPORT_OFFLINE_KEYS_DIR` to point at the operator keypair. This
is a real limitation on independent reproduction: a third party without the
signing key can re-derive every other section, and can verify the artifact's
seals, the sealed two-environment record and its re-derivation from the raw
runner records, but cannot regenerate `reproducible_payload_hash` end to end.

**What the chain proves, and what it does not.** Validation walks artifact ->
sealed record -> raw runner records, requiring them to agree field for field,
the record to re-derive from the raw records, and its seal to verify. Three
facts are MEASURED at guard time rather than read: this host's fingerprint
(`OE40`), the guest's fingerprint components (`OE42`), and the SHA-256 of the
archive, executable and manifests actually on disk (`OE43`).

It does NOT prove that either environment matrix was executed. `OE42` measures a
property of the VM, not of the run — anyone able to run the guard can run the
same probe against the same VM and record the result. No artifact-level check
can close that gap, because the verifier and the author are the same principal.
That is exactly what the artifact's `anti_tamper_is_deterrence_not_absolute`
disclosure means, and it is the same honest limitation §7 already states about
offline licensing: this tier DETERS fabrication and makes it laborious and
visible; it does not make it impossible.

Two earlier versions of this paragraph claimed more — first that a Hyper-V
guest's live identity comparison would disagree with a fabricated second
machine, then that an editor could not match a live fingerprint measurement.
Independent review demonstrated both false. Neither is claimed here.

Provision Environment 2:
`pnpm run offline:provision-environment-2 -- -Action all -IsoPath <verified media>`.

Build: `python packaging/build_offline_package.py --public-key <hex file>`.
