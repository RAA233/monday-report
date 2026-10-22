# Roadmap

This is the honest list of what is unfinished, why, and roughly what it costs.

It is derived from `evals/ga/blocker_registry.v1.json` — 28 machine-checked
controls that gate general availability — plus work items found in code and in
stopped branches. Effort labels (`SMALL` / `MEDIUM` / `LARGE`) are the
registry's own.

**Current gate:** `GA_BLOCKED` — 20 BLOCKED, 5 SKIPPED, 2 PASS,
1 REVIEW_REQUIRED. See [STATUS.md](../STATUS.md).

---

## Good first contributions

Ranked by *value per unit of pain*, not by importance.

### 1. Replace the AGPL PDF backend — `MEDIUM`

`PyMuPDF` is AGPL-3.0-or-commercial and is the main reason this project is
AGPL. Swapping it for `pypdf` or `pdfplumber` (both permissive) would:

- remove the AGPL obligation from distributed binaries, and
- make a future permissive relicensing possible.

**Where:** `backend/app/store.py` (PDF parsing), `backend/requirements.txt`.
**Care needed:** embedded-text extraction *and* native PDF table rows must keep
working; `audit:pdf-parser` and `audit:parser-regression` must stay green, and
the FORGE evaluation must still pass 65/65 required checks.

### 2. Wire the orphaned guards into `audit:all` — `SMALL`

45 of ~122 `audit:*` scripts are never run by the main chain, including every
offline guard and both behavioural-tier adapter guards. Three of them
(`offline_license_guard.py`, `offline_runtime_guard.py`,
`offline_secret_scan_guard.py`) are referenced by **no** `package.json` script
at all — they are committed and unreachable.

**Why it matters:** a guard nobody runs is documentation, not verification.
**Care needed:** some genuinely need a live stack or Postgres; those belong in
the CI strict job rather than `audit:all`. Decide per guard and say which.

### 3. Documentation for newcomers — `SMALL`

The 10 subsystem design docs are strong, but there is **no API reference**, no
troubleshooting guide, and no CHANGELOG. `docs/ARCHITECTURE.md` (added with
this release) is a start, not a finish.

### 4. Scope the Failure explorer to the active workspace — `SMALL`

**A confirmed defect, and a good first PR.** `src/redesign/pages/Failures.tsx`
promises "every extracted failure event **in this workspace**" and renders the
active workspace's name in its kicker, but the list it shows is tenant-wide.
The provider reads `GET /failures` with no `workspace_id`
(`src/lib/api.ts`), and the page's `filtered` memo narrows only by severity,
validation status and the search box — never by workspace.

Reproduce it with two workspaces in one tenant, each holding a failure: Ask
reports one failure, while the Failure explorer shows "2 of 2 shown" under the
first workspace's heading.

The backend already supports `GET /failures?workspace_id=…`. Either pass the
scope through, or filter on `failure.workspace_id` in the memo — and the
honest-UI rule means whichever you pick, the lede and the counter must agree
with it.

### 5. Extend fault-battery coverage — `SMALL`, and repeatable

Only **13 of the 117 guards** have a `*_faults_guard.py` twin that seeds a
defect and requires the guard to refuse. The principle — a guard that cannot
fail is a bug — is sound; the coverage is thin. Pick a guard that protects
something load-bearing, write its twin, and confirm the twin fails when the
guard is weakened.

---

## Operations and observability

None of this exists. It is the largest category of BLOCKED controls and the
most mechanical to implement.

| Control | Effort | What is missing |
|---|---|---|
| `structured-production-logging` | MEDIUM | No structured log emission; no correlation ids |
| `metrics-monitoring` | MEDIUM | No metrics endpoint, no dashboards, no alerting |
| `worker-heartbeat` | MEDIUM | Worker liveness is unobservable |
| `backup-restore-drill` | MEDIUM | No executed backup/restore procedure or evidence |
| `dependency-vuln-scan` | MEDIUM | No scanning of npm or PyPI dependencies in CI |
| `external-malware-scanner` | MEDIUM | Built-in baseline scanner only; no ClamAV-class integration |

A contributor who landed logging + metrics + heartbeat with guards would move
three blockers and make the system operable.

---

## Durability and correctness

The hard problems. Each is `LARGE` and each is honestly scoped in the docs.

### `audit-tail-truncation-detection` — `LARGE`

The HMAC chain proves every recorded event is authentic. It **cannot** prove
none were removed from the end, because there is no external anchor. Fixing it
means anchoring the chain head somewhere the application cannot rewrite
(an append-only external service, a transparency log, periodic notarisation).

### `persistence-locking-transactions` + `correction-cross-process-atomicity` — `LARGE`

Whole-snapshot concurrent mutation is last-writer-risk. Field corrections are
serialised in-process only; cross-process atomicity is unimplemented. The
`local-snapshot-write-loss` work (see `docs/unfinished/`) is relevant history:
accepted mutations were observed being silently dropped, deterministically, on
the export-blocked path.

### `tenant-authorization-enforcement` — `LARGE`, currently BEHAVIOURALLY_FAILED

The API-layer boundary is implemented and RLS exists, but multi-tenant storage,
workspace membership/ACLs, and the full enforcement story are not complete.

### `phase06-trust-boundary` — `LARGE`

The local-AI trust boundary. Related: the AI provider seam already refuses to
let a model own a citation, which is the hard half of the design.

### `migration-validity` — `EXTERNAL_DECISION`

`db/migrations/0003` references tables no earlier migration creates, so the
legacy sequence is deliberately **un-appliable** and left byte-immutable.
`db/baseline/` is the corrected fresh-install set. Resolving this means
deciding whether to rewrite history (and invalidate recorded checksums) or
formally retire the legacy set. **This is a judgement call, not a coding task.**

---

## Production-target infrastructure

| Control | Effort | Status |
|---|---|---|
| `production-database-adapter` | LARGE | Behavioural tier ACCEPTED; production target `NOT_ACCEPTED` |
| `production-queue-adapter` | LARGE | Behavioural tier ACCEPTED; production target `NOT_ACCEPTED` |

Behaviour is proven against **disposable** TLS PostgreSQL and TLS Redis
Streams — 13 and 18 proof domains respectively, including forced RLS,
cross-tenant isolation, ack-after-durable-commit, dead-letter handling, and
payload-preserving replay.

What is **not** proven: a real managed endpoint, real credentials, private
networking, durable replicated storage, executed backup/restore/failover
drills, monitoring, and operational ownership.

**Important:** the evidence modules refuse to self-certify and reject every
in-repo proof as non-qualifying. Closing these requires evidence from genuine
production infrastructure, not more test code. Do not try to make these green
with better mocks — the design specifically forbids it.

---

## Offline edition

Code is merged and working. The **release** is incomplete.

1. **The packaged frontend bug.** One package was built and failed acceptance:
   the shipped SPA hardcoded `http://127.0.0.1:8000` while the offline runtime
   serves same-origin on `127.0.0.1:47613`, so the UI could not reach its own
   backend. A fix exists on a branch but was never merged —
   see [`docs/unfinished/offline-same-origin-build.md`](unfinished/offline-same-origin-build.md).
2. **Two-environment byte reproduction** (E1 host + E2 clean VM on identical
   package bytes) was never completed — the second environment kept failing
   for environmental reasons. See
   [`docs/unfinished/offline-two-environment-certification.md`](unfinished/offline-two-environment-certification.md).
3. **SaaS and hybrid licence providers** are fail-closed placeholders
   (`saas_subscription_placeholder`, `hybrid_offline_lease_placeholder`). Only
   the offline signed provider is implemented. This is the intended seam for a
   hosted edition.
4. **Code signing** — the Inno Setup script exists but is not compiled in this
   toolchain, and nothing is signed.

---

## Product gaps

- **Per-field provenance in Report Studio** — `src/redesign/pages/Studio.tsx`
  notes that per-field provenance marking is not implemented; provenance is
  currently per-section.
- **`formatted-export-provenance`** and **`official-export-gate`** — BLOCKED
  controls covering provenance in rendered exports and the official-export
  gate's full conditions.
- **`OUTCOME_1_FUNCTIONAL_MATRIX`** is marked STALE-PENDING-REVIEW: it was
  accepted against the now-deleted v1 interface, so UI-facing rows need
  re-validation against the canonical frontend.

---

## Technical debt

### `backend/app/store.py` — 8,591 lines

About **45% of all backend code** in one module. It holds the snapshot store,
every parser (ZIP / CSV / XLSX / DOCX / EML / PDF), export rendering, and the
HMAC audit chain.

This is the single biggest barrier to new contributors. Decomposing it is
valuable and risky in equal measure: the guard battery is your safety net, so
do it in small, guard-verified steps rather than one heroic refactor.

### No unit-test framework

There is no pytest/vitest/jest at all — the 117 guard scripts are the suite.
That is a deliberate and defensible choice for *acceptance* testing, but it
makes fine-grained unit testing of pure functions (trajectory maths, unit
conversion, canonical serialisation) awkward. Adding pytest **alongside** the
guards, without weakening them, would be welcome.

---

## Explicitly out of scope

So nobody sinks time into a direction the design rejects:

- **Making a model own a citation.** Citations come from deterministic
  extraction. The AI seam is built so a model cannot be the provenance source.
- **Making calculated trajectory authoritative.** It is "a deterministic
  drafting aid, not certified directional-survey software." Calculated values
  must never overwrite source values, and gaps must never be bridged.
- **A waiver path for GA blockers.** Deliberately absent. Verified per-user
  identity and signature verification do not exist yet, so a waiver would just
  be another false-ready route.
- **Regenerating the GA artifact to turn `GA50` green.** That manufactures a GA
  claim. The gate is stale on purpose.
