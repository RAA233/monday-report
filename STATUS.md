# Project Status — read this before you trust anything

**Short version: Monday Report is a working, deeply verified prototype. It is
not generally available, and it is not ready for real customer data.**

The project's own release gate says so, in machine-checked form:

```
release_recommendation: GA_BLOCKED
ga_ready:               false
client_data_ready:      false
release_candidate_ready:false
```

That verdict is not pessimism or boilerplate. It is computed from a committed
registry of 28 controls, and the project is deliberately engineered so that
**nobody can quietly make it say otherwise**. This document explains what works,
what does not, and how to read the project's own honesty machinery.

---

## 1. What actually works today

You can clone this repo, run two commands, and use a real application. No
database, no Docker, no Redis, no cloud account, no API key.

**Document intake and extraction**
- Browser upload of ZIP / files / folders with byte limits, sanitised
  tenant-scoped storage paths, real SHA-256 hashes, and duplicate detection
- Parsers for text, CSV, XLSX, DOCX, EML, and embedded-text PDF, plus native
  PDF table rows and a `pdf_report_profile_v1` daily-report profile
- A baseline malware scanner that blocks EICAR-style content, risky
  executable/script extensions, and macro-enabled Office files
- OCR routing for scanned PDFs (requires a local Tesseract to actually extract)

**Domain intelligence — all source-cited**
- Casing schematic rows and 24-hour activity timelines extracted from source
  reports with page-level citations and confidence
- Directional survey stations extracted **source-only**, with page provenance
  and deterministic conflict flags
- A documented `minimum_curvature v1` trajectory calculation behind an explicit
  review gate, rendering plan-view and vertical-profile SVGs. Calculated values
  display **side by side** with source values and never overwrite them; gaps are
  skipped rather than bridged
- `deterministic_hydraulics v1` observations with explicit units only
- Benchmarking with variance tables, anomaly creation, and review-required
  interpretations

**Reporting**
- Report Studio with five report variants, a readiness board, and preview
- Official exports to JSON / CSV / HTML / PDF / XLSX, gated so unresolved
  validation blocks an official export
- Downloads only through expiring signed URLs

**Security foundation** (each with a design doc in `docs/`)
- Per-user opaque credentials (≥32 random bytes, SHA-256 at rest, raw token
  shown once), resolved server-side to a request-scoped identity
- Route-level RBAC: 23 permissions, default-deny, across all 48 routes;
  permission checked **before** resource lookup so a 404 cannot leak existence
- API-layer tenant authorisation closing an IDOR gap, with existence-hiding 404s
- Versioned HMAC-SHA256 audit chain with forward-only keying
- Database-enforced tenant isolation via PostgreSQL row-level security
- A deterministic migration runner with advisory locking and checksum-drift refusal

**Frontend**
- A single canonical React 19 + TypeScript interface, 20 routes, all implemented
  (no placeholder screens). The older v1 interface was retired and deleted
- Accessibility-conscious: route announcements, 200%-zoom sweeps, and
  keyboard-path coverage in the e2e suite

**AI**
- A provider seam with three implementations: deterministic (default, no model),
  loopback local model (Ollama / LM Studio), and an optional online API provider
  that is **default-off**, key-sealed at rest, and hardened against SSRF
- The model never owns a citation. Citations come from deterministic extraction

**Offline edition**
- A localhost-only packaged Windows build: bundled Python, no Internet, no Node,
  no Docker, no PostgreSQL, no Redis at the customer site
- Ed25519-signed, machine-bound licences with privacy-preserving fingerprinting
  (raw hardware values never leave the device; a MAC address alone can never
  satisfy a binding)
- Expiry degrades to read-only. It never deletes, encrypts, or hides customer
  data, and backup stays available in every licence state

**CI**
- Three jobs: hermetic build/typecheck, a strict audit against two disposable
  PostgreSQL clusters, and a Windows deterministic job

---

## 2. What does not work, or is not proven

Be precise about the distinction here, because the project is:

| | Meaning |
|---|---|
| **Behavioural tier — ACCEPTED** | The code does the right thing, proven in *disposable test infrastructure* (throwaway Docker PostgreSQL / Redis) |
| **Production-target tier — NOT_ACCEPTED** | Real managed endpoints, private networking, durable replicated storage, executed backup/restore/failover drills, monitoring, and operational ownership are **not** proven |

Three verdicts are retained in code **on purpose**:

```
PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED
PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED
FOUR_READINESS_CONTEXTS_NOT_ACCEPTED
```

The production-target evidence modules treat every existing in-repo proof as
*non-qualifying* and refuse to self-certify. In their own words:
`production_parity=false` "is not a bug to be worked around; it is the honest
current answer."

**The 28 tracked controls, current tally:**

| Disposition | Count |
|---|---|
| BLOCKED | 20 |
| SKIPPED (environment-dependent) | 5 |
| PASS | 2 |
| REVIEW_REQUIRED (external) | 1 |

The two PASS controls are `rbac-role-separation` and
`verified-reviewer-identity`. Everything else is open.

**Notable gaps, grouped**

- **Operations / observability** — structured production logging, metrics and
  monitoring, worker heartbeat, backup/restore drill. All unimplemented.
- **Supply chain** — no dependency vulnerability scanning, no external malware
  scanner integration.
- **Durability** — audit **tail truncation is undetected** (no external anchor).
  Cross-process correction atomicity and full transactional persistence are not
  provided. Whole-snapshot concurrent mutation is last-writer-risk.
- **Licensing** — the SaaS and hybrid licence providers are deliberate
  fail-closed placeholders. Only the offline signed provider is implemented.
- **Offline release** — the code is merged, but one packaged build was produced
  and found broken (the shipped UI could not reach its own backend). The fix
  exists but is unmerged, and the two-environment byte-reproduction plus the
  live-elevated operator certification were never completed.
- **Product** — per-field provenance in Report Studio is not implemented.
- **Testing reach** — 45 of the ~122 `audit:*` scripts are not wired into
  `audit:all`, including the offline and behavioural-tier guards.
- **Technical debt** — `backend/app/store.py` is 8,591 lines, about 45% of all
  backend code.

See [docs/ROADMAP.md](docs/ROADMAP.md) for these as prioritised work items.

---

## 3. How to read the honesty machinery

This is the unusual part of the project, and worth understanding before you
judge it.

**There are zero `TODO`, `FIXME`, or `XXX` comments in the entire codebase.**
That is not because nothing is unfinished. Incompleteness is tracked as 28
machine-checked entries in `evals/ga/blocker_registry.v1.json`, each with a
category, severity, owner type, a concrete `policy_reference` pointing at the
deficiency, and a `resolution_condition`.

The gate that reads that registry (`backend/app/ga_readiness.py`) is built so
that:

- `SKIPPED`, missing evidence, and missing commands **never** count as a pass
- blocker counts derive from registry categories, so "0 blockers" cannot be
  produced by editing an ID list
- **no waiver can resolve a blocker** in this version — there is no env var, no
  configured actor, and no unsigned file that can flip a control green

### `pnpm run audit:all` exits non-zero, and that is correct

The expected outcome is **exactly one failure**:
`GA50 commit-binding-is-ancestor`.

CI asserts that precisely — and **turns red if `audit:all` ever goes green**,
because a silently-resolved GA gate must be a deliberate, reviewed event rather
than a drift. Per the release policy: *CI green here means "no regression beyond
the known GA_BLOCKED baseline", not "generally available".*

**Why GA50 fails:** the tracked GA artifact (`docs/GA_GAP_ASSESSMENT.v2.json`)
is bound to commit `80f4583`, which **is** an ancestor of `main` but is ~147
commits behind it, against a `MAX_COMMITS_BEHIND = 1` staleness bound. It is a
*staleness* failure, not an ancestry failure. Regenerating the artifact to make
the gate green would manufacture a GA claim, so it has been left alone
deliberately.

A consequence worth savouring: the `ci-execution` control is still recorded
BLOCKED even though CI now exists and runs — because the tracked artifact
predates CI landing by 18 merges. The system refuses to credit itself.

### Why most proofs read as "absent"

Across the 28 controls, measurement classes are: ABSENT 15, NOT_EVALUABLE 7,
BEHAVIOURALLY_FAILED 2, BEHAVIOURALLY_PROVEN 2, IMPLEMENTED_BUT_UNMEASURED 1,
EXTERNAL 1.

The gate only believes what is **committed**. Most proofs ran in throwaway
Docker environments whose artifacts were never committed (`output/` is
git-ignored), so it reports them absent. That is the gate working as designed,
not a reporting bug.

---

## 4. Should you use this?

| You want to… | Verdict |
|---|---|
| Read a worked example of evidence-based verification engineering | **Yes.** This is the most interesting thing in the repo. |
| Run it locally and explore the product | **Yes.** Two commands, no infrastructure. |
| Build on the extraction / trajectory / citation code | **Yes**, with the AGPL-3.0 obligations in mind. |
| Deploy it for a real drilling operation | **No.** Not GA. Operations, observability, backup, and production-target infrastructure are unproven. |
| Put real customer data in it | **No.** `client_data_ready: false`, and the client-readiness gate will block you. |
| Treat its outputs as certified engineering results | **No.** The trajectory calculation is explicitly "a deterministic drafting aid, not certified directional-survey software", and every derived value is review-required. |

---

*This file reflects `main`. The authoritative, machine-readable source is
`evals/ga/blocker_registry.v1.json` plus `docs/GA_GAP_ASSESSMENT.v2.json`.
If this document and the registry ever disagree, the registry wins.*
