# Monday Report

Runnable React/TypeScript MVP scaffold for the Monday Report local AI, chat-first intelligence workspace.

## What Is Implemented

- React SaaS workspace with local AI chat as the main surface, plus upload, dashboard, failure explorer, validation queue, and architecture screens.
- Report Studio lets users write morning drilling reports from scratch, switch between DDR/BHA/mud/survey normal formats, review client issue readiness, apply a FORGE-style daily-report structure, preview Monday Report branding, render casing schematics and activity timelines, and export a draft Markdown report.
- Casing schematic rows and the 24 hr activity timeline are extracted from source DDR/PDF evidence with page-level citations and confidence, shown in Report Studio and the Monday Report with explicit source-derived vs reference provenance, and fall back to labelled reference geometry (never presented as client-confirmed) when no source is found.
- Directional survey stations (MD, inclination, azimuth, and TVD/DLS/N-S/E-W only when explicitly stated) are extracted source-only from survey tables and labelled narrative with page provenance, confidence, deterministic conflict flags, and an explicit "No source survey stations — confirm or enter from DDR" state.
- A documented minimum-curvature calculation (`docs/TRAJECTORY_CALCULATION.md`, method `minimum_curvature v1`) derives per-interval and cumulative trajectory geometry from eligible source stations behind an explicit review gate: calculated values render side-by-side with source values (never overwriting them), conflicts and gaps are skipped rather than bridged, relative coordinates are labelled as such, and the output is a deterministic drafting aid, not certified directional-survey software.
- A review-gated calculated trajectory plan view (plain accessible SVG, no chart dependency) renders one path per calculation segment with equal ft axes (north up, east right), planned/actual dash-and-marker distinction, an anchor marker, explicit "relative to the first calculated station — not absolute well coordinates" labelling, an honest zero-lateral-extent fallback, and no certification claim.
- A calculated vertical trajectory profile renders one panel per calculation segment plotting horizontal displacement from that segment's anchor (unsigned magnitude, never an absolute position) against calculated TVD increasing downward — segment-aware, review-required, honest about zero-lateral wells, and not certified survey computation.
- Source-derived hydraulics observations (`docs/HYDRAULICS_EXTRACTION.md`, parser `deterministic_hydraulics v1`) extract explicitly labelled flow rate, SPP, mud weight, ECD, PV, YP, pump rate, and nozzle text with explicit units only (documented kPa/L·min/sg conversions, ambiguous values dropped), page citations, observed/planned/unknown status, pump- and mud-system-aware conflict detection, and review flags — informational and review-required, with Hydraulics and Torque & Drag diagnostics remaining recommended-only.
- Field-level corrections (`docs/FIELD_CORRECTIONS.md`, `audit:field-corrections`) let an operator correct a **registered** extracted field through an auditable, tenant-scoped, **versioned** overlay: the original source value is preserved, only registry-listed report-identity fields are correctable (unknown/sensitive fields return a stable 422), values are type/length/finite-number validated, re-correcting supersedes the prior record (version history), reverting keeps history, the whole route is serialized in-process (single-active-lineage, no lost writes; cross-process atomicity pending Phase 04), and a redacted hash-chained audit event records who/what/when/why without leaking the raw source, corrected, or reason text — surfaced in the report draft as review-required overlays that never overwrite source lineage, with no anomaly/benchmark/failure/validation mutation. The actor is now the resolved request actor from the authenticated-identity foundation (`docs/AUTHENTICATED_IDENTITY.md`), and the correction routes are permission-gated by the route-level RBAC authority (`docs/ROUTE_RBAC.md`); verified per-user reviewer identity and tenant authorization remain declared blockers, and this is a foundation, not a fully closed append-only/immutable control.
- Benchmarking adds approved market/operator comparison for drilling rate, configurable Gordon average and Noble top-quartile seed values, variance tables, seven-day trend visuals, anomaly creation, Hydraulics and Torque & Drag recommendations, review-required AI interpretations, and Management of Change evidence export content.
- Chat calls the FastAPI scaffold when available, exposes local AI runtime status, and falls back to deterministic local analysis when offline.
- Backend scaffold uses durable local JSON state so API and worker share uploads, jobs, and redacted hash-chain audit logs before PostgreSQL/Redis lands.
- Browser ZIP/file/folder intake with configurable byte limits, sanitized tenant-scoped storage paths, local byte storage, real SHA-256 hashes, report-family classification, duplicate candidates, configurable OCR routing/extraction, and parser gap warnings.
- Builtin baseline malware scanner blocks EICAR-style test content, risky executable/script extensions, and macro-enabled Office files before processing; client mode requires explicit scanner configuration.
- Uploaded source files and extracted child files can be downloaded only through expiring signed URLs; client mode requires a configured signing secret.
- Worker foundation safely expands ZIP packages with configurable entry and uncompressed-size limits, parses text, CSV, XLSX, DOCX, EML, PyMuPDF-backed embedded-text PDF files, native PDF table rows, and `pdf_report_profile_v1` DDR fields/sections into typed chunks with source lineage. Image/scanned-PDF files route to OCR review when no local engine is configured, or to `ocr_text_v1` chunks when `MONDAY_REPORT_OCR_ENGINE=tesseract` and `MONDAY_REPORT_TESSERACT_CMD` are configured.
- Extraction scaffold creates cited MWD signal-loss failure records, NPT hours, company attribution, and validation tasks from parsed chunks; NPT hour parsing prefers explicit NPT labels so casing/depth values are not treated as time.
- Validation API updates extracted records, Monday Report API creates report JSON, and export API blocks unresolved official exports before writing hashed JSON/CSV/HTML/PDF/XLSX artifacts with signed download URLs.
- Official report exports now include metrics, validation posture, source coverage, FORGE-style casing schematic rows, 24 hr activity timeline, branded HTML/PDF output, and expanded XLSX sections.
- Official report exports now include Market Benchmark evidence, benchmark source/version, current measurements, variance calculations, triggered anomaly rules, diagnostic recommendations, AI review state, and audit/MOC evidence fields in JSON/CSV/HTML/PDF/XLSX outputs.
- Client-data readiness endpoint and tracker panel flag demo/local-scaffold blockers before real client packages are accepted, enforce retention policy, require real active infrastructure adapters, and unsafe client mode requires an API key while blocking data reads, chat, report creation, and exports until ready.
- Local AI defaults to Ollama with `gemma4:e2b`; readiness verifies both endpoint reachability and the pinned model.
- Parser/OCR fixture eval readiness requires a passing `MONDAY_REPORT_PARSER_EVAL_REPORT`; real-client approval also requires the referenced fixture manifest to carry a reviewed anonymized-client attestation.
- The locally held Utah FORGE report corpus in `16A(78)-32_Daily_Reports/` (publicly accessible reports, with redistribution rights not confirmed in the local corpus) is ignored by Git; `audit:forge-corpus` parses representative PDFs, verifies drilling/completion markers, and writes `output/forge-corpus/forge_corpus_summary.json`.
- A reviewed FORGE ground-truth evaluation set (`evals/forge/manifest.v1.json` + `expectations.v1.json`, spec in `docs/FORGE_EVAL_PROMOTION.md`) pins five SHA-256 corpus documents with page-reviewed expected values and explicit absences; `audit:forge-eval-spec` validates the committed specification portably (in `audit:all`), while `audit:forge-evals` runs the real upload→worker→draft pipeline against the local corpus and reports `SKIPPED` (never PASS) when the corpus is absent. The evaluation is **promoted**: after general D1–D4 parser fixes (bracketed well identifiers, casing-context gating with mixed-fraction diameters, corroborated dot-thousands survey depths with `AZM` labels, header-region completion classification) the unchanged ground truth passes **65/65 required checks** on the real corpus, with the two informational report-number checks still failing and non-gating, and `audit:parser-regression` pins the defect classes portably inside `audit:all`. FORGE evidence never substitutes for client readiness evidence.
- `fixtures:anonymized` creates a generated 13-family fixture pack for local smoke tests only; production client intake must use reviewed anonymized client fixtures, not generated evidence.
- Partner preview packaging creates one ZIP with the built web app, backend, worker loop, Gemma 4 E2B defaults, sample import package, and import/export smoke script.
- Client-data approval tooling writes an explicit approved/blocked evidence report from the live readiness endpoint.
- GA readiness is a truthful, registry-backed gate (`docs/GA_READINESS_INTEGRITY.md`, `evals/ga/blocker_registry.v1.json`, `audit:ga-readiness-integrity`): every known GA blocker is a committed registry entry with category/severity/owner/resolution condition, and the gate emits one check per entry with an explicit disposition (`PASS`/`FAIL`/`BLOCKED`/`SKIPPED`/`NOT_APPLICABLE`/`REVIEW_REQUIRED`). Blocker counts derive from registry categories (not hand-maintained ID sets), `SKIPPED`/missing-evidence/missing-commands never count as pass, `--skip-commands` can never yield `GA_READY`, evidence is bound to a clean git commit/tree with a canonical self-hash and redacted paths, and no waiver can resolve a blocker in this version. A known-but-unimplemented control (RBAC, keyed audit integrity, migration runner, CI, backup, etc.) is a declared `BLOCKED` entry, so the gate reports truthful non-zero blocker counts and **stays `GA_BLOCKED` even with PostgreSQL and Redis provisioned**.
- Runtime backend status exposes requested versus active repository and queue adapters so PostgreSQL/Redis environment variables cannot masquerade as implemented infrastructure.
- Authenticated identity foundation (`docs/AUTHENTICATED_IDENTITY.md`, `audit:identity-rbac`): opaque per-user credentials (≥32 random bytes; only a SHA-256 hash + non-secret fingerprint stored; raw token returned once, never logged/audited) are resolved **server-side** to a **request-scoped** identity, isolated per request and enforced with **default-deny** RBAC on the existing roles (`ADMIN`/`ENGINEER`/`VALIDATOR`/`MANAGER`; no all-role fallback, client-supplied identity headers ignored). Admin-only `/auth/users` + `/auth/credentials` (and the local `python -m backend.app.identity_admin` CLI) provision and revoke credentials; the configured-tenant boundary is enforced; audit and field-correction actors reflect the authenticated user; a bootstrap identity is never persisted on startup. In **client mode the legacy shared key is rejected** — an active persisted per-user credential is required (the shared key is a `demo_bootstrap` identity for local/demo use only). This is a **foundation**: multi-tenant authorization and verified reviewer identity remain declared blockers, and `ga:readiness` stays **`GA_BLOCKED`**.
- Complete route-level RBAC (`docs/ROUTE_RBAC.md`, `audit:route-rbac`): a single generic authorization authority (`backend/app/permissions.py`) with 23 stable permissions and a conservative role→permission matrix (the legacy `VIEWER` role stays unactivated) enforces a permission on **every privileged read and every mutation**; a classified route inventory (`ROUTE_ACCESS_POLICY`) covers all 48 routes, `route_policy_fully_enforced()` proves each `permission_required` route carries its guard, the two download routes are public **signed-capability** endpoints (resource-bound, expiring, GET-only, token verified **first** so an invalid token cannot probe existence or write audit), and every denial writes a redacted audit event (permission/route/method). Permission is checked **before** any resource lookup (no existence leak). The **detailed** `/readiness/client-data` report is `permission_required("view_runtime_status")` (only minimal `/health` stays public; absolute paths scrubbed from readiness detail). `benchmark_permissions()` now delegates to this authority with its historical 12-key shape preserved. Multi-tenant resource authorization, verified reviewer workflow, and keyed audit integrity remain declared blockers; the `rbac-role-separation` control is now **evidence-driven PASS** (resolution condition met; registry unchanged, only the evaluator probe is evidence-based) while the other controls keep `ga:readiness` at **`GA_BLOCKED`**.
- Fresh environments start without seeded failure records; set client tenant/user identity with environment variables before the first API start.
- Extract drilling failure/NPT records from uploaded evidence with companies, wells, rigs, BHA/tool context, severity, confidence, validation status, cost impact, and source citations.
- Deterministic analyst-chat behavior for clear questions, ambiguous comparisons, unsupported prediction requests, risk questions, repeated tools, NPT, and exports.
- Filter system shared by explorer and chat: query, date, company, tool, severity, and validation state.
- Rule-based risk scoring for companies and tool serials.
- Human validation workflow that updates local event state.
- PostgreSQL/RLS-oriented schema artifact in `db/schema.sql`.
- Local AI-first execution plan in `docs/MONDAY_REPORT_EXECUTION_PLAN.md`.
- Implementation-ready product and engineering spec in `docs/MONDAY_REPORT_IMPLEMENTATION_SPEC.md`.
- Project tracker, phase gates, and audit notes in `docs/PROJECT_TRACKER.md`.

## Run Locally

```powershell
$env:CI='true'
pnpm install
pnpm run dev
```

Then open the local URL printed by Vite.

To run the first FastAPI backend slice:

```powershell
python -m pip install -r backend/requirements.txt
pnpm run dev:api
```

Useful backend checks:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/health -UseBasicParsing
pnpm run worker:once
pnpm run audit:phase
pnpm run test:ui
pnpm run test:e2e
pnpm run audit:client-data
pnpm run audit:bootstrap
pnpm run audit:state-persistence
pnpm run audit:signed-url-guards
pnpm run audit:upload-limits
pnpm run audit:upload-ownership
pnpm run audit:upload-idempotency
pnpm run audit:source-lineage
pnpm run audit:citation-format
pnpm run audit:source-citations
pnpm run audit:tracker-clarity
pnpm run audit:golden-fixtures
pnpm run audit:parser-fixture-evals
pnpm run audit:parser-fixture-report
pnpm run audit:pdf-parser
pnpm run audit:parser-regression
pnpm run audit:forge-corpus
pnpm run audit:forge-eval-spec
pnpm run audit:forge-evals
pnpm run audit:ocr-routing
pnpm run audit:ocr-extraction
pnpm run audit:local-ai
pnpm run audit:partner-package
pnpm run audit:partner-approval
pnpm run audit:client-approval
pnpm run audit:client-ops
pnpm run audit:report-export-idempotency
pnpm run audit:report-template
pnpm run audit:field-corrections
pnpm run audit:benchmarking
pnpm run audit:runtime-backends
pnpm run audit:infra-readiness
pnpm run audit:ga-readiness
pnpm run audit:integrity
pnpm run audit:auth
pnpm run audit:redaction
pnpm run audit:malware
pnpm run audit:storage-paths
pnpm run audit:archive-safety
pnpm run audit:retention
pnpm run audit:all
```

Client-readiness helper:

```powershell
pnpm run fixtures:anonymized
pnpm run ga:env
pnpm run audit:ga-readiness
```

`pnpm run ga:readiness` runs strict GA approval evidence and exits non-zero until real-client readiness is fully green.

For a production check in a non-interactive shell:

```powershell
$env:CI='true'
pnpm run build
```

To build the single-file partner preview ZIP:

```powershell
pnpm run package:partner-preview
pnpm run audit:partner-package
pnpm run package:partner-approval
```

The output is `output/package/Monday_Report_Partner_Preview.zip`, with approval evidence beside it in `output/package/Monday_Report_Partner_Preview_APPROVAL.md` and `.json`. It is for local partner testing only and is not approved for real client data.

To write the real-client approval evidence report:

```powershell
pnpm run package:client-approval
```

The output is `output/client-data/Monday_Report_Client_Data_APPROVAL.md` and `.json`. A `BLOCKED` report is expected until `/readiness/client-data` is fully green; see `docs/CLIENT_DATA_READINESS.md` for the required environment.

## Production Next Steps

- Replace local JSON state with PostgreSQL repositories and Redis-backed workers.
- Replace local file storage with production object storage and queued Python parser workers.
- Harden OCR/PDF extraction on reviewed anonymized client fixtures, configure a production OCR engine, and complete customer-grade golden fixture coverage using `docs/GOLDEN_FIXTURE_MANIFEST.example.json`; then run `generate_parser_fixture_eval_report.py` and set `MONDAY_REPORT_PARSER_EVAL_REPORT` to the passing report.
- Build the Phase 06 local-AI extraction router on the reviewed pipeline, using the promoted FORGE evaluation set (65/65 required on the real corpus) as its acceptance target.
- Add Postgres migrations from `db/schema.sql`.
- Add auth/SSO, tenant-aware request context, persistent audit hardening, and source preview authorization.
- Replace deterministic extraction with local LLM provider abstraction and evaluation sets before using customer data.
- Keep `gemma4:e2b` installed in Ollama for partner testing, or override `MONDAY_REPORT_LOCAL_LLM_MODEL` only after the replacement model is audited.
- Polish production PDF/XLSX templates and signed export presentation.
- Set `MONDAY_REPORT_CLIENT_DATA_MODE=client` only after `/readiness/client-data` reports ready with reviewed fixture attestation.
- For clean client bootstrap, set `MONDAY_REPORT_TENANT_NAME`, `MONDAY_REPORT_TENANT_SLUG`, `MONDAY_REPORT_USER_EMAIL`, and `MONDAY_REPORT_USER_FULL_NAME` before the first API start. Default startup creates a neutral workspace only; failure records are created from uploaded evidence.
