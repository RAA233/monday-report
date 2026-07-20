# Monday Report Project Tracker

## Current Phase

The executable MVP path is now phase-gated end to end and the local client-data approval environment is green. It bootstraps a clean client tenant without startup failure records, requires an API key in client mode, rejects oversized uploads at the API boundary, enforces configured ZIP entry and uncompressed-size limits, blocks unsafe client-mode data operations until readiness is green, activates PostgreSQL/RLS state and Redis-backed queue processing in client mode, exposes requested versus active runtime backends, stores accepted bytes under sanitized tenant-scoped paths, verifies SHA-256, applies configurable retention to expired data artifacts, requires explicit client-mode malware scanner configuration, blocks baseline malware signatures before processing, downloads uploaded source files through signed URLs, defaults local AI to Ollama `gemma4:e2b`, parses text/CSV/XLSX/DOCX/EML/PyMuPDF-backed PDF child files and native PDF table rows into typed document chunks, builds `pdf_report_profile_v1` DDR field/section profiles from PDFs, preserves page/table/row-aware PDF citations, extracts configured local OCR into `ocr_text_v1` chunks with image-page citations, extracts cited MWD signal-loss failures with NPT/company fields, opens validation tasks, creates source-backed Report Studio drafts, provides reviewed MR-SCHEMA-1 DDR/BHA/mud/survey/directional Report Studio variants with client issue readiness, opens Client Home first with live rig workspace and MR-list access, creates Monday Report JSON, exports JSON/CSV/HTML/PDF/XLSX artifacts, answers chat with citations and structured workflow cards, renders the Product Roadmap cockpit with an execution board, records redacted hash-chain audit events, creates a single-file partner preview ZIP, and writes approved real-client readiness evidence. Remaining work follows the roadmap lanes: stronger schematic extraction, normalized PostgreSQL repositories, controlled client-package dry runs, production OCR command management, and external malware scanning.

## Clear Tracker Snapshot

| Lane | Status | Meaning | Next Action |
|---|---|---|---|
| Accepted now | Pass | Executable MVP is working with Client Home, rig/MR list access, chat, report studio, Benchmarking, roadmap, upload, parser worker, typed citations, validation, exports, signed downloads, audit, client approval, and readiness gates. | Keep every slice behind targeted audits and `pnpm run audit:all` in demo posture. |
| Safe operating mode | Pass | Demo mode remains local; approved client mode uses PostgreSQL/RLS state, Redis queue, protected storage, API key, signing secret, and reviewed fixture/eval evidence. | Keep secrets out of Git and regenerate approval after environment changes. |
| Real-client approval | Blocked | Live client-data approval can report `APPROVED` in a fully provisioned local environment (separate from GA), but the registry-backed GA gate reports `GA_BLOCKED` because software/security/governance controls remain unresolved (`docs/GA_READINESS_INTEGRITY.md`); "0 software blockers" was a coverage artifact of the former gate and is corrected. | Resolve the registry-backed GA blockers (identity/RBAC, keyed audit, persistence/migration, CI, backup, approval) in separate PRs before any GA claim. |
| Next execution order | Pending | Source-driven casing schematic, 24 hr activity timeline, directional survey-station extraction, the review-gated minimum-curvature trajectory calculation, the segment-aware calculated plan view, the per-segment vertical trajectory profile, source-derived hydraulics observations, the promoted FORGE evaluation (general D1–D4 parser fixes; unchanged ground truth passes 65/65 required on the real corpus; portable parser-regression guard in `audit:all`), the auditable versioned field-level correction & review-provenance foundation (`docs/FIELD_CORRECTIONS.md`, `audit:field-corrections`; registry-gated, in-process-serialized, configured-actor context), and the truthful registry-backed GA readiness gate (`docs/GA_READINESS_INTEGRITY.md`, `evals/ga/blocker_registry.v1.json`, `audit:ga-readiness-integrity`) are complete; the GA gate now reports `GA_BLOCKED` with truthful non-zero blocker counts across software, security_review, infrastructure, configuration, and client_approval categories (no category is falsely zero, and PostgreSQL+Redis provisioning alone cannot yield GA_READY); remaining lanes: resolve the registry-backed blockers (per-user identity/RBAC, keyed/anti-truncation audit integrity, persistence/migration safety + cross-process atomicity, CI + dependency scanning, logging/metrics/heartbeat, backup/restore, formatted export provenance, Phase 06 local-AI trust boundary, external malware scanner, client/organizational approval). | Pull the Phase 06 local LLM extraction router on the promoted evaluation set, then controlled client-package trials. |

## Current Tracker

- Working now: Client Home, rig/MR list access, chat-first workflow, Benchmarking module, batched direct/ZIP upload, SHA-256 storage, malware baseline blocking, parser-worker queue, source chunks, failure extraction, validation tasks, Monday Report creation, JSON/CSV/HTML/PDF/XLSX exports, signed source/export downloads, redacted audit logs, and readiness reporting.
- Recently added: typed source locators, readable citation labels, source-file actions directly from chat citation cards, command-center chat workflow, source-backed Report Studio drafts, MR-SCHEMA-1 DDR/BHA/mud/survey/directional report variants, client issue-readiness board, Benchmarking with Gordon/Noble seed config, critical anomaly workflow, diagnostic recommendations, MOC evidence exports, Product Roadmap execution board, direct-upload persistence batching, manifest-backed fixture readiness, Gemma 4 E2B local AI default, single-file partner preview packaging, page-aware PDF chunks, native PDF table row citations, high-confidence PDF report profiles, configurable local OCR extraction into image-page chunks, source-driven casing/timeline schematic rows with provenance, source-only directional survey-station extraction with page citations, conflict flags, and an honest no-source state, a documented review-gated minimum-curvature trajectory calculation (`docs/TRAJECTORY_CALCULATION.md`) that never overwrites source values, a segment-aware calculated plan-view visualization (plain accessible SVG, equal ft scale, explicit relative-coordinate labelling, never bridging skipped stations), and a per-segment vertical trajectory profile (horizontal displacement from each segment anchor vs calculated TVD increasing downward, never overlaying incompatible TVD references).
- Real-client posture: approved in the local client environment with active PostgreSQL, active Redis, local AI, security configuration, golden fixture/eval evidence, and reviewed fixture attestation all passing.
- Operator command: run `pnpm run audit:all` after every meaningful code change; run `pnpm run package:partner-approval` before sending the partner ZIP; run `pnpm run package:client-approval` to write the current real-client approval/blocker report.

## 2026-07-14 Benchmarking Release Evidence

Verification completed on `2026-07-14` in `Asia/Riyadh` (`UTC+03:00`) from starting revision `78a67ef37537b1e0d440accc8dbe003886f3b8f4` on branch `main`. No manual state, storage, export, API, web, or GA environment overrides were used.

Root causes closed:

- `scripts/phase_audit.py` loaded `output/ga-readiness/monday_report_ga.env` during import, which contaminated ordinary audit and E2E callers. GA environment loading is now explicit, non-destructive, path-safe, and followed by runtime URL refresh.
- `scripts/roadmap_guard.py` required obsolete `09-roadmap.png`. It now enforces Benchmarking at `04-benchmarking.png`, Roadmap at `10-roadmap.png`, the exact view order/count, unique labels/files/indices, valid filenames, and existing navigation markers.

Release files reviewed: `README.md`, `backend/app/main.py`, `backend/app/schemas.py`, `backend/app/store.py`, `db/migrations/0003_benchmarking.sql`, `package.json`, `scripts/audit_harness_guard.py`, `scripts/benchmarking_guard.py`, `scripts/phase_audit.py`, `scripts/roadmap_guard.py`, `scripts/ui_quality_e2e.mjs`, `src/App.tsx`, `src/components/BenchmarkingModule.tsx`, `src/components/ReportStudio.tsx`, `src/lib/api.ts`, `src/styles.css`, and this tracker.

| Final command | Exit | Completed (UTC+03:00) | Evidence |
|---|---:|---|---|
| `pnpm run build` | 0 | `2026-07-14 13:06:18` | TypeScript and Vite production build passed; 1,600 modules transformed. |
| `pnpm run audit:benchmarking` | 0 | `2026-07-14 13:06:29` | Seeds, thresholds, anomaly workflow, permissions, review gates, audit events, and JSON/CSV/HTML/PDF/XLSX evidence passed. |
| `pnpm run audit:roadmap` | 0 | `2026-07-14 13:06:38` | Current module labels, order, screenshot filenames, routes, and audit wiring passed. |
| `pnpm run test:e2e` | 0 | `2026-07-14 13:06:53` | Nine ZIP files, seven parsed documents, six chunks, validation gate, five exports, signed downloads, chat, and audit coverage passed. |
| `pnpm run test:ui` | 0 | `2026-07-14 13:07:45` | All navigation/actions and 12 screenshots passed with zero browser errors. |
| `pnpm run audit:all` | 0 | `2026-07-14 13:08:52` | Full software, parser, report, security, readiness, Benchmarking, and package-approval chain passed. |
| `pnpm run ga:readiness` | 0 | `2026-07-14 13:09:14` | `GA_READY`; zero software, configuration, infrastructure, evidence/approval, or uncategorized blockers. |
| `pnpm run report:ui-screenshots` | 0 | `2026-07-14 13:09:30` | 15-page UI evidence PDF regenerated and visually inspected. |
| `pnpm run package:partner-preview` | 0 | `2026-07-14 13:57:04` | Partner ZIP rebuilt from the production bundle. |
| `pnpm run audit:harness` (post-tracker) | 0 | `2026-07-14 14:00:19` | Import isolation, explicit loading, precedence, path handling, URL refresh, and roadmap markers passed. |
| `pnpm run audit:roadmap` (post-tracker) | 0 | `2026-07-14 14:00:39` | Final tracker state retained the exact Benchmarking/Roadmap sequence. |
| `pnpm run audit:benchmarking` (post-tracker) | 0 | `2026-07-14 14:00:58` | Final source state retained all Benchmarking and export evidence behavior. |
| `pnpm run audit:all` (post-tracker) | 0 | `2026-07-14 14:02` | Full chain passed again and rebuilt the archive with current tracked documentation. |
| `pnpm run package:partner-approval` | 0 | `2026-07-14 14:03:24` | Final rebuilt archive `APPROVED` for partner demo/testing with synthetic data only. |

Evidence paths:

- UI manifest: `output/qa/ui_quality_e2e_manifest.json`
- Benchmarking screenshot: `output/screenshots/ui-quality/04-benchmarking.png`
- Roadmap screenshot: `output/screenshots/ui-quality/10-roadmap.png`
- Render-reviewed UI PDF: `output/pdf/monday_report_ui_quality_screenshots.pdf`
- GA evidence: `output/ga-readiness/Monday_Report_GA_READINESS.json` and `.md`
- Partner package: `output/package/Monday_Report_Partner_Preview.zip` (`388611` bytes; SHA-256 `9571a5f04cc849721e1ba370de3b1effb89919384e80f6b7ff5f800574a4787b`)
- Partner approval: `output/package/Monday_Report_Partner_Preview_APPROVAL.json` and `.md`

Security review: `git diff --check` passed; the GA environment file remains ignored; no credential, private-key, local-state, cache, log, browser-profile, or machine-path artifact was found in the release ZIP. Archive CRC validation passed and all required Benchmarking files were present. The ZIP intentionally contains only a placeholder `partner.env.example`, never a populated environment file.

Git result: release commit `f7b66353704d0d99f36698298e73c6164c85ccf0` (`Add benchmarking module and evidence workflow`) was pushed successfully from branch `main` to the private `origin` repository `RAA233/monday-report`; local, remote-tracking, and GitHub branch heads matched after dispatch. Remaining release constraint: the partner ZIP is approved only for synthetic demo/testing and is not a real-client-data dispatch package.

## 2026-07-15 Source-Driven Schematic Extraction Evidence

Increment completed on `2026-07-15` from starting revision `29be738b467b597158ac2f21867c269dd64c051d` on branch `claude/init-11040f`. Scope: the casing schematic and 24 hr activity timeline now derive from parsed DDR/PDF source evidence with page-level citations and confidence, carry explicit `source`/`reference` provenance through the report draft, Report Studio, and Monday Report JSON, and fall back to labelled reference geometry (never presented as client-confirmed) when no source is found.

Files changed:

- `backend/app/schemas.py` — new `CasingString` and `ActivitySegment` models; additive `casing_strings`, `activity_timeline`, `schematic_source` fields on `ReportDraftResponse` (legacy `casing_program`/`operations_log` strings preserved).
- `backend/app/store.py` — deterministic structured extraction (`_extract_casing_strings`, `_extract_activity_timeline` with unit normalization, time-range validation, and overlap conflict flagging), casing/timeline evidence chunks, shared profile-selection and row builders, and source-driven `create_monday_report` schematic blocks with reference fallback.
- `backend/app/main.py` — report-draft casing/timeline builders now derive from the best PDF profile; new structured response fields and provenance audit metadata on `report_draft.generate`.
- `src/lib/api.ts` — `ApiCasingString`/`ApiActivitySegment` interfaces mirroring the Pydantic models plus additive draft fields.
- `src/components/ReportStudio.tsx`, `src/styles.css` — per-row `Source-derived · p.N · NN% confidence` vs `Reference · confirm from DDR` provenance badges and banners (text + `aria-label`, not colour alone); reference defaults demoted to fallback-only.
- `scripts/pdf_parser_guard.py`, `scripts/report_draft_guard.py`, `scripts/ui_quality_e2e.mjs` — behavioural assertions for structured extraction, cited chunks, source/reference provenance, conflicting-depth surfacing, cross-workspace isolation, audit provenance, no-fabrication, and a Report Studio provenance UI check.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed; 1,600 modules transformed. |
| `pnpm run audit:pdf-parser` | 0 | 16/16 checks: structured casing/timeline extraction, cited chunks, source-derived draft, and no-fabrication passed. |
| `pnpm run audit:report-draft` | 0 | 11/11 checks: source/reference provenance, conflicting-depth surfacing, cross-workspace isolation, and provenance audit metadata passed. |
| `pnpm run audit:report-variants` | 0 | Reviewed variant schema consistency retained. |
| `pnpm run audit:source-lineage` | 0 | Chunk-to-citation source lineage intact. |
| `pnpm run test:e2e` | 0 | 22/22 checks: audited upload/parse/validate/report/export workflow passed. |
| `pnpm run test:ui` | 0 | 83/83 checks incl. Report Studio schematic provenance visible; zero browser errors. |
| `pnpm run audit:all` | 0 | Full chain: 313 PASS, 0 FAIL. |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED` with **0 software blockers**; remaining blockers are configuration/infrastructure/evidence only (demo environment without the provisioned client env), unchanged by this increment. |
| `pnpm run report:ui-screenshots` | 0 | 15-page UI evidence PDF regenerated and visually reviewed. |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png` (provenance badges/banners visible), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Notes:

- `well_schematic.hole_sections` is a **direct deterministic projection** of the reviewed casing rows (interval top→shoe per casing name) only when casing rows are source-derived, so the well schematic cannot contradict the source-driven casing schematic; no bit size or new engineering value is inferred. It stays reference geometry when only reference casing rows exist. Independent hole-section/trajectory/directional/hydraulics extraction remains deferred follow-up work.
- Benchmarking behaviour is unchanged: Gordon `528` / Noble `588` configurable benchmarks, Hydraulics and Torque & Drag recommended-only, and review-required AI interpretations all retained (`audit:benchmarking` 23/23).
- Synthetic partner-demo approval remains separate from real-client production approval; reference schematic rows are always labelled and never described as extracted from client evidence.
- Follow-up: trajectory/hydraulics/directional schematic extraction, formatted HTML/PDF/XLSX provenance columns, deeper field-level correction workflow, local-LLM extraction router (Phase 06), and normalized PostgreSQL repositories (Phase 04).

Git result: feature commit `2b24ce23c3ac816a5b7fd642d45925096bc30227` (`feat(reporting): extract casing and activity evidence`) was delivered through pull request #1 (`https://github.com/RAA233/monday-report/pull/1`), rebase-merged into `main` as `63ebf5a`/`f52b7df` after review of files, mergeability, and scope. Software verification passed with zero software blockers, and this increment is not represented as production/client dispatch approval.

## 2026-07-15 Source-Driven Survey-Station Extraction Evidence

Increment completed on `2026-07-15` from base revision `f52b7df8ece538c04a7bf16c15e95bc75cb69871` (merged casing/timeline `main`) on branch `feat/source-survey-stations`. Scope: directional survey stations (MD, inclination, azimuth, plus TVD/DLS/N-S/E-W **only when explicitly stated in the source**) now extract deterministically from PDF survey tables, delimited text tables, and labelled narrative with page-level citations, deterministic confidence, exact-duplicate removal, same-MD/decreasing-MD conflict flags, metre-to-feet conversion only on explicit units, a 200-row cap with recorded truncation, and an honest no-source state (`survey_stations = []`, `survey_source = "none"`, UI text "No source survey stations — confirm or enter from DDR"). **No trajectory geometry is calculated, interpolated, or fabricated** — minimum-curvature/TVD/DLS/displacement derivation remains explicitly out of scope.

Files changed:

- `backend/app/schemas.py` — new validated `SurveyStation` model (`source: Literal["source"]` only — no reference fallback exists for surveys); additive `survey_stations`/`survey_source` on `ReportDraftResponse`.
- `backend/app/store.py` — deterministic survey extraction (`_extract_survey_stations` with header mapping, unit handling, range validation, dedup, conflict flagging, deterministic ordering, row cap), `survey_station` evidence chunks, shared `survey_rows_from_profiles` builder used by both the report draft and `create_monday_report` (`morning_report.survey_stations` + `survey_source`).
- `backend/app/main.py` — report draft populates `survey_stations`/`survey_source`; `report_draft.generate` audit metadata adds survey source, source/conflict row counts, truncation state.
- `src/lib/api.ts` — `ApiSurveyStation` mirror plus additive draft fields.
- `src/components/ReportStudio.tsx`, `src/styles.css` — semantic "Directional survey stations" table with per-row `Source-derived · p. N · NN% confidence` badges, `Conflict — review` flags, `—` for absent values, the exact no-source empty state, and a Trajectory control tile station count (scalar MD/TVD/DLS retained).
- `scripts/pdf_parser_guard.py`, `scripts/report_draft_guard.py`, `scripts/ui_quality_e2e.mjs` — behavioural coverage: clean table, duplicate, same-MD conflict, invalid inclination rejection, explicit metre conversion, missing TVD/DLS staying missing, page evidence chunks, no-fabrication, repeat-extraction determinism, no-evidence and cross-workspace isolation, draft/Monday-Report-JSON consistency, audit provenance, and the survey section/empty-state UI assertion.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:pdf-parser` | 0 | 21/21 checks: structured survey extraction, conflicts flagged not merged, cited survey chunks, source-derived draft rows, deterministic re-extraction, and no fabrication passed. |
| `pnpm run audit:report-draft` | 0 | 15/15 checks: source/none provenance, conflict visibility with reduced confidence, cross-workspace isolation, survey audit metadata, and Monday Report JSON consistency passed. |
| `pnpm run audit:report-variants` | 0 | 11/11 checks retained. |
| `pnpm run audit:source-lineage` | 0 | 6/6 checks retained. |
| `pnpm run audit:benchmarking` | 0 | 23/23 checks: Gordon `528`/Noble `588`, Hydraulics and Torque & Drag recommended-only, and review-required AI interpretations unchanged. |
| `pnpm run test:e2e` | 0 | 22/22 checks with fresh branch servers. |
| `pnpm run test:ui` | 0 | 85/85 checks (incl. the survey section and exact empty-state text) with zero browser errors. |
| `pnpm run audit:all` | 0 | Full chain: 326 PASS, 0 FAIL. One environmental rerun was required because `rg` was missing from the shell PATH for the stale-branding scan; the machine's installed ripgrep binary was supplied and the chain passed with no guard changes. |
| `pnpm run ga:readiness` | 0 | `GA_READY` in the locally provisioned approval environment with **0 software blockers**; this remains local approval evidence, not real-client dispatch approval. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated and visually reviewed (survey empty state and provenance visible; Benchmarking and Roadmap unchanged). |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png` (Directional survey stations section with exact no-source state), `output/screenshots/ui-quality/04-benchmarking.png` and `output/screenshots/ui-quality/10-roadmap.png` (unchanged order), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Notes:

- Survey stations are **source extraction only**: the survey-extraction increment introduced no engineering calculation, and missing optional values stay missing. (The later minimum-curvature increment below adds calculated geometry in a structurally separate, review-gated block without changing this extractor.)
- Conflicting same-MD rows and decreasing-MD evidence remain visible with `conflict = true` and confidence clamped to `<= 0.5`; nothing is silently merged, repaired, or discarded.
- Tenant/workspace isolation verified: another workspace's survey profile cannot populate a draft; citations stay within the owning workspace.
- Benchmarking behaviour is unchanged, and `market_benchmark.current_dls` is untouched; no benchmark measurement is auto-populated from survey data.
- Synthetic partner-demo approval remains separate from real-client production approval.
- Follow-up: trajectory geometry (documented minimum-curvature calculator), directional/trajectory visualization, hydraulics visual extraction, formatted HTML/PDF/XLSX export provenance, field-level correction workflow, local-LLM extraction router (Phase 06), and normalized PostgreSQL repositories (Phase 04).

## 2026-07-16 Minimum-Curvature Trajectory Calculation Evidence

Increment completed on `2026-07-16` from base revision `a0e6d7fc3232ae113e1b0c7871418eed25c75bf9` (merged survey-station `main`) on branch `feat/trajectory-min-curvature`. Scope: a documented, test-backed **minimum-curvature calculation foundation** (`minimum_curvature v1`, specification in `docs/TRAJECTORY_CALCULATION.md`) derives per-interval dogleg/DLS/ΔTVD/ΔN-S/ΔE-W and cumulative positions from calculation-eligible source survey stations. **Calculation only — no trajectory chart.** Every result carries `source="calculated"`, `review_state="review_required"`, method and version; source survey values are never overwritten, conflicts and gaps are skipped per reason and never bridged, planned/actual sequences stay separate, per-axis coordinate anchoring is explicit (`source_absolute`/`relative_first_station`/`none` — relative values are never presented as absolute well coordinates), the near-antipodal singularity fails safely, and the pure result is deterministic and timestamp-free. This is a drafting aid, **not certified directional-survey software**, and calculated DLS is never written into Benchmarking.

Files changed:

- `docs/TRAJECTORY_CALCULATION.md` — required technical specification: canonical formulas, unit/coordinate conventions, zero/near-zero/antipodal numerical policy, anchoring, provenance, no-overwrite policy, worked test vectors, engineering-review disclaimer.
- `backend/app/trajectory.py` — pure deterministic module (`dogleg_angle_rad`, `ratio_factor`, `calculate_minimum_curvature_interval`, `calculate_trajectory`) with no store/API/filesystem/env/timestamp dependencies.
- `backend/app/schemas.py` — `TrajectoryCoordinateReference`, `TrajectoryAnchor`, `TrajectoryInterval`, `CalculatedTrajectoryStation`, `TrajectorySkipSummary`, `TrajectoryCalculation`; additive `trajectory`/`trajectory_source` on `ReportDraftResponse`.
- `backend/app/store.py` — shared `trajectory_from_survey_rows` builder used by both the report draft and `morning_report.trajectory_calculation` (+ `trajectory_source`) so draft and Monday Report JSON stay identical.
- `backend/app/main.py` — draft population and hash-chained `report_draft.generate` audit metadata (method/version, review state, segment/interval/eligible counts, skip totals, coordinate-reference modes).
- `src/lib/api.ts` — exact TypeScript mirrors (`ApiTrajectoryCalculation` et al.) plus optional draft fields.
- `src/components/ReportStudio.tsx`, `src/styles.css` — side-by-side `TVD calc`/`DLS calc` columns labelled `Calculated · minimum curvature v1 · review required`, informational source/calculated delta notes (no pass/fail engineering tolerance), calculation summary with reference modes and skip counts, keyboard-accessible calculated N/S–E/W details block, `—` for excluded rows.
- `scripts/trajectory_calculation_guard.py` + `package.json` (`audit:trajectory-calculation`, wired into `audit:all`) — 31 behavioural vectors including the exact worked example (MD 3500/15°/20° → 3600/25°/45°), zero/near-zero continuity, antipodal safe failure, no-bridge segmentation, anchoring modes, no-overwrite, determinism, and a 200-station bounded set.
- `scripts/report_draft_guard.py`, `scripts/pdf_parser_guard.py`, `scripts/ui_quality_e2e.mjs` — integration coverage: calculated interval with mixed anchors and audit provenance, no-bridge through the conflict block (honest `trajectory_source="none"` end-to-end from a real PDF), draft↔Monday-Report-JSON equality, source-vs-calculated disagreement without overwrite, and a UI check that no calculation claim renders without stations.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules incl. `trajectory.py` compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:trajectory-calculation` | 0 | 31/31 vectors passed. |
| `pnpm run audit:pdf-parser` | 0 | 22/22 checks (incl. honest no-bridge trajectory "none" from real PDF parsing). |
| `pnpm run audit:report-draft` | 0 | 21/21 checks (calc interval, mixed anchors, no-overwrite, JSON equality, audit provenance). |
| `pnpm run audit:report-variants` | 0 | 11/11 retained. |
| `pnpm run audit:source-lineage` | 0 | 6/6 retained. |
| `pnpm run audit:benchmarking` | 0 | 23/23 — Gordon `528`/Noble `588`, recommended-only diagnostics, review-required AI interpretations unchanged; no calculated-DLS auto-population. |
| `pnpm run test:e2e` | 0 | 22/22 with fresh branch servers. |
| `pnpm run test:ui` | 0 | 86/86 with zero browser errors (incl. no-fabricated-calculation UI check). |
| `pnpm run audit:all` | 0 | Full chain: 364 PASS, 0 FAIL. One environmental rerun: the temp-dir ripgrep copy used by the stale-branding scan had been cleaned; the machine's installed ripgrep binary was restored and the chain passed with no guard changes. |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED`: software-owned GA checks pass (**0 software blockers**); remaining blockers are configuration/external-infrastructure/reviewed-evidence requirements in the current environment. Not client/production authorization. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated and visually reviewed (survey empty state intact, no calculation claims without stations, Benchmarking/Roadmap unchanged). |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png`, `04-benchmarking.png`, `10-roadmap.png` (unchanged order), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Notes:

- The calculation block is structurally separate from source stations; source TVD/DLS/N-S/E-W are immutable and disagreements render side-by-side with an informational delta only.
- `input_confidence_min` reflects the lowest source-extraction confidence among input stations — never numerical accuracy or certification.
- Synthetic partner-demo approval remains separate from real-client production approval.
- Follow-up: directional/trajectory visualization (chart), hydraulics extraction, formatted HTML/PDF/XLSX export provenance, field-level correction workflow, local-LLM extraction router (Phase 06), normalized PostgreSQL repositories (Phase 04).

Git result: PR #3 (`https://github.com/RAA233/monday-report/pull/3`) was reviewed (scope, numerics, lightweight reverification) and rebase-merged into `main` as `4c479b6153362af6289dddd0926218b6e9bc9e35` on `2026-07-16`; the merged tree is byte-identical to verified commit `c7ecf61`. The remote feature branch was deleted; the local branch remains (safe `-d` refused after the rebase hash rewrite).

## 2026-07-16 Calculated Trajectory Plan-View Visualization Evidence

Increment completed on `2026-07-16` from base revision `4c479b6153362af6289dddd0926218b6e9bc9e35` (merged minimum-curvature `main`) on branch `feat/trajectory-plan-view`. Scope: a review-gated, segment-aware **plan view (E/W vs N/S)** of the calculated trajectory stations in Report Studio — plain accessible SVG with no chart dependency and **no calculation changes** (`backend/app/trajectory.py` mathematics untouched; the only backend change is the mandated additive `survey_type` identity on calculated stations so consumers never infer type from array order).

Behaviour:

- One polyline per explicit calculation segment; paths are **never bridged** across conflicts, missing angles, zero/decreasing MD, antipodal skips, or survey-type boundaries (E2E asserts two 2-point paths for the two-segment fixture).
- Equal ft scale on both axes (north up, east right, letterboxed — never stretched); deterministic viewBox, padding, and tick generation; anchor station marked and labelled.
- Planned/actual paths distinguished by dash pattern, marker shape, and legend text — never colour alone.
- Relative coordinates labelled exactly: "relative to the first calculated station — not absolute well coordinates"; per-axis mixed references supported; no geographic terminology.
- Degenerate handling uses the 0.01 ft display-precision epsilon only (no arbitrary engineering threshold): zero-lateral wells show "Plan-view lateral extent is effectively zero; review the calculated station table." while legitimate small laterals render scaled up.
- `Calculated · minimum curvature v1 · review required` and the not-certified disclaimer accompany the plot; SVG carries `role="img"`, `<title>`, `<desc>`; the calculated-positions details list remains the full text fallback.
- No plot and no calculation claim render when `trajectory_source = "none"` (asserted); the survey empty state is unchanged.

Files changed: `src/components/TrajectoryPlanView.tsx` (new reusable component), `src/components/ReportStudio.tsx`, `src/styles.css`, `backend/app/trajectory.py` + `backend/app/schemas.py` + `src/lib/api.ts` (additive `survey_type` on calculated stations, guard-asserted), `scripts/trajectory_calculation_guard.py` (now 32 vectors incl. explicit segment/type identity), `scripts/report_draft_guard.py`, `scripts/ui_quality_e2e.mjs` (deterministic seeded fixture + 10 new assertions), `docs/TRAJECTORY_CALCULATION.md` (visualization semantics note), tracker/roadmap/README.

Deterministic UI fixture: `test:ui` now seeds a synthetic survey PDF (built by reusing the importable `build_pdf_fixture` helper from `scripts/pdf_parser_guard.py`) into the served workspace via `POST /uploads/direct` plus an exit-checked `python -m backend.app.worker` run — two eligible station pairs separated by a same-MD conflict pair, giving exactly two calculation segments, a source-TVD anchor, and relative N/S–E/W. The suite asserts the no-source state **before** seeding and therefore expects a fresh/isolated server state; this verification ran the API with an isolated `MONDAY_REPORT_STATE_PATH`/storage/export root so the demo `.local_data` state was never touched.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:trajectory-calculation` | 0 | 32/32 vectors (31 prior + explicit segment/survey-type identity). |
| `pnpm run audit:pdf-parser` | 0 | 22/22 retained. |
| `pnpm run audit:report-draft` | 0 | 21/21 incl. calculated-station identity contract. |
| `pnpm run audit:report-variants` / `audit:source-lineage` | 0 | 11/11, 6/6 retained. |
| `pnpm run audit:benchmarking` | 0 | 23/23 — Benchmarking untouched. |
| `pnpm run test:e2e` | 0 | 22/22 against fresh isolated-state servers. |
| `pnpm run test:ui` | 0 | **96/96 with zero browser errors** — seeded plan-view geometry, segment-path counts, relative/review/disclaimer labels, accessible title, and the no-source no-plot state all asserted. |
| `pnpm run audit:all` | 0 | Full chain: **368 PASS, 0 FAIL**. One environmental rerun: the live-server phase audit spawns `worker:once`, which must share the isolated state env used by the API — the first attempt un-exported it mid-run; re-ran with consistent env, no guard changed. |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED`: software-owned checks pass (**0 software blockers**); remaining blockers are configuration/external-infrastructure/reviewed-evidence requirements. Not client/production authorization. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated; `03-report-studio.png` visually shows the seeded survey table, calc columns with the source/calculated delta note, and the two-segment plan view with anchor marker and relative-coordinate labelling; Benchmarking/Roadmap order unchanged. |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png`, `04-benchmarking.png`, `10-roadmap.png` (unchanged order), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Follow-up: vertical trajectory profile, hydraulics visualization/extraction, formatted HTML/PDF/XLSX export provenance, field-level correction workflow, local-LLM extraction router (Phase 06), normalized PostgreSQL repositories (Phase 04).

Git result: PR #4 (`https://github.com/RAA233/monday-report/pull/4`) was reviewed (scope, additive contract, geometry, fixture isolation) and rebase-merged into `main` as `caff8848bc7d0e491a5253b96164e15f333d8c43` on `2026-07-16`; the merged tree is byte-identical to verified commit `f655538`. The remote feature branch was deleted; the local branch remains (safe `-d` refused after the rebase hash rewrite).

## 2026-07-16 Vertical Trajectory Profile Evidence

Increment completed on `2026-07-16` from base revision `caff8848bc7d0e491a5253b96164e15f333d8c43` (merged plan-view `main`) on branch `feat/trajectory-vertical-profile`. Scope: a review-gated **vertical trajectory profile** rendering **one panel per explicit calculation segment** — horizontal displacement from that segment's anchor (ft, positive right, unsigned magnitude) against calculated TVD (ft, **increasing downward**). Incompatible TVD references are never overlaid on a shared axis, paths never bridge segment breaks, and MD is never used as a horizontal coordinate.

Behaviour and contract:

- `horizontal_displacement_ft` is added additively to calculated stations as **backend result assembly** (`math.hypot(ns − segment_anchor_ns, ew − segment_anchor_ew)`): each segment's anchor is exactly 0 ft by construction, **non-zero source-absolute N/E anchors never produce a global-origin magnitude** (guard vector: a station 3 ft N / 4 ft E of a `(1000, 2000)` anchor reports 5 ft, not ~2241 ft), planned/actual sequences keep independent anchors, and the field is never populated on source survey rows. No minimum-curvature formula, eligibility, segmentation, threshold, or anchoring change; no React-side engineering math.
- Shared display helpers (`niceTickStep`/`tickValues`/`formatFt`/display epsilon) extracted to `src/lib/trajectoryGeometry.ts` (display mapping only); the plan view was refactored onto them with unchanged rendering.
- Equal ft-per-pixel scale with letterboxing; deterministic viewBox/ticks; no interpolation; zero-lateral segments render as TVD progression at HD 0 with "Horizontal displacement is effectively zero; this profile represents calculated TVD progression." (0.01 ft display epsilon only — no arbitrary engineering threshold); small valid laterals render scaled.
- Labels: `Calculated · minimum curvature v1 · review required`, not-certified disclaimer, "Horizontal displacement is calculated from this segment's first calculated station", per-axis TVD reference mode, relative-N/E note when applicable; per-panel `role="img"`/`<title>`/`<desc>`; the calculated-positions details fallback now lists `HD … ft from segment anchor`.
- One test-only correction during verification: the rotated SVG y-axis label is not reliably reported visible by Playwright, so the TVD-down assertion targets the accompanying HTML note; one styling correction scoped the shared SVG classes to both visuals (profile panels initially rendered with SVG-default black fill).

Files changed: `backend/app/trajectory.py` (HD assembly only), `backend/app/schemas.py` + `src/lib/api.ts` (mirrored field), `src/lib/trajectoryGeometry.ts` (new shared display helpers), `src/components/TrajectoryVerticalProfile.tsx` (new), `src/components/TrajectoryPlanView.tsx` (helper refactor, rendering unchanged), `src/components/ReportStudio.tsx`, `src/styles.css`, `scripts/trajectory_calculation_guard.py` (38 vectors), `scripts/report_draft_guard.py`, `scripts/ui_quality_e2e.mjs` (7 new profile assertions on the existing seeded fixture), `docs/TRAJECTORY_CALCULATION.md` (HD definition + profile axis conventions), tracker/roadmap/README.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:trajectory-calculation` | 0 | **38/38** — all prior minimum-curvature vectors plus 6 HD vectors (3-4-5, absolute-anchor, per-segment reset, planned/actual anchors, vertical zero-HD, determinism/delta-consistency). |
| `pnpm run audit:pdf-parser` | 0 | 22/22 retained. |
| `pnpm run audit:report-draft` | 0 | 21/21 incl. HD contract (anchor 0, later station > 0) and draft↔JSON equality. |
| `pnpm run audit:report-variants` / `audit:source-lineage` | 0 | 11/11, 6/6 retained. |
| `pnpm run audit:benchmarking` | 0 | 23/23 — Benchmarking untouched; no HD feeds any measurement. |
| `pnpm run test:e2e` | 0 | 22/22 against fresh isolated-state servers. |
| `pnpm run test:ui` | 0 | **103/103 with zero browser errors** — per-segment profile panels, no bridged paths, HD-zero anchors, axis/anchor/reference labels, accessible titles, and all prior plan-view/no-source assertions. |
| `pnpm run audit:all` | 0 | Full chain: **374 PASS, 0 FAIL**. |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED`: software-owned checks pass (**0 software blockers**); remaining blockers are configuration/external-infrastructure/reviewed-evidence requirements. Not client/production authorization. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated; `03-report-studio.png` visually shows the survey table, plan view, and both properly-styled per-segment vertical profile panels; Benchmarking/Roadmap order unchanged. |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png`, `04-benchmarking.png`, `10-roadmap.png` (unchanged order), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Follow-up: hydraulics visualization/extraction, formatted HTML/PDF/XLSX export provenance, field-level correction workflow, local-LLM extraction router (Phase 06), normalized PostgreSQL repositories (Phase 04).

Git result: PR #5 (`https://github.com/RAA233/monday-report/pull/5`) was reviewed and rebase-merged into `main` as `f9e1e5bad628cf6d0217509c71d5eb2c105f6773` on `2026-07-16`; the merged tree is byte-identical to verified commit `8fbf6b2`. The remote feature branch was deleted; the local branch remains (safe `-d` refused after the rebase hash rewrite).

## 2026-07-16 Hydraulics Observation Extraction Evidence

Increment completed on `2026-07-16` from base revision `f9e1e5bad628cf6d0217509c71d5eb2c105f6773` (merged vertical-profile `main`) on branch `feat/hydraulics-observations`. Scope: **source-derived hydraulics observations** (parser `deterministic_hydraulics v1`, specification in `docs/HYDRAULICS_EXTRACTION.md`) — flow rate, standpipe pressure, mud weight, ECD, PV, YP, pump rate, and text-only nozzle configuration extracted from labelled narrative (multiple measurements per line) and unit-headed tables with **explicit units only** (documented kPa→psi ×0.1450377377, L/min→gpm ÷3.785411784, sg→ppg ×8.345404452; ambiguous values such as bare `MW 1.15` and negative flow/pressure are never emitted), page-cited `hydraulic_observation` chunks, and an honest no-source state (`hydraulics_observations = []`, `hydraulics_source = "none"`, UI text "No source hydraulics observations — confirm or enter from DDR").

Behaviour and boundaries:

- **Context-aware conflicts**: the conflict key is (measurement, time, observation_status, equipment, fluid system) — Pump 1 vs Pump 2, active vs kill mud, and planned vs observed values never conflict merely because their values differ; same-context disagreements are flagged with confidence ≤ 0.5, never merged.
- **`observation_status`** is `observed`/`planned`/`unknown` from explicit source wording only; equipment (`Pump 2`) and fluid system (`kill mud`) labels are captured; raw and normalized time are both retained and never inferred; a missing time never drops a row.
- **No engineering sanity ranges**: structurally valid but out-of-band values (documented order-of-magnitude review bands) are retained with `review_flag=true` / `review_reason="source value requires review"` — a review prompt, not an acceptance judgement.
- **Recommendation boundary preserved and guard-asserted**: extraction never creates, triggers, clears, or reprioritizes the recommended-only Hydraulics/Torque & Drag `DiagnosticAction`s and never writes any Benchmarking measurement; no hydraulic calculation of any kind (no ECD/pressure-loss/HHP/HSI/surge-swab/nozzle TFA).
- Shared `hydraulics_rows_from_profiles` builder keeps the Report Draft and `morning_report.hydraulics_observations` identical; the legacy scalar `mud_weight` draft field is unchanged; audit metadata carries aggregate counts only (source/conflict/review/status/truncation + parser id), never raw source text; 100-row cap with recorded truncation.
- Report Studio "Hydraulics observations" table shows Measurement / Value / Source value / Status / Time / Equipment-system / Evidence with the wording "Source-derived observations — informational and review-required. Hydraulics and Torque & Drag diagnostics remain recommended-only."; the Hydraulics control tile gains only a source-observation count.

Files changed: `backend/app/schemas.py` (`HydraulicObservation` + additive draft fields), `backend/app/store.py` (parser, chunks, shared builder, Monday-Report block), `backend/app/main.py` (draft + audit metadata), `src/lib/api.ts` (mirrors), `src/components/ReportStudio.tsx` (table + tile count), `scripts/hydraulics_extraction_guard.py` (new, wired as `audit:hydraulics-extraction` into `audit:all`), `scripts/pdf_parser_guard.py`, `scripts/report_draft_guard.py`, `scripts/ui_quality_e2e.mjs` (fixture hydraulics lines + 6 assertions), `docs/HYDRAULICS_EXTRACTION.md` (new spec), `package.json`, tracker/roadmap/README.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py` | 0 | Backend modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:hydraulics-extraction` | 0 | **21/21** — conversions, context-aware conflicts, review flags, nozzle text-only, rejection rules, determinism, truncation, tables, chunks, draft↔JSON equality, isolation, audit aggregates, legacy mud-weight, and the recommendation/Benchmarking boundary. |
| `pnpm run audit:pdf-parser` | 0 | 23/23 (incl. the labelled mud-weight observation). |
| `pnpm run audit:report-draft` | 0 | 22/22 (incl. the honest hydraulics none state). |
| `pnpm run audit:report-variants` / `audit:source-lineage` | 0 | 11/11, 6/6 retained. |
| `pnpm run audit:trajectory-calculation` | 0 | **38/38 regression clean.** |
| `pnpm run audit:benchmarking` | 0 | **23/23 regression clean.** |
| `pnpm run test:e2e` | 0 | 22/22 against fresh isolated-state servers. |
| `pnpm run test:ui` | 0 | **109/109 with zero browser errors** — hydraulics empty state pre-seed, seeded table rows, recommended-only wording, and all prior survey/trajectory assertions. |
| `pnpm run audit:all` | 0 | Full chain: **397 PASS, 0 FAIL.** |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED`: software-owned checks pass (**0 software blockers**); remaining blockers are configuration/external-infrastructure/reviewed-evidence requirements. Not client/production authorization. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated; `03-report-studio.png` shows the populated hydraulics table beneath the survey table, plan view, and vertical profiles; Benchmarking/Roadmap order unchanged. |

Evidence paths: `output/screenshots/ui-quality/03-report-studio.png`, `04-benchmarking.png`, `10-roadmap.png` (unchanged order), `output/pdf/monday_report_ui_quality_screenshots.pdf`, `output/qa/ui_quality_e2e_manifest.json`.

Follow-up: FORGE eval promotion, local-LLM extraction router (Phase 06), formatted HTML/PDF/XLSX export provenance, field-level correction workflow, normalized PostgreSQL repositories (Phase 04), hydraulics trend visualization (later slice on this extraction).

Git result: PR #6 (`https://github.com/RAA233/monday-report/pull/6`) was reviewed and rebase-merged into `main` as `c81e3563f72d02f6db4c4a9604f68eba7ad7a16e` on `2026-07-18`; the merged tree is byte-identical to the verified head. The remote feature branch was deleted; the local branch remains (safe `-d` refused after the rebase hash rewrite).

## 2026-07-18 FORGE Evaluation Promotion Evidence

Increment completed on `2026-07-18` from base revision `c81e3563f72d02f6db4c4a9604f68eba7ad7a16e` (merged hydraulics `main`) on branch `feat/forge-eval-promotion`. Scope: **reviewed FORGE ground-truth evaluation set** (`evals/forge/manifest.v1.json` + `evals/forge/expectations.v1.json`, documented in `docs/FORGE_EVAL_PROMOTION.md`) — a fixed stratified five-document selection (three drilling phases, two completion templates) pinned by corpus-relative path, SHA-256, and page count, with 65 required and 2 explicitly informational manually reviewed checks (`equals`, `approximately_equals`, `contains_row`, `row_count`, `absent`, `source_state`, `evidence_present`). Two distinct gates: portable `audit:forge-eval-spec` (in `audit:all`, runs without the corpus) and corpus-backed `audit:forge-evals` (real upload → worker (`backend.app.worker.run_once`) → profile → report-draft path per document in isolated temporary state; `SKIPPED`, never PASS, when the corpus is absent).

**Honest current result: PROMOTION BLOCKED.** The evaluation executed end-to-end (5/5 documents through the real pipeline) and recorded **11 required ground-truth failures across four parser defects** — D1 well-name bracket truncation (5 docs), D2 casing narrative overmatch fabricating rows from operational text (3 docs, including inch-fraction bit/pipe sizes misread as casing OD), D3 labeled-survey dot-thousands depth misparse with dropped azimuth (1 doc), D4 completion reports misclassified `daily_drilling_report` instead of the in-taxonomy generic `pdf_report` (2 docs). Per the no-parser-change rule, expectations were **not** weakened; a separate parser-fix PR is required, after which `audit:forge-evals` is rerun to complete promotion. 54/65 required checks pass (scalars, positive explicit-unit hydraulics with page evidence, survey count/evidence, honest absences, draft source states); recommendation/Benchmarking isolation and untouched demo state are guard-asserted. No parser, API, UI, or persistence file changed; no raw PDF, page image, prose, personnel name, or absolute path is committed.

Files changed: `evals/forge/manifest.v1.json` + `evals/forge/expectations.v1.json` (new committed reviewed authority), `scripts/forge_eval_common.py` (shared validator/engine), `scripts/forge_eval_spec_guard.py` (portable gate, 19 checks incl. rejection matrix), `scripts/build_forge_eval_manifest.py` (committed-manifest verification, never regenerates), `scripts/forge_eval_guard.py` (corpus-backed evaluator + `output/forge-evals/forge_eval_report.json`), `docs/FORGE_EVAL_PROMOTION.md` (new), `package.json` (two new commands; spec gate wired into `audit:all`), tracker/roadmap/README.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py scripts/forge_eval_*.py scripts/build_forge_eval_manifest.py` | 0 | Backend unchanged and new scripts compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:forge-eval-spec` | 0 | **19/19** — committed spec validates; duplicate IDs, absolute/backslash paths, bad SHA, missing/orphan coverage, unsupported check types, negative tolerance, long prose all rejected; tolerance enforcement and optional-cannot-mask-required proven. |
| `pnpm run audit:forge-corpus` | 0 | Existing corpus guard retained and green. |
| `pnpm run audit:forge-evals` | 1 | **Honest failing promotion gate**: 5/5 documents verified (SHA + page count) and processed through real upload/worker/draft; 67 checks — 54/65 required pass, **11 required failures = recorded parser defects D1–D4**, 2 informational failures; isolation clean (0 failures/validation tasks/anomalies/reports, demo state byte-identical); report at `output/forge-evals/forge_eval_report.json` with zero absolute paths. `PROMOTION BLOCKED` pending a separate parser-fix PR. |
| `pnpm run audit:pdf-parser` | 0 | 23/23 regression clean (no parser change). |
| `pnpm run audit:hydraulics-extraction` | 0 | 21/21 regression clean. |
| `pnpm run audit:trajectory-calculation` | 0 | **38/38 regression clean.** |
| `pnpm run audit:report-draft` | 0 | 22/22 regression clean. |
| `pnpm run audit:source-lineage` | 0 | 6/6 retained. |
| `pnpm run audit:benchmarking` | 0 | **23/23 regression clean.** |
| `pnpm run test:e2e` | 0 | 22/22 against fresh isolated-state servers. |
| `pnpm run test:ui` | 0 | **109/109 with zero browser errors** — no UI change. |
| `pnpm run audit:all` | 0 | Full chain: **416 PASS, 0 FAIL** (adds the 19-check portable FORGE spec gate; corpus-backed evaluation deliberately not in `audit:all`, so its skip/fail state can never masquerade as chain green). |
| `pnpm run ga:readiness` | 1 | `GA_BLOCKED`: software-owned checks pass (**0 software blockers**); remaining blockers are configuration/external-infrastructure/reviewed-evidence requirements. Not client/production authorization. |
| `pnpm run report:ui-screenshots` | 0 | UI evidence PDF regenerated; `03-report-studio.png`, `04-benchmarking.png`, `10-roadmap.png` order unchanged. |

Evidence paths: `output/forge-evals/forge_eval_report.json`, `output/forge-evals/forge_manifest_verification.json`, `output/forge-corpus/forge_corpus_summary.json`, `output/screenshots/ui-quality/` (order unchanged), `output/pdf/monday_report_ui_quality_screenshots.pdf`.

Licensing: the local corpus folder carries no license/notice file, so redistribution is not asserted; raw PDFs stay untracked and committed expectations hold minimal technical facts only (no prose, images, personnel names, or phone numbers). FORGE evidence is extraction-quality evidence only and never substitutes for anonymized-client readiness evidence.

Follow-up: **FORGE parser-fix PR (D1–D4) then rerun `audit:forge-evals` to complete promotion**, local-LLM extraction router (Phase 06), formatted HTML/PDF/XLSX export provenance, field-level correction workflow, normalized PostgreSQL repositories (Phase 04), hydraulics trend visualization.

Git result: PR #7 (`https://github.com/RAA233/monday-report/pull/7`), retitled `Add FORGE corpus evaluation baseline` with an explicit promotion-blocked body before merge, was reviewed and rebase-merged into `main` as `d3671aad2265360968c0c6b433dacc083d1b4f2f` on `2026-07-18`; the merged tree is byte-identical to verified head `d8de756`. The remote feature branch was deleted; the local branch remains (safe `-d` refused after the rebase hash rewrite).

## 2026-07-18 FORGE Parser-Fix Promotion Evidence

Increment completed on `2026-07-18` from base revision `d3671aad2265360968c0c6b433dacc083d1b4f2f` (merged FORGE-baseline `main`) on branch `feat/forge-parser-fixes`. Scope: **general parser fixes for the four recorded FORGE defects (D1–D4)** — no FORGE filename or document-ID special case, and the committed evaluation ground truth (`evals/forge/manifest.v1.json`, `evals/forge/expectations.v1.json`) is **byte-unchanged** (SHA-256 `ddb2094c…` / `ff6b7d19…` before and after).

Fixes (all in `backend/app/store.py`, each behind failing-first vectors in the new portable `scripts/parser_regression_guard.py`, wired as `audit:parser-regression` into `audit:all`):

- **D1 well identifiers**: the well-field capture accepts brackets, `#`, and `&`, stops before an adjacent same-line `Label:` boundary via a tempered lookahead, and trims only demonstrably unmatched trailing delimiters — balanced bracketed suffixes stay byte-correct, and existing well/rig/operator/report-number fixtures are pinned unchanged.
- **D2 casing fabrication**: casing rows require positive casing context (casing/liner label with same-line semicolon inheritance, noun adjacency, ran/set/cemented/landed verbs, shoe association, or planned/proposed casing wording); bit/PDC/nozzle/drill-pipe/HWDP/BHA/hole-opener/pipe-handling/casing-readiness narrative is rejected outright; mixed fractions parse as complete diameters (`12 1/4"` → 12.25 in, `9 5/8"` → 9.625 in, `9-5/8` and `13 3/8"` supported) with the leftmost stated size winning and denominators never re-matched; depths become shoe depths only with explicit shoe/set/landed/planned association or label context.
- **D3 survey depth/azimuth**: `AZM`/`AZ`/`AZI`/`AZIMUTH` labels and `AZM (deg)` headers parse explicitly (azimuth is never fabricated when absent); a dot-grouped labelled MD token (`D{1,3}(.DDD)+`) is promoted to a thousands reading only with same-record corroboration — an explicitly foot-marked MD paired with a same-record feet-basis TVD that the decimal reading would impossibly undercut (the inline path additionally requires an explicit TVD foot marker; the table path requires an in-cell foot marker on the MD cell) — as a source-token disambiguation aid; ambiguous multi-dot tokens are skipped, never guessed and never crash extraction; legitimate decimals (152.5, 8530.2), inclination, DLS, metre conversions, and different-datum MD<TVD rows are untouched, and **no global MD≥TVD conflict rule was added** to `_validated_survey_row`.
- **D4 completion classification**: completion headings (`DAILY COMPLETION REPORT` / `COMPLETION REPORT` / `WELL COMPLETION REPORT`) are detected in the first page's header region only and veto only the generic marker-score fallback to yield the existing `pdf_report` type; explicit DDR headings always win, incidental completion narrative never downgrades a drilling report, no new document-type enum was added, and filenames are never consulted.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py scripts/parser_regression_guard.py` | 0 | Modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck and Vite production build passed. |
| `pnpm run audit:parser-regression` | 0 | **52/52** — the 23 pre-fix failing vectors now pass with all regression pins intact (bracketed/hash/ampersand wells, adjacent-label boundary, dangling-delimiter trim, five casing positives incl. fractions, eight casing negatives, thirteen survey vectors incl. corroborated promotion, datum safety, and the ambiguous multi-dot no-crash vector, ten classification vectors incl. word-bounded DDR-marker evidence — `address` and longer embedded tokens never count as DDR while standalone `DDR` headings/words keep the repository's affirmative-marker semantics, determinism, end-to-end upload→worker→profile/draft on synthetic PDFs, isolation). |
| `pnpm run audit:pdf-parser` | 0 | 23/23 regression clean — fixture values byte-identical. |
| `pnpm run audit:hydraulics-extraction` | 0 | 21/21 regression clean. |
| `pnpm run audit:trajectory-calculation` | 0 | **38/38 regression clean.** |
| `pnpm run audit:report-draft` | 0 | 22/22 regression clean. |
| `pnpm run audit:report-variants` / `audit:source-lineage` | 0 | 11/11, 6/6 retained. |
| `pnpm run audit:benchmarking` | 0 | **23/23 regression clean.** |
| `pnpm run audit:forge-eval-spec` | 0 | 19/19 — committed spec still validates portably. |
| `pnpm run audit:forge-evals` | 0 | **PROMOTED: 65/65 required PASS** — 5/5 SHA-verified documents through the real upload → worker → profile → draft pipeline; zero required failures; the two informational report-number checks remain non-required, unchanged, and still failing as documented future scope; recommendation/Benchmarking isolation clean; demo state byte-identical; report at `output/forge-evals/forge_eval_report.json` with zero absolute paths. |

FORGE evidence remains extraction-quality evidence only and never substitutes for anonymized-client readiness evidence.

Follow-up: local-LLM extraction router (Phase 06) validated against the promoted evaluation set, formatted HTML/PDF/XLSX export provenance, field-level correction workflow, normalized PostgreSQL repositories (Phase 04), hydraulics trend visualization.

## 2026-07-19 Field-Level Correction Foundation Evidence

Increment completed on `2026-07-19` from base revision `fcf6c6a47217d05657231d58a8f835b7e0ece249` (merged parser-fix `main`) on branch `feat/review-corrections-foundation`. Scope: an **auditable, tenant-scoped, versioned field-level correction & review-provenance foundation** (`docs/FIELD_CORRECTIONS.md`) selected from the enterprise GA readiness ledger — it **addresses (as a foundation, not fully closes)** the "no correction / revision-history entity" gap (extractions could previously only be accepted or rejected, never corrected with a preserved from/to trail). `pnpm run ga:readiness` reports `GA_BLOCKED` with **0 software / 0 configuration / 0 evidence blockers** and exactly **2 external-infrastructure blockers** (PostgreSQL, Redis), so this increment targets a priority-2 audit/data-integrity/operator-control deficiency rather than a readiness-reported software blocker.

Behaviour and boundaries:

- **Versioned overlay (not immutable append-only), source never overwritten.** A `FieldCorrection` records `source_value` / `corrected_value` / `correction_reason` / configured-actor context / timestamp / status without mutating the parsed document, `report_profile`, chunks, or citation lineage. Re-correcting the same `(workspace, target_type, field_key)` supersedes the prior record (version chain, updating its status/linkage — a persisted record is mutated, so this is versioned history in the snapshot, not an immutable event log); reverting flips status without destroying history.
- **Registry-gated correctable fields.** Only fields in the centralized `corrections_registry` (the report-identity scalars) may be corrected; unknown or sensitive fields (audit/hash, actor/role/permission, tenant/workspace ownership, recommendation/DiagnosticAction, Benchmarking metrics, parser method/version, source page/confidence/snippet/hash, FORGE expectations, validation-gate, model/prompt provenance, immutable identifiers, timestamps) return a stable `422`; no attribute is set dynamically from `field_key`; values are type/length/control-char/finite-number validated.
- **In-process serialization (not cross-process).** The whole correction route is serialized by a re-entrant lock so the single-active-lineage and no-lost-write invariants hold under threadpool concurrency (6-way concurrent guard vector); cross-process atomicity requires normalized persistence (Phase 04) and stays an open GA blocker.
- **Redacted, hash-chained audit.** `field_correction.record` / `field_correction.revert` events attribute the actor and carry attribution + shape only (field key, target type, value-present/changed booleans, reason length, version linkage) — never the raw source value, corrected value, or reason text; correction state and audit event persist in one `save()` (no in-process divergence); the audit chain stays sealed.
- **Recommendation / Benchmarking boundary intact.** Recording a correction creates no anomaly events, benchmark measurements, failures, or validation tasks, and never touches the recommended-only Hydraulics / Torque & Drag diagnostics.
- **Additive persistence, no migration.** The `field_corrections` collection is stored inside the existing tenant snapshot; old snapshots load as empty and both the local-JSON and PostgreSQL (JSONB) backends persist it with no migration.
- **Report Draft overlay.** `GET /workspaces/{id}/report-draft` returns active corrections in `field_corrections` as review-required overlays; the source-derived scalar/casing/survey/hydraulics values are unchanged. Applying corrected values into official JSON / formatted exports is deliberately out of scope (the separate export-provenance increment). The actor is the single **configured actor context** (`actor_source="configured"`), **not a verified per-user reviewer**, until the identity/RBAC increment lands.

**Honest GA-blocker status:** AUDIT-004 and DLP-09 are **addressed as a foundation, not fully closed** (versioned, not immutable; in-process, not cross-process). AUDIT-001 is **not closed** (no verified per-user reviewer identity — the actor is process-configured).

Files changed: `backend/app/schemas.py` (`FieldCorrection`/`FieldCorrectionCreate`/`FieldCorrectionRevert` + `ReportDraftResponse.field_corrections`), `backend/app/corrections_registry.py` (new correctable-field registry + validation), `backend/app/store.py` (snapshot collection + re-entrant lock + `record_field_correction`/`revert_field_correction`/`list_field_corrections` + `record_field_corrections`/`view_field_corrections` permissions), `backend/app/main.py` (three routes + registry endpoint + `require_permission` + draft surfacing + whole-route lock), `src/lib/api.ts` (`ApiFieldCorrection` mirrors + typed client methods), `scripts/field_correction_guard.py` (new, wired as `audit:field-corrections` into `audit:all`), `docs/FIELD_CORRECTIONS.md` (new), `package.json`, tracker/roadmap/README.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py scripts/field_correction_guard.py` | 0 | Modules compile. |
| `pnpm run build` | 0 | `tsc` typecheck (api.ts mirrors) and Vite production build passed. |
| `pnpm run audit:field-corrections` | 0 | **16/16** — configured-actor context + provenance, registry deny of unknown/sensitive fields (422), value validation (control-char/oversize/non-finite numeric rejected), registry catalog, redacted hash-chained audit with no raw source/corrected/reason text, version supersession, active-only filter, revert + 409, draft overlay without source overwrite, recommendation/Benchmarking/failure/validation isolation, workspace scoping, least-privilege permission hook, 6-way concurrent single-active-lineage/no-lost-write, persistence round-trip. |
| `pnpm run audit:report-draft` | 0 | 22/22 regression clean (additive `field_corrections` field). |
| `pnpm run audit:pdf-parser` / `audit:parser-regression` | 0 | 23/23, 52/52 regression clean. |
| `pnpm run audit:hydraulics-extraction` / `audit:trajectory-calculation` | 0 | 21/21, **38/38** regression clean. |
| `pnpm run audit:benchmarking` | 0 | **23/23** — recommended-only boundary intact. |
| `pnpm run audit:integrity` / `audit:redaction` / `audit:auth` | 0 | Audit hash-chain, redaction, and API-auth guards clean after the new audit actions. |
| `pnpm run audit:forge-eval-spec` / `audit:forge-evals` | 0 | 19/19; **corpus-backed 65/65 required PASS** — deterministic extraction unchanged. |

FORGE evidence and this correction foundation are software-owned readiness evidence only; neither confers client or production authorization.

Follow-up: immutable-event correction history (close AUDIT-004) + verified per-user reviewer identity/RBAC (close AUDIT-001) + cross-process atomicity via normalized persistence (Phase 04), field-correction application into official JSON / formatted export provenance, Phase 06 local-AI extraction router, hydraulics trend visualization. A likely next increment is **GA readiness-gate integrity** — making `ga:readiness` encode the known software/security/persistence/CI blockers so "0 software blockers" can never mislead.

## 2026-07-19 GA Readiness-Gate Integrity Evidence

Increment completed on `2026-07-19` from base revision `baf24b27bfe7dfbca3276eab241f9e7954aa32b6` (merged correction-foundation `main`) on branch `feat/ga-readiness-integrity`. Scope: a **truthful, registry-backed GA readiness gate** (`docs/GA_READINESS_INTEGRITY.md`) that prevents a false `GA_READY`. It does **not** implement the underlying RBAC, keyed audit chain, persistence redesign, CI platform, backup system, or Phase 06 router — those are declared as unresolved blockers until separate approved PRs satisfy their resolution conditions.

Contradiction corrected: the former gate computed blocker counts by intersecting failing checks with a hand-maintained 7-ID software set, so any gap without a check contributed **0** — reporting "software blockers: 0" while RBAC, per-user identity, keyed/anti-truncation audit integrity, migration runner, CI, dependency scanning, backup/restore, and more were absent. Provisioning PostgreSQL and Redis alone would have removed the only two visible blockers.

Behaviour and boundaries:

- **Committed blocker registry** (`evals/ga/blocker_registry.v1.json`, 28 entries): each carries id/label/category/severity/owner_type/policy_source/policy_reference/check_id/resolution_condition/allow_not_applicable/manual_review_required/description, every entry citing an existing policy source (no invented owners/authorities). A strict parser validates it.
- **Registry↔check parity**: the gate emits exactly one check per entry; a parity guard fails on a missing check, an orphan check, a duplicate id, an unknown category, or a missing resolution condition / policy reference. The former hand-maintained category ID sets are removed; blocker counts derive from each check's registry `category` (`uncategorized` is zero by parity, not by manual partition).
- **Disposition semantics** (`PASS`/`FAIL`/`BLOCKED`/`SKIPPED`/`NOT_APPLICABLE`/`REVIEW_REQUIRED`, additive to the preserved `pass`/`warn`/`fail` status): SKIPPED and missing evidence and missing/empty command execution never map to PASS; `BLOCKED`/`SKIPPED`/`FAIL`/`REVIEW_REQUIRED` all block; NOT_APPLICABLE requires an opt-in entry plus justification and no v1 entry opts in, so critical controls can never be dismissed. **No waiver, env var, static actor, or unsigned file can resolve a blocker in v1** (deferred until authenticated identity + signature verification exist).
- **Hardened weak checks**: official-export gate no longer passes on method-callable presence (`BLOCKED`); demo-seed detection uses stable identity markers (not a never-emitted audit action); parser coverage requires the promoted FORGE evidence (report present, 65/65, committed manifest/expectations SHA match) not an env flag; audit keyed-integrity and tail-truncation are separate `BLOCKED` controls; local-AI reachability stays narrow with the Phase 06 trust boundary registered separately.
- **Evidence integrity**: `output/ga-readiness/Monday_Report_GA_READINESS.json` binds `git_commit`/`git_tree`/`worktree_clean`, `registry_version`/`registry_sha256`, `commands_skipped`, and a canonical `payload_sha256` (UTF-8, sorted keys, `(",",":")`, self-excluded); a dirty worktree or skipped commands can never yield `GA_READY`; a fail-closed path-redaction scan refuses to write machine-specific paths.
- **Fail-closed decision**: `GA_READY` requires client mode, parity, every check PASS/justified-NA, all software commands run+pass, clean commit/tree, and a verifiable hash. **The repository remains `GA_BLOCKED` even with PostgreSQL+Redis provisioned**, because software/security/governance controls (and client approval, `REVIEW_REQUIRED`) remain unresolved.

Current truthful GA counts (registry-backed): **software 14, security_review 4, infrastructure 3, configuration 1, client_approval 1, data_review_evidence 0 (evidenced), total 23 blocking of 28 declared** in a demo/local run; the historical "0 software blockers" evidence rows above predate this gate and are superseded.

Files changed: `evals/ga/blocker_registry.v1.json` (new), `backend/app/ga_readiness.py` (new evaluator/registry/hashing), `backend/app/readiness.py` (hardened demo_seed_removed), `backend/app/schemas.py` (additive readiness-check metadata), `scripts/ga_readiness_guard.py` (registry-backed rewrite), `scripts/ga_readiness_integrity_guard.py` (new, `audit:ga-readiness-integrity` into `audit:all`), `src/lib/api.ts` (additive optional mirrors), `package.json`, `docs/GA_READINESS_INTEGRITY.md` (new), `docs/CLIENT_DATA_READINESS.md`, roadmap/README.

| Final command | Exit | Evidence |
|---|---:|---|
| `python -m py_compile backend/app/*.py scripts/ga_readiness_*.py` | 0 | Modules compile. |
| `pnpm run build` | 0 | `tsc` (additive api.ts mirrors) + Vite build passed. |
| `pnpm run audit:ga-readiness-integrity` | 0 | **44/44** — registry schema + rejections, parity (missing/orphan check), disposition blocking, skip/empty/missing-evidence never PASS, `--skip-commands` cannot be GA_READY, NOT_APPLICABLE restrictions, critical controls not N/A, hardened export/parser/audit checks, degenerate 0/0 FORGE report fails, evidence commit/tree/hash + tamper, path redaction, client-approval REVIEW_REQUIRED, PostgreSQL+Redis-provisioned-still-GA_BLOCKED, count reconciliation, legacy compatibility, determinism. |
| `pnpm run audit:field-corrections` / `audit:report-draft` | 0 | 16/16, 22/22 regression clean. |
| `audit:pdf-parser` / `parser-regression` / `hydraulics` / `trajectory` / `benchmarking` | 0 | 23/23, 52/52, 21/21, **38/38**, **23/23**. |
| `audit:integrity` / `audit:redaction` / `audit:auth` | 0 | clean. |
| `pnpm run audit:forge-eval-spec` / `audit:forge-evals` | 0 | 19/19; **65/65 required PASS** — deterministic extraction unchanged. |
| `pnpm run ga:readiness` | 1 | **`GA_BLOCKED` with truthful non-zero blockers** (software 14, security_review 4, infrastructure 3, configuration 1, client_approval 1); no category falsely zero. Not client/production authorization. |

## Phase Gate Rule

Every implementation slice must pass these checks before it is considered accepted:

- Frontend build: `pnpm run build`
- Audit harness environment-isolation guard: `pnpm run audit:harness`
- UI quality E2E and screenshots: `pnpm run test:ui`
- Backend compile: `python -m py_compile backend/app/*.py`
- API health: `GET http://127.0.0.1:8000/health`
- Frontend health: `GET http://127.0.0.1:5173`
- Audit endpoint: `GET http://127.0.0.1:8000/audit-logs`
- Audited processing workflow through `/uploads/direct`, `/processing-jobs`, `worker:once`, `/documents`, `/documents/{id}/chunks`, `/failures`, `/validation-tasks`, `/monday-reports`, and report exports
- Full E2E workflow: `pnpm run test:e2e`
- Client data readiness: `pnpm run audit:client-data`
- Clean client bootstrap: `pnpm run audit:bootstrap`
- State persistence guard: `pnpm run audit:state-persistence`
- Client-mode signed URL guard: `pnpm run audit:signed-url-guards`
- Upload size guard: `pnpm run audit:upload-limits`
- Upload ownership guard: `pnpm run audit:upload-ownership`
- Upload idempotency guard: `pnpm run audit:upload-idempotency`
- Source lineage guard: `pnpm run audit:source-lineage`
- Citation format guard: `pnpm run audit:citation-format`
- Source citation action guard: `pnpm run audit:source-citations`
- Runtime mock-data guard: `pnpm run audit:runtime-mock-data`
- Tracker clarity guard: `pnpm run audit:tracker-clarity`
- Product roadmap guard: `pnpm run audit:roadmap`
- Extracted text sanitization guard: `pnpm run audit:text-sanitization`
- Golden fixture readiness guard: `pnpm run audit:golden-fixtures`
- Parser/OCR fixture eval guard: `pnpm run audit:parser-fixture-evals`
- Parser/OCR eval report generator guard: `pnpm run audit:parser-fixture-report`
- PDF parser guard: `pnpm run audit:pdf-parser`
- Trajectory calculation guard: `pnpm run audit:trajectory-calculation`
- Hydraulics extraction guard: `pnpm run audit:hydraulics-extraction`
- OCR routing guard: `pnpm run audit:ocr-routing`
- OCR extraction guard: `pnpm run audit:ocr-extraction`
- Local AI runtime status guard: `pnpm run audit:local-ai`
- Partner preview package guard: `pnpm run audit:partner-package`
- Partner preview approval guard: `pnpm run audit:partner-approval`
- Client-data approval guard: `pnpm run audit:client-approval`
- Client operation guard: `pnpm run audit:client-ops`
- Source-backed report draft guard: `pnpm run audit:report-draft`
- Report variant schema guard: `pnpm run audit:report-variants`
- Report export idempotency guard: `pnpm run audit:report-export-idempotency`
- Benchmarking guard: `pnpm run audit:benchmarking`
- Runtime backend guard: `pnpm run audit:runtime-backends`
- Infrastructure readiness guard: `pnpm run audit:infra-readiness`
- Audit integrity guard: `pnpm run audit:integrity`
- Client API auth guard: `pnpm run audit:auth`
- Audit metadata redaction guard: `pnpm run audit:redaction`
- Malware scanner guard: `pnpm run audit:malware`
- Storage path guard: `pnpm run audit:storage-paths`
- Archive safety guard: `pnpm run audit:archive-safety`
- Retention policy guard: `pnpm run audit:retention`
- Stale branding scan for removed names
- Update this tracker when phase status changes

Run the combined local gates:

```powershell
pnpm run audit:phase
pnpm run audit:harness
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
pnpm run audit:runtime-mock-data
pnpm run audit:tracker-clarity
pnpm run audit:roadmap
pnpm run audit:text-sanitization
pnpm run audit:golden-fixtures
pnpm run audit:parser-fixture-evals
pnpm run audit:parser-fixture-report
pnpm run audit:pdf-parser
pnpm run audit:trajectory-calculation
pnpm run audit:hydraulics-extraction
pnpm run audit:ocr-routing
pnpm run audit:ocr-extraction
pnpm run audit:local-ai
pnpm run audit:partner-package
pnpm run audit:partner-approval
pnpm run audit:client-approval
pnpm run audit:client-ops
pnpm run audit:report-draft
pnpm run audit:report-variants
pnpm run audit:report-export-idempotency
pnpm run audit:benchmarking
pnpm run audit:runtime-backends
pnpm run audit:infra-readiness
pnpm run audit:integrity
pnpm run audit:auth
pnpm run audit:redaction
pnpm run audit:malware
pnpm run audit:storage-paths
pnpm run audit:archive-safety
pnpm run audit:retention
pnpm run audit:all
```

## Phase Status

| Phase | Status | Scope | Acceptance Evidence | Next Action |
|---|---|---|---|---|
| 00 | Complete | Product/spec lock | Execution plan and implementation spec exist | Keep specs updated from real build decisions |
| 01 | Complete | Chat-first frontend | Client Home opens first and routes directly into Local AI Chat | Keep chat actions aligned with official report creation/export |
| 02 | Complete | FastAPI scaffold | API health/session/chat/upload/report endpoints respond | Replace memory store with PostgreSQL repositories |
| 03 | Complete | Tracker/test/audit | Tracker UI, audit endpoint, audited upload workflow, phase audit script | Run audit gate after every slice |
| 04 | Active | Persistence/queue | Client approval environment activates PostgreSQL/RLS state and Redis queue; demo mode keeps local JSON | Expand snapshot storage into normalized PostgreSQL repositories |
| 05 | Complete | Parser/OCR | ZIP safety, typed parser chunks, native PDF table rows, `pdf_report_profile_v1` field/section extraction, OCR extraction, reviewed 13-family fixture manifest, and parser/OCR eval report pass | Maintain reviewed fixture/eval evidence as parsers evolve |
| 06 | Active | Local AI extraction | Deterministic scaffold extracts cited MWD failures, NPT hours, company, and validation tasks from parsed chunks; local AI defaults to Ollama `gemma4:e2b` and verifies the pinned model is available | Wire Ollama/LM Studio router, strict schemas, confidence scoring, and metrics |
| 07 | Complete | Validated exports | E2E verifies unresolved validation blocks export, validates extracted failures, creates report, exports JSON/CSV/HTML/PDF/XLSX artifacts, inspects artifact signatures, and downloads through signed URLs | Polish report templates |
| 08 | Complete | Real-client readiness | Live client-data approval is APPROVED with PostgreSQL/RLS, Redis, API key, signing secret, protected storage, retention, malware scanner, parser/OCR evals, reviewed fixture attestation, and local Gemma runtime | Run controlled client-package dry runs and maintain approval evidence |
| 09 | Complete | Morning report studio | Chat command center and Report Studio now show workflow steps, insight cards, risk register, tool actions, technical telemetry, source-backed draft generation, DDR/BHA/mud/survey/directional variants, issue-readiness board, source-driven casing/well schematic with provenance, AI plan checks, source-driven activity timeline, a source-only directional survey-station table with conflict flags plus side-by-side review-gated minimum-curvature calculations, and draft export | Extend the evidence pipeline to FORGE eval promotion and the Phase 06 local-AI router (hydraulics observations complete) |
| 10 | Complete | Roadmap cockpit | Product Roadmap view, execution board, typed roadmap data, UI screenshot coverage, tracker gate, and `audit:roadmap` guard are wired | Use roadmap execution board lanes to pull the next client-pilot hardening slice |
| 11 | Complete | Client landing and rig MR access | Client Home renders live workspaces, rig/MR list rows, import coverage, and JSON/CSV/HTML/PDF/XLSX export coverage | Add workspace-specific drilldowns and keep screenshot evidence refreshed |
| 12 | Complete | Reviewed normal report schemas | MR-SCHEMA-1 defines DDR, BHA, mud, survey, and directional extraction markers, drafting checks, and output sections; casing schematic, 24 hr activity timeline, and directional survey stations extract from source evidence with page provenance, and minimum-curvature trajectory geometry is calculated behind an explicit review gate | Pull directional/trajectory and hydraulics visualization next |

## Audit Notes

- Demo audit storage is durable local JSON in `.local_data/`; approved client mode stores state in the PostgreSQL state snapshot repository and uses protected upload/export roots.
- Persistent audit logs must move to PostgreSQL before customer data testing.
- Readiness reports requested infrastructure separately from active adapters; placeholder PostgreSQL/Redis URLs do not certify client mode while `local_json` and `inline_worker` are active.
- `/runtime/backends` exposes requested versus active repository and queue adapters, URL-presence booleans, client-readiness state, and blocking checks for the tracker.
- `MONDAY_REPORT_CLIENT_DATA_MODE=client` blocks uploads, chat, document reads, validation updates, report creation, and exports until `/readiness/client-data` reports ready.
- Client mode requires `MONDAY_REPORT_API_KEY` and the `X-Monday-Report-Key` header for protected API calls.
- Blocked unsafe client-mode operations emit `client_data.operation_blocked`.
- New audit events are hash-chain sealed; `/audit-logs/integrity` reports sealed, legacy, or broken ledger status.
- Sensitive audit metadata is redacted before sealing; prompts, filenames, paths, tokens, emails, and names are stored as fingerprints.
- `/retention/run` supports dry-run and explicit apply modes for expired uploads, parsed artifacts, reports, exports, and managed local files.
- `MONDAY_REPORT_MALWARE_SCANNER=builtin` explicitly enables the baseline scanner for client readiness; direct uploads and ZIP child files with blocked signatures are audited.
- Direct uploads batch the initial file record, scan result, processing job, queue enqueue, and audit persistence into a single clean-path save; blocked uploads still persist malware evidence before returning HTTP 422.
- Metadata and direct upload names plus ZIP entry names are sanitized before storage; traversal and reserved device names remain under tenant storage, and metadata-only completion fails closed until bytes exist.
- Embedded-text PDFs parse through `pdf_text_v1`; PyMuPDF is used when available, native table rows become evidence chunks, chunks carry page/table/row-specific PDF locator metadata, and `pdf_report_profile_v1` extracts DDR report number, well, rig, operator, hole size, MD, TVD, mud weight, operations, safety, casing, BHA, survey, and time breakdown sections.
- PDF profile fields and sections become cited chunks and prefill Report Studio drafts; NPT extraction now prefers explicit NPT-hour labels and ignores casing/depth units such as `6500 ft`.
- CSV, Excel, Word, and email chunks carry typed locator metadata for citation review.
- Chat citations render typed locator labels with source filenames.
- Chat citations can request signed source-file links from the evidence card.
- `/workspaces/{workspace_id}/report-draft` generates editable Report Studio fields from parsed documents, chunks, failures, validation tasks, and citations, then records `report_draft.generate`.
- Report Studio now exposes MR-SCHEMA-1 normal-format variants for DDR, BHA/tools, mud/hydraulics, survey quality, and directional steering reports; `pnpm run audit:report-variants` verifies required sections, extraction markers, drafting checks, output sections, UI coverage, and audit wiring.
- Client Home opens as the first screen and shows live rig workspaces, latest Monday Reports, open review counts, import coverage, and official JSON/CSV/HTML/PDF/XLSX export coverage.
- Product Roadmap is a guarded app surface; `audit:roadmap` verifies data, execution board markers, navigation, tracker gate, UI screenshot coverage, and `audit:all` wiring.
- Extracted text is scrubbed before chunking and before PostgreSQL JSONB persistence so PDF/table control characters cannot block corpus processing.
- Golden fixture readiness requires `MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST` to reference an `anonymized_client` manifest with all required fixture families and real files; real-client readiness also requires a reviewed anonymized-client attestation.
- Parser/OCR eval readiness requires `MONDAY_REPORT_PARSER_EVAL_REPORT` to reference a passing report covering all required fixture families with passing checks; `scripts/generate_parser_fixture_eval_report.py` creates that report from `MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST`, and incomplete reports warn in demo mode and fail in client mode.
- Image files and scanned PDFs route through `ocr_route_v1`, create file-level validation tasks, and emit `ocr.route` when OCR is unconfigured.
- `MONDAY_REPORT_OCR_ENGINE=tesseract` plus `MONDAY_REPORT_TESSERACT_CMD` enables local OCR extraction into `ocr_text_v1` chunks with image-page locators and `ocr.extract_complete` audit events; production OCR configuration and anonymized OCR evals remain real-client blockers.
- Phase and E2E audit scripts create isolated workspaces per run so old demo state cannot inflate report totals or mask extraction failures.
- Signed source and report export downloads serve generated bytes with explicit attachment headers after verifying signed tokens and audit readiness.
- Archive limits are configured through `MONDAY_REPORT_MAX_ZIP_ENTRIES` and `MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES`; limit rejections emit `archive.rejected` and mark terminal uploads failed.
- Official Monday Report exports return HTTP 409 while workspace validation tasks remain open; client mode ignores unresolved-validation override attempts.
- Repeated report exports reuse verified existing artifacts and audit `monday_report.export_reused` instead of creating duplicate records.
- Client-mode signed URL creation and download return HTTP 409 until `MONDAY_REPORT_SIGNING_SECRET` is configured with a real secret.
- Upload intake returns HTTP 413 and records `upload.rejected` when a file exceeds `MONDAY_REPORT_MAX_UPLOAD_BYTES`.
- Upload completion rejects and audits file IDs that belong to a different upload, preventing cross-upload processing lineage.
- Upload completion is idempotent for repeated file IDs and repeated complete requests; existing jobs are reused instead of duplicated.
- `/local-ai/status` reports Ollama or LM Studio configuration, pinned model, model availability, reachability, and hosted fallback posture; default partner model is `gemma4:e2b`.
- Partner preview package output: `output/package/Monday_Report_Partner_Preview.zip`; launcher defaults local AI to Ollama `gemma4:e2b`, starts API/web/worker loop, includes a sample ZIP import package, and ships an import/export smoke script.
- Partner preview approval output: `output/package/Monday_Report_Partner_Preview_APPROVAL.md` and `.json`; scope is partner demo/testing with synthetic data only.
- Client-data approval output: `output/client-data/Monday_Report_Client_Data_APPROVAL.md` and `.json`; current approved local client environment reports `APPROVED` after every `/readiness/client-data` check passes, including reviewed fixture attestation.
- Fresh startup creates a neutral workspace only; failure records must come from uploaded evidence or explicit fixture/eval commands.
- Every chat, upload, validation, report generation, signed URL, and admin policy action must produce an audit event.

## Authenticated identity foundation (2026-07-19)

Increment on branch `feat/authenticated-identity-foundation` from merged base
`c867b24d7eb91938f5530a000391c7832ed20ff9`. Scope: a **bounded authenticated
identity + request actor + RBAC foundation** (`docs/AUTHENTICATED_IDENTITY.md`).

- **Identity/credentials**: opaque per-user credentials (≥32 random bytes; only a
  SHA-256 hash + non-secret fingerprint stored; raw token returned once, never
  logged/audited/persisted) resolved **server-side** to a **request-scoped**
  identity (contextvar, cleared per request; concurrency-safe). Client-supplied
  identity headers are never trusted.
- **Client-mode hardening (review corrections)**: the legacy shared key is
  **rejected in client mode** (401) — no client-mode shared-key administrator;
  an active persisted non-bootstrap per-user credential is required. A bootstrap
  identity is **never persisted on startup** (derived in memory). Initial client
  admins are provisioned out-of-band with the local `python -m
  backend.app.identity_admin` CLI (no unauthenticated network bootstrap route).
- **RBAC**: existing roles only (`ADMIN`/`ENGINEER`/`VALIDATOR`/`MANAGER`;
  `VIEWER` not enabled), **default-deny**, no all-role fallback. The route
  inventory uses only the four approved categories; sensitive mutation routes are
  `permission_required` with `enforcement_status` `enforced` or **`pending`**.
  Pending routes keep `rbac-role-separation` a declared blocker.
- **Tenant**: the configured-tenant boundary is enforced (credential/user/runtime
  tenant must match); full multi-tenant/workspace authorization is **not**
  delivered.
- **Blockers intentionally left open**: this increment **closes no GA blocker** —
  `per-user-identity`, `rbac-role-separation` (route coverage incomplete),
  `tenant-authorization-enforcement`, and `verified-reviewer-identity` remain
  declared `BLOCKED`/`REVIEW_REQUIRED`; registry resolution conditions are
  unchanged and **`ga:readiness` remains `GA_BLOCKED`**.

| Command | Exit | Result |
| --- | --- | --- |
| `pnpm run audit:identity-rbac` | 0 | **73/73** — server-side credential resolution, request scoping + failure-path concurrency, default-deny RBAC, configured-tenant boundary, admin-only provisioning/revocation, one-time token, no token leakage, client-mode shared-key rejection, no startup persistence, route-inventory parity (pending rows keep RBAC blocked), GA stays `GA_BLOCKED`. |
| `pnpm run audit:auth` | 0 | **9/9** — 503/401 fail-closed, client-mode shared-key rejected, per-user credential accepted, revoked fails, demo-mode compatibility. |
| `pnpm run audit:ga-readiness-integrity` | 0 | 44/44 — unchanged; identity blockers remain BLOCKED. |
| `pnpm run ga:readiness` | 1 | **`GA_BLOCKED`** — the foundation closes no blocker. |

## Route-level RBAC enforcement (2026-07-19)

Increment on branch `feat/complete-route-rbac` from the merged
authenticated-identity foundation `main`. Scope: **complete route-level RBAC**
(`docs/ROUTE_RBAC.md`) built on the merged identity foundation. It is a bounded
**authorization** increment — it does **not** implement multi-tenant resource
authorization, verified reviewer workflow, keyed audit integrity, or a
persistence redesign.

- **Authorization authority**: new `backend/app/permissions.py` is now the single
  source of truth — 23 stable permission ids (the 12 historical
  Benchmarking/field-correction keys preserved exactly + 11 route-grounded keys),
  a conservative role→permission matrix, and **default-deny** evaluation.
  `store.benchmark_permissions()` is a thin compatibility wrapper delegating here,
  so the Benchmarking 12-key contract is byte-for-byte unchanged.
- **Roles**: only the four active roles (`ADMIN`/`ENGINEER`/`VALIDATOR`/`MANAGER`);
  the legacy **`VIEWER` role stays unactivated** with no permissions. Separations
  are conservative and route-grounded (e.g. VALIDATOR owns the validation queue
  and AI approval but cannot upload or issue reports; ENGINEER ingests and drafts
  but cannot approve/resolve/issue or view audit history; `run_retention` and
  identity administration are ADMIN-only).
- **Enforcement**: every privileged read and every mutation now requires a
  permission (`require_permission` / `require_benchmark_permission`), checked
  **before** any resource lookup so existence never leaks (403, not 404). The two
  download routes are public **signed-capability** endpoints (resource-bound,
  expiring, GET-only). Every denial writes a redacted audit event carrying the
  permission, route, and method.
- **Route inventory**: `ROUTE_ACCESS_POLICY` classifies all **48** routes
  (`public`/`authenticated_read`/`permission_required`) with an `auth_mechanism`;
  `route_policy_fully_enforced()` requires zero errors, zero `pending`, and a
  static proof that each `permission_required` route carries its declared guard.
  Validated: 48 routes, 0 errors, 0 pending, fully enforced.
- **`rbac-role-separation` is now evidence-driven PASS** (corrected during PR #12
  review): its registry resolution condition is met, so
  `ga_readiness._rbac_role_separation_probe()` evaluates the actual policy/route
  evidence (distinct least-privilege roles, default-deny, `route_policy_fully_
  enforced()`) instead of defaulting to BLOCKED. The **blocker registry is
  unchanged** — only the evaluator probe became evidence-based. This resolves the
  role-separation **mechanism** only; the separate `per-user-identity`
  **deployment**, `tenant-authorization-enforcement`, `verified-reviewer-identity`,
  and audit-integrity blockers are unchanged, so **`ga:readiness` remains
  `GA_BLOCKED`** (25 blockers; resolving one control never leaks `GA_READY`).

### Review corrections (PR #12, 2026-07-19)

Corrections applied before merge, each behavior-proven in `route_rbac_guard.py`:
- **Detailed readiness protected** (Part D): `/readiness/client-data` moved from
  public to `permission_required("view_runtime_status")` — it exposed blocker
  ids, dispositions, remediation, deployment mode, and **absolute filesystem
  paths**. Only minimal `/health` stays public, and the absolute paths were
  scrubbed from readiness detail (`backend/app/readiness.py`).
- **Authorize-before-lookup everywhere** (Part E): field-corrections
  (create/list/revert), `workspace_benchmarking`, `create_benchmark_measurement`,
  `report_draft`, `create_monday_report`, and `create_direct_upload` (both modes)
  now check the permission before any 404 / 409 / readiness gate. An automated
  scan over all handlers confirms zero residual lookup-before-authorization.
- **Signed downloads verify the token first** (Part H): both `/signed/*` handlers
  now verify the signed token before any resource lookup, readiness gate, or audit
  write — closing an unauthenticated existence oracle and audit-write vector.

| Command | Exit | Result |
| --- | --- | --- |
| `pnpm run audit:route-rbac` | 0 | **103/103** — policy structure/parity, role→permission matrix, every-mutation denial for roles lacking the permission, privileged-read denial, signed-capability (resource-bound/expiring/GET-only, **token-verified-first, no existence oracle, no audit write**), permission-before-lookup ordering (unauthorized same-403 vs authorized-404), minimal public `/health` + **gated detailed readiness** (401/403/200, no path leak), client-mode docs hidden, redacted denial audit, evidence-driven `rbac-role-separation` **PASS**, and regression that tenant/reviewer/audit-integrity blockers stay BLOCKED and GA stays `GA_BLOCKED`. |
| `pnpm run audit:identity-rbac` | 0 | 73/73 — updated: `rbac-role-separation` now evidence-driven PASS. |
| `pnpm run ga:readiness` | 1 | **`GA_BLOCKED`** — 25 blockers remain (rbac resolved; software 14→13). |

### Tenant resource authorization — API-layer IDOR fix (branch `feat/tenant-resource-authorization`)

Built on the merged identity + route-RBAC foundation, this bounded increment closes an
API-layer **IDOR** gap: every entity already carried `tenant_id` and every request already
resolved one, but no handler compared them, so any authenticated caller could reach another
tenant's resource by UUID. Now, after the permission gate, every resource route compares the
looked-up resource's `tenant_id` to the request tenant
(`backend/app/tenant_authorization.py`, `docs/TENANT_AUTHORIZATION.md`).
- **Authority**: `request_tenant_id()` reads the tenant only from the server-side identity
  (never a system/all-tenant fallback; a missing identity denies); `owns()`/`tenant_visible()`
  are default-deny; an explicit `system_tenant_context(operation)` covers worker/CLI access.
  No route accepts a client-supplied tenant.
- **Enforcement**: `auth → permission (403, before lookup) → lookup + tenant ownership
  (existence-hiding 404 for a missing *or* cross-tenant resource) → operation`. Lists,
  aggregates, dashboard, audit log, and chat evidence are tenant-filtered; the benchmarking
  status builder is tenant-scoped in the store.
- **Signed capabilities** bind the owning tenant at issuance (a caller cannot mint a token for
  another tenant's resource) and re-check it at redemption, after the existing
  token-verified-first ordering.
- **Denial audit**: a genuine cross-tenant hit writes `authz.cross_tenant_denied` with the
  request's tenant/actor and no foreign detail; a truly-missing resource writes none.
- **Readiness**: `tenant-authorization-enforcement` stays **BLOCKED** via an evidence-driven
  probe (API-layer half implemented; resolution also requires **Postgres RLS** over the
  normalized store, out of scope). The **blocker registry is unchanged**; GA stays
  `GA_BLOCKED`. **Out of scope**: multi-tenant storage, workspace membership/ACLs, normalized
  persistence, and RLS activation.

Additive schema fields were unnecessary (every entity already carried `tenant_id`); there is
no startup backfill. Behavior is proven by `scripts/tenant_authorization_guard.py`
(`pnpm run audit:tenant-authorization`, **71/71**), chained into `audit:all`.

| Command | Exit | Result |
| --- | --- | --- |
| `pnpm run audit:tenant-authorization` | 0 | **90/90** — module default-deny; ownership graph fails closed on a contradictory resource→parent→tenant chain and a divergent child stamp; cross-tenant single-resource access is existence-hiding 404 across every route family (same-tenant succeeds); lists/aggregates/dashboard/report-draft/generated-report exclude foreign+contradictory rows before counting; benchmarking status excludes a foreign approved benchmark value; per-route tenant-ownership parity holds (and fails when a resource route drops its dependency); signed capabilities bind the tenant at issuance + redemption and a legacy unbound token is rejected; child creation copies the parent tenant; identity context isolated + resets after exception; cross-tenant denial audited with request-tenant context and no foreign detail; old snapshot loads with no backfill; `tenant-authorization-enforcement` BLOCKED, RBAC intact, GA `GA_BLOCKED`. |

### PR #13 review corrections (before merge)

Applied after an adversarial multi-dimension review of the branch, each behavior-proven
in `tenant_authorization_guard.py`:
- **Ownership graph, fail-closed** (Part E/M): `_tenant_owned`/`_tenant_items` now verify
  the full resource→parent→tenant chain (`tenant_authorization.owned_via_graph`), so a
  record whose direct `tenant_id` matches the request but whose parent belongs to another
  tenant is rejected; `list_upload_files`/`list_document_chunks` verify each child's own
  stamp instead of trusting FK inheritance.
- **Benchmarking aggregate leak** (Part G, HIGH): `_build_benchmarking_status` and its
  helpers (`_benchmark_comparisons`, `_benchmark_by_name`, `_comparison_status`,
  `_evaluate_anomaly_rules`, `_benchmark_source_references`) now tenant-scope
  **benchmark_values and anomaly_rules**, not just measurements/anomaly events — a foreign
  tenant's *approved* benchmark config no longer surfaces in a tenant's own status.
- **Report input scoping** (Part G): `report_draft` and `create_monday_report` +
  `_open_validation_tasks_for_workspace` tenant-scope their per-workspace aggregations.
- **Per-route parity guard** (Part F): `tenant_ownership_fully_enforced()` proves every
  resource-scoped route invokes a tenant-ownership dependency; the readiness probe consumes
  it as machine-readable evidence (no longer a global substring test).
- **Audit consistency** (Part J): a genuine cross-tenant probe of an existing foreign
  workspace on the benchmarking route is now recorded as `authz.cross_tenant_denied`.
| `pnpm run audit:all` | 0 | Full guard battery green on an isolated stack, incl. FORGE **65/65**, trajectory **38/38**, Benchmarking **23/23**, route-RBAC **103/103**, identity-RBAC **73/73**, and the new tenant guard **71/71**. |
| `$env:CI='true'; pnpm run build` | 0 | `tsc` (strict, `noEmit`) + `vite build` clean. |
| `pnpm run ga:readiness` | 1 | **`GA_BLOCKED`** — 25 blockers; `tenant-authorization-enforcement` stays BLOCKED via the evidence-driven probe (API-layer done; Postgres RLS pending). |

### Versioned HMAC audit integrity (branch `feat/versioned-audit-hmac`)

Replaces the forgeable unkeyed SHA-256 audit chain with a versioned keyed
HMAC-SHA256 foundation (`backend/app/audit_keys.py`, `docs/AUDIT_INTEGRITY.md`).
- **Envelope**: v2 events (`integrity_version=2`, HMAC-SHA256) sign a canonical,
  redacted payload (sorted-key UTF-8, explicit nulls, deterministic) over the
  event id, timestamp, actor (id/source/roles), tenant, action, resource, metadata,
  and previous hash.
- **Key provider**: env-injected active key (≥32 bytes) + retained
  verification-only versions for rotation; verification selects each event's
  recorded key id/version; short/malformed/duplicate keys are rejected; only
  non-secret metadata (id/version/fingerprint) is exposed — key material is never
  persisted, logged, or placed in evidence.
- **Legacy transition**: historical events are never re-signed; the first v2 event
  chains to the legacy head; mixed chains verify honestly (`integrity_state` =
  `legacy_valid`/`mixed_valid`/`keyed_valid`/`key_unavailable`/`broken`); no startup
  or read-route rewrite. The backward-compatible `status` field is preserved.
- **Client fail-closed**: a request-scoped write without a valid key raises
  `AuditIntegrityUnavailable` → **503** before any append/save (no unkeyed event, no
  partial business mutation); demo/system writes fall back to labelled legacy.
- **Atomicity**: `audit_lock` serializes read-previous→HMAC→append→save; a snapshot
  failure rolls back the append and re-raises. In-process only; cross-process
  persistence locking stays a declared blocker.
- **No external anchor**: tail truncation remains undetectable and
  `audit-tail-truncation-detection` stays **BLOCKED**; `audit-keyed-integrity` is
  evidence-driven PASS-capable; **registry unchanged**; GA stays `GA_BLOCKED`.

| Command | Exit | Result |
| --- | --- | --- |
| `pnpm run audit:audit-keyed-integrity` | 0 | **58/58** — baseline forgeability + tail-truncation reproduced; HMAC seal/verify; public-SHA forgery + tampered field + wrong/unknown key + missing HMAC rejected; canonicalization stable/deterministic; legacy transition with no rewrite; rotation with retained keys; client fail-closed; atomicity + concurrency; no key leakage; keyed-integrity evidence-driven PASS-capable, tail-truncation BLOCKED, GA `GA_BLOCKED`. |

### Verified reviewer attribution (branch `feat/verified-reviewer-attribution`)

Attributes field-correction (record + revert) and validation outcomes to a
**verified authenticated human reviewer** instead of the single configured actor
(`docs/VERIFIED_REVIEWER_ATTRIBUTION.md`, closes AUDIT-001 for correction/validation).
- **Verified reviewer**: `actor_source=authenticated` + active non-bootstrap user +
  active credential + user/credential/identity bound to the request tenant +
  permission-eligible (`record_field_corrections` / `resolve_validation` via
  `has_permission`). All facts are server-derived; client-supplied
  reviewer/tenant/email fields are ignored.
- **Client fail-closed**: a `demo_bootstrap`/configured/system actor, inactive user,
  revoked credential, cross-tenant, or unauthorized reviewer is rejected with
  `ReviewerNotVerified` → **403** BEFORE any outcome mutation or audit append.
- **Attribution**: `reviewer_*` (and distinct `revert_reviewer_*`) fields persist the
  reviewer id, credential id, non-secret **fingerprint**, roles, actor source, and a
  verify timestamp on the outcome; the **keyed** audit event's actor matches. No raw
  token or credential hash is stored. Demo actions are labelled unverified.
- **Compatibility**: additive fields; old snapshots load without reviewer fields (no
  backfill); local JSON + Postgres JSONB preserve attribution.
- **Readiness**: `ga_verified_reviewer_identity` is **evidence-driven PASS** (wiring
  + schema + runtime accept/reject logic); **registry unchanged**;
  `audit-keyed-integrity` PASS-capable, `audit-tail-truncation-detection` and the
  persistence/transaction blockers stay **BLOCKED**; GA stays `GA_BLOCKED`. AI-content
  approval and report issuance are outside this control's resolution condition
  (documented as a future increment).

| Command | Exit | Result |
| --- | --- | --- |
| `pnpm run audit:verified-reviewer` | 0 | **50/50** — verified reviewer records/reverts/validates with server-derived attribution + matching keyed audit; demo/system/configured/cross-tenant/revoked/disabled/unauthorized rejected before mutation; client-supplied reviewer/tenant/email ignored; no token/hash leakage; concurrency-distinct; old snapshot loads without backfill; JSON+JSONB preserve; evidence-driven PASS; HMAC/tenant/RBAC/registry/GA/FORGE/trajectory/benchmarking regressions intact. |
