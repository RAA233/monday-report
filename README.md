# Monday Report

Runnable React/TypeScript MVP scaffold for the Monday Report local AI, chat-first intelligence workspace.

## What Is Implemented

- React SaaS workspace with local AI chat as the main surface, plus upload, dashboard, failure explorer, validation queue, and architecture screens.
- Report Studio lets users write morning drilling reports from scratch, apply a FORGE-style daily-report structure, preview Monday Report branding, render casing schematics and activity timelines, and export a draft Markdown report.
- Chat calls the FastAPI scaffold when available, exposes local AI runtime status, and falls back to deterministic local analysis when offline.
- Backend scaffold uses durable local JSON state so API and worker share uploads, jobs, and redacted hash-chain audit logs before PostgreSQL/Redis lands.
- Browser ZIP/file/folder intake with configurable byte limits, sanitized tenant-scoped storage paths, local byte storage, real SHA-256 hashes, report-family classification, duplicate candidates, configurable OCR routing/extraction, and parser gap warnings.
- Builtin baseline malware scanner blocks EICAR-style test content, risky executable/script extensions, and macro-enabled Office files before processing; client mode requires explicit scanner configuration.
- Uploaded source files and extracted child files can be downloaded only through expiring signed URLs; client mode requires a configured signing secret.
- Worker foundation safely expands ZIP packages with configurable entry and uncompressed-size limits, parses text, CSV, XLSX, DOCX, EML, PyMuPDF-backed embedded-text PDF files, and native PDF table rows into typed chunks with source lineage. Image/scanned-PDF files route to OCR review when no local engine is configured, or to `ocr_text_v1` chunks when `MONDAY_REPORT_OCR_ENGINE=tesseract` and `MONDAY_REPORT_TESSERACT_CMD` are configured.
- Extraction scaffold creates cited MWD signal-loss failure records, NPT hours, company attribution, and validation tasks from parsed chunks.
- Validation API updates extracted records, Monday Report API creates report JSON, and export API blocks unresolved official exports before writing hashed JSON/CSV/HTML/PDF/XLSX artifacts with signed download URLs.
- Client-data readiness endpoint and tracker panel flag demo/local-scaffold blockers before real client packages are accepted, enforce retention policy, require real active infrastructure adapters, and unsafe client mode requires an API key while blocking data reads, chat, report creation, and exports until ready.
- Local AI defaults to Ollama with `gemma4:e2b`; readiness verifies both endpoint reachability and the pinned model.
- Parser/OCR fixture eval readiness requires a passing `MONDAY_REPORT_PARSER_EVAL_REPORT`; real-client approval also requires the referenced fixture manifest to carry a reviewed anonymized-client attestation.
- The local `16A(78)-32_Daily_Reports/` open-source FORGE corpus is ignored by Git; `audit:forge-corpus` parses representative PDFs, verifies drilling/completion markers, and writes `output/forge-corpus/forge_corpus_summary.json`.
- `fixtures:anonymized` creates a generated 13-family fixture pack for local smoke tests only; production client intake must use reviewed anonymized client fixtures, not generated evidence.
- Partner preview packaging creates one ZIP with the built web app, backend, worker loop, Gemma 4 E2B defaults, sample import package, and import/export smoke script.
- Client-data approval tooling writes an explicit approved/blocked evidence report from the live readiness endpoint.
- Runtime backend status exposes requested versus active repository and queue adapters so PostgreSQL/Redis environment variables cannot masquerade as implemented infrastructure.
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
pnpm run audit:forge-corpus
pnpm run audit:ocr-routing
pnpm run audit:ocr-extraction
pnpm run audit:local-ai
pnpm run audit:partner-package
pnpm run audit:partner-approval
pnpm run audit:client-approval
pnpm run audit:client-ops
pnpm run audit:report-export-idempotency
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

Client-readiness helper:

```powershell
pnpm run fixtures:anonymized
```

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
- Promote the open-source FORGE daily-report corpus into reviewed extraction templates and export fixtures without committing the raw ignored PDF folder.
- Add Postgres migrations from `db/schema.sql`.
- Add auth/SSO, tenant-aware request context, persistent audit hardening, and source preview authorization.
- Replace deterministic extraction with local LLM provider abstraction and evaluation sets before using customer data.
- Keep `gemma4:e2b` installed in Ollama for partner testing, or override `MONDAY_REPORT_LOCAL_LLM_MODEL` only after the replacement model is audited.
- Polish production PDF/XLSX templates and signed export presentation.
- Set `MONDAY_REPORT_CLIENT_DATA_MODE=client` only after `/readiness/client-data` reports ready with reviewed fixture attestation.
- For clean client bootstrap, set `MONDAY_REPORT_TENANT_NAME`, `MONDAY_REPORT_TENANT_SLUG`, `MONDAY_REPORT_USER_EMAIL`, and `MONDAY_REPORT_USER_FULL_NAME` before the first API start. Default startup creates a neutral workspace only; failure records are created from uploaded evidence.
