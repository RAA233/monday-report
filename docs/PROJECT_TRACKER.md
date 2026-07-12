# Monday Report Project Tracker

## Current Phase

The executable MVP path is now phase-gated end to end and the local client-data approval environment is green. It bootstraps a clean client tenant without startup failure records, requires an API key in client mode, rejects oversized uploads at the API boundary, enforces configured ZIP entry and uncompressed-size limits, blocks unsafe client-mode data operations until readiness is green, activates PostgreSQL/RLS state and Redis-backed queue processing in client mode, exposes requested versus active runtime backends, stores accepted bytes under sanitized tenant-scoped paths, verifies SHA-256, applies configurable retention to expired data artifacts, requires explicit client-mode malware scanner configuration, blocks baseline malware signatures before processing, downloads uploaded source files through signed URLs, requires a real signing secret for client-mode signed URLs, defaults local AI to Ollama `gemma4:e2b` and verifies model availability, safely expands ZIP packages, parses text/CSV/XLSX/DOCX/EML/PyMuPDF-backed PDF child files and native PDF table rows into typed document chunks, preserves page/table/row-aware PDF citations, extracts configured local OCR into `ocr_text_v1` chunks with image-page citations, evaluates parser/OCR fixture reports and reviewed fixture attestation before parser coverage can certify readiness, extracts cited MWD signal-loss failures with NPT/company fields, opens and updates validation tasks, creates Monday Report JSON, blocks official exports while validation remains open, exports JSON/CSV/HTML/PDF/XLSX artifacts, downloads exports through signed URLs, answers chat with citations, records redacted hash-chain audit events, creates a single-file partner preview ZIP, and writes approved real-client readiness evidence. Remaining work is production hardening: normalized PostgreSQL repositories, production OCR command management, local LLM extraction, polished report templates, controlled client-package dry runs, and external malware scanning.

## Clear Tracker Snapshot

| Lane | Status | Meaning | Next Action |
|---|---|---|---|
| Accepted now | Pass | Executable MVP is working with chat, upload, parser worker, typed citations, validation, exports, signed downloads, audit, client approval, and readiness gates. | Keep every slice behind targeted audits and `pnpm run audit:all` in demo posture. |
| Safe operating mode | Pass | Demo mode remains local; approved client mode uses PostgreSQL/RLS state, Redis queue, protected storage, API key, signing secret, and reviewed fixture/eval evidence. | Keep secrets out of Git and regenerate approval after environment changes. |
| Real-client approval | Pass | Live client approval reports `APPROVED`; GA readiness reports `GA_READY`; readiness has zero blockers. | Run controlled client-package dry runs before broad distribution. |
| Next execution order | Pending | Client dry runs, FORGE template promotion, local LLM extraction router, normalized PostgreSQL repositories, OCR/malware production hardening. | Start with screenshot-backed QA and controlled client-package trials. |

## Current Tracker

- Working now: chat-first workflow, direct/ZIP upload, SHA-256 storage, malware baseline blocking, parser-worker queue, source chunks, failure extraction, validation tasks, Monday Report creation, JSON/CSV/HTML/PDF/XLSX exports, signed source/export downloads, redacted audit logs, and readiness reporting.
- Recently added: typed source locators, readable citation labels, source-file actions directly from chat citation cards, manifest-backed golden fixture readiness, manifest-driven parser/OCR eval report generation, parser/OCR eval report readiness, Gemma 4 E2B local AI default, single-file partner preview packaging, PyMuPDF-backed page-aware PDF chunks, native PDF table row citations, and configurable local OCR extraction into image-page chunks.
- Real-client posture: approved in the local client environment with active PostgreSQL, active Redis, local AI, security configuration, golden fixture/eval evidence, and reviewed fixture attestation all passing.
- Operator command: run `pnpm run audit:all` after every meaningful code change; run `pnpm run package:partner-approval` before sending the partner ZIP; run `pnpm run package:client-approval` to write the current real-client approval/blocker report.

## Phase Gate Rule

Every implementation slice must pass these checks before it is considered accepted:

- Frontend build: `pnpm run build`
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
- Golden fixture readiness guard: `pnpm run audit:golden-fixtures`
- Parser/OCR fixture eval guard: `pnpm run audit:parser-fixture-evals`
- Parser/OCR eval report generator guard: `pnpm run audit:parser-fixture-report`
- PDF parser guard: `pnpm run audit:pdf-parser`
- OCR routing guard: `pnpm run audit:ocr-routing`
- OCR extraction guard: `pnpm run audit:ocr-extraction`
- Local AI runtime status guard: `pnpm run audit:local-ai`
- Partner preview package guard: `pnpm run audit:partner-package`
- Partner preview approval guard: `pnpm run audit:partner-approval`
- Client-data approval guard: `pnpm run audit:client-approval`
- Client operation guard: `pnpm run audit:client-ops`
- Report export idempotency guard: `pnpm run audit:report-export-idempotency`
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
pnpm run audit:golden-fixtures
pnpm run audit:parser-fixture-evals
pnpm run audit:parser-fixture-report
pnpm run audit:pdf-parser
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

## Phase Status

| Phase | Status | Scope | Acceptance Evidence | Next Action |
|---|---|---|---|---|
| 00 | Complete | Product/spec lock | Execution plan and implementation spec exist | Keep specs updated from real build decisions |
| 01 | Complete | Chat-first frontend | App defaults to Local AI Chat and builds | Add persisted report preview/export |
| 02 | Complete | FastAPI scaffold | API health/session/chat/upload/report endpoints respond | Replace memory store with PostgreSQL repositories |
| 03 | Complete | Tracker/test/audit | Tracker UI, audit endpoint, audited upload workflow, phase audit script | Run audit gate after every slice |
| 04 | Active | Persistence/queue | Client approval environment activates PostgreSQL/RLS state and Redis queue; demo mode keeps local JSON | Expand snapshot storage into normalized PostgreSQL repositories |
| 05 | Complete | Parser/OCR | ZIP safety, typed parser chunks, native PDF table rows, OCR extraction, reviewed 13-family fixture manifest, and parser/OCR eval report pass | Maintain reviewed fixture/eval evidence as parsers evolve |
| 06 | Active | Local AI extraction | Deterministic scaffold extracts cited MWD failures, NPT hours, company, and validation tasks from parsed chunks; local AI defaults to Ollama `gemma4:e2b` and verifies the pinned model is available | Wire Ollama/LM Studio router, strict schemas, confidence scoring, and metrics |
| 07 | Complete | Validated exports | E2E verifies unresolved validation blocks export, validates extracted failures, creates report, exports JSON/CSV/HTML/PDF/XLSX artifacts, inspects artifact signatures, and downloads through signed URLs | Polish report templates |
| 08 | Complete | Real-client readiness | Live client-data approval is APPROVED with PostgreSQL/RLS, Redis, API key, signing secret, protected storage, retention, malware scanner, parser/OCR evals, reviewed fixture attestation, and local Gemma runtime | Run controlled client-package dry runs and maintain approval evidence |

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
- Metadata and direct upload names plus ZIP entry names are sanitized before storage; traversal and reserved device names remain under tenant storage, and metadata-only completion fails closed until bytes exist.
- Embedded-text PDFs parse through `pdf_text_v1`; PyMuPDF is used when available, native table rows become evidence chunks, and chunks carry page/table/row-specific PDF locator metadata.
- CSV, Excel, Word, and email chunks carry typed locator metadata for citation review.
- Chat citations render typed locator labels with source filenames.
- Chat citations can request signed source-file links from the evidence card.
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
