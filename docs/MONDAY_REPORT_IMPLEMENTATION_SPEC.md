# Monday Report Implementation Specification v1

## 1. Product Requirements Document

### Problem Statement

Rig teams receive high-value evidence in messy daily drilling reports, BHA reports, MWD/LWD reports, RSS reports, mud motor reports, bit records, mud reports, NPT logs, scanned PDFs, Excel workbooks, Word files, CSV exports, emails, and images. Failures, service-company responsibility, tool serial history, NPT exposure, root causes, and recommendations are scattered across files and formats. Manual weekly reporting is slow, inconsistent, and hard to cite.

Monday Report solves this by turning a mixed rig-report package into a local-AI-first, citation-backed weekly intelligence report. The main user experience is chat: users ask what failed, what caused NPT, which tools repeated, and which records need validation before exporting the official Monday Report.

### Product Goals

- Prove the full MVP path: upload -> extraction -> validation -> chat -> Monday Report export.
- Preserve source lineage from every answer and generated report statement to file/page/sheet/row/bounding box/email context.
- Keep customer drilling data private through tenant isolation, RBAC, signed URLs, encrypted storage, and local-first LLM routing.
- Support practical drilling workflows around BHA, MWD/LWD, RSS, mud motor, bit, mud, service-company, NPT, root-cause, and recommendation analysis.
- Let reviewers correct low-confidence or conflicting AI extraction before management reporting.

### Non-Goals

- No autonomous prediction engine in MVP.
- No offset-well benchmarking in MVP.
- No WITSML, EDM, SAP, Maximo, email inbox, or SharePoint integration in MVP.
- No automatic corrective-action dispatch or vendor scorecard automation.
- No training on customer data.
- No hosted LLM use unless tenant policy explicitly permits it.

### Target Users

- Tenant admin: configures tenant, users, RBAC, retention, and hosted fallback policy.
- Drilling engineer: uploads reports, reviews drilling events, asks operational questions.
- Performance engineer: monitors NPT, ROP-impacting failures, company/tool performance.
- Reliability engineer: tracks tool serial failures, repeated issues, root causes, recommendations.
- Manager/executive: consumes weekly Monday Report and cited summaries.
- Validator/reviewer: resolves low-confidence extraction, conflicts, and canonical entity cleanup.

### MVP Success Criteria

- A mixed ZIP with DDR, BHA, MWD/LWD, RSS, mud motor, bit, mud, scanned PDF, Excel, email, and NPT files can be inventoried.
- At least PDF, Excel, Word, CSV, text, email body, and image/OCR routing are represented in the processing pipeline.
- Extracted failures, NPT events, companies, tools, root causes, recommendations, citations, and confidence scores persist with `tenant_id`.
- Chat answers "What failed this week?", "Which company caused most NPT?", "Show all motor failures", and "Generate Monday Report" with citations.
- Validation queue catches low confidence, conflicting evidence, missing citations, repeated serials, and high severity events.
- Official Monday Report exports to PDF and Excel with source citations and confidence notes.
- Tenant isolation tests prove one tenant cannot read another tenant's uploads, chunks, chat, reports, or exports.

### Key User Journeys

1. Admin creates tenant, invites users, assigns roles, configures local model and storage policy.
2. Drilling engineer creates a workspace for a field, rig fleet, well campaign, or weekly reporting period.
3. Engineer uploads a ZIP or folder package of rig reports and service-company files.
4. System scans, hashes, inventories, parses, OCRs, classifies, extracts, chunks, embeds, cites, and queues validations.
5. Reviewer resolves validation tasks and edits companies/tools/failure/NPT records.
6. User asks chat questions and follows cited evidence.
7. User opens dashboard cards for failures, NPT, company/tool performance, validation backlog, and confidence.
8. User generates the official Monday Report and exports PDF/Excel.

### Exact Happy Path

1. Login as drilling engineer.
2. Select tenant `NorthStar Drilling` and workspace `Gulf Campaign - Week 27`.
3. Upload `week_27_rig_reports.zip`.
4. Upload service stores the ZIP, computes SHA-256, starts `processing_jobs`.
5. Workers unzip, inventory files, parse text/tables, OCR scanned pages, classify DDR/BHA/MWD/LWD/RSS/mud motor/bit/mud/NPT/email records.
6. Local AI extracts failures, NPT events, companies, tools, root causes, recommendations, confidence, and citations.
7. Validation queue flags low-confidence MWD serial conflict and one missing NPT source.
8. Reviewer corrects company alias and validates the MWD failure.
9. User asks "What failed this week?" and receives cited failure summary.
10. User asks "Generate Monday Report" and reviews draft.
11. User exports PDF and Excel; audit logs record export, source versions, and user.

## 2. MVP Scope Lock

### Included in MVP

- Auth/session flow, tenant model, users, roles, basic RBAC.
- Workspace/project setup with wells and rigs.
- ZIP upload and folder-style file selection in frontend.
- Object storage for original files and generated exports.
- File inventory with path, MIME, hash, duplicate detection, size, parser status.
- Parser adapters for PDF, Excel, Word, CSV, text, email, and image/OCR routing.
- Local OCR for scanned reports and image attachments.
- Report chunking with source coordinate metadata.
- pgvector embeddings for report chunks.
- Local AI report classification and extraction.
- Failures, NPT events, companies, tools, citations, validation tasks, chat, dashboards, Monday Report generation, PDF/Excel export, audit logs.

### Excluded From MVP

- Predictive failure model trained from customer history.
- Offset-well benchmarking and basin-wide analytics.
- Real-time rig data streams.
- External integrations with WITSML, EDM, WellView, SAP, SharePoint, Teams, Outlook, or vendor portals.
- Automated vendor performance penalties, procurement workflows, or corrective-action dispatch.
- Multilingual extraction beyond English unless fixtures prove readiness.
- Custom report designer.

### Must Not Be Built Yet

- Black-box "will this tool fail?" prediction.
- Model fine-tuning on customer data.
- Auto-email ingestion.
- Advanced workflow automation.
- Enterprise BI connectors.
- Multi-region replication and customer-managed keys, unless a security buyer blocks MVP.

### Scope Rationale

The MVP must prove that Monday Report can transform mixed rig-report evidence into reliable, cited output. The value chain is upload -> extraction -> validation -> chat -> Monday Report export. Prediction, benchmarking, and integrations only matter after the extracted data is trusted.

## 3. User Stories

### Tenant Admin

- User goal: set up a private tenant, users, RBAC, model policy, retention, and audit visibility.
- Acceptance criteria: admin can invite users, assign admin/engineer/manager/validator roles, disable hosted LLM fallback, set retention, and view audit logs.
- Edge cases: duplicate email invite, disabled user, expired invitation, attempted hosted fallback when disallowed.
- Required backend support: tenants, users, roles, policy fields, audit logs, auth middleware.
- Required frontend support: admin settings, invite form, role editor, privacy policy indicators.
- Required AI/data support: tenant LLM policy checked before every classification, extraction, chat, and report-generation call.

### Drilling Engineer

- User goal: upload weekly rig reports and ask operational questions with source citations.
- Acceptance criteria: upload ZIP, see inventory, ask "What failed this week?", inspect cited DDR/BHA/MWD/LWD/RSS records, generate draft Monday Report.
- Edge cases: corrupted ZIP, duplicate files, missing report date, mixed wells, unknown report type.
- Required backend support: uploads, files, reports, failures, citations, chat endpoints.
- Required frontend support: upload shell, inventory table, chat-first home, source drawer.
- Required AI/data support: report classification, failure extraction, NPT extraction, citation mapping.

### Performance Engineer

- User goal: quantify NPT, identify top service-company and tool contributors, and export results.
- Acceptance criteria: dashboard shows total NPT, NPT by company/tool/well/rig, filtered results export to Excel.
- Edge cases: NPT in free text only, inconsistent units, partial downtime, ambiguous responsible party.
- Required backend support: NPT tables, aggregation queries, filter API.
- Required frontend support: dashboard cards, filters, drill-down tables, export actions.
- Required AI/data support: NPT detection, unit normalization, confidence scoring.

### Reliability Engineer

- User goal: track repeated tool failures and root causes by serial number, model, manufacturer, and provider.
- Acceptance criteria: can filter MWD, RSS, mud motor, bit, BHA failures; repeated serials are highlighted; root causes and recommendations are cited.
- Edge cases: serial missing, serial alias typo, shared rental tools, conflicting teardown notes.
- Required backend support: tools, tool_instances, failures, citations, validation tasks.
- Required frontend support: tool filters, repeated-issue view, validation edit forms.
- Required AI/data support: tool extraction, serial normalization, dedupe logic, root-cause extraction.

### Manager/Executive

- User goal: review a concise weekly Monday Report with citations and confidence notes.
- Acceptance criteria: can open latest report, read summary, see high-risk items, export PDF/Excel, and trace claims to source files.
- Edge cases: validation backlog unresolved, low confidence, missing citations, no failures in period.
- Required backend support: monday_reports, exports, signed URLs, audit logging.
- Required frontend support: report preview, export buttons, confidence warnings.
- Required AI/data support: report generation prompt, citation completeness checks.

### Validator/Reviewer

- User goal: correct AI extraction before official reporting.
- Acceptance criteria: can edit company, tool, failure, NPT, root cause, recommendation, severity, confidence status, and mark validated/rejected/conflict.
- Edge cases: multiple candidate sources, conflicting DDR and service-company report, duplicate events.
- Required backend support: validation_tasks, write-back APIs, canonical entity updates, audit log diff.
- Required frontend support: review queue, edit forms, side-by-side source snippets.
- Required AI/data support: validation reason generation, correction feedback to alias dictionaries and extraction evaluations.

## 4. Engineering Epics

### Epic 1: Authentication and Tenant Foundation

- Purpose: enforce tenant-scoped access from the first request.
- Features: login/session, tenants, users, roles, RBAC middleware, tenant context.
- Backend tasks: auth callbacks, `current_user`, tenant guard, role checks, audit context.
- Frontend tasks: login state, tenant selector, role-aware navigation.
- AI/data tasks: pass tenant policy into LLM router.
- DevOps tasks: auth secrets, environment config, migration setup.
- Testing tasks: session tests, tenant isolation tests, RBAC negative tests.
- Acceptance criteria: every API request resolves tenant and role before data access.

### Epic 2: Workspace/Project Setup

- Purpose: organize reports by campaign, asset, field, rig, well, and reporting period.
- Features: CRUD workspaces, wells, rigs, aliases.
- Backend tasks: models, endpoints, uniqueness constraints, audit events.
- Frontend tasks: workspace create/select, context banner.
- AI/data tasks: workspace metadata included in extraction prompts.
- DevOps tasks: seed development tenant/workspace.
- Testing tasks: CRUD and permission tests.
- Acceptance criteria: reports cannot be uploaded outside a workspace.

### Epic 3: Upload and File Inventory

- Purpose: accept mixed rig-report packages safely.
- Features: ZIP upload, direct file upload, hash, MIME detection, duplicate detection, inventory.
- Backend tasks: signed upload URL, file records, storage write, ZIP expansion, scan job.
- Frontend tasks: upload panel, progress, inventory table, duplicate warnings.
- AI/data tasks: none except downstream job triggers.
- DevOps tasks: object storage bucket, local storage emulator.
- Testing tasks: ZIP, large file, duplicate, corrupted file tests.
- Acceptance criteria: uploaded files and ZIP child entries persist with lineage and processing status.

### Epic 4: Document Parsing

- Purpose: extract text and structured tables.
- Features: PDF text, Excel sheets/cells, Word paragraphs, CSV rows, text, email body/attachments.
- Backend tasks: parser job orchestration and error tracking.
- Frontend tasks: parser status and source preview.
- AI/data tasks: parser adapters with coordinates.
- DevOps tasks: parser container dependencies.
- Testing tasks: golden parser fixtures.
- Acceptance criteria: parser outputs source-aware documents and chunks for supported direct files and ZIP child entries.
- Current scaffold: supported chunks can produce cited MWD signal-loss failure records with NPT/company fields and validation tasks.

### Epic 5: OCR Processing

- Purpose: recover text from scanned PDFs/images.
- Features: OCR routing, page images, bounding boxes, OCR confidence.
- Backend tasks: OCR job statuses and artifacts.
- Frontend tasks: OCR status badge and warning.
- AI/data tasks: local OCR adapter, coordinate normalization.
- DevOps tasks: Tesseract/PaddleOCR container or local service.
- Testing tasks: scanned DDR and image fixtures.
- Acceptance criteria: OCR text stores bounding boxes and quality scores.

### Epic 6: Chunking and Citation Mapping

- Purpose: make every extracted claim traceable.
- Features: chunk text, token boundaries, page/sheet/row/bbox/email metadata.
- Backend tasks: `report_chunks`, `citations`, indexing.
- Frontend tasks: citation renderer and source drawer.
- AI/data tasks: chunking algorithm and snippet selection.
- DevOps tasks: pgvector extension.
- Testing tasks: citation round-trip tests.
- Acceptance criteria: any extracted record links to at least one source citation or enters validation.

### Epic 7: Local AI Classification

- Purpose: classify report family before extraction.
- Features: DDR/BHA/MWD/LWD/RSS/motor/bit/mud/NPT/email/scanned classification.
- Backend tasks: classification job and persistence.
- Frontend tasks: report-type labels.
- AI/data tasks: strict JSON prompt, local model router, confidence threshold.
- DevOps tasks: Ollama/LM Studio runtime config.
- Testing tasks: classification accuracy fixtures.
- Acceptance criteria: unknown/low-confidence files route to review or generic chunking.

### Epic 8: Local AI Extraction

- Purpose: extract failures, NPT, companies, tools, root causes, recommendations.
- Features: JSON extraction, confidence, dedupe, citations.
- Backend tasks: persistence endpoints and job handlers.
- Frontend tasks: extracted records and validation links.
- AI/data tasks: prompt pack, schemas, validators, normalization dictionaries.
- DevOps tasks: model versioning and prompt versioning.
- Testing tasks: precision/recall and citation accuracy tests.
- Acceptance criteria: extraction output validates against JSON schemas.

### Epic 9: Database Persistence

- Purpose: store normalized rig intelligence with tenant isolation.
- Features: migrations, RLS, indexes, constraints, processing jobs.
- Backend tasks: ORM/models, migrations, repository methods.
- Frontend tasks: none beyond API integration.
- AI/data tasks: write structured extraction results.
- DevOps tasks: Postgres/pgvector provisioning and backups.
- Testing tasks: migration and RLS tests.
- Acceptance criteria: tenant-owned tables enforce `tenant_id`.

### Epic 10: Validation Queue

- Purpose: prevent low-confidence AI output from becoming official.
- Features: review reasons, edit forms, validate/reject/conflict, audit diffs.
- Backend tasks: validation APIs, canonical entity update logic.
- Frontend tasks: queue, task detail, source preview, edit actions.
- AI/data tasks: review rules and feedback capture.
- DevOps tasks: none beyond queue workers.
- Testing tasks: edit, reject, validate, audit tests.
- Acceptance criteria: report export warns when blocking validations remain.

### Epic 11: AI Chat and Retrieval

- Purpose: make chat the main product workflow.
- Features: SQL retrieval, vector retrieval, filters, citations, clarification, export actions.
- Backend tasks: chat sessions/messages, retrieval service, LLM calls, streaming response.
- Frontend tasks: chat UI, cited answer blocks, follow-ups, filter chips.
- AI/data tasks: chat prompt, retrieval ranking, answer faithfulness checks.
- DevOps tasks: local LLM health checks.
- Testing tasks: chat faithfulness and tenant isolation tests.
- Acceptance criteria: core drilling questions answer with citations and no unsupported claims.

### Epic 12: Dashboard Metrics

- Purpose: provide visual checks and management summaries.
- Features: failures, NPT, severity, validation, confidence, company/tool/well/rig charts.
- Backend tasks: aggregate endpoints.
- Frontend tasks: cards, charts, drill-down filters.
- AI/data tasks: none.
- DevOps tasks: query performance indexes.
- Testing tasks: dashboard query correctness.
- Acceptance criteria: dashboard totals match extracted records under filters.

### Epic 13: Monday Report Generation

- Purpose: generate the official weekly report.
- Features: report draft, citations, confidence notes, approval status.
- Backend tasks: report generation API and persistence.
- Frontend tasks: report preview/editor.
- AI/data tasks: Monday Report prompt and JSON schema.
- DevOps tasks: template assets.
- Testing tasks: report content and citation tests.
- Acceptance criteria: report cannot claim facts without citation or "unknown".

### Epic 14: Export to PDF and Excel

- Purpose: deliver management-ready outputs.
- Features: PDF layout, Excel workbook tabs, signed URLs.
- Backend tasks: export service, storage, URL signing.
- Frontend tasks: export buttons and status.
- AI/data tasks: report JSON to templates.
- DevOps tasks: headless render or document library dependencies.
- Testing tasks: PDF/Excel generation tests.
- Acceptance criteria: exports match report JSON and include appendix records.

### Epic 15: Security and Audit Logs

- Purpose: protect confidential rig-report data.
- Features: RLS, RBAC, malware scan, signed URLs, encrypted storage, audit logs, retention.
- Backend tasks: audit middleware, security checks, deletion workflow.
- Frontend tasks: privacy indicators and admin settings.
- AI/data tasks: hosted fallback policy enforcement.
- DevOps tasks: secrets, KMS, scanner, monitoring.
- Testing tasks: penetration-style tenant and URL tests.
- Acceptance criteria: security controls are testable and visible in logs.

### Epic 16: QA and Evaluation

- Purpose: make extraction reliable before scaling.
- Features: golden fixtures, regression tests, extraction scorecards, demo script.
- Backend tasks: fixture loaders and test APIs.
- Frontend tasks: E2E flows.
- AI/data tasks: extraction accuracy harness.
- DevOps tasks: CI pipeline.
- Testing tasks: all MVP test categories.
- Acceptance criteria: release cannot pass without fixture and security test gates.

## 5. Detailed Engineering Tickets by Sprint

### Sprint 1: Foundation

| Ticket | Description | Dependencies | Technical Notes | Acceptance Criteria | Tests | Complexity | Owner |
|---|---|---|---|---|---|---|---|
| S1-01 Repo and app scaffold | Create frontend/backend/worker structure, env files, lint/test commands. | none | Keep frontend React/Next-compatible; backend FastAPI. | `dev`, `test`, `migrate` commands documented. | CI smoke. | M | DevOps |
| S1-02 Auth session skeleton | Implement login/session middleware and current user endpoint. | S1-01 | Use provider abstraction. | Protected API rejects anonymous requests. | Auth unit/integration. | M | backend |
| S1-03 Tenant and RBAC schema | Add tenants, users, roles, role memberships. | S1-02 | All tenant-owned records carry `tenant_id`. | Admin can assign roles. | RLS/RBAC tests. | L | backend |
| S1-04 Workspace/well/rig models | Add workspace, wells, rigs CRUD. | S1-03 | Alias arrays for messy report names. | Workspace required before upload. | CRUD tests. | M | backend |
| S1-05 Upload shell UI | Add upload page with ZIP/file selector and empty inventory. | S1-04 | Preserve chat-first nav. | User can select files and see staged names. | E2E smoke. | M | frontend |
| S1-06 Object storage adapter | Implement local/S3-compatible storage writes and signed URLs. | S1-03 | Store original file immutable path. | Upload creates file storage object. | Storage integration. | L | backend |
| S1-07 Queue foundation | Add Redis/queue job model and worker heartbeat. | S1-06 | Track `processing_jobs`. | Upload enqueues scan job. | Queue integration. | M | DevOps |
| S1-08 Database migrations | Set up migration runner and pgvector extension. | S1-03 | Include RLS baseline. | Clean DB migrates from empty. | Migration test. | M | backend |

### Sprint 2: Parsing and Lineage

| Ticket | Description | Dependencies | Technical Notes | Acceptance Criteria | Tests | Complexity | Owner |
|---|---|---|---|---|---|---|---|
| S2-01 ZIP extraction worker | Extract ZIP recursively and reject path traversal. | S1-07 | Preserve original relative path. | Nested ZIP inventory works. | Corrupt/path traversal tests. | M | AI/data |
| S2-02 File inventory service | MIME, extension, hash, duplicate, size, parser status. | S2-01 | Store per file row. | Inventory table updates. | Duplicate tests. | M | backend |
| S2-03 PDF parser | Extract text by page with page metadata. | S2-02 | Mark scanned pages for OCR. | Text PDF creates chunks. | PDF fixture tests. | M | AI/data |
| S2-04 Excel parser | Extract sheet, row, cell ranges. | S2-02 | Keep sheet/row/cell citation metadata. | Bit/NPT Excel rows parse. | Excel fixture tests. | L | AI/data |
| S2-05 Word parser | Extract paragraphs and headings. | S2-02 | Preserve paragraph index. | Word DDR parses. | DOCX fixture tests. | M | AI/data |
| S2-06 CSV/text/email parser | Parse CSV rows, plain text, email body, attachments. | S2-02 | Email citations include subject/body/attachment. | Email NPT evidence indexed. | CSV/email tests. | L | AI/data |
| S2-07 OCR routing | Detect image/scanned pages and enqueue OCR. | S2-03 | No OCR engine quality tuning yet. | Scanned PDF routes to OCR. | OCR routing tests. | M | AI/data |
| S2-08 Chunking service | Chunk parsed text with source lineage metadata. | S2-03/S2-04/S2-05/S2-06 | Store token-ish chunks and snippets. | Every chunk has source locator. | Chunk/citation tests. | L | AI/data |

### Sprint 3: Local AI Extraction and Validation

| Ticket | Description | Dependencies | Technical Notes | Acceptance Criteria | Tests | Complexity | Owner |
|---|---|---|---|---|---|---|---|
| S3-01 Local LLM router | Route prompts to Ollama/LM Studio and enforce tenant policy. | S1-03 | Hosted fallback disabled by default. | Local health check visible. | Policy tests. | L | backend |
| S3-02 Classification prompt | Classify report type with strict JSON. | S3-01/S2-08 | Include unknown and confidence. | Report family persists. | Classification eval. | M | AI/data |
| S3-03 Company extraction | Extract service company/operator/contractor names. | S3-01/S2-08 | Alias dictionary updates via validation. | Companies persist with citations. | Entity eval. | M | AI/data |
| S3-04 Tool extraction | Extract tool type, model, serial, provider. | S3-03 | Handle MWD/LWD/RSS/motor/bit/BHA. | Tool instances persist. | Tool eval. | L | AI/data |
| S3-05 Failure extraction | Extract failures, severity, root cause, recommendations. | S3-04 | Use strict schema and citation validator. | Failure rows created with citations and validation tasks. | Extraction eval. | XL | AI/data |
| S3-06 NPT extraction | Extract NPT duration, responsible entity, activity context. | S3-03 | Normalize hours. | NPT rows created. | NPT eval. | L | AI/data |
| S3-07 Confidence scoring | Compute model, parser, citation, and conflict confidence. | S3-05/S3-06 | Confidence below threshold creates validation. | Low-confidence tasks appear. | Confidence tests. | M | AI/data |
| S3-08 Validation queue MVP | Review/edit/validate/reject extracted records. | S3-07 | Audit diffs. | Reviewer can validate one failure. | E2E validation. | L | frontend/backend |

### Sprint 4: Chat, Dashboard, Report, Export, QA

| Ticket | Description | Dependencies | Technical Notes | Acceptance Criteria | Tests | Complexity | Owner |
|---|---|---|---|---|---|---|---|
| S4-01 Embeddings and vector search | Generate embeddings and retrieve report chunks. | S2-08/S3-01 | Local embedding preferred. | Vector search returns cited chunks. | Retrieval tests. | L | AI/data |
| S4-02 Structured retrieval | SQL retrieval for failures, NPT, tools, companies. | S3-05/S3-06 | Combine with filters. | Chat can answer NPT/company questions. | Query tests. | M | backend |
| S4-03 Chat service | Persist sessions/messages, answer with citations and clarification. | S4-01/S4-02 | RAG plus SQL, no unsupported predictions. | Core prompts answer correctly. | Faithfulness tests. | XL | backend/AI |
| S4-04 Dashboard MVP | Cards/charts for failures, NPT, severity, validation, confidence. | S3-05/S3-06 | Drill-down into filtered explorer. | Totals match DB. | Dashboard tests. | L | frontend |
| S4-05 Monday Report generator | Generate report JSON from validated + flagged records. | S4-03 | Include unresolved validation warnings. | Draft report created. | Report schema tests. | L | AI/data |
| S4-06 PDF/Excel export | Create PDF and Excel files with citations/appendix. | S4-05 | Store exports and signed URLs. | User downloads both. | Export tests. | L | backend |
| S4-07 Audit log coverage | Log upload, extraction, validation, chat, export, admin actions. | all | Include actor, tenant, IP, resource. | Admin can inspect logs. | Audit tests. | M | security |
| S4-08 Demo fixture QA | Run golden dataset through full flow. | all | Include corrupted and duplicate files. | Demo script passes. | E2E/perf/security. | XL | QA |

## 6. First 30-Day Build Plan

### Week 1: Foundation

- Set repo structure for frontend, FastAPI backend, workers, migrations, and shared schemas.
- Implement auth/session skeleton, tenant model, user roles, workspace model, wells, rigs.
- Build upload shell UI and storage adapter.
- Add Redis queue and `processing_jobs` lifecycle.
- Create initial migrations with pgvector and RLS baseline.
- Milestone: authenticated user can create workspace and upload a ZIP object into tenant-scoped storage.

### Week 2: Parsing

- Implement ZIP extraction with path traversal protection.
- Build file inventory with SHA-256, MIME, extension, duplicate detection, and parser status.
- Add parser adapters for PDF, Excel, Word, CSV, text, and email.
- Add basic OCR routing for image files and scanned PDF pages.
- Implement source lineage and report chunking.
- Milestone: mixed rig-report package produces searchable chunks with page/sheet/row/paragraph/email metadata.

### Week 3: Local AI Extraction

- Configure Ollama/LM Studio local model router and tenant model policy.
- Implement classification, company, tool, failure, NPT, root cause, recommendation, and citation prompts.
- Persist extracted entities, failures, NPT events, citations, confidence scores.
- Create validation queue and edit/validate/reject workflow.
- Milestone: system extracts cited MWD/RSS/motor/bit/NPT records and reviewer validates one low-confidence result.

### Week 4: Chat, Dashboard, Report, Export

- Implement hybrid chat retrieval with structured SQL plus vector chunks.
- Build dashboard MVP cards and drill-down filters.
- Generate Monday Report draft with unresolved-validation warning.
- Export PDF and Excel with appendix and citations.
- Add audit log coverage and golden fixture QA.
- Milestone: demo flow from mixed upload to cited Monday Report PDF/Excel passes.

## 7. System Architecture Diagram in Text

```text
User Browser
  -> React/Next.js Web Frontend
      - Local AI chat
      - Upload/inventory
      - Validation queue
      - Dashboards
      - Monday Report preview/export

Frontend
  -> FastAPI Backend/API Gateway
      - Auth/session middleware
      - Tenant/RBAC guard
      - REST APIs
      - Audit middleware
      - Signed URL broker

Backend
  -> Auth Provider / Session Store
  -> PostgreSQL + pgvector
      - tenant-owned records
      - RLS policies
      - report chunks and embeddings
  -> Object Storage
      - original uploads
      - parsed artifacts
      - exports
  -> Redis / Queue
      - processing_jobs
      - parser/OCR/extraction/export jobs

Queue Workers
  -> Upload Scanner / Malware Scanner
  -> Parser Modules
      - PDF, Excel, Word, CSV, text, email, image
  -> OCR Service
      - local OCR with bounding boxes
  -> Chunking + Embedding Service
  -> Local LLM Runtime
      - Ollama or LM Studio
      - classification, extraction, chat, report generation
  -> Citation Service
  -> Export Service
      - PDF and Excel

Observability
  -> Structured logs
  -> Metrics
  -> Audit logs
  -> Worker health checks
```

## 8. Service Design

| Service | Responsibility | Inputs | Outputs | Tables Touched | Failure Modes | Retry Behavior | Logging |
|---|---|---|---|---|---|---|---|
| Web frontend | User workflows and chat-first UI. | API responses, file selections. | UI actions, uploads, edits. | none directly | network errors, stale auth | user retry | client event + API correlation ID |
| Backend API | Tenant-scoped REST boundary. | HTTP requests. | JSON responses/jobs. | all tenant tables | unauthorized, validation error | no automatic retry except idempotent GET | request, actor, tenant, status |
| Upload service | Signed upload, storage write, upload records. | files/ZIP metadata. | upload/file rows, jobs. | uploads, files, processing_jobs | large file, storage fail | retry storage with idempotency key | file hash, storage URI, result |
| File inventory service | Hash/MIME/duplicate/parser selection. | stored files. | inventory status. | files, processing_jobs | unknown MIME, duplicate | retry safe | parser decision log |
| Parser service | Extract text/tables/email bodies. | file URI. | parsed pages/rows/chunks. | report_documents, report_chunks | corrupt file, parser exception | retry 2 times then failed | parser version, error stack |
| OCR service | Extract text from scanned pages/images. | image/page artifact. | OCR text, bbox, confidence. | report_chunks, files | poor image, timeout | retry once then validation warning | OCR engine, quality score |
| Chunking service | Create retrieval chunks with lineage. | parsed text/tables. | chunks, snippets. | report_chunks | chunk overflow, missing locator | retry after parser fix | chunk counts, locator coverage |
| Embedding service | Embed chunks for vector search. | chunk text. | vector embeddings. | report_chunks | model unavailable | queue retry exponential | model, dimensions, latency |
| Extraction service | Local AI classification/extraction. | chunks, metadata, tenant policy. | entities, failures, NPT, confidence. | reports, companies, tools, failures, npt_events, citations | invalid JSON, local model offline | retry with repair prompt then validation | prompt version, model, schema result |
| Citation service | Map extracted claims to source locators. | extraction spans, chunks. | citation records. | citations | missing locator, snippet mismatch | no retry; route validation | citation completeness |
| Validation service | Human review and corrections. | tasks, edits. | canonical records and audit diffs. | validation_tasks, companies, tools, failures, npt_events, audit_logs | edit conflict | optimistic locking retry | before/after diff |
| Chat service | Hybrid SQL/vector answers. | prompt, filters, tenant context. | cited answer, follow-ups. | chat_sessions, chat_messages, failures, npt_events, report_chunks | ambiguous prompt, unsupported claim | ask clarification | retrieval trace |
| Dashboard service | Aggregate metrics. | filters. | charts/cards. | failures, npt_events, validation_tasks | slow query | cached read retry | query timing |
| Monday Report service | Generate report JSON and approval state. | reporting period, records, prompt. | monday_reports. | monday_reports, failures, npt_events, citations | unresolved validation | warn/block based policy | source coverage |
| Export service | Render PDF/Excel. | monday_report JSON. | storage URI + signed URL. | monday_reports, audit_logs | template error | retry once | output size/hash |
| Audit service | Record sensitive actions. | action metadata. | immutable audit rows. | audit_logs | write failure | fail closed for sensitive actions | actor, action, resource |

## 9. Database Schema v1

All tenant-owned tables include `tenant_id uuid not null references tenants(id)`. RLS policy uses `tenant_id = current_setting('app.tenant_id')::uuid`. Use `created_at`, `updated_at` on mutable tables. UUIDs default to `gen_random_uuid()`.

### Table Specs

| Table | Columns and Types | PK/FK | Indexes | Constraints and Tenant Strategy | Example Row |
|---|---|---|---|---|---|
| `tenants` | `id uuid`, `name text`, `slug text`, `region text`, `plan text`, `local_llm_policy jsonb`, `retention_days int`, `encryption_key_ref text` | PK `id` | unique `slug` | root tenant table; no RLS by tenant but admin guarded | `{name:"NorthStar Drilling", slug:"northstar", region:"ksa"}` |
| `users` | `id uuid`, `tenant_id uuid`, `email citext`, `full_name text`, `auth_provider_id text`, `status text` | PK `id`, FK tenant | unique `(tenant_id,email)` | status in active/disabled/invited | `{email:"drilling@northstar.com", status:"active"}` |
| `roles` | `id uuid`, `tenant_id uuid`, `name text`, `permissions jsonb` | PK `id`, FK tenant | unique `(tenant_id,name)` | allowed names admin/engineer/validator/manager/viewer | `{name:"validator"}` |
| `workspaces` | `id uuid`, `tenant_id uuid`, `name text`, `asset text`, `campaign text`, `period_start date`, `period_end date`, `status text` | PK `id`, FK tenant | `(tenant_id,status)`, `(tenant_id,period_start)` | tenant RLS, active/archived | `{name:"Gulf Campaign W27"}` |
| `wells` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `name text`, `field text`, `country text`, `aliases text[]` | PK `id`, FK tenant/workspace | `(tenant_id,name)` | unique canonical name per tenant when possible | `{name:"Well-A12", aliases:["A-12"]}` |
| `rigs` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `name text`, `contractor text`, `rig_type text`, `aliases text[]` | PK `id`, FK tenant/workspace | `(tenant_id,name)` | tenant RLS | `{name:"Rig-07", contractor:"Desert Drilling"}` |
| `uploads` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `submitted_by uuid`, `source_type text`, `status text`, `manifest jsonb` | PK `id`, FK tenant/workspace/user | `(tenant_id,workspace_id,status)` | source_type zip/folder/files | `{source_type:"zip", status:"processing"}` |
| `files` | `id uuid`, `tenant_id uuid`, `upload_id uuid`, `original_path text`, `storage_uri text`, `sha256 text`, `mime_type text`, `byte_size bigint`, `status text`, `malware_status text` | PK `id`, FK tenant/upload | unique `(tenant_id,sha256)`, `(tenant_id,upload_id)` | immutable original path; tenant RLS | `{original_path:"DDR_2026-07-01.pdf", status:"parsed"}` |
| `report_documents` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `file_id uuid`, `well_id uuid`, `rig_id uuid`, `report_type text`, `report_date date`, `title text`, `classification_confidence numeric` | PK `id`, FKs | `(tenant_id,report_type)`, `(tenant_id,report_date)` | report_type enum-like text | `{report_type:"DDR", report_date:"2026-07-01"}` |
| `report_chunks` | `id uuid`, `tenant_id uuid`, `report_document_id uuid`, `file_id uuid`, `chunk_text text`, `source_locator jsonb`, `embedding vector(1536)`, `tsv tsvector`, `parser_confidence numeric` | PK `id`, FKs | GIN `tsv`, HNSW `embedding`, `(tenant_id,report_document_id)` | source_locator required | `{source_locator:{page:3}, chunk_text:"Lost MWD signal..."}` |
| `companies` | `id uuid`, `tenant_id uuid`, `canonical_name text`, `aliases text[]`, `role_types text[]`, `validation_status text` | PK `id`, FK tenant | unique `(tenant_id,canonical_name)`, GIN aliases | canonical edits audited | `{canonical_name:"ABC Directional Services"}` |
| `tools` | `id uuid`, `tenant_id uuid`, `tool_type text`, `manufacturer text`, `model text`, `size_label text`, `aliases text[]` | PK `id`, FK tenant | `(tenant_id,tool_type)`, GIN aliases | tool_type MWD/LWD/RSS/mud_motor/bit/BHA/etc. | `{tool_type:"MWD", model:"PulsePro X"}` |
| `tool_instances` | `id uuid`, `tenant_id uuid`, `tool_id uuid`, `provider_company_id uuid`, `serial_number text`, `configuration jsonb` | PK `id`, FKs | unique `(tenant_id,serial_number)` | serial can be unknown but then not unique | `{serial_number:"MWD-77821"}` |
| `extracted_entities` | `id uuid`, `tenant_id uuid`, `report_document_id uuid`, `entity_type text`, `normalized_value text`, `raw_value text`, `confidence numeric`, `citation_id uuid` | PK `id`, FKs | `(tenant_id,entity_type,normalized_value)` | raw and normalized retained | `{entity_type:"company", raw_value:"ABC Dir Svc"}` |
| `failures` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `well_id uuid`, `rig_id uuid`, `company_id uuid`, `tool_instance_id uuid`, `event_date date`, `event_type text`, `severity text`, `summary text`, `root_cause text`, `recommendation text`, `confidence numeric`, `validation_status text` | PK `id`, FKs | `(tenant_id,event_date)`, `(tenant_id,severity)`, `(tenant_id,validation_status)` | severity Low/Medium/High/Critical | `{event_type:"MWD failure", severity:"High"}` |
| `npt_events` | `id uuid`, `tenant_id uuid`, `failure_id uuid`, `workspace_id uuid`, `company_id uuid`, `tool_instance_id uuid`, `npt_hours numeric`, `cost_estimate_usd numeric`, `activity text`, `responsibility text`, `confidence numeric` | PK `id`, FKs | `(tenant_id,npt_hours)`, `(tenant_id,company_id)` | hours >= 0 | `{npt_hours:8.5, activity:"POOH to replace MWD"}` |
| `citations` | `id uuid`, `tenant_id uuid`, `file_id uuid`, `report_document_id uuid`, `report_chunk_id uuid`, `locator_type text`, `locator jsonb`, `snippet text`, `confidence numeric` | PK `id`, FKs | `(tenant_id,file_id)`, GIN locator | locator_type pdf/excel/word/csv/image/email/snippet | `{locator_type:"pdf", locator:{page:3}}` |
| `validation_tasks` | `id uuid`, `tenant_id uuid`, `target_type text`, `target_id uuid`, `reason text`, `priority text`, `status text`, `assigned_to uuid`, `reviewed_by uuid`, `resolution_note text` | PK `id`, FK tenant/users | `(tenant_id,status,priority)` | status open/resolved/rejected | `{target_type:"failure", reason:"low confidence"}` |
| `chat_sessions` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `user_id uuid`, `title text`, `filters jsonb` | PK `id`, FKs | `(tenant_id,workspace_id,user_id)` | tenant RLS | `{title:"Week 27 NPT review"}` |
| `chat_messages` | `id uuid`, `tenant_id uuid`, `chat_session_id uuid`, `role text`, `content text`, `retrieval_trace jsonb`, `citation_ids uuid[]`, `model_name text` | PK `id`, FK session | `(tenant_id,chat_session_id)` | role user/assistant/system/tool | `{role:"assistant", content:"3 failures..."}` |
| `monday_reports` | `id uuid`, `tenant_id uuid`, `workspace_id uuid`, `period_start date`, `period_end date`, `status text`, `report_json jsonb`, `pdf_uri text`, `excel_uri text`, `generated_by uuid`, `approved_by uuid` | PK `id`, FKs | `(tenant_id,workspace_id,period_start)` | status draft/review/approved/exported | `{status:"draft"}` |
| `audit_logs` | `id uuid`, `tenant_id uuid`, `actor_user_id uuid`, `action text`, `resource_type text`, `resource_id uuid`, `ip_address inet`, `metadata jsonb` | PK `id`, FKs | `(tenant_id,created_at)`, `(tenant_id,action)` | append-only | `{action:"validation.update"}` |
| `processing_jobs` | `id uuid`, `tenant_id uuid`, `upload_id uuid`, `file_id uuid`, `job_type text`, `status text`, `attempts int`, `error text`, `payload jsonb`, `started_at timestamptz`, `finished_at timestamptz` | PK `id`, FKs | `(tenant_id,status,job_type)`, `(tenant_id,upload_id)` | attempts <= max_attempts | `{job_type:"parse_pdf", status:"queued"}` |

## 10. API Specification v1

Common error cases: `401 unauthenticated`, `403 forbidden`, `404 not found or cross-tenant`, `409 conflict`, `422 validation_error`, `429 rate_limited`, `500 internal_error`, `503 local_model_unavailable`.

| Method | Path | Purpose | Request Body | Response Body | Authorization | Error Cases |
|---|---|---|---|---|---|---|
| GET | `/auth/session` | Get current user, tenant, roles. | none | `{user,tenant,roles}` | authenticated | 401 |
| POST | `/auth/logout` | End session. | none | `{ok:true}` | authenticated | 401 |
| GET | `/tenants/current` | Read tenant policy. | none | `{tenant,local_llm_policy}` | any tenant user | 403 |
| PATCH | `/tenants/current` | Update tenant settings. | `{name,retention_days,local_llm_policy}` | `{tenant}` | admin | 403,422 |
| GET | `/workspaces` | List workspaces. | query filters | `{items}` | engineer+ | 403 |
| POST | `/workspaces` | Create workspace. | `{name,period_start,period_end,asset,campaign}` | `{workspace}` | engineer+ | 422 |
| GET | `/workspaces/{id}` | Get workspace. | none | `{workspace}` | workspace member | 404 |
| POST | `/uploads` | Create upload and signed URL. | `{workspace_id,file_name,byte_size,mime_type}` | `{upload,file,signed_url}` | engineer+ | 413,422 |
| POST | `/uploads/direct` | Store local file bytes, hash, audit, and enqueue processing. | `multipart: workspace_id,file_name,source_type,file` | `{upload,file,signed_url}` | engineer+ | 413,422 |
| POST | `/uploads/{id}/complete` | Mark upload complete and enqueue scan. | `{file_ids}` | `{upload,status}` | engineer+ | 404,409 |
| GET | `/uploads/{id}/files` | List inventory. | none | `{files}` | workspace member | 404 |
| GET | `/documents` | List parsed documents, optionally filtered by workspace. | `workspace_id?` | `{items}` | workspace member | 404 |
| GET | `/documents/{id}/chunks` | List parsed source chunks for one document. | none | `{items}` | workspace member | 404 |
| POST | `/upload-files/{id}/signed-url` | Create expiring source-file download URL. | none | `{url,expires_at}` | workspace member | 404,409 |
| GET | `/signed/upload-files/{id}` | Download source file with signed token. | `token` | file bytes | signed URL | 403,404,409 |
| GET | `/reports` | List report documents. | filters | `{items}` | workspace member | 403 |
| GET | `/extractions/entities` | List extracted entities. | filters | `{items}` | engineer+ | 403 |
| GET | `/failures` | List failures. | filters: period, company, tool, severity | `{items}` | workspace member | 403 |
| PATCH | `/failures/{id}` | Edit failure during validation. | `{event_type,severity,summary,root_cause,recommendation}` | `{failure}` | validator+ | 404,409 |
| GET | `/npt-events` | List NPT events. | filters | `{items}` | workspace member | 403 |
| GET | `/companies` | List companies. | filters | `{items}` | workspace member | 403 |
| PATCH | `/companies/{id}` | Edit canonical name/aliases. | `{canonical_name,aliases}` | `{company}` | validator+ | 409 |
| GET | `/tools` | List tools and instances. | filters | `{items}` | workspace member | 403 |
| GET | `/validation-tasks` | List validation tasks. | filters | `{items}` | validator+ | 403 |
| PATCH | `/validation-tasks/{id}` | Update scaffold validation status. | `{status,resolution_note}` | `{task}` | validator+ | 404 |
| POST | `/validation-tasks/{id}/resolve` | Resolve task. | `{status,edits,resolution_note}` | `{task,target}` | validator+ | 409 |
| POST | `/chat/sessions` | Create chat. | `{workspace_id,title,filters}` | `{session}` | workspace member | 422 |
| POST | `/chat/sessions/{id}/messages` | Ask question. | `{content,filters}` | `{message,answer,citations,followups}` | workspace member | 503 |
| GET | `/dashboards/summary` | Get dashboard cards/charts. | filters | `{cards,charts}` | workspace member | 403 |
| GET | `/readiness/client-data` | Read real-client data readiness gates. | none | `{mode,status,checks}` | admin/security | 503 |
| POST | `/monday-reports` | Generate draft. | `{workspace_id,period_start,period_end,filters}` | `{report}` | engineer+ | 409 unresolved_validation |
| GET | `/monday-reports` | List generated scaffold reports. | `workspace_id?` | `{items}` | workspace member | 403 |
| GET | `/monday-reports/{id}` | Read report. | none | `{report}` | workspace member | 404 |
| POST | `/monday-reports/{id}/exports/{format}` | Create scaffold export. | `format: json/csv/html/pdf/xlsx` | `{export}` | engineer+ | 404,422 |
| POST | `/monday-reports/{id}/exports` | Create bundled multi-format export. | `{formats:["pdf","xlsx"]}` | `{exports}` | engineer+ | 409 |
| POST | `/report-exports/{id}/signed-url` | Create expiring signed download URL. | none | `{url,expires_at}` | engineer+ | 404 |
| GET | `/signed/report-exports/{id}` | Download export with signed token. | `token` | file bytes | signed URL | 403,404 |
| GET | `/audit-logs` | Read audit logs. | filters | `{items}` | admin/security | 403 |

## 11. AI Prompt Pack v1

General rules for all prompts:

- Use only supplied evidence.
- Preserve drilling terminology exactly when known: DDR, BHA, MWD, LWD, RSS, mud motor, bit, mud report, NPT, POOH, RIH, TD, MD, TVD, WOB, RPM, flow rate, differential pressure.
- Return strict JSON only for extraction prompts.
- Use `"unknown"` when evidence is missing.
- Include source citations with file ID, page/sheet/row/paragraph/bbox/email locator, and snippet.
- Include confidence from 0.0 to 1.0.
- Do not assign blame unless the evidence states responsibility.
- Flag conflicts and low-confidence fields.

### Report Type Classification

```text
System: You classify drilling report documents for Monday Report. Use only the provided text, file metadata, and source locator metadata. Return strict JSON.

User: Classify this document.
Input: {file_name, mime_type, chunks:[{chunk_id,text,locator}]}

Output schema:
{"report_type":"DDR|BHA|MWD_LWD|RSS|MUD_MOTOR|BIT_RECORD|MUD_REPORT|NPT_REPORT|EMAIL|SCANNED_IMAGE|LESSONS_LEARNED|UNKNOWN","report_date":"YYYY-MM-DD|unknown","well":"string|unknown","rig":"string|unknown","service_company":"string|unknown","confidence":0.0,"citations":[...],"validation_warnings":[]}

Example: A sheet titled "Motor Run Summary" with stator/differential columns returns MUD_MOTOR.
Validation: confidence below 0.70 requires validation_warnings.
```

### Rig/Well/Company Extraction

```text
System: Extract rig, well, operator, contractor, and service-company entities from drilling evidence. Return strict JSON and do not normalize beyond obvious whitespace/case.
Fields: well_name, well_aliases, rig_name, rig_contractor, operator, service_companies[{raw_name,role_type}], confidence, citations.
Example: "ABC Directional Services on location for MWD/RSS" -> service company role "directional/MWD/RSS provider".
Validation: if multiple companies could be responsible for NPT, set responsibility:"unknown" and conflict:true.
```

### Tool Extraction

```text
System: Extract drilling tools and tool instances. Include BHA, MWD, LWD, RSS, mud motor, bit, jar, stabilizer, pulser, battery, and mud system components when relevant.
Output: {"tools":[{"tool_type","manufacturer","model","size_label","serial_number","provider_company","run_number","bha_context","confidence","citations","warnings"}]}
Example: "PulsePro X SN MWD-77821 lost signal" -> tool_type "MWD", model "PulsePro X", serial_number "MWD-77821".
Validation: serial_number unknown is allowed but must reduce confidence.
```

### Failure Detection

```text
System: Detect drilling failures, tool failures, operational failures, and service failures. Return strict JSON.
Output: {"failures":[{"event_type","event_date","well","rig","hole_section","depth_md","formation","company","tool_type","tool_serial","severity","summary","evidence_text","confidence","citations","conflicts"}]}
Example: "Lost MWD signal at 10,342 ft MD; POOH to replace MWD" -> event_type "MWD failure", severity "High".
Validation: no citation means confidence <= 0.40 and validation_required true.
```

### NPT Detection

```text
System: Extract non-productive time. Normalize durations to hours. Do not invent cost unless provided.
Output: {"npt_events":[{"date","activity","npt_hours","responsible_company","related_failure","cost_estimate_usd","confidence","citations","warnings"}]}
Example: "Rig waiting on replacement RSS 9 hrs" -> npt_hours 9, activity "waiting on replacement RSS".
Validation: ambiguous downtime goes to validation.
```

### Root Cause Extraction

```text
System: Extract stated and inferred root causes. Separate evidence from interpretation.
Output: {"root_causes":[{"failure_ref","stated_root_cause","inferred_root_cause","inference_basis","confidence","citations"}]}
Validation: if only inference exists, confidence <= 0.75 and wording must include "likely" or "probable".
```

### Recommendation Extraction

```text
System: Extract corrective actions and recommendations. Preserve action owner and timing if present.
Output: {"recommendations":[{"failure_ref","recommendation","owner":"operator|contractor|service_company|unknown","urgency","confidence","citations"}]}
Validation: do not create recommendations unsupported by source unless asked to draft; mark drafted recommendations as AI-generated.
```

### Citation Mapping

```text
System: Map each extracted claim to source evidence. Return the best citation locator and snippet. Reject citations that do not support the claim.
Output: {"citations":[{"claim_id","file_id","locator_type","locator","snippet","supports_claim":true,"confidence"}]}
Validation: snippet must contain or directly support the extracted fact.
```

### Chat Answer Generation

```text
System: You are Monday Report Local AI. Answer drilling questions using structured SQL results and retrieved report chunks. Cite every factual claim. Ask a clarification question when the prompt is ambiguous. Refuse deterministic predictions.
Output: prose answer plus structured metadata: {answer, citations, followups, export_actions, confidence_notes}.
Example user: "Which company caused most NPT?" Answer with totals by responsible company, cite NPT rows, state uncertainty when responsibility is unknown.
```

### Clarification Question Generation

```text
System: Generate one concise clarification question when a user prompt lacks dimension, period, well, rig, company, or tool type.
Examples: "Compare failures" -> "Compare by company, tool type, well, rig, or severity?"
Validation: do not ask for clarification if filters already provide the missing context.
```

### Monday Report Generation

```text
System: Generate the official weekly Monday Report from validated and flagged extraction records. Use the required template. Every fact must include citations or say "unknown". Include unresolved validation warnings and confidence notes.
Output strict JSON matching monday_report schema.
Validation: block "approved" status if high-severity records lack citations or unresolved validation tasks remain.
```

## 12. Extraction JSON Schemas

Schemas are abbreviated for implementation; enforce with JSON Schema in backend.

```json
{
  "report_classification": {
    "required": ["file_id", "report_type", "confidence", "citations"],
    "properties": {
      "file_id": "uuid",
      "report_type": "enum",
      "report_date": "date|unknown",
      "well": "string|unknown",
      "rig": "string|unknown",
      "confidence": "number 0..1",
      "citations": "citation[]",
      "warnings": "string[]"
    }
  },
  "company_extraction": {
    "required": ["raw_name", "canonical_candidate", "role_type", "confidence", "citations"],
    "optional": ["aliases", "responsibility_context"]
  },
  "tool_extraction": {
    "required": ["tool_type", "confidence", "citations"],
    "optional": ["manufacturer", "model", "size_label", "serial_number", "provider_company", "bha_context"]
  },
  "failure_event": {
    "required": ["event_type", "summary", "severity", "confidence", "citations"],
    "optional": ["event_date", "well", "rig", "company", "tool_type", "tool_serial", "depth_md", "root_cause", "recommendation"]
  },
  "npt_event": {
    "required": ["activity", "npt_hours", "confidence", "citations"],
    "optional": ["responsible_company", "related_failure_id", "cost_estimate_usd", "date"]
  },
  "root_cause": {
    "required": ["failure_ref", "stated_root_cause", "confidence", "citations"],
    "optional": ["inferred_root_cause", "inference_basis"]
  },
  "recommendation": {
    "required": ["failure_ref", "recommendation", "confidence", "citations"],
    "optional": ["owner", "urgency", "ai_generated"]
  },
  "citation": {
    "required": ["file_id", "locator_type", "locator", "snippet", "confidence"],
    "optional": ["report_document_id", "report_chunk_id"]
  },
  "monday_report": {
    "required": ["period", "workspace", "executive_summary", "sections", "citations", "confidence_notes"],
    "optional": ["pdf_uri", "excel_uri", "approval"]
  }
}
```

## 13. Citation Strategy

- PDF page citation: `{locator_type:"pdf", page:3, bbox:null, snippet}`. Use page number from parser/OCR, not model guess.
- Excel citation: `{locator_type:"excel", sheet:"Run Summary", row:18, cell_range:"A18:H18", snippet}`.
- Word citation: `{locator_type:"word", paragraph_index:42, heading:"Operations Summary", snippet}`.
- CSV citation: `{locator_type:"csv", row:87, columns:["activity","npt"], snippet}`.
- Image OCR citation: `{locator_type:"image", page:1, bbox:{x,y,width,height}, ocr_confidence, snippet}`.
- Email citation: `{locator_type:"email", subject, body_part:"body|attachment", attachment_file_id, snippet}`.
- Extracted snippet citation: store exact snippet from parser output, claim ID, and confidence.
- Source lineage: claim -> citation -> chunk -> document -> file -> upload -> workspace -> tenant.
- Rendering: show short citation chips in chat/report, expandable source drawer with locator and snippet.
- Confidence: display claim confidence and source confidence separately when available.

## 14. Validation Queue Design

Flag for review when:

- Extraction confidence < 0.75.
- Citation confidence < 0.80.
- No citation for a factual claim.
- Severity High/Critical.
- NPT hours > 4 or cost estimate > threshold.
- Conflicting source statements.
- Unknown responsible company for material NPT.
- Repeated tool serial failure.
- New company/tool alias not in canonical dictionary.

Reviewer workflow:

1. Open task and view extracted value plus source citations.
2. Edit fields such as company, tool serial, failure type, severity, NPT hours, root cause, recommendation.
3. Validate, reject, or mark conflict.
4. Corrections update canonical companies/tools/aliases when reviewer confirms.
5. Audit log stores before/after values, actor, timestamp, source citations, and reason.
6. Future extraction uses alias dictionaries and evaluation fixtures, not automatic model training.

## 15. Chat Retrieval Design

Chat combines:

- Structured SQL for failures, NPT, companies, tools, wells, rigs, validation status.
- Vector search over report chunks for explanatory context.
- Metadata filters: workspace, period, well, rig, company, tool type, severity, validation.
- Citation renderer from citation IDs and retrieved chunks.
- Clarification prompts when dimension or period is missing.
- Follow-up suggestions based on retrieved facts.
- Export actions for filtered results and Monday Report generation.

Example flows:

- "What failed this week?" -> SQL failures by period, vector chunks for summaries, answer by severity with citations.
- "Which company caused most NPT?" -> aggregate NPT by responsible company, flag unknown responsibility, cite NPT rows.
- "Show all motor failures." -> filter failures where tool type mud motor or event type motor failure, cite motor reports and DDR.
- "Compare MWD failures by service company." -> group MWD failures by company, show serials, NPT, confidence.
- "Generate Monday Report." -> check validation backlog, draft report JSON, return preview and export action.
- "Which evidence supports this answer?" -> show citation list, snippets, file/page/sheet/row links, and retrieval trace.

## 16. Dashboard MVP Specification

| Card/Chart | Query Logic | Filters | Drill-Down | Empty State | Export |
|---|---|---|---|---|---|
| Total failures | count `failures` | period, well, rig, company, tool, severity | open failure explorer | "No failures extracted for filters" | CSV/Excel |
| Failures by company | group failures by `company_id` | same | company detail | "No company attribution" | chart + rows |
| Failures by tool type | group by `tools.tool_type` | same | tool filtered explorer | "No tool data" | chart + rows |
| Failures by rig | group by `rig_id` | period, rig | rig detail | "No rig selected" | chart |
| Failures by well | group by `well_id` | period, well | well detail | "No well selected" | chart |
| NPT hours | sum `npt_events.npt_hours` | period, company, tool, well, rig | NPT table | "No NPT extracted" | Excel |
| NPT by company | group NPT by responsible company | same | company/NPT detail | "Responsibility unknown" | chart + rows |
| NPT by tool | group NPT by tool instance/type | same | tool detail | "No tool-linked NPT" | chart |
| Severity distribution | count by severity | period/company/tool | severity filter | "No severity data" | chart |
| Validation backlog | count open validation tasks | priority/status | validation queue | "No open tasks" | task export |
| Extraction confidence | average confidence by report/failure/NPT | period/type | low-confidence list | "No confidence data" | QA export |

## 17. Official Monday Report Template

### Structure

1. Cover section: title, tenant, workspace, reporting period, generated by, generated time, status.
2. Reporting period.
3. Workspace/well/rig context.
4. Executive summary.
5. Key operational highlights.
6. Failure summary.
7. NPT summary.
8. Company performance.
9. Tool performance.
10. Repeated issues.
11. Root causes.
12. Corrective actions.
13. Recommendations.
14. High-risk items.
15. Data quality notes.
16. Source citations.
17. Appendix with extracted records.

### JSON Representation

```json
{
  "title": "Monday Report",
  "period": {"start": "2026-07-01", "end": "2026-07-07"},
  "workspace": {"name": "Gulf Campaign W27", "wells": [], "rigs": []},
  "executive_summary": [{"text": "...", "citation_ids": [], "confidence": 0.91}],
  "key_operational_highlights": [],
  "failure_summary": [],
  "npt_summary": [],
  "company_performance": [],
  "tool_performance": [],
  "repeated_issues": [],
  "root_causes": [],
  "corrective_actions": [],
  "recommendations": [],
  "high_risk_items": [],
  "data_quality_notes": [],
  "source_citations": [],
  "appendix_records": []
}
```

### PDF Layout Recommendation

- Cover page with title, period, workspace, confidentiality footer.
- One-page executive summary.
- Section pages with compact tables and citation footnotes.
- Appendix with full extracted records and confidence.
- Header/footer includes tenant, report period, page number, generated timestamp.

### Excel Workbook Tabs

- `Cover`
- `Executive Summary`
- `Failures`
- `NPT Events`
- `Company Performance`
- `Tool Performance`
- `Validation Backlog`
- `Citations`
- `Appendix Extracted Records`
- `Data Quality`

## 18. Security Specification

- Tenant isolation: `tenant_id` on every object, RLS on all tenant tables, API tenant guard, no cross-tenant object keys.
- RBAC roles: admin, engineer, validator, manager, viewer, security auditor.
- RLS approach: set `app.tenant_id` and `app.user_id` per request transaction.
- Signed URLs: short-lived, tenant-scoped, read/write purpose-specific, logged.
- Malware scan workflow: upload -> quarantine -> scan -> clean status -> processing; infected files blocked and audited.
- Encryption: TLS in transit, encrypted object storage, encrypted DB disks, optional key reference per tenant.
- Audit events: login, upload, parse, extraction, validation edit, chat answer, report generation, export, signed URL, admin policy changes, deletion.
- Admin controls: hosted fallback disabled by default, retention policy, user disable, role changes, audit export.
- LLM privacy: local-first; hosted fallback requires tenant policy, per-call audit, no training, no raw file upload unless explicitly allowed.
- Data retention: tenant-configurable retention days with legal hold option.
- Deletion workflow: soft-delete workspace, revoke signed URLs, enqueue object deletion, tombstone audit, purge after retention.

## 19. Testing and Evaluation Plan

- Unit tests: domain services, validators, schema parsing, RBAC helpers.
- Integration tests: auth, tenants, uploads, ZIP expansion, queue, storage, parser outputs, DB writes.
- E2E tests: upload ZIP, inventory, validate, chat, dashboard, report export.
- Parser tests: PDF, Excel, Word, CSV, text, email, corrupted files.
- OCR tests: scanned PDF quality, image bbox, low-quality routing.
- AI extraction tests: precision/recall for failures, NPT, companies, tools, citations.
- Citation tests: every claim source locator resolves to stored file/chunk.
- Chat faithfulness tests: answer only from SQL/chunks; unsupported prediction refusal.
- Dashboard tests: aggregate totals match DB rows under filters.
- Export tests: PDF/Excel content equals report JSON.
- Security tests: tenant isolation, RBAC, signed URL expiry, malware workflow.
- Performance tests: 500-file ZIP, 2 GB upload handling, worker throughput, chat latency.

Golden fixture dataset:

- DDR.
- BHA report.
- MWD/LWD report.
- RSS report.
- Mud motor report.
- Bit record.
- Mud report.
- NPT report.
- Scanned PDF.
- Excel workbook.
- Email with attachment.
- Corrupted file.
- Duplicate file.

## 20. Demo Script

1. Login as drilling engineer.
2. Select `Gulf Campaign W27`.
3. Upload mixed rig-report ZIP.
4. Show inventory: DDR, BHA, MWD/LWD, RSS, mud motor, bit, mud, NPT, scanned PDF, Excel, email.
5. Show processing pipeline and OCR-routed scanned report.
6. Open extracted failures and highlight MWD failure, motor failure, stuck pipe, NPT event.
7. Validate one low-confidence MWD serial conflict.
8. Ask chat: "What failed this week?"
9. Ask chat: "Which company caused most NPT?"
10. Show dashboard cards for failures, NPT, company/tool performance, validation backlog.
11. Ask chat: "Generate Monday Report."
12. Preview report with citations and confidence notes.
13. Export PDF and Excel.
14. Open citation drawer to show PDF page and Excel row evidence.

## 21. Risks and Blockers

| Risk | Mitigation | Early Detection |
|---|---|---|
| Messy files | Build robust inventory, parser fallbacks, validation queue. | High parser failure rate in fixtures. |
| Poor OCR | Use local OCR quality scores and route low quality to review. | OCR confidence below threshold. |
| Local model weakness | Evaluate multiple local models, strict schemas, repair prompts. | Low extraction F1 on golden set. |
| Hallucinated extraction | Require citations, unknown values, schema validation. | Claim without supporting citation. |
| Weak citations | Store parser coordinates before AI extraction. | Citation round-trip test failures. |
| Tenant leakage | RLS, API guards, storage key isolation, tests. | Cross-tenant negative tests. |
| Slow processing | Async workers, chunk batching, progress states. | Worker queue latency metrics. |
| Unclear Monday Report format | Lock template before Week 4. | Report review churn with SME. |
| Lack of sample reports | Create anonymized golden fixture set. | Week 1 fixture gap. |

## 22. Immediate Next Actions

Build first:

1. Backend skeleton with tenant/RBAC, migrations, object storage, queue, and upload APIs.
2. Parser/worker foundation with ZIP extraction, inventory, and source lineage.
3. Local LLM router and strict JSON extraction harness.
4. Validation queue and citation renderer.
5. Chat retrieval using SQL plus vector chunks.

Decisions needed:

- React SPA versus Next.js app router for production.
- Auth provider.
- Object storage target for MVP.
- Redis/queue library.
- Local OCR engine.
- Ollama versus LM Studio default runtime.
- Initial local LLM and embedding model.
- Exact Monday Report PDF/Excel branding.
- Confidence thresholds for validation blocking.

Sample data needed:

- Anonymized DDR, BHA, MWD/LWD, RSS, mud motor, bit, mud, NPT, scanned PDF, Excel, email, corrupted file, duplicate file.
- Expected answer key for failures, NPT, companies, tools, citations, root causes, recommendations.

Engineering tasks to start:

- Create migration set for schema v1.
- Implement upload/storage/queue path.
- Build parser fixture harness.
- Draft strict JSON prompt tests.
- Build validation task API and UI.

Delay:

- Prediction.
- Offset benchmarking.
- External integrations.
- Automated vendor workflows.
- Hosted LLM fallback beyond policy plumbing.
- Advanced analytics beyond MVP dashboards.
