# Monday Report Execution Plan

## 1. MVP Definition

Monday Report MVP is a secure, local-AI-first SaaS workspace where a user uploads rig-report packages, asks questions first, validates extracted failures, and generates a weekly Monday Report with citations. Must-have: auth, tenant/workspace setup, ZIP/folder upload, file inventory, PDF/Excel/Word/CSV/text parsing, OCR routing, local AI classification and extraction, citations, validation queue, chat, dashboard, filters, Monday Report export, and audit logs. Should-have: advanced table extraction, tool-serial normalization, saved chat answers, and Excel/PDF templates. Later: prediction models, offset-well benchmarking, automated email intake, and external integrations.

Build chat, upload, extraction, and validation first. The fastest proof of value is: upload a mixed DDR/BHA/MWD/LWD/mud motor/RSS/bit/NPT package, ask "What failed this week?", review cited results, and export a Monday Report.

## 2. User Workflow

The user logs in, creates or joins an organization, creates a workspace for a campaign, rig, asset, or well set, then opens Local AI Chat. The user uploads a ZIP or selects a folder. Workers unzip, scan, parse, OCR, classify, chunk, embed, and extract failures, tools, companies, NPT, root causes, recommendations, and citations. The user asks AI questions, applies filters, reviews low-confidence records in the validation queue, generates the official Monday Report, and exports PDF or Excel.

## 3. MVP Feature List

Implement SaaS authentication, tenant organizations, workspaces/projects, ZIP upload, file inventory, parser workers, OCR, local AI report classification, local AI extraction, source citations, validation tasks, chat over reports, dashboard metrics, filters, Monday Report generation, PDF/Excel export, and audit logs. Chat is the main entry point; dashboards support questions instead of replacing them.

## 4. Technical Architecture

Recommended MVP stack: React or Next.js frontend, FastAPI backend, Python workers, PostgreSQL with pgvector, object storage, Redis or managed queue, local OCR, and local LLM runtime through Ollama or LM Studio. Add an LLM provider abstraction with local-first routing and optional hosted fallback only when tenant policy allows it. Every API call is tenant-scoped; every persisted object carries `tenant_id`.

## 5. Database Schema

Core tables:

- `tenants`: plan, region, retention policy, encryption key reference.
- `users`: tenant, email, auth provider ID, role status.
- `workspaces/projects`: tenant, asset, campaign, status.
- `wells` and `rigs`: tenant-owned drilling context with aliases.
- `uploads` and `files`: upload batch, original path, storage URI, SHA-256, parser status.
- `report_documents` and `report_chunks`: report type, date, pages/sheets/rows, chunk text, embeddings.
- `companies`, `tools`, and `tool_instances`: canonical names, aliases, provider relationships, serial numbers.
- `failures` and `npt_events`: event type, severity, root cause, recommendation, NPT hours, cost, confidence.
- `extracted_entities` and `citations`: entity spans, source file, page, sheet, row, snippet.
- `chat_sessions` and `chat_messages`: user prompts, retrieved chunks, structured query trace.
- `validation_tasks`: target record, reason, status, reviewer.
- `monday_reports`: weekly report JSON, PDF URI, Excel URI, approval state.
- `audit_logs`: actor, action, resource, IP, metadata.

## 6. AI Extraction Pipeline

Pipeline: upload, unzip, malware scan, file type detection, hash/dedupe, text extraction, OCR for scanned PDFs/images, table extraction, chunking, embeddings, report classification, entity extraction, failure extraction, NPT extraction, citation mapping, confidence scoring, deduplication, validation queue creation, and dashboard refresh. Local AI handles classification and extraction first; deterministic parsers preserve coordinates and table lineage.

## 7. Prompt Strategy

Create separate system prompts for report classification, company extraction, tool extraction, failure detection, NPT detection, root cause extraction, recommendation extraction, chat answer generation, Monday Report generation, and clarification questions. Each prompt must require drilling terminology, strict JSON output, confidence, citation spans, and "unknown" when evidence is missing.

## 8. Monday Report Format

Official weekly output: executive summary, key events, failures, NPT summary, company performance, tool performance, repeated issues, high-risk items, root causes, recommendations, source citations, and AI confidence notes. Each statement must trace to a source file, page, sheet, row, or extracted snippet.

## 9. Dashboard Design

MVP dashboards show total failures, failures by company/tool/rig/well, NPT hours, NPT by company/tool, severity, validation status, and extraction confidence. Dashboard cards should answer "where is the risk?" and let users jump back into chat with the active filter.

## 10. AI Chat Design

Chat uses hybrid retrieval: structured SQL for failures/NPT/tools/companies plus vector search over report chunks. Answers include citations, active filters, clarification questions, follow-ups, export actions, and dashboard generation from answers. The assistant should refuse unsupported deterministic predictions and explain evidence limits.

## 11. Security Design

Use tenant isolation, RBAC, encrypted object storage, secure uploads, malware scanning, signed file URLs, audit logs, LLM privacy controls, no training on customer data, and admin access controls. Local AI is default to reduce report exposure. Hosted fallback must be per-tenant, logged, and disabled by default.

## 12. Implementation Roadmap

Phase 1: foundation, auth, tenants, workspaces, upload shell. Phase 2: document processing and OCR. Phase 3: local AI classification and extraction. Phase 4: validation and database persistence. Phase 5: chat and retrieval. Phase 6: dashboards. Phase 7: Monday Report generation. Phase 8: security hardening. Phase 9: prediction and advanced analytics.

## 13. Engineering Tasks

Frontend: chat-first shell, upload, inventory, filters, validation queue, dashboard, export flows. Backend: tenant API, upload API, report API, chat API, validation API, export API, audit API. AI/data: parsers, OCR, embeddings, extraction prompts, evaluation set, dedupe. DevOps: local model runtime, queues, object storage, migrations, observability. Security: RBAC, RLS, signed URLs, malware scanning, audit retention. QA: fixtures, parser tests, extraction scoring, citation tests, tenant isolation tests.

## 14. Testing Plan

Test upload handling, ZIP extraction, parser coverage, OCR quality, extraction accuracy, citation accuracy, tenant isolation, chat answer faithfulness, dashboard totals, export generation, and performance on large mixed report packages. Build a golden fixture set with DDR, BHA, MWD/LWD, RSS, mud motor, bit record, mud report, email, scanned PDF, and NPT report examples.

## 15. Risks and Mitigations

Main risks: messy source files, hallucinated extraction, weak citations, tenant leakage, slow OCR, local model quality, and unclear report standards. Mitigate with deterministic parsing, strict JSON prompts, validation queues, RLS tests, async workers, model evaluation sets, and a locked Monday Report template.

## 16. Final Build Recommendation

Use React or Next.js, FastAPI, Python workers, PostgreSQL/pgvector, object storage, Redis queue, local OCR, and Ollama or LM Studio local LLM runtime. MVP scope should prove chat-first upload-to-report flow before prediction. First 30 days: auth, workspace, upload, parsing, local AI extraction, citations, validation queue, chat, and draft Monday Report export. Recommended team: one frontend engineer, one backend engineer, one AI/data engineer, one drilling SME, and one QA/security owner. Blockers: sample report access, accepted Monday Report template, tenant policy for local versus hosted models, OCR choice, and export branding.
