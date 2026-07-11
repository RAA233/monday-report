import type { LucideIcon } from "lucide-react";
import {
  Bot,
  CheckCircle2,
  ClipboardList,
  Database,
  FileSearch,
  Gauge,
  LockKeyhole,
  ShieldCheck,
  Workflow
} from "lucide-react";

export type PhaseStatus = "complete" | "in_progress" | "pending" | "blocked";
export type GateStatus = "pass" | "watch" | "pending";

export interface ProjectPhase {
  id: string;
  name: string;
  status: PhaseStatus;
  owner: string;
  objective: string;
  evidence: string;
  nextAction: string;
  icon: LucideIcon;
}

export interface TestGate {
  id: string;
  name: string;
  status: GateStatus;
  command: string;
  lastResult: string;
}

export interface TrackerLane {
  id: string;
  title: string;
  status: GateStatus;
  summary: string;
  items: string[];
}

export interface AuditEvent {
  id: string;
  event: string;
  scope: string;
  result: string;
  timestamp: string;
}

export const projectPhases: ProjectPhase[] = [
  {
    id: "phase-00",
    name: "Plan and scope lock",
    status: "complete",
    owner: "Product + drilling SME",
    objective: "Lock local-AI-first MVP, user workflows, schema, API, prompt pack, and security posture.",
    evidence: "Execution plan and implementation spec are committed under docs/.",
    nextAction: "Use tracker gates before every new execution slice.",
    icon: ClipboardList
  },
  {
    id: "phase-01",
    name: "Chat-first frontend",
    status: "complete",
    owner: "Frontend",
    objective: "Make Local AI Chat the main Monday Report surface with citations and fallback behavior.",
    evidence: "Vite build passes and chat opens as the default view.",
    nextAction: "Add report preview/export wiring after backend persistence lands.",
    icon: Bot
  },
  {
    id: "phase-02",
    name: "FastAPI scaffold",
    status: "complete",
    owner: "Backend",
    objective: "Provide tenant, workspace, upload, chat, dashboard, report, and audit API boundaries.",
    evidence: "Health, session, dashboard, chat, upload, and Monday Report endpoints respond locally.",
    nextAction: "Replace in-memory store with PostgreSQL repositories.",
    icon: Workflow
  },
  {
    id: "phase-03",
    name: "Tracker, test, and audit gates",
    status: "complete",
    owner: "QA + security",
    objective: "Track phases, run repeatable checks, and expose audit visibility.",
    evidence: "Tracker page, live audit panel, audit endpoint, and phase audit script are passing.",
    nextAction: "Run pnpm run audit:phase after every implementation slice.",
    icon: Gauge
  },
  {
    id: "phase-04",
    name: "PostgreSQL and Redis persistence",
    status: "in_progress",
    owner: "Backend + DevOps",
    objective: "Move API state and worker jobs out of memory into RLS-backed storage.",
    evidence: "Local JSON remains the demo default; client mode can activate a PostgreSQL-backed tenant state repository with RLS and Redis-backed processing-job queue when those services are reachable.",
    nextAction: "Expand the PostgreSQL adapter from state snapshot storage into normalized table repositories.",
    icon: Database
  },
  {
    id: "phase-05",
    name: "Parser and OCR pipeline",
    status: "in_progress",
    owner: "AI/data",
    objective: "Parse ZIP, PDF, Excel, Word, CSV, email, images, and scanned pages with source lineage.",
    evidence: "Worker enforces ZIP entry and uncompressed-size limits, expands accepted ZIP packages safely, parses text, CSV, XLSX, DOCX, EML, PyMuPDF-backed PDF child files, native PDF table rows, and configured OCR output into typed page/table/row/image-aware source chunks. Parser/OCR eval report readiness now blocks incomplete fixture evidence, and the generator produces readiness reports from anonymized manifests.",
    nextAction: "Run the parser/OCR eval report generator against real anonymized fixtures and configure production OCR.",
    icon: FileSearch
  },
  {
    id: "phase-06",
    name: "Local AI extraction",
    status: "in_progress",
    owner: "AI/data + drilling SME",
    objective: "Classify reports and extract failures, NPT, companies, tools, root causes, recommendations, and citations.",
    evidence: "Deterministic extraction scaffold creates cited MWD signal-loss failures; local AI runtime status endpoint defaults to Ollama gemma4:e2b and verifies the pinned model is available.",
    nextAction: "Wire Ollama/LM Studio router, strict JSON schemas, confidence scoring, and golden extraction metrics.",
    icon: ShieldCheck
  },
  {
    id: "phase-07",
    name: "Validated Monday Report export",
    status: "complete",
    owner: "Frontend + backend",
    objective: "Generate report artifacts only after validation gates are visible.",
    evidence: "Validation update, report creation, JSON/CSV/HTML/PDF/XLSX exports, signed download URLs, and E2E audit are passing.",
    nextAction: "Polish production report templates and reviewer approval gates.",
    icon: CheckCircle2
  },
  {
    id: "phase-08",
    name: "Real-client readiness gates",
    status: "in_progress",
    owner: "Security + backend + QA",
    objective: "Prevent real client data from entering unsafe demo/local-scaffold environments.",
    evidence: "Client-data readiness endpoint, runtime backend status, tracker panel, API auth guard, upload guard, archive safety guard, infrastructure readiness guard, retention guard, malware guard, storage path guard, client-operation guard, signed source-file URLs, upload-size limit, local AI status, redacted audit hash chain, and audit command report pass/warn/fail posture.",
    nextAction: "Replace local JSON with PostgreSQL/RLS, wire Redis workers, external malware scanning, production parsers, and local model runtime.",
    icon: LockKeyhole
  }
];

export const clearTrackerLanes: TrackerLane[] = [
  {
    id: "accepted-now",
    title: "Accepted Now",
    status: "pass",
    summary: "Executable local MVP path is working and phase-gated for synthetic/demo data.",
    items: [
      "Chat-first UI with API fallback and source-backed answers.",
      "Direct and ZIP uploads with hashing, malware baseline checks, safe storage paths, and signed downloads.",
      "Parser worker covers text, CSV, XLSX, DOCX, EML, PyMuPDF-backed PDF text, native PDF table rows, OCR routing/extraction, typed locators, manifest-driven parser/OCR eval reports, and source citation actions.",
      "Partner preview ZIP includes the built app, API, worker loop, Gemma 4 E2B defaults, sample import package, and import/export smoke script.",
      "Validation-gated Monday Report exports JSON, CSV, HTML, PDF, and XLSX with signed artifact downloads.",
      "`audit:all` is the accepted local proof gate after every slice."
    ]
  },
  {
    id: "safe-operating-mode",
    title: "Safe Operating Mode",
    status: "watch",
    summary: "Use demo/local mode only until real-client readiness reports green.",
    items: [
      "Current state is durable local JSON under `.local_data/`, not PostgreSQL/RLS.",
      "Current worker is inline/local, not Redis-backed queue processing.",
      "Client mode intentionally blocks unsafe reads, chat, reports, exports, and source downloads until readiness passes.",
      "Readiness warnings are expected while infrastructure, scanner, signing, and model settings are unconfigured."
    ]
  },
  {
    id: "real-client-blockers",
    title: "Real-Client Blockers",
    status: "watch",
    summary: "Local client-readiness can go green with active Postgres, Redis, and fixture evidence; production intake still needs reviewed client evidence.",
    items: [
      "Use reviewed anonymized client fixtures instead of generated engineering fixtures before production intake.",
      "Replace the OCR shim used by local smoke tests with production Tesseract or an approved OCR command.",
      "Move upload/export roots to approved encrypted tenant storage.",
      "Set production API key, signing secret, retention policy, and external malware scanner posture.",
      "Continue expanding PostgreSQL from state snapshot storage to normalized table repositories."
    ]
  },
  {
    id: "next-execution-order",
    title: "Next Execution Order",
    status: "pending",
    summary: "The next high-value work should convert the local MVP into production-grade ingestion and extraction.",
    items: [
      "Build a manifest-backed golden fixture pack for DDR, BHA, MWD/LWD, RSS, mud motor, bit, mud, scanned PDF, Excel, email, corrupted, and duplicate files.",
      "Run `generate_parser_fixture_eval_report.py` and set `MONDAY_REPORT_PARSER_EVAL_REPORT` from the passing report.",
      "Harden OCR extraction on anonymized scanned-PDF fixtures and production engine configuration.",
      "Wire local LLM extraction router, strict schemas, confidence scoring, and metrics.",
      "Start PostgreSQL/RLS repository adapter and Redis worker adapter after parser/eval coverage is stable."
    ]
  }
];

export const testGates: TestGate[] = [
  {
    id: "gate-build",
    name: "Frontend build",
    status: "pass",
    command: "pnpm run build",
    lastResult: "TypeScript and Vite production build passed."
  },
  {
    id: "gate-python",
    name: "Backend compile",
    status: "pass",
    command: "python -m py_compile backend/app/*.py",
    lastResult: "FastAPI scaffold modules compile."
  },
  {
    id: "gate-api",
    name: "API health",
    status: "pass",
    command: "Invoke-RestMethod http://127.0.0.1:8000/health",
    lastResult: "Local API returns status ok."
  },
  {
    id: "gate-cors",
    name: "Frontend API access",
    status: "pass",
    command: "Invoke-WebRequest /auth/session with Origin http://127.0.0.1:5173",
    lastResult: "CORS allows the local web app origin."
  },
  {
    id: "gate-audit",
    name: "Audit visibility",
    status: "pass",
    command: "GET /audit-logs",
    lastResult: "Live audit endpoint returns workspace, upload, chat, and report events."
  },
  {
    id: "gate-upload",
    name: "Audited processing workflow",
    status: "pass",
    command: "pnpm run audit:phase",
    lastResult: "Audit gate uploads a ZIP package, verifies SHA-256 and size, runs worker:once, and verifies child files plus parsed chunks."
  },
  {
    id: "gate-parser",
    name: "Parser chunking",
    status: "pass",
    command: "GET /documents and /documents/{id}/chunks",
    lastResult: "Worker persists parsed document records and source chunks for text, CSV, XLSX, DOCX, EML, PyMuPDF-backed PDF files, and native PDF table rows inside ZIPs."
  },
  {
    id: "gate-source-lineage",
    name: "Source lineage",
    status: "pass",
    command: "pnpm run audit:source-lineage",
    lastResult: "Guard verifies CSV, Excel, Word, and email chunks carry typed locators with parser and extraction metadata."
  },
  {
    id: "gate-citation-format",
    name: "Citation format",
    status: "pass",
    command: "pnpm run audit:citation-format",
    lastResult: "Guard verifies chat citation labels render PDF pages, CSV rows, Excel sheets, Word sections, email subjects, text chunks, and source filenames."
  },
  {
    id: "gate-source-citations",
    name: "Source citation actions",
    status: "pass",
    command: "pnpm run audit:source-citations",
    lastResult: "Guard verifies chat citations can request signed source-file URLs and expose a visible source link/status."
  },
  {
    id: "gate-pdf-parser",
    name: "PDF text parser",
    status: "pass",
    command: "pnpm run audit:pdf-parser",
    lastResult: "Guard verifies two-page PDFs parse with PyMuPDF, native table rows become page/table/row citations, cited extraction uses the table row, and audit events stay sealed."
  },
  {
    id: "gate-ocr-routing",
    name: "OCR routing",
    status: "pass",
    command: "pnpm run audit:ocr-routing",
    lastResult: "Guard verifies image and scanned-PDF files create OCR route documents, file-level review tasks, and ocr.route audit events."
  },
  {
    id: "gate-ocr-extraction",
    name: "OCR extraction",
    status: "pass",
    command: "pnpm run audit:ocr-extraction",
    lastResult: "Guard verifies configured local OCR extracts scanned-PDF text into image-page chunks, feeds cited failure extraction, and audits ocr.extract_complete."
  },
  {
    id: "gate-zip",
    name: "ZIP package expansion",
    status: "pass",
    command: "pnpm run audit:phase",
    lastResult: "ZIP entries are sanitized, stored as child files, parsed when supported, and audited."
  },
  {
    id: "gate-archive-safety",
    name: "Archive safety",
    status: "pass",
    command: "pnpm run audit:archive-safety",
    lastResult: "Guard verifies ZIP entry/size limits reject unsafe packages, fail terminal uploads, and emit audit events."
  },
  {
    id: "gate-extraction",
    name: "Failure extraction",
    status: "pass",
    command: "pnpm run audit:phase",
    lastResult: "Worker extracts cited MWD signal-loss failures, NPT hours, company, and validation tasks from parsed chunks."
  },
  {
    id: "gate-report-export",
    name: "Report export",
    status: "pass",
    command: "pnpm run test:e2e",
    lastResult: "E2E validates an extracted failure, exports JSON/CSV/HTML/PDF/XLSX, inspects artifact signatures, and downloads deterministic signed export responses."
  },
  {
    id: "gate-report-export-idempotency",
    name: "Export idempotency",
    status: "pass",
    command: "pnpm run audit:report-export-idempotency",
    lastResult: "Repeated report exports reuse an existing verified artifact, audit reuse, and avoid duplicate export records."
  },
  {
    id: "gate-e2e",
    name: "Full E2E workflow",
    status: "pass",
    command: "pnpm run audit:all",
    lastResult: "Isolated workspace upload -> signed source download -> worker -> parse -> extract -> validate -> report -> signed export -> chat -> audit passed."
  },
  {
    id: "gate-source-downloads",
    name: "Signed source downloads",
    status: "pass",
    command: "pnpm run test:e2e",
    lastResult: "E2E downloads original and extracted source files through deterministic signed byte responses and verifies SHA-256."
  },
  {
    id: "gate-fixtures",
    name: "Production fixture expansion",
    status: "watch",
    command: "pnpm run audit:golden-fixtures",
    lastResult: "Guard verifies missing, synthetic, and partial manifests do not certify readiness; a complete anonymized manifest with actual files passes the fixture check."
  },
  {
    id: "gate-parser-fixture-evals",
    name: "Parser/OCR fixture evals",
    status: "watch",
    command: "pnpm run audit:parser-fixture-evals",
    lastResult: "Guard verifies missing/incomplete eval reports do not certify readiness and observed worker output can produce a passing 13-family parser/OCR eval report."
  },
  {
    id: "gate-parser-fixture-report",
    name: "Parser/OCR eval report generator",
    status: "watch",
    command: "pnpm run audit:parser-fixture-report",
    lastResult: "Guard verifies the manifest-backed report generator fails without configured OCR and writes a readiness-certifying report with configured OCR."
  },
  {
    id: "gate-anonymized-fixtures",
    name: "Anonymized fixture pack",
    status: "watch",
    command: "pnpm run fixtures:anonymized",
    lastResult: "Generates a 13-family anonymized engineering fixture pack and manifest for local client-readiness smoke tests."
  },
  {
    id: "gate-client-readiness",
    name: "Client data readiness",
    status: "watch",
    command: "pnpm run audit:client-data",
    lastResult: "Readiness endpoint reports demo/local scaffold blockers before real client packages are accepted."
  },
  {
    id: "gate-client-approval",
    name: "Client data approval",
    status: "watch",
    command: "pnpm run audit:client-approval",
    lastResult: "Approval command writes approved/blocked evidence from live readiness and fails closed until every real-client gate is passing."
  },
  {
    id: "gate-local-ai",
    name: "Local AI runtime status",
    status: "watch",
    command: "pnpm run audit:local-ai",
    lastResult: "Runtime endpoint reports disabled, Gemma 4 E2B configured-offline, pinned model availability, and hosted fallback posture."
  },
  {
    id: "gate-partner-package",
    name: "Partner preview package",
    status: "watch",
    command: "pnpm run audit:partner-package",
    lastResult: "Guard verifies the single-file partner preview ZIP contains the app, API, worker loop, sample import package, Gemma 4 E2B defaults, and import/export smoke launcher."
  },
  {
    id: "gate-partner-approval",
    name: "Partner preview approval",
    status: "watch",
    command: "pnpm run audit:partner-approval",
    lastResult: "Guard verifies package approval criteria and records approval scope as partner demo/testing with synthetic data only."
  },
  {
    id: "gate-client-ops",
    name: "Client operation guard",
    status: "pass",
    command: "pnpm run audit:client-ops",
    lastResult: "Unsafe client mode blocks chat, document reads, report creation, and exports with audited 423 responses."
  },
  {
    id: "gate-infra-readiness",
    name: "Infrastructure readiness",
    status: "pass",
    command: "pnpm run audit:infra-readiness",
    lastResult: "Guard verifies placeholder PostgreSQL/Redis URLs do not make client mode ready while local_json and inline_worker remain active."
  },
  {
    id: "gate-runtime-backends",
    name: "Runtime backends",
    status: "pass",
    command: "pnpm run audit:runtime-backends",
    lastResult: "Guard verifies requested PostgreSQL/Redis settings are shown separately from active local_json and inline_worker adapters."
  },
  {
    id: "gate-api-auth",
    name: "Client API auth",
    status: "pass",
    command: "pnpm run audit:auth",
    lastResult: "Client mode fails closed without an API key, rejects bad keys, accepts a valid key, and audits failures."
  },
  {
    id: "gate-audit-integrity",
    name: "Audit integrity",
    status: "pass",
    command: "pnpm run audit:integrity",
    lastResult: "Fresh ledgers are hash-chain sealed, and tampered audit metadata is detected as broken."
  },
  {
    id: "gate-audit-redaction",
    name: "Audit redaction",
    status: "pass",
    command: "pnpm run audit:redaction",
    lastResult: "Sensitive prompts, filenames, paths, tokens, emails, and names are fingerprinted before audit sealing."
  },
  {
    id: "gate-retention",
    name: "Retention policy",
    status: "pass",
    command: "pnpm run audit:retention",
    lastResult: "Dry-run reports expired artifacts; apply removes only expired data records and managed files while preserving fresh uploads."
  },
  {
    id: "gate-upload-limits",
    name: "Upload size limits",
    status: "pass",
    command: "pnpm run audit:upload-limits",
    lastResult: "Oversized metadata and direct uploads return HTTP 413 and emit upload.rejected audit events."
  },
  {
    id: "gate-upload-ownership",
    name: "Upload ownership",
    status: "pass",
    command: "pnpm run audit:upload-ownership",
    lastResult: "Cross-upload completion is rejected, audited, and creates no processing job under the wrong upload."
  },
  {
    id: "gate-upload-idempotency",
    name: "Upload idempotency",
    status: "pass",
    command: "pnpm run audit:upload-idempotency",
    lastResult: "Repeated upload completion reuses existing jobs, audits duplicate file IDs, and preserves completed status."
  },
  {
    id: "gate-client-bootstrap",
    name: "Clean client bootstrap",
    status: "pass",
    command: "pnpm run audit:bootstrap",
    lastResult: "Smoke test creates a fresh client tenant/user/workspace with demo seed disabled."
  },
  {
    id: "gate-state-persistence",
    name: "State persistence",
    status: "pass",
    command: "pnpm run audit:state-persistence",
    lastResult: "Guard verifies local JSON state stays parseable after repeated saves, recovers transient partial reads, and leaves no temp files."
  },
  {
    id: "gate-malware",
    name: "Malware blocking",
    status: "pass",
    command: "pnpm run audit:malware",
    lastResult: "Guard verifies explicit scanner readiness, direct malware rejection, ZIP child blocking, and audited malware events."
  },
  {
    id: "gate-storage-paths",
    name: "Storage path safety",
    status: "pass",
    command: "pnpm run audit:storage-paths",
    lastResult: "Guard verifies metadata/direct upload names and ZIP entries remain under tenant storage; metadata-only completion fails closed until bytes exist."
  }
];

export const auditEvents: AuditEvent[] = [
  {
    id: "audit-001",
    event: "Spec accepted",
    scope: "docs",
    result: "PRD, implementation spec, schema, API, prompt pack, and test plan created.",
    timestamp: "2026-07-07"
  },
  {
    id: "audit-002",
    event: "Frontend verified",
    scope: "app",
    result: "Chat-first UI builds and local API fallback is available.",
    timestamp: "2026-07-07"
  },
  {
    id: "audit-003",
    event: "Backend scaffold verified",
    scope: "api",
    result: "Health, session, dashboard, chat, upload, and report endpoints tested.",
    timestamp: "2026-07-07"
  }
];

export function getTrackerSummary(): { complete: number; active: number; pending: number; blocked: number } {
  return {
    complete: projectPhases.filter((phase) => phase.status === "complete").length,
    active: projectPhases.filter((phase) => phase.status === "in_progress").length,
    pending: projectPhases.filter((phase) => phase.status === "pending").length,
    blocked: projectPhases.filter((phase) => phase.status === "blocked").length
  };
}
