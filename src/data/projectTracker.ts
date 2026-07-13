import type { LucideIcon } from "lucide-react";
import {
  Bot,
  CheckCircle2,
  ClipboardList,
  Database,
  FileText,
  FileSearch,
  Gauge,
  HardHat,
  LockKeyhole,
  Milestone,
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
    objective: "Keep Local AI Chat as the primary analysis surface with citations and fallback behavior.",
    evidence: "Client Home opens first and routes directly into Local AI Chat, Report Studio, upload, validation, dashboard, and roadmap surfaces.",
    nextAction: "Keep chat actions aligned with official report creation and export workflows.",
    icon: Bot
  },
  {
    id: "phase-02",
    name: "FastAPI scaffold",
    status: "complete",
    owner: "Backend",
    objective: "Provide tenant, workspace, upload, chat, dashboard, report, and audit API boundaries.",
    evidence: "Health, session, dashboard, chat, batched direct upload, and Monday Report endpoints respond locally.",
    nextAction: "Replace snapshot persistence with normalized PostgreSQL repositories.",
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
    evidence: "Client approval environment activates PostgreSQL-backed tenant state with RLS plus Redis-backed processing queue; local JSON remains the demo default.",
    nextAction: "Expand the PostgreSQL adapter from state snapshot storage into normalized table repositories.",
    icon: Database
  },
  {
    id: "phase-05",
    name: "Parser and OCR pipeline",
    status: "complete",
    owner: "AI/data",
    objective: "Parse ZIP, PDF, Excel, Word, CSV, email, images, and scanned pages with source lineage.",
    evidence: "Worker parses text, CSV, XLSX, DOCX, EML, PyMuPDF PDF text, native PDF rows, pdf_report_profile_v1 fields/sections, and configured OCR output into typed locators; reviewed 13-family fixture manifest and parser/OCR eval report pass.",
    nextAction: "Maintain reviewed fixture/eval evidence as parser families evolve.",
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
    status: "complete",
    owner: "Security + backend + QA",
    objective: "Prevent real client data from entering unsafe demo/local-scaffold environments.",
    evidence: "Live client-mode readiness is approved with PostgreSQL/RLS, Redis queue, API key, signing secret, protected storage paths, retention policy, builtin malware scanner, parser/OCR evals, reviewed fixture attestation, and local Gemma runtime.",
    nextAction: "Run controlled client-package dry runs and keep approval evidence current.",
    icon: LockKeyhole
  },
  {
    id: "phase-09",
    name: "Morning report studio",
    status: "in_progress",
    owner: "Frontend + drilling SME",
    objective: "Turn real daily drilling report patterns into a branded authoring and preview workflow.",
    evidence: "Chat renders command-center workflow steps; Report Studio has DDR/BHA/mud/survey format variants, issue-readiness board, technical telemetry, casing/well schematics, AI plan/execute checks, and guarded source-backed draft generation.",
    nextAction: "Promote visible normal-format variants and stronger schematic extraction into reviewed parser/drafting fixtures.",
    icon: FileText
  },
  {
    id: "phase-10",
    name: "Roadmap cockpit",
    status: "complete",
    owner: "Product + QA",
    objective: "Expose the Monday Report delivery path from current MVP hardening through package, pilot, and client-data approval.",
    evidence: "Product Roadmap view, execution board, typed roadmap data, UI screenshot coverage, tracker gate, and audit:roadmap guard are wired.",
    nextAction: "Use the roadmap lanes to pull the next client-pilot hardening slice.",
    icon: Milestone
  },
  {
    id: "phase-11",
    name: "Client landing and rig MR access",
    status: "complete",
    owner: "Frontend + product",
    objective: "Make the first screen a client command surface for rigs, Monday Reports, import coverage, export coverage, and roadmap actions.",
    evidence: "Client Home renders live API workspaces, MR list records, open review counts, supported import families, and JSON/CSV/HTML/PDF/XLSX export formats.",
    nextAction: "Add workspace-specific drilldowns and preserve screenshot coverage after each UI polish slice.",
    icon: HardHat
  }
];

export const clearTrackerLanes: TrackerLane[] = [
  {
    id: "accepted-now",
    title: "Accepted Now",
    status: "pass",
    summary: "Executable local MVP path is working and phase-gated for synthetic/demo data.",
    items: [
      "Client Home opens first with real API workspaces, rig/MR list access, import coverage, export coverage, and roadmap command actions.",
      "Chat-first UI with API fallback, structured workflow steps, insight cards, risk register, command actions, citations, and source-backed answers.",
      "Direct and ZIP uploads with hashing, malware baseline checks, safe storage paths, signed downloads, and batched clean-path persistence.",
      "Parser worker covers text, CSV, XLSX, DOCX, EML, PyMuPDF-backed PDF text, native PDF table rows, pdf_report_profile_v1 DDR fields/sections, OCR routing/extraction, typed locators, manifest-driven parser/OCR eval reports, and source citation actions.",
      "Partner preview ZIP includes the built app, API, worker loop, Gemma 4 E2B defaults, sample import package, and import/export smoke script.",
      "Validation-gated Monday Report exports JSON, CSV, HTML, PDF, and XLSX with signed artifact downloads.",
      "Report Studio provides a technical morning-report console with DDR/BHA/mud/survey variants, issue-readiness board, readiness telemetry, source-backed draft generation, casing/well schematic, AI plan/execute checks, timeline, and draft export.",
      "Roadmap cockpit maps current build, next corpus/eval work, hardening, package, client pilot lanes, release gates, risk controls, and next controlled moves.",
      "Official exports include GA-style metrics, validation posture, source coverage, standard daily-report sections, casing rows, well schematic, AI execution plan, timeline, branded HTML/PDF output, and expanded XLSX sections.",
      "GA readiness guard separates software-owned checks from configuration, infrastructure, and reviewed-evidence blockers.",
      "`audit:all` is the accepted local proof gate after every slice."
    ]
  },
  {
    id: "safe-operating-mode",
    title: "Safe Operating Mode",
    status: "pass",
    summary: "Client-mode approval is available when the generated GA env, Docker services, and reviewed fixture evidence are loaded.",
    items: [
      "Demo mode still uses durable local JSON under `.local_data/`.",
      "Approved client mode uses PostgreSQL state, Redis queue, protected local storage roots, API key, and signing secret.",
      "Client mode blocks unsafe reads, chat, reports, exports, and source downloads until readiness passes.",
      "The live approval endpoint currently reports ready when the generated client env is active."
    ]
  },
  {
    id: "real-client-blockers",
    title: "Real-Client Approval",
    status: "pass",
    summary: "The local client-approval environment is green with zero readiness blockers.",
    items: [
      "PostgreSQL/RLS state snapshot adapter is active.",
      "Redis-backed processing queue is active.",
      "Reviewed anonymized fixture attestation and 13-family parser/OCR eval report pass.",
      "Local Ollama `gemma4:e2b` is reachable and hosted fallback remains disabled.",
      "Client approval JSON reports `APPROVED`."
    ]
  },
  {
    id: "next-execution-order",
    title: "Next Execution Order",
    status: "pending",
    summary: "The next high-value work should turn approved local readiness into repeatable client-package pilots.",
    items: [
      "Run controlled client-package dry runs with the approved client-mode environment.",
      "Promote the visible DDR/BHA/mud/survey report variants into reviewed extraction and drafting tests.",
      "Promote the local FORGE open-source daily-report corpus into reviewed extraction evals without committing raw ignored PDFs.",
      "Pull roadmap lane items in order: normal-format schema variants, stronger schematic extraction, normalized persistence, then controlled client pilot.",
      "Wire local LLM extraction router, strict schemas, confidence scoring, and metrics.",
      "Expand PostgreSQL from snapshot state into normalized table repositories.",
      "Harden production OCR command management and external malware scanner integration."
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
    id: "gate-ui-quality",
    name: "UI quality E2E",
    status: "pass",
    command: "pnpm run test:ui",
    lastResult: "Browser E2E verifies Client Home, rig/MR list access, import/export coverage, chat, Report Studio variants, issue readiness, upload, tracker, roadmap execution board, and screenshot capture."
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
    lastResult: "Worker persists parsed document records and source chunks for text, CSV, XLSX, DOCX, EML, PyMuPDF-backed PDF files, native PDF table rows, and PDF report profile fields/sections inside ZIPs."
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
    id: "gate-chat-workflow",
    name: "Chat workflow contract",
    status: "pass",
    command: "pnpm run audit:chat-workflow",
    lastResult: "Guard verifies structured chat answers include workflow steps, insight cards, risk register, tool actions, and report export actions."
  },
  {
    id: "gate-report-draft",
    name: "Source-backed report draft",
    status: "pass",
    command: "pnpm run audit:report-draft",
    lastResult: "Guard verifies parsed documents, chunks, citations, failures, validation tasks, PDF profile hints, and audit events produce form-ready Report Studio draft fields."
  },
  {
    id: "gate-roadmap",
    name: "Product roadmap",
    status: "pass",
    command: "pnpm run audit:roadmap",
    lastResult: "Guard verifies typed roadmap data, execution board markers, app navigation, UI E2E screenshot coverage, tracker gate, and audit:all wiring."
  },
  {
    id: "gate-text-sanitization",
    name: "Extractor text sanitization",
    status: "pass",
    command: "pnpm run audit:text-sanitization",
    lastResult: "Guard verifies extracted text, PDF table rows, and PostgreSQL JSON payloads are scrubbed of NUL/control characters."
  },
  {
    id: "gate-runtime-mock-data",
    name: "Runtime mock-data removal",
    status: "pass",
    command: "pnpm run audit:runtime-mock-data",
    lastResult: "Guard verifies runtime source starts from live API failures only and blocks reintroduced seeded sample records."
  },
  {
    id: "gate-pdf-parser",
    name: "PDF text parser",
    status: "pass",
    command: "pnpm run audit:pdf-parser",
    lastResult: "Guard verifies PyMuPDF DDR profiles extract report fields/sections, create cited chunks, prefill Report Studio, cite native table rows, and avoid treating casing depths as NPT hours."
  },
  {
    id: "gate-forge-corpus",
    name: "FORGE daily-report corpus",
    status: "pass",
    command: "pnpm run audit:forge-corpus",
    lastResult: "Guard inspects the local ignored 16A(78)-32_Daily_Reports folder, verifies drilling/completion report markers, and writes output/forge-corpus/forge_corpus_summary.json."
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
    id: "gate-report-template",
    name: "Report export template",
    status: "pass",
    command: "pnpm run audit:report-template",
    lastResult: "Guard verifies JSON/HTML/PDF/XLSX exports include GA-style metrics, standard daily-report sections, casing/well schematic, AI execution plan, timeline, and branded operations sections."
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
    status: "pass",
    command: "pnpm run audit:golden-fixtures",
    lastResult: "Guard verifies missing, synthetic, and partial manifests do not certify coverage; reviewed anonymized fixture attestation is present for client approval."
  },
  {
    id: "gate-parser-fixture-evals",
    name: "Parser/OCR fixture evals",
    status: "pass",
    command: "pnpm run audit:parser-fixture-evals",
    lastResult: "Guard verifies missing/incomplete eval reports do not certify readiness and observed worker output can produce a passing 13-family parser/OCR eval report."
  },
  {
    id: "gate-parser-fixture-report",
    name: "Parser/OCR eval report generator",
    status: "pass",
    command: "pnpm run audit:parser-fixture-report",
    lastResult: "Guard verifies the manifest-backed report generator fails without configured OCR and writes a readiness-certifying report with configured OCR."
  },
  {
    id: "gate-anonymized-fixtures",
    name: "Anonymized fixture pack",
    status: "pass",
    command: "pnpm run fixtures:anonymized",
    lastResult: "Generates a 13-family anonymized engineering fixture pack and manifest for local smoke tests only."
  },
  {
    id: "gate-client-readiness",
    name: "Client data readiness",
    status: "pass",
    command: "pnpm run audit:client-data",
    lastResult: "Live client-mode endpoint reports ready with PostgreSQL, Redis, security config, local AI, and reviewed fixture evidence."
  },
  {
    id: "gate-client-approval",
    name: "Client data approval",
    status: "pass",
    command: "pnpm run audit:client-approval",
    lastResult: "Approval command reports APPROVED from the live readiness endpoint."
  },
  {
    id: "gate-local-ai",
    name: "Local AI runtime status",
    status: "pass",
    command: "pnpm run audit:local-ai",
    lastResult: "Runtime endpoint reports disabled, Gemma 4 E2B configured-offline, pinned model availability, and hosted fallback posture."
  },
  {
    id: "gate-partner-package",
    name: "Partner preview package",
    status: "pass",
    command: "pnpm run audit:partner-package",
    lastResult: "Guard verifies the single-file partner preview ZIP contains the app, API, worker loop, sample import package, Gemma 4 E2B defaults, and import/export smoke launcher."
  },
  {
    id: "gate-partner-approval",
    name: "Partner preview approval",
    status: "pass",
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
    id: "gate-ga-readiness",
    name: "GA readiness classification",
    status: "pass",
    command: "pnpm run audit:ga-readiness",
    lastResult: "Strict GA readiness reports GA_READY with zero software, configuration, infrastructure, or evidence blockers."
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
    result: "Client Home, chat workflow, Report Studio variants, and Roadmap execution board build and pass browser E2E.",
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
