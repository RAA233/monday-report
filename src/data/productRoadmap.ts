export type RoadmapStatus = "complete" | "active" | "queued" | "watch";
export type RoadmapTone = "good" | "info" | "warning" | "danger" | "neutral";

export interface CapabilitySignal {
  id: string;
  label: string;
  value: string;
  detail: string;
  tone: RoadmapTone;
}

export interface RoadmapItem {
  id: string;
  title: string;
  owner: string;
  status: RoadmapStatus;
  gate: string;
  evidence: string;
  next: string;
}

export interface RoadmapLane {
  id: string;
  label: string;
  intent: string;
  status: RoadmapStatus;
  items: RoadmapItem[];
}

export interface RoadmapExecutionCard {
  id: string;
  label: string;
  value: string;
  detail: string;
  command: string;
  tone: RoadmapTone;
}

export interface ReleaseGate {
  id: string;
  label: string;
  status: RoadmapStatus;
  command: string;
  evidence: string;
}

export interface RoadmapRisk {
  id: string;
  risk: string;
  owner: string;
  control: string;
  severity: "low" | "medium" | "high";
}

export const capabilitySignals: CapabilitySignal[] = [
  {
    id: "signal-client-landing",
    label: "Client command",
    value: "rig/MR list",
    detail: "Client Home opens to real rig workspaces, Monday Report access, and import/export coverage.",
    tone: "good"
  },
  {
    id: "signal-report-intelligence",
    label: "Report intelligence",
    value: "MR-SCHEMA-1",
    detail: "Reviewed DDR, BHA, mud, survey, and directional schema variants now drive Studio targets.",
    tone: "good"
  },
  {
    id: "signal-local-ai",
    label: "Local AI default",
    value: "gemma4:e2b",
    detail: "Ollama runtime is the default posture with hosted fallback disabled for client mode.",
    tone: "good"
  },
  {
    id: "signal-client-data",
    label: "Client data gate",
    value: "approved",
    detail: "Client-mode readiness requires PostgreSQL, Redis, protected storage, signing, OCR, and audit evidence.",
    tone: "good"
  },
  {
    id: "signal-roadmap",
    label: "Roadmap proof",
    value: "execution board",
    detail: "Navigation, UI screenshots, tracker gate, execution board, and audit wiring are checked by audit:roadmap.",
    tone: "info"
  }
];

export const roadmapExecutionBoard: RoadmapExecutionCard[] = [
  {
    id: "exec-current-slice",
    label: "Current slice",
    value: "schema variants",
    detail: "MR-SCHEMA-1 promotes DDR, BHA, mud, survey, and directional formats into guarded extraction and drafting targets.",
    command: "pnpm run audit:report-variants",
    tone: "good"
  },
  {
    id: "exec-next-pull",
    label: "Next audited pull",
    value: "Phase 06 router",
    detail: "Casing schematic extraction, timeline, survey stations, trajectory visuals, hydraulics observations, and the promoted FORGE evaluation (65/65 required on the real corpus after general D1-D4 parser fixes) are complete; the Phase 06 local LLM extraction router is the next pull on the same reviewed pipeline.",
    command: "pnpm run audit:forge-evals",
    tone: "warning"
  },
  {
    id: "exec-ga-proof",
    label: "GA proof",
    value: "GA_BLOCKED",
    detail: "The truthful registry-backed GA gate reports GA_BLOCKED with non-zero blockers across software, security, infrastructure, configuration, and client approval; PostgreSQL+Redis provisioning alone cannot yield GA_READY.",
    command: "pnpm run ga:readiness",
    tone: "warning"
  },
  {
    id: "exec-package",
    label: "Package",
    value: "partner approved",
    detail: "Partner ZIP and approval ledger remain separate from client-data approval evidence.",
    command: "pnpm run package:partner-approval",
    tone: "good"
  }
];

export const roadmapLanes: RoadmapLane[] = [
  {
    id: "lane-now",
    label: "Now",
    intent: "Stabilize the high-end MVP around chat, report authoring, and auditable client-data readiness.",
    status: "active",
    items: [
      {
        id: "item-client-landing",
        title: "Client landing command surface",
        owner: "Frontend + product",
        status: "complete",
        gate: "test:ui",
        evidence: "Client Home exposes live rig workspaces, MR list access, import coverage, export formats, and roadmap command actions.",
        next: "Connect rig rows to workspace-specific dashboards and report creation filters."
      },
      {
        id: "item-chat-command-center",
        title: "Chat command center",
        owner: "Frontend + AI",
        status: "complete",
        gate: "audit:chat-workflow",
        evidence: "Workflow steps, insight cards, risk register, tool actions, citations, and export actions render in chat.",
        next: "Connect report-draft actions to parsed client evidence with stricter schema outputs."
      },
      {
        id: "item-report-studio",
        title: "Advanced report studio",
        owner: "Frontend + drilling SME",
        status: "complete",
        gate: "audit:report-variants",
        evidence: "MR-SCHEMA-1 targets drive drafting; casing, timeline, survey stations, and hydraulics observations extract with provenance and explicit units, minimum-curvature geometry is review-gated, both trajectory visuals render segment-aware paths, and an auditable versioned field-level correction foundation (registry-gated, in-process-serialized, configured-actor context) records corrections without overwriting source lineage.",
        next: "The authenticated-identity foundation (per-user credentials, request-scoped actor, default-deny RBAC, admin provisioning/revocation, configured-tenant boundary) is delivered; close the remaining declared blockers — full tenant/workspace authorization, complete route-level RBAC, verified per-user reviewer identity, keyed audit integrity, and cross-process atomicity — then build the Phase 06 local-AI extraction router and apply reviewed corrections into official JSON/formatted export provenance."
      },
      {
        id: "item-ui-execution-board",
        title: "High-end UX execution board",
        owner: "Frontend + product",
        status: "complete",
        gate: "audit:roadmap",
        evidence: "Roadmap execution board exposes the current slice, next audited pull, GA proof, and package posture.",
        next: "Keep UI screenshots and tracker evidence refreshed after each visible product slice."
      }
    ]
  },
  {
    id: "lane-next",
    label: "Next",
    intent: "Turn the locally held Utah FORGE daily-report corpus into repeatable extraction and drafting proof.",
    status: "queued",
    items: [
      {
        id: "item-forge-evals",
        title: "FORGE corpus evals",
        owner: "AI/data",
        status: "complete",
        gate: "audit:forge-evals",
        evidence: "Reviewed manifest and expectations pin five SHA-256 documents; after general D1-D4 parser fixes the unchanged ground truth passes 65/65 required checks on the real upload, worker, and draft path, and the portable parser-regression guard pins the defect classes in audit:all.",
        next: "Feed the promoted evaluation set into the Phase 06 local-AI extraction router as its reviewed acceptance target."
      },
      {
        id: "item-citation-drafts",
        title: "Citation-backed AI drafts",
        owner: "AI/data + backend",
        status: "queued",
        gate: "audit:source-lineage",
        evidence: "Parser chunks carry typed locators for PDFs, office files, email, tables, and OCR pages.",
        next: "Require every AI-generated morning report claim to map back to source locators."
      }
    ]
  },
  {
    id: "lane-harden",
    label: "Harden",
    intent: "Remove fragile runtime paths and make every client operation reversible, traceable, and permissioned.",
    status: "active",
    items: [
      {
        id: "item-normalized-storage",
        title: "Normalized Postgres repositories",
        owner: "Backend",
        status: "watch",
        gate: "audit:runtime-backends",
        evidence: "Client mode uses PostgreSQL/RLS snapshot state and Redis queue with readiness checks.",
        next: "Move failures, documents, validation tasks, report artifacts, and audit events into normalized tables."
      },
      {
        id: "item-security-controls",
        title: "Security controls",
        owner: "Security + QA",
        status: "active",
        gate: "audit:all",
        evidence: "Signed URLs, API auth, redaction, malware baseline, retention, storage paths, and archive safety pass.",
        next: "Add external malware scanner adapter and admin evidence viewer before broad client pilots."
      }
    ]
  },
  {
    id: "lane-package",
    label: "Package",
    intent: "Prepare partner and client pilots with one-command launch, import, export, and approval evidence.",
    status: "queued",
    items: [
      {
        id: "item-partner-installer",
        title: "Partner preview installer",
        owner: "Release engineering",
        status: "complete",
        gate: "audit:partner-package",
        evidence: "Preview ZIP carries app, API, worker loop, Gemma 4 E2B defaults, sample import, and smoke launcher.",
        next: "Convert preview ZIP into a signed installer when external code-signing materials are available."
      },
      {
        id: "item-import-export",
        title: "Import and export hardening",
        owner: "Frontend + backend",
        status: "active",
        gate: "test:e2e",
        evidence: "Upload, parse, validate, JSON/CSV/HTML/PDF/XLSX export, signed downloads, and idempotency pass.",
        next: "Add report-template diff checks against reviewed daily-report references."
      }
    ]
  },
  {
    id: "lane-pilot",
    label: "Client Pilot",
    intent: "Move from local approval to controlled client evidence pilots with full audit and rollback posture.",
    status: "queued",
    items: [
      {
        id: "item-client-dry-run",
        title: "Controlled client dry run",
        owner: "QA + product",
        status: "queued",
        gate: "ga:readiness",
        evidence: "The registry-backed GA gate reports GA_BLOCKED with truthful non-zero blockers; a client dry run is gated until the registered software/security/governance blockers are resolved.",
        next: "Resolve the registry-backed GA blockers in separate PRs, then run a timed client package pilot using approved env and sanitized acceptance data."
      },
      {
        id: "item-approval-ledger",
        title: "Approval ledger",
        owner: "Security + product",
        status: "queued",
        gate: "package:client-approval",
        evidence: "Client approval JSON records readiness checks and approval scope.",
        next: "Add signer identity, dataset scope, and client acceptance notes to the dispatch package."
      }
    ]
  }
];

export const releaseGates: ReleaseGate[] = [
  {
    id: "gate-design",
    label: "Design",
    status: "complete",
    command: "test:ui",
    evidence: "Screenshots cover Client Home, chat, studio, upload, dashboard, explorer, validation, tracker, roadmap, and architecture."
  },
  {
    id: "gate-build",
    label: "Build",
    status: "complete",
    command: "build",
    evidence: "TypeScript and Vite production build pass."
  },
  {
    id: "gate-audit",
    label: "Audit",
    status: "active",
    command: "audit:all",
    evidence: "Full local audit chain covers API, parser, reports, security, readiness, and package approval."
  },
  {
    id: "gate-package",
    label: "Package",
    status: "active",
    command: "package:partner-preview",
    evidence: "Single ZIP package remains the current partner testing artifact."
  },
  {
    id: "gate-pilot",
    label: "Pilot",
    status: "queued",
    command: "package:client-approval",
    evidence: "Client pilot starts only after approved env, readiness JSON, and acceptance scope are attached."
  }
];

export const roadmapRisks: RoadmapRisk[] = [
  {
    id: "risk-schema-drift",
    risk: "Daily-report formats drift across contractors and wells.",
    owner: "Drilling SME",
    control: "Versioned MR-SCHEMA-1 schema variants and reference-format evals.",
    severity: "medium"
  },
  {
    id: "risk-ai-claim-source",
    risk: "AI draft text could overstate claims without a source locator.",
    owner: "AI/data",
    control: "Citation-required draft generation and validation-blocked exports.",
    severity: "high"
  },
  {
    id: "risk-client-package",
    risk: "Partner package can be confused with client-approved production dispatch.",
    owner: "Release engineering",
    control: "Separate partner preview and client approval ledgers with visible scope labels.",
    severity: "medium"
  }
];
