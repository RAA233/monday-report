export type Severity = "Low" | "Medium" | "High" | "Critical";

export type ValidationStatus =
  | "validated"
  | "needs_review"
  | "conflict"
  | "rejected";

export type ReportFamily =
  | "Daily drilling report"
  | "BHA report"
  | "Bit record"
  | "Mud report"
  | "Directional report"
  | "MWD/LWD report"
  | "Motor report"
  | "Fishing report"
  | "Cementing report"
  | "Casing report"
  | "Completion report"
  | "NPT report"
  | "Lessons learned"
  | "Text report"
  | "Email"
  | "Image/OCR"
  | "Archive"
  | "Unknown";

export interface Citation {
  id: string;
  file: string;
  page?: number;
  sheet?: string;
  row?: number;
  snippet: string;
}

export interface FailureEvent {
  id: string;
  eventType: string;
  eventDate: string;
  well: string;
  rig: string;
  section: string;
  holeSizeIn: number;
  depthMdFt: number;
  formation: string;
  company: string;
  toolType: string;
  toolName: string;
  toolSerial: string;
  summary: string;
  rootCause: string;
  recommendation: string;
  nptHours: number;
  costImpactUsd: number;
  severity: Severity;
  confidence: number;
  validationStatus: ValidationStatus;
  citations: Citation[];
}

export interface UploadInventoryItem {
  id: string;
  name: string;
  relativePath: string;
  size: number;
  extension: string;
  reportFamily: ReportFamily;
  status: "queued" | "parsed" | "duplicate" | "needs_ocr" | "unsupported";
  warning?: string;
}

export interface PipelineStage {
  id: string;
  label: string;
  description: string;
  deterministic: boolean;
}

export interface FilterState {
  query: string;
  dateRange: "all" | "30d" | "90d" | "6m";
  company: string;
  toolType: string;
  severity: string;
  validationStatus: string;
}

export interface TaxonomyItem {
  eventType: string;
  keywords: string[];
  causes: string[];
  relatedTools: string[];
  severity: Severity;
}

export const defaultFilters: FilterState = {
  query: "",
  dateRange: "all",
  company: "All companies",
  toolType: "All tools",
  severity: "All severities",
  validationStatus: "All validation"
};

export const pipelineStages: PipelineStage[] = [
  {
    id: "scan",
    label: "Scan",
    description: "Create batch, malware-check files, hash content, and preserve folder lineage.",
    deterministic: true
  },
  {
    id: "parse",
    label: "Parse",
    description: "Extract text, sheets, rows, metadata, tables, email bodies, and image pages.",
    deterministic: true
  },
  {
    id: "classify",
    label: "Classify",
    description: "Local AI identifies DDR, BHA, MWD/LWD, motor, NPT, EOWR, and service-company reports.",
    deterministic: false
  },
  {
    id: "extract",
    label: "Extract",
    description: "Local AI extracts companies, tools, failures, NPT, sections, depths, root causes, and actions.",
    deterministic: false
  },
  {
    id: "validate",
    label: "Validate",
    description: "Route high-severity, ambiguous, conflicting, or low-confidence records to review.",
    deterministic: false
  },
  {
    id: "index",
    label: "Index",
    description: "Write structured facts, citations, search text, embeddings, and dashboard metrics.",
    deterministic: true
  }
];

export const taxonomy: TaxonomyItem[] = [
  {
    eventType: "MWD failure",
    keywords: ["mwd failed", "no pulse", "toolface lost", "survey missed", "lost signal"],
    causes: ["electronics", "battery", "pulser", "telemetry", "shock"],
    relatedTools: ["MWD probe", "pulser", "battery module"],
    severity: "High"
  },
  {
    eventType: "Mud motor failure",
    keywords: ["motor failure", "stalled", "chunking", "no differential", "stator"],
    causes: ["temperature", "solids", "overload", "parameter abuse"],
    relatedTools: ["mud motor", "stator", "rotor"],
    severity: "High"
  },
  {
    eventType: "Stuck pipe",
    keywords: ["stuck", "overpull", "no rotation", "pack off", "differential sticking"],
    causes: ["cuttings bed", "filter cake", "key seat", "high overbalance"],
    relatedTools: ["drill pipe", "BHA", "jar"],
    severity: "Critical"
  },
  {
    eventType: "Lost circulation",
    keywords: ["losses", "lost returns", "total losses", "LCM", "seepage"],
    causes: ["fractures", "depletion", "high ECD", "weak formation"],
    relatedTools: ["mud system", "pumps", "LCM pill"],
    severity: "High"
  },
  {
    eventType: "Bit failure",
    keywords: ["dull", "lost cone", "bit balled", "low ROP", "broken cutter"],
    causes: ["abrasive formation", "vibration", "poor hydraulics", "bit selection"],
    relatedTools: ["PDC bit", "roller cone bit"],
    severity: "Medium"
  },
  {
    eventType: "Waiting on service company",
    keywords: ["WOSC", "wait on directional", "wait on MWD", "crew delayed"],
    causes: ["logistics", "personnel", "spares", "planning"],
    relatedTools: ["service crew", "replacement tools"],
    severity: "Medium"
  }
];
