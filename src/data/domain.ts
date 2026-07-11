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

export const sampleFailures: FailureEvent[] = [
  {
    id: "ev-1001",
    eventType: "MWD failure",
    eventDate: "2026-02-14",
    well: "Well-A12",
    rig: "Rig-07",
    section: "12.25 in intermediate",
    holeSizeIn: 12.25,
    depthMdFt: 10342,
    formation: "Hartha",
    company: "ABC Directional Services",
    toolType: "MWD",
    toolName: "PulsePro X",
    toolSerial: "MWD-77821",
    summary: "MWD telemetry was lost while drilling; BHA was pulled to replace the tool.",
    rootCause: "Probable pulser electronics failure after shock events.",
    recommendation: "Review shock sub placement, battery lot, and pulser maintenance records before next run.",
    nptHours: 8.5,
    costImpactUsd: 255000,
    severity: "High",
    confidence: 0.84,
    validationStatus: "needs_review",
    citations: [
      {
        id: "cit-1001",
        file: "DDR_2026-02-14.pdf",
        page: 3,
        snippet: "Lost MWD signal at 10,342 ft MD. POOH to replace MWD tool."
      }
    ]
  },
  {
    id: "ev-1002",
    eventType: "Mud motor failure",
    eventDate: "2026-03-02",
    well: "Well-A12",
    rig: "Rig-07",
    section: "8.5 in production",
    holeSizeIn: 8.5,
    depthMdFt: 14220,
    formation: "Zubair",
    company: "Gulf Motor Rentals",
    toolType: "Mud motor",
    toolName: "7 in high-torque motor",
    toolSerial: "MTR-4410",
    summary: "Motor differential dropped and high vibration was observed before pulling out.",
    rootCause: "Likely stator elastomer damage aggravated by high temperature and solids.",
    recommendation: "Use high-temperature elastomer and tighten solids-control checks.",
    nptHours: 13.25,
    costImpactUsd: 397500,
    severity: "High",
    confidence: 0.89,
    validationStatus: "validated",
    citations: [
      {
        id: "cit-1002",
        file: "Motor_Run_07.xlsx",
        sheet: "Run Summary",
        row: 18,
        snippet: "Differential pressure unstable; motor pulled due to suspected stator failure."
      }
    ]
  },
  {
    id: "ev-1003",
    eventType: "Stuck pipe",
    eventDate: "2026-03-18",
    well: "Well-B04",
    rig: "Rig-12",
    section: "12.25 in intermediate",
    holeSizeIn: 12.25,
    depthMdFt: 11810,
    formation: "Nahr Umr",
    company: "Desert Drilling Co.",
    toolType: "BHA",
    toolName: "Rotary BHA",
    toolSerial: "BHA-B04-03",
    summary: "String became stuck while reaming down; jars fired and circulation restored.",
    rootCause: "Pack-off from poor hole cleaning while reaming after high ROP interval.",
    recommendation: "Increase high-vis sweeps and monitor cuttings loading before reaming trips.",
    nptHours: 18,
    costImpactUsd: 540000,
    severity: "Critical",
    confidence: 0.92,
    validationStatus: "validated",
    citations: [
      {
        id: "cit-1003",
        file: "DDR_Rig12_2026-03-18.docx",
        page: 5,
        snippet: "Stuck pipe at 11,810 ft MD; pack-off suspected from cuttings accumulation."
      }
    ]
  },
  {
    id: "ev-1004",
    eventType: "Lost circulation",
    eventDate: "2026-04-06",
    well: "Well-C31",
    rig: "Rig-03",
    section: "17.5 in surface",
    holeSizeIn: 17.5,
    depthMdFt: 5230,
    formation: "Dammam",
    company: "North Fluids",
    toolType: "Mud system",
    toolName: "LCM pill",
    toolSerial: "MUD-NA",
    summary: "Partial losses escalated to severe losses while drilling weak carbonate.",
    rootCause: "Fractured/weak interval combined with elevated ECD.",
    recommendation: "Reduce ECD, prepare staged LCM, and update offset loss risk map.",
    nptHours: 6.75,
    costImpactUsd: 202500,
    severity: "High",
    confidence: 0.79,
    validationStatus: "needs_review",
    citations: [
      {
        id: "cit-1004",
        file: "Mud_Report_C31_0406.pdf",
        page: 2,
        snippet: "Loss rate increased after pump-up; 80 bbl LCM pill mixed."
      }
    ]
  },
  {
    id: "ev-1005",
    eventType: "Bit failure",
    eventDate: "2026-04-20",
    well: "Well-A12",
    rig: "Rig-07",
    section: "8.5 in production",
    holeSizeIn: 8.5,
    depthMdFt: 15190,
    formation: "Zubair",
    company: "Helix Bits",
    toolType: "Bit",
    toolName: "8.5 in PDC HXR516",
    toolSerial: "BIT-8834",
    summary: "ROP collapsed and bit dull grade showed broken cutters after pull.",
    rootCause: "Torsional vibration and abrasive streak caused cutter damage.",
    recommendation: "Revise bit selection and add stick-slip mitigation parameters.",
    nptHours: 4,
    costImpactUsd: 120000,
    severity: "Medium",
    confidence: 0.87,
    validationStatus: "validated",
    citations: [
      {
        id: "cit-1005",
        file: "Bit_Record_A12.xlsx",
        sheet: "Dull Grade",
        row: 11,
        snippet: "Broken cutters noted; severe stick-slip recorded before pull."
      }
    ]
  },
  {
    id: "ev-1006",
    eventType: "Waiting on service company",
    eventDate: "2026-05-01",
    well: "Well-D09",
    rig: "Rig-11",
    section: "6 in lateral",
    holeSizeIn: 6,
    depthMdFt: 17140,
    formation: "Arab-D",
    company: "ABC Directional Services",
    toolType: "RSS",
    toolName: "SteerForce 675",
    toolSerial: "RSS-2265",
    summary: "Replacement RSS arrived late after toolface control issue.",
    rootCause: "Spare tool logistics and customs clearance delay.",
    recommendation: "Pre-position critical RSS/MWD spares for lateral sections.",
    nptHours: 9,
    costImpactUsd: 270000,
    severity: "Medium",
    confidence: 0.73,
    validationStatus: "needs_review",
    citations: [
      {
        id: "cit-1006",
        file: "Email_thread_RSS_delay.eml",
        snippet: "Replacement RSS will arrive on night transport; rig waiting on service company."
      }
    ]
  },
  {
    id: "ev-1007",
    eventType: "MWD failure",
    eventDate: "2026-05-22",
    well: "Well-D09",
    rig: "Rig-11",
    section: "6 in lateral",
    holeSizeIn: 6,
    depthMdFt: 18340,
    formation: "Arab-D",
    company: "ABC Directional Services",
    toolType: "MWD",
    toolName: "PulsePro X",
    toolSerial: "MWD-77821",
    summary: "Repeat MWD signal instability occurred on the same serial number.",
    rootCause: "Repeat electronics/connector issue suspected; source reports disagree on battery condition.",
    recommendation: "Quarantine serial MWD-77821 until teardown report is reviewed.",
    nptHours: 5.5,
    costImpactUsd: 165000,
    severity: "High",
    confidence: 0.68,
    validationStatus: "conflict",
    citations: [
      {
        id: "cit-1007",
        file: "MWD_LWD_Daily_D09.pdf",
        page: 7,
        snippet: "MWD signal intermittent; same serial observed from previous failure history."
      }
    ]
  }
];
