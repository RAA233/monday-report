import type {
  FailureEvent,
  FilterState,
  ReportFamily,
  Severity,
  UploadInventoryItem,
  ValidationStatus
} from "../data/domain";

export interface MetricsSummary {
  totalFailures: number;
  totalNptHours: number;
  costImpactUsd: number;
  criticalAndHigh: number;
  averageConfidence: number;
  validationBacklog: number;
  repeatedToolSerials: number;
}

export interface ChatAnswer {
  kind: "answer" | "clarification" | "unsupported" | "export";
  title: string;
  message: string;
  rows: FailureEvent[];
  citations: string[];
  choices?: string[];
}

export interface RiskItem {
  label: string;
  score: number;
  drivers: string[];
}

const reportFamilyRules: Array<[ReportFamily, RegExp]> = [
  ["Daily drilling report", /(ddr|daily|drilling.report)/i],
  ["BHA report", /\bbha\b|bottom.hole/i],
  ["Bit record", /\bbit\b|dull.grade/i],
  ["Mud report", /\bmud\b|fluids?/i],
  ["Directional report", /directional|dd.report/i],
  ["MWD/LWD report", /\bmwd\b|\blwd\b|logging.while/i],
  ["Motor report", /\bmotor\b|stator|rotor/i],
  ["Fishing report", /fish|overshot|spear/i],
  ["Cementing report", /cement/i],
  ["Casing report", /casing/i],
  ["Completion report", /completion/i],
  ["NPT report", /\bnpt\b|non.productive/i],
  ["Lessons learned", /lesson|after.action|end.of.well|eowr/i],
  ["Text report", /\.(txt|md|log)$/i],
  ["Email", /\.(eml|msg)$/i],
  ["Image/OCR", /\.(png|jpg|jpeg|tif|tiff|bmp)$/i],
  ["Archive", /\.(zip|7z|rar)$/i]
];

const severityWeight: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4
};

export function classifyReportFamily(name: string): ReportFamily {
  const match = reportFamilyRules.find(([, pattern]) => pattern.test(name));
  return match?.[0] ?? "Unknown";
}

export function buildInventory(files: File[]): UploadInventoryItem[] {
  const seen = new Set<string>();

  return files.map((file, index) => {
    const relativePath = getRelativePath(file);
    const extension = extractExtension(file.name);
    const duplicateKey = `${file.name.toLowerCase()}-${file.size}`;
    const isDuplicate = seen.has(duplicateKey);
    seen.add(duplicateKey);

    const reportFamily = classifyReportFamily(relativePath);
    const status = getInventoryStatus(extension, reportFamily, isDuplicate);

    return {
      id: `file-${index}-${file.name}`,
      name: file.name,
      relativePath,
      size: file.size,
      extension,
      reportFamily,
      status,
      warning: getInventoryWarning(status, reportFamily)
    };
  });
}

export function summarizeMetrics(events: FailureEvent[]): MetricsSummary {
  const totalNptHours = events.reduce((sum, event) => sum + event.nptHours, 0);
  const costImpactUsd = events.reduce((sum, event) => sum + event.costImpactUsd, 0);
  const averageConfidence =
    events.reduce((sum, event) => sum + event.confidence, 0) / Math.max(events.length, 1);
  const criticalAndHigh = events.filter(
    (event) => event.severity === "Critical" || event.severity === "High"
  ).length;
  const validationBacklog = events.filter(
    (event) => event.validationStatus === "needs_review" || event.validationStatus === "conflict"
  ).length;
  const serialCounts = countBy(events, (event) => event.toolSerial);

  return {
    totalFailures: events.length,
    totalNptHours,
    costImpactUsd,
    criticalAndHigh,
    averageConfidence,
    validationBacklog,
    repeatedToolSerials: Object.values(serialCounts).filter((count) => count > 1).length
  };
}

export function filterFailures(events: FailureEvent[], filters: FilterState): FailureEvent[] {
  const query = filters.query.trim().toLowerCase();
  const earliestDate = getEarliestDate(filters.dateRange);

  return events.filter((event) => {
    const haystack = [
      event.eventType,
      event.well,
      event.rig,
      event.company,
      event.toolType,
      event.toolName,
      event.toolSerial,
      event.section,
      event.formation,
      event.summary,
      event.rootCause
    ]
      .join(" ")
      .toLowerCase();

    return (
      (!query || haystack.includes(query)) &&
      (!earliestDate || new Date(event.eventDate) >= earliestDate) &&
      (filters.company === "All companies" || event.company === filters.company) &&
      (filters.toolType === "All tools" || event.toolType === filters.toolType) &&
      (filters.severity === "All severities" || event.severity === filters.severity) &&
      (filters.validationStatus === "All validation" ||
        normalizeValidationLabel(event.validationStatus) === filters.validationStatus)
    );
  });
}

export function answerQuestion(
  question: string,
  events: FailureEvent[],
  filters: FilterState
): ChatAnswer {
  const normalized = question.trim().toLowerCase();
  const filteredEvents = filterFailures(events, filters);

  if (!normalized) {
    return {
      kind: "clarification",
      title: "Choose an analysis target",
      message: "Start with a failure type, company, tool, well, rig, section, NPT, or risk question.",
      rows: [],
      citations: [],
      choices: [
        "Show MWD failures in 12.25 in sections",
        "Compare NPT by service company",
        "Which tool serials have repeated failures?"
      ]
    };
  }

  if (normalized.includes("definitely") || normalized.includes("guarantee")) {
    return {
      kind: "unsupported",
      title: "Unsupported deterministic prediction",
      message:
        "The uploaded evidence can support relative risk, repeated-failure signals, and similar past cases, but it cannot prove which tool will definitely fail.",
      rows: [],
      citations: []
    };
  }

  if (normalized.includes("not uploaded") || normalized.includes("external reports")) {
    return {
      kind: "unsupported",
      title: "Source data is not available",
      message:
        "I can only answer from reports that are uploaded, indexed, and within your tenant permissions.",
      rows: [],
      citations: []
    };
  }

  if (
    normalized.includes("local ai") ||
    normalized.includes("local model") ||
    normalized.includes("offline")
  ) {
    return {
      kind: "answer",
      title: "Local AI operating model",
      message:
        "Monday Report should route classification, extraction, retrieval, and report drafting through a local model first, then use hosted providers only as an approved fallback.",
      rows: filteredEvents.slice(0, 5),
      citations: collectCitationLabels(filteredEvents.slice(0, 5))
    };
  }

  if (normalized === "compare failures" || normalized === "compare failure") {
    return {
      kind: "clarification",
      title: "Comparison needs a dimension",
      message: "Choose how to compare failures so I can avoid guessing.",
      rows: [],
      citations: [],
      choices: ["By company", "By tool type", "By well", "By rig"]
    };
  }

  if (normalized.includes("monday report") || normalized.includes("weekly report")) {
    const rows = filteredEvents
      .slice()
      .sort((left, right) => riskScore(right) - riskScore(left))
      .slice(0, 6);
    const totalNpt = filteredEvents.reduce((sum, event) => sum + event.nptHours, 0);
    const reviewCount = filteredEvents.filter(
      (event) => event.validationStatus === "needs_review" || event.validationStatus === "conflict"
    ).length;

    return {
      kind: "answer",
      title: "Monday Report draft",
      message: `Draft executive summary: ${filteredEvents.length} extracted failures, ${totalNpt.toFixed(
        1
      )} NPT hours, and ${reviewCount} items needing validation before export.`,
      rows,
      citations: collectCitationLabels(rows)
    };
  }

  if (normalized.includes("export")) {
    return {
      kind: "export",
      title: "Export job staged",
      message:
        "The current filtered result set is ready for CSV or Excel export with confidence scores and citations.",
      rows: filteredEvents,
      citations: collectCitationLabels(filteredEvents)
    };
  }

  if (normalized.includes("risk") || normalized.includes("predict")) {
    const riskyRows = filteredEvents
      .slice()
      .sort((left, right) => riskScore(right) - riskScore(left))
      .slice(0, 5);

    return {
      kind: "answer",
      title: "Relative risk based on uploaded evidence",
      message:
        "Risk is calculated from severity, NPT, repeat serials, validation status, and extraction confidence. It is advisory until more validated history is available.",
      rows: riskyRows,
      citations: collectCitationLabels(riskyRows)
    };
  }

  const scopedRows = scopeRowsForQuestion(normalized, filteredEvents);

  if (normalized.includes("most") && normalized.includes("company")) {
    const companyCounts = countBy(scopedRows, (event) => event.company);
    const topCompany = Object.entries(companyCounts).sort((a, b) => b[1] - a[1])[0];
    return {
      kind: "answer",
      title: "Company with the most matching failures",
      message: topCompany
        ? `${topCompany[0]} has the most matching failures in the current evidence set (${topCompany[1]} events).`
        : "No matching failures were found for the active filters.",
      rows: scopedRows,
      citations: collectCitationLabels(scopedRows)
    };
  }

  if (normalized.includes("npt") || normalized.includes("lost time")) {
    const rows = scopedRows
      .slice()
      .sort((left, right) => right.nptHours - left.nptHours)
      .slice(0, 6);
    const hours = rows.reduce((sum, event) => sum + event.nptHours, 0);

    return {
      kind: "answer",
      title: "NPT evidence summary",
      message: `${hours.toFixed(1)} NPT hours are visible in the matching events. High-NPT events should keep source citations and validation state attached before management reporting.`,
      rows,
      citations: collectCitationLabels(rows)
    };
  }

  if (normalized.includes("repeat") || normalized.includes("repeated")) {
    const serialCounts = countBy(filteredEvents, (event) => event.toolSerial);
    const rows = filteredEvents.filter((event) => serialCounts[event.toolSerial] > 1);
    return {
      kind: "answer",
      title: "Repeated tool failures",
      message:
        rows.length > 0
          ? "These tool serials appear more than once in the failure evidence."
          : "No repeated serial-number failures were found under the active filters.",
      rows,
      citations: collectCitationLabels(rows)
    };
  }

  return {
    kind: "answer",
    title: "Source-backed failure results",
    message:
      scopedRows.length > 0
        ? "I found matching failure evidence. Review confidence and validation state before using this in an official decision."
        : "No matching extracted failures were found. Try widening the filters or asking for a broader event type.",
    rows: scopedRows.slice(0, 8),
    citations: collectCitationLabels(scopedRows)
  };
}

export function companyRisk(events: FailureEvent[]): RiskItem[] {
  return Object.entries(groupBy(events, (event) => event.company))
    .map(([company, companyEvents]) => ({
      label: company,
      score: clamp(
        companyEvents.reduce((sum, event) => sum + riskScore(event), 0) /
          Math.max(companyEvents.length, 1),
        0,
        100
      ),
      drivers: topDrivers(companyEvents)
    }))
    .sort((left, right) => right.score - left.score);
}

export function toolRisk(events: FailureEvent[]): RiskItem[] {
  return Object.entries(groupBy(events, (event) => event.toolSerial))
    .map(([serial, serialEvents]) => ({
      label: serial,
      score: clamp(
        serialEvents.reduce((sum, event) => sum + riskScore(event), 0) /
          Math.max(serialEvents.length, 1) +
          (serialEvents.length > 1 ? 12 : 0),
        0,
        100
      ),
      drivers: topDrivers(serialEvents)
    }))
    .sort((left, right) => right.score - left.score);
}

export function uniqueCompanies(events: FailureEvent[]): string[] {
  return ["All companies", ...Array.from(new Set(events.map((event) => event.company))).sort()];
}

export function uniqueTools(events: FailureEvent[]): string[] {
  return ["All tools", ...Array.from(new Set(events.map((event) => event.toolType))).sort()];
}

export function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0
  }).format(value);
}

export function formatHours(value: number): string {
  return `${value.toFixed(value % 1 === 0 ? 0 : 1)} h`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function getRelativePath(file: File): string {
  const fileWithRelativePath = file as File & { webkitRelativePath?: string };
  return fileWithRelativePath.webkitRelativePath || file.name;
}

function extractExtension(fileName: string): string {
  const match = /\.([a-z0-9]+)$/i.exec(fileName);
  return match?.[1]?.toLowerCase() ?? "";
}

function getInventoryStatus(
  extension: string,
  reportFamily: ReportFamily,
  isDuplicate: boolean
): UploadInventoryItem["status"] {
  if (isDuplicate) {
    return "duplicate";
  }

  if (reportFamily === "Image/OCR") {
    return "needs_ocr";
  }

  if (!extension || reportFamily === "Unknown") {
    return "unsupported";
  }

  return "parsed";
}

function getInventoryWarning(
  status: UploadInventoryItem["status"],
  reportFamily: ReportFamily
): string | undefined {
  if (status === "duplicate") {
    return "Duplicate candidate by name and size.";
  }

  if (status === "needs_ocr") {
    return "Route through OCR/layout extraction.";
  }

  if (status === "unsupported") {
    return "Inventory only until a parser adapter is configured.";
  }

  if (reportFamily === "Archive") {
    return "Archive registered; production workers would recursively unpack it.";
  }

  return undefined;
}

function getEarliestDate(dateRange: FilterState["dateRange"]): Date | null {
  const reference = new Date("2026-07-06T00:00:00");
  const daysByRange: Record<FilterState["dateRange"], number | null> = {
    all: null,
    "30d": 30,
    "90d": 90,
    "6m": 183
  };
  const days = daysByRange[dateRange];

  if (!days) {
    return null;
  }

  const earliest = new Date(reference);
  earliest.setDate(reference.getDate() - days);
  return earliest;
}

function normalizeValidationLabel(status: ValidationStatus): string {
  const labels: Record<ValidationStatus, string> = {
    validated: "Validated",
    needs_review: "Needs review",
    conflict: "Conflict",
    rejected: "Rejected"
  };
  return labels[status];
}

function scopeRowsForQuestion(question: string, events: FailureEvent[]): FailureEvent[] {
  const tokens: Array<[string, (event: FailureEvent) => boolean]> = [
    ["mwd", (event) => event.toolType.toLowerCase() === "mwd" || event.eventType.toLowerCase().includes("mwd")],
    ["lwd", (event) => event.toolType.toLowerCase() === "lwd" || event.eventType.toLowerCase().includes("lwd")],
    ["motor", (event) => event.toolType.toLowerCase().includes("motor")],
    ["rss", (event) => event.toolType.toLowerCase() === "rss"],
    ["stuck", (event) => event.eventType.toLowerCase().includes("stuck")],
    ["bit", (event) => event.toolType.toLowerCase() === "bit"],
    ["12.25", (event) => event.holeSizeIn === 12.25],
    ["8.5", (event) => event.holeSizeIn === 8.5]
  ];
  const activePredicates = tokens
    .filter(([token]) => question.includes(token))
    .map(([, predicate]) => predicate);

  if (activePredicates.length === 0) {
    return events;
  }

  return events.filter((event) => activePredicates.every((predicate) => predicate(event)));
}

function collectCitationLabels(events: FailureEvent[]): string[] {
  return events.flatMap((event) =>
    event.citations.map((citation) => {
      const locator = citation.page
        ? `p. ${citation.page}`
        : citation.sheet
          ? `${citation.sheet}${citation.row ? ` r.${citation.row}` : ""}`
          : "source";
      return `${citation.file} (${locator})`;
    })
  );
}

function riskScore(event: FailureEvent): number {
  const severity = severityWeight[event.severity] * 14;
  const npt = Math.min(event.nptHours * 1.8, 24);
  const validationPenalty = event.validationStatus === "conflict" ? 10 : 0;
  const confidence = event.confidence * 10;
  return clamp(severity + npt + validationPenalty + confidence, 0, 100);
}

function topDrivers(events: FailureEvent[]): string[] {
  const drivers = new Set<string>();
  events.forEach((event) => {
    drivers.add(event.eventType);
    if (event.nptHours >= 8) {
      drivers.add("high NPT");
    }
    if (event.validationStatus === "conflict") {
      drivers.add("conflicting evidence");
    }
    if (event.severity === "Critical" || event.severity === "High") {
      drivers.add(`${event.severity.toLowerCase()} severity`);
    }
  });
  return Array.from(drivers).slice(0, 3);
}

function countBy<T>(items: T[], getKey: (item: T) => string): Record<string, number> {
  return items.reduce<Record<string, number>>((counts, item) => {
    const key = getKey(item);
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
}

function groupBy<T>(items: T[], getKey: (item: T) => string): Record<string, T[]> {
  return items.reduce<Record<string, T[]>>((groups, item) => {
    const key = getKey(item);
    groups[key] = groups[key] ?? [];
    groups[key].push(item);
    return groups;
  }, {});
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
