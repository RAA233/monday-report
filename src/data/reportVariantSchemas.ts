export type FormatVariantId = "ddr" | "bha" | "mud" | "survey" | "directional";

export interface ReportFormatVariant {
  id: FormatVariantId;
  schemaId: string;
  label: string;
  shortLabel: string;
  scope: string;
  phase: string;
  presentOps: string;
  nextOps: string;
  safety: string;
  risks: string;
  operationsLog: string;
  requiredSections: string[];
  extractionMarkers: string[];
  draftingChecks: string[];
  outputSections: string[];
}

export const reportVariantSchemaVersion = "MR-SCHEMA-1";

export const defaultOperationsLog = [
  "00:00-06:00 | Drill ahead and maintain hole cleaning parameters.",
  "06:00-12:00 | Survey, circulate bottoms up, monitor torque and drag.",
  "12:00-18:00 | Condition mud, inspect surface equipment, update BHA record.",
  "18:00-24:00 | Continue drilling and prepare morning handover."
].join("\n");

export const reportFormatVariants: ReportFormatVariant[] = [
  {
    id: "ddr",
    schemaId: "mr-ddr-v1",
    label: "Daily drilling",
    shortLabel: "DDR",
    scope: "Full morning handover",
    phase: "Drilling morning report",
    presentOps:
      "Summarize the active 24 hr drilling operation with well/job information, present operations, drilling parameters, casing, mud, BHA, survey, time breakdown, NPT, and approvals.",
    nextOps:
      "Continue planned operation, update directional plan, verify casing readiness, and prepare a clean morning handover with source-backed highlights.",
    safety:
      "Confirm BOP, well-control barriers, pressure-control notes, lifting exposure, and handover hazards before client issue.",
    risks:
      "Watch hole cleaning, torque and drag, ECD margin, lost circulation, MWD signal continuity, and casing-point readiness.",
    operationsLog: defaultOperationsLog,
    requiredSections: ["Well/job", "Operations", "Parameters", "Mud/BHA/survey", "Casing", "Timeline", "NPT", "Approvals"],
    extractionMarkers: ["report no", "well", "rig", "present operations", "mud weight", "bha", "survey", "time breakdown", "npt"],
    draftingChecks: ["well identity", "active operation", "depth and hole size", "barrier note", "time summary", "approval gate"],
    outputSections: ["Header", "Operations", "Parameters", "Mud/BHA/survey", "Casing schematic", "Timeline", "NPT", "Approvals"]
  },
  {
    id: "bha",
    schemaId: "mr-bha-v1",
    label: "BHA and tools",
    shortLabel: "BHA",
    scope: "Run performance and tool risk",
    phase: "BHA performance report",
    presentOps:
      "Summarize BHA run status, bit performance, RSS/MWD/LWD response, downhole tool reliability, vibration indicators, and any service-company exposure.",
    nextOps:
      "Confirm tool serials, run hours, failure/NPT evidence, replacement status, and recommended operating parameters before the next run.",
    safety:
      "Confirm handling controls, red-zone exposure, pressure isolation, and tool-change lifting plan before operational handover.",
    risks:
      "Watch MWD signal quality, shock and vibration, motor/RSS response, bit wear, connection failures, and repeat-tool exposure.",
    operationsLog: [
      "00:00-06:00 | Review BHA run status, tool response, and signal quality.",
      "06:00-12:00 | Confirm tool serials, bit/BHA hours, and service-company notes.",
      "12:00-18:00 | Reconcile failures, NPT, trips, replacements, and corrective actions.",
      "18:00-24:00 | Prepare next-run guidance and validation-backed handover."
    ].join("\n"),
    requiredSections: ["BHA", "Bit", "MWD/LWD/RSS", "Tool serials", "Run hours", "Failures", "NPT", "Actions"],
    extractionMarkers: ["bha", "bit", "mwd", "lwd", "rss", "serial", "run hours", "failure", "npt"],
    draftingChecks: ["assembly identity", "tool serials", "run hours", "failure linkage", "replacement status", "next-run action"],
    outputSections: ["BHA summary", "Bit record", "Tool serials", "Run performance", "Failure/NPT", "Corrective actions"]
  },
  {
    id: "mud",
    schemaId: "mr-mud-v1",
    label: "Mud and hydraulics",
    shortLabel: "Mud",
    scope: "Fluid condition and hole cleaning",
    phase: "Mud and hydraulics report",
    presentOps:
      "Summarize mud properties, active volume, treatments, losses/gains, solids control, ECD margin, hole cleaning, and any fluid-related NPT.",
    nextOps:
      "Confirm rheology trend, density target, chemical treatments, losses response, hole-cleaning plan, and mud engineer approvals.",
    safety:
      "Confirm chemical handling controls, pit management, pressure-control exposure, and spill response posture.",
    risks:
      "Watch ECD margin, losses, gas cut, barite sag, hole cleaning, stuck-pipe indicators, and incompatible treatments.",
    operationsLog: [
      "00:00-06:00 | Review mud density, rheology, volumes, and treatment plan.",
      "06:00-12:00 | Confirm solids control, losses/gains, ECD, and hole cleaning.",
      "12:00-18:00 | Reconcile mud-related NPT, chemicals, and approvals.",
      "18:00-24:00 | Prepare hydraulics guidance and next-shift treatment plan."
    ].join("\n"),
    requiredSections: ["Mud weight", "Rheology", "Volumes", "Treatments", "Losses/gains", "ECD", "Hole cleaning", "Approvals"],
    extractionMarkers: ["mud weight", "rheology", "pv", "yp", "gel", "losses", "gains", "ecd", "solids control"],
    draftingChecks: ["density target", "rheology trend", "loss response", "volume balance", "chemical handling", "approval note"],
    outputSections: ["Fluid properties", "Hydraulics", "Treatments", "Losses/gains", "Hole cleaning", "Approvals"]
  },
  {
    id: "survey",
    schemaId: "mr-survey-v1",
    label: "Survey quality",
    shortLabel: "Survey",
    scope: "Survey acceptance and QA",
    phase: "Survey quality report",
    presentOps:
      "Summarize accepted surveys, inclination/azimuth trend, DLS, MWD quality, target position, survey flags, and source acceptance status.",
    nextOps:
      "Confirm next survey plan, correction requirements, survey acceptance notes, anti-collision status, and source-backed trajectory notes.",
    safety:
      "Confirm survey QA, anti-collision review, directional-change communication, and well-control constraints before handover.",
    risks:
      "Watch survey quality flags, DLS spikes, target drift, MWD signal continuity, and anti-collision separation.",
    operationsLog: [
      "00:00-06:00 | Review accepted surveys, target position, and survey quality flags.",
      "06:00-12:00 | Confirm MWD quality, DLS, and plan compliance.",
      "12:00-18:00 | Reconcile survey flags, anti-collision review, and trajectory risks.",
      "18:00-24:00 | Prepare next survey acceptance checks."
    ].join("\n"),
    requiredSections: ["Surveys", "Inclination", "Azimuth", "DLS", "MWD quality", "Target", "Anti-collision", "Plan"],
    extractionMarkers: ["survey", "inclination", "azimuth", "dls", "mwd quality", "target", "anti-collision", "acceptance"],
    draftingChecks: ["accepted survey", "inclination trend", "azimuth trend", "DLS risk", "quality flag", "anti-collision note"],
    outputSections: ["Survey table", "Trajectory trend", "Quality flags", "Target position", "Anti-collision", "Next survey plan"]
  },
  {
    id: "directional",
    schemaId: "mr-directional-v1",
    label: "Directional steering",
    shortLabel: "DIR",
    scope: "Steering plan and directional execution",
    phase: "Directional steering report",
    presentOps:
      "Summarize toolface response, slide/rotate efficiency, RSS or motor steering behavior, target-window position, and directional-plan compliance.",
    nextOps:
      "Confirm steering objective, correction plan, motor/RSS settings, toolface guidance, survey cadence, and source-backed directional actions.",
    safety:
      "Confirm directional-change communication, anti-collision clearance, stuck-pipe exposure, and well-control constraints before the next shift.",
    risks:
      "Watch toolface instability, DLS excursions, motor stall, RSS command quality, target drift, vibration, and survey delay exposure.",
    operationsLog: [
      "00:00-06:00 | Review toolface response, slide/rotate efficiency, and target-window position.",
      "06:00-12:00 | Confirm RSS or motor steering settings, MWD quality, and directional plan compliance.",
      "12:00-18:00 | Reconcile correction plan, DLS exposure, and anti-collision notes.",
      "18:00-24:00 | Prepare steering guidance and survey cadence for next shift."
    ].join("\n"),
    requiredSections: ["Objective", "Toolface", "Slide/rotate", "DLS", "Target window", "MWD/RSS", "Anti-collision", "Actions"],
    extractionMarkers: ["directional", "toolface", "slide", "rotate", "rss", "motor", "target window", "correction plan", "dls"],
    draftingChecks: ["steering objective", "toolface response", "slide/rotate split", "target position", "correction plan", "anti-collision note"],
    outputSections: ["Directional objective", "Steering execution", "Toolface response", "Target window", "Correction plan", "Actions"]
  }
];
