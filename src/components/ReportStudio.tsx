import { useMemo, useState } from "react";
import type { JSX } from "react";
import {
  BarChart3,
  CalendarDays,
  CheckCircle2,
  Clock3,
  ClipboardList,
  Cpu,
  Download,
  FileText,
  Gauge,
  HardHat,
  Layers3,
  Route,
  Ruler,
  ShieldAlert,
  ShieldCheck,
  WandSparkles
} from "lucide-react";
import { Badge } from "./Badge";
import type { LucideIcon } from "lucide-react";

interface ReportForm {
  reportDate: string;
  reportNo: string;
  well: string;
  rig: string;
  operator: string;
  phase: string;
  holeSize: string;
  mdFt: string;
  tvdFt: string;
  mudWeight: string;
  presentOps: string;
  nextOps: string;
  safety: string;
  risks: string;
  casingProgram: string;
  operationsLog: string;
}

interface CasingInterval {
  name: string;
  od: string;
  topFt: number;
  shoeFt: number;
  status: string;
}

interface ActivitySegment {
  time: string;
  description: string;
}

interface StandardReportSection {
  title: string;
  status: string;
  detail: string;
}

interface AiExecutionStep {
  step: string;
  status: string;
  detail: string;
}

interface StudioMetric {
  label: string;
  value: string;
  detail: string;
  tone: "good" | "warning" | "danger" | "info";
}

interface ControlMatrixItem {
  label: string;
  value: string;
  detail: string;
}

const defaultCasingProgram = [
  "Conductor | 20 in | 0 | 130 | Set",
  "Surface | 13.375 in | 0 | 1629 | Set",
  "Intermediate | 9.625 in | 0 | 6500 | Planned",
  "Production | 7 in | 0 | 10987 | Planned"
].join("\n");

const defaultOperationsLog = [
  "00:00-06:00 | Drill ahead and maintain hole cleaning parameters.",
  "06:00-12:00 | Survey, circulate bottoms up, monitor torque and drag.",
  "12:00-18:00 | Condition mud, inspect surface equipment, update BHA record.",
  "18:00-24:00 | Continue drilling and prepare morning handover."
].join("\n");

export function ReportStudio(): JSX.Element {
  const [form, setForm] = useState<ReportForm>(() => initialReportForm());

  const casing = useMemo(() => parseCasingProgram(form.casingProgram), [form.casingProgram]);
  const activities = useMemo(() => parseOperationsLog(form.operationsLog), [form.operationsLog]);
  const summary = useMemo(() => buildExecutiveSummary(form), [form]);
  const standardSections = useMemo(
    () => buildStandardReportSections(form, casing, activities),
    [form, casing, activities]
  );
  const aiPlan = useMemo(() => buildAiExecutionPlan(form, casing, activities), [form, casing, activities]);
  const clientChecks = useMemo(() => buildClientIssueChecklist(form, casing, activities), [form, casing, activities]);
  const studioMetrics = useMemo(
    () => buildStudioMetrics(form, casing, activities, clientChecks),
    [form, casing, activities, clientChecks]
  );

  function updateField(field: keyof ReportForm, value: string): void {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function applyAiDraft(): void {
    setForm((current) => ({
      ...current,
      presentOps:
        current.presentOps.trim() ||
        "Rig is drilling ahead with active monitoring of hole cleaning, directional response, mud properties, and equipment readiness.",
      nextOps:
        current.nextOps.trim() ||
        "Continue drilling to plan, verify survey trend, circulate bottoms up, update casing and cement readiness, and prepare the morning handover package.",
      safety:
        current.safety.trim() ||
        "No incidents entered. Confirm BOP status, slips/trips exposure, lifting controls, and pressure-control barriers before shift handover.",
      risks:
        current.risks.trim() ||
        "Watch torque and drag trend, ECD margin, lost-circulation indicators, MWD signal quality, and casing shoe integrity.",
      operationsLog: current.operationsLog.trim() ? current.operationsLog : defaultOperationsLog,
      casingProgram: current.casingProgram.trim() ? current.casingProgram : defaultCasingProgram
    }));
  }

  function applyForgeTemplate(): void {
    setForm({
      reportDate: currentDateInputValue(),
      reportNo: "DDR-001",
      well: "FORGE 16A(78)-32",
      rig: "Frontier Rig 16",
      operator: "Monday Report",
      phase: "Drilling morning report",
      holeSize: "12.25 in",
      mdFt: "8,620",
      tvdFt: "7,980",
      mudWeight: "10.2 ppg",
      presentOps:
        "Summarize 24 hr activity using the open-source FORGE daily-report structure: well/job information, present operations, casing, mud, BHA, survey, consumables, and time breakdown.",
      nextOps:
        "Continue planned operation, update directional plan, verify casing readiness, and prepare a clean morning handover with source-backed highlights.",
      safety:
        "BOP and well-control notes must be confirmed by the drilling supervisor before client issue.",
      risks:
        "Track hole cleaning, torque and drag, MWD signal continuity, casing-point readiness, and any non-productive time.",
      casingProgram: defaultCasingProgram,
      operationsLog: defaultOperationsLog
    });
  }

  function downloadDraft(): void {
    const blob = new Blob([renderMarkdownReport(form, summary, casing, activities, standardSections, aiPlan, clientChecks)], {
      type: "text/markdown;charset=utf-8"
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `Monday_Report_${safeFilePart(form.well)}_${form.reportDate || "draft"}.md`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return (
    <main className="report-studio">
      <section className="workspace-title studio-title">
        <div>
          <p className="eyebrow">Morning report studio</p>
          <h1>Technical daily-report command console</h1>
          <p>
            Build normal daily reports with source-backed sections, advanced schematic context,
            AI execution checks, validation gates, and branded export readiness.
          </p>
        </div>
        <Badge tone="info">MR-DDR-2</Badge>
      </section>

      <section className="studio-ops-strip" aria-label="Report studio technical telemetry">
        {studioMetrics.map((metric) => (
          <StudioMetricCard key={metric.label} metric={metric} />
        ))}
      </section>

      <section className="studio-grid">
        <form className="studio-editor panel" aria-label="Morning report editor">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Editor</p>
              <h2>Report inputs</h2>
            </div>
            <FileText size={20} aria-hidden="true" />
          </div>

          <div className="studio-field-grid">
            <LabeledInput
              icon={CalendarDays}
              label="Date"
              type="date"
              value={form.reportDate}
              onChange={(value) => updateField("reportDate", value)}
            />
            <LabeledInput
              label="Report no."
              value={form.reportNo}
              onChange={(value) => updateField("reportNo", value)}
            />
            <LabeledInput label="Well" value={form.well} onChange={(value) => updateField("well", value)} />
            <LabeledInput label="Rig" value={form.rig} onChange={(value) => updateField("rig", value)} />
            <LabeledInput
              label="Operator"
              value={form.operator}
              onChange={(value) => updateField("operator", value)}
            />
            <LabeledInput label="Phase" value={form.phase} onChange={(value) => updateField("phase", value)} />
            <LabeledInput
              icon={Ruler}
              label="Hole size"
              value={form.holeSize}
              onChange={(value) => updateField("holeSize", value)}
            />
            <LabeledInput label="MD ft" value={form.mdFt} onChange={(value) => updateField("mdFt", value)} />
            <LabeledInput label="TVD ft" value={form.tvdFt} onChange={(value) => updateField("tvdFt", value)} />
            <LabeledInput
              label="Mud weight"
              value={form.mudWeight}
              onChange={(value) => updateField("mudWeight", value)}
            />
          </div>

          <LabeledTextarea
            label="Present operations"
            value={form.presentOps}
            onChange={(value) => updateField("presentOps", value)}
          />
          <LabeledTextarea
            label="Next 24 hr plan"
            value={form.nextOps}
            onChange={(value) => updateField("nextOps", value)}
          />
          <LabeledTextarea
            label="Safety and well-control notes"
            value={form.safety}
            onChange={(value) => updateField("safety", value)}
          />
          <LabeledTextarea label="Risks and AI watchlist" value={form.risks} onChange={(value) => updateField("risks", value)} />
          <LabeledTextarea
            label="Casing program"
            hint="Name | OD | Top ft | Shoe ft | Status"
            value={form.casingProgram}
            onChange={(value) => updateField("casingProgram", value)}
          />
          <LabeledTextarea
            label="24 hr activity timeline"
            hint="00:00-06:00 | Activity summary"
            value={form.operationsLog}
            onChange={(value) => updateField("operationsLog", value)}
          />

          <div className="studio-actions">
            <button className="primary-action" type="button" onClick={applyAiDraft}>
              <WandSparkles size={18} aria-hidden="true" />
              AI draft
            </button>
            <button className="secondary-action" type="button" onClick={applyForgeTemplate}>
              <Layers3 size={18} aria-hidden="true" />
              FORGE style
            </button>
            <button className="secondary-action" type="button" onClick={downloadDraft}>
              <Download size={18} aria-hidden="true" />
              Export draft
            </button>
          </div>
        </form>

        <aside className="studio-preview" aria-label="Branded report preview">
          <DailyReportPreview
            form={form}
            summary={summary}
            casing={casing}
            activities={activities}
            standardSections={standardSections}
            aiPlan={aiPlan}
            clientChecks={clientChecks}
          />
        </aside>
      </section>
    </main>
  );
}

interface LabeledInputProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  icon?: LucideIcon;
  type?: "text" | "date";
}

function StudioMetricCard({ metric }: { metric: StudioMetric }): JSX.Element {
  return (
    <article className={`studio-metric-card studio-metric-${metric.tone}`}>
      {studioMetricIcon(metric.label)}
      <span>{metric.label}</span>
      <strong>{metric.value}</strong>
      <p>{metric.detail}</p>
    </article>
  );
}

function studioMetricIcon(label: string): JSX.Element {
  if (label === "Completeness") {
    return <BarChart3 size={19} aria-hidden="true" />;
  }
  if (label === "Schematic") {
    return <HardHat size={19} aria-hidden="true" />;
  }
  if (label === "AI engine") {
    return <Cpu size={19} aria-hidden="true" />;
  }
  if (label === "Gate") {
    return <ShieldAlert size={19} aria-hidden="true" />;
  }
  return <Route size={19} aria-hidden="true" />;
}

function LabeledInput({ label, value, onChange, icon: Icon, type = "text" }: LabeledInputProps): JSX.Element {
  return (
    <label className="studio-field">
      <span>
        {Icon && <Icon size={15} aria-hidden="true" />}
        {label}
      </span>
      <input type={type} value={value} onChange={(event) => onChange(event.currentTarget.value)} />
    </label>
  );
}

interface LabeledTextareaProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
}

function LabeledTextarea({ label, value, onChange, hint }: LabeledTextareaProps): JSX.Element {
  return (
    <label className="studio-field studio-field-wide">
      <span>
        {label}
        {hint && <em>{hint}</em>}
      </span>
      <textarea value={value} rows={hint ? 5 : 4} onChange={(event) => onChange(event.currentTarget.value)} />
    </label>
  );
}

interface DailyReportPreviewProps {
  form: ReportForm;
  summary: string;
  casing: CasingInterval[];
  activities: ActivitySegment[];
  standardSections: StandardReportSection[];
  aiPlan: AiExecutionStep[];
  clientChecks: string[];
}

function DailyReportPreview({
  form,
  summary,
  casing,
  activities,
  standardSections,
  aiPlan,
  clientChecks
}: DailyReportPreviewProps): JSX.Element {
  const controlMatrix = buildControlMatrix(form, casing, activities, clientChecks);

  return (
    <div className="daily-report-sheet">
      <header className="daily-report-header">
        <div className="report-brand-mark">MR</div>
        <div>
          <p>Monday Report</p>
          <h2>Morning Drilling Report</h2>
        </div>
        <Badge tone="good">draft</Badge>
      </header>

      <div className="daily-report-band">
        <span>{form.reportDate || "Date not set"}</span>
        <span>{form.reportNo || "Draft"}</span>
        <span>{form.phase || "Operation phase"}</span>
      </div>

      <section className="report-info-grid">
        <ReportFact label="Well" value={form.well} />
        <ReportFact label="Rig" value={form.rig} />
        <ReportFact label="Operator" value={form.operator} />
        <ReportFact label="Hole" value={form.holeSize} />
        <ReportFact label="MD" value={formatDepth(form.mdFt)} />
        <ReportFact label="TVD" value={formatDepth(form.tvdFt)} />
        <ReportFact label="Mud" value={form.mudWeight} />
        <ReportFact label="Status" value="AI-assisted draft" />
      </section>

      <section className="report-control-matrix" aria-label="Technical report control matrix">
        {controlMatrix.map((item) => (
          <article key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <p>{item.detail}</p>
          </article>
        ))}
      </section>

      <section className="report-section">
        <div className="report-section-title">
          <WandSparkles size={17} aria-hidden="true" />
          <h3>Executive summary</h3>
        </div>
        <p>{summary}</p>
      </section>

      <section className="report-section standard-format-section">
        <div className="report-section-title">
          <ClipboardList size={17} aria-hidden="true" />
          <h3>Standard daily report format</h3>
        </div>
        <div className="standard-format-grid">
          {standardSections.map((section) => (
            <article key={section.title}>
              <span>{section.status}</span>
              <strong>{section.title}</strong>
              <p>{section.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="report-two-column">
        <div className="report-section">
          <div className="report-section-title">
            <Clock3 size={17} aria-hidden="true" />
            <h3>Current and next operations</h3>
          </div>
          <p>{fallbackText(form.presentOps, "No present operations entered.")}</p>
          <p>{fallbackText(form.nextOps, "No next 24 hr plan entered.")}</p>
        </div>
        <div className="report-section">
          <div className="report-section-title">
            <ShieldCheck size={17} aria-hidden="true" />
            <h3>Safety and AI watchlist</h3>
          </div>
          <p>{fallbackText(form.safety, "No safety notes entered.")}</p>
          <p>{fallbackText(form.risks, "No risk watchlist entered.")}</p>
        </div>
      </section>

      <section className="report-two-column report-visual-row">
        <div className="report-section">
          <div className="report-section-title">
            <Layers3 size={17} aria-hidden="true" />
            <h3>Casing and well schematic</h3>
          </div>
          <CasingSchematic casing={casing} currentDepth={parseDepth(form.mdFt)} />
          <div className="schematic-note-grid">
            <span>Hole {form.holeSize || "not entered"}</span>
            <span>Current MD {formatDepth(form.mdFt)}</span>
            <span>{casing.length} casing string(s)</span>
          </div>
        </div>
        <div className="report-section">
          <div className="report-section-title">
            <Clock3 size={17} aria-hidden="true" />
            <h3>24 hr activity timeline</h3>
          </div>
          <div className="activity-timeline">
            {activities.map((activity, index) => (
              <div className="timeline-row" key={`${activity.time}-${index}`}>
                <strong>{activity.time}</strong>
                <span>{activity.description}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="report-two-column">
        <div className="report-section">
          <div className="report-section-title">
            <Gauge size={17} aria-hidden="true" />
            <h3>AI plan and execute</h3>
          </div>
          <div className="ai-plan-list">
            {aiPlan.map((item) => (
              <article key={item.step}>
                <span>{item.status}</span>
                <strong>{item.step}</strong>
                <p>{item.detail}</p>
              </article>
            ))}
          </div>
        </div>
        <div className="report-section">
          <div className="report-section-title">
            <CheckCircle2 size={17} aria-hidden="true" />
            <h3>Client issue checks</h3>
          </div>
          <ul className="client-check-list">
            {clientChecks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}

function ReportFact({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div>
      <span>{label}</span>
      <strong>{value || "Not entered"}</strong>
    </div>
  );
}

function CasingSchematic({ casing, currentDepth }: { casing: CasingInterval[]; currentDepth: number }): JSX.Element {
  const maxDepth = Math.max(currentDepth, ...casing.map((item) => item.shoeFt), 1000);
  const colors = ["#0e7490", "#2563eb", "#047857", "#b45309"];

  return (
    <div className="casing-schematic">
      <svg viewBox="0 0 360 360" role="img" aria-label="Casing depth schematic">
        <line x1="44" y1="36" x2="44" y2="316" />
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => {
          const y = 36 + tick * 280;
          return (
            <g key={tick}>
              <line x1="36" y1={y} x2="322" y2={y} className="depth-grid" />
              <text x="50" y={y - 4}>{Math.round(maxDepth * tick).toLocaleString()} ft</text>
            </g>
          );
        })}
        {casing.map((item, index) => {
          const y1 = 36 + (Math.max(0, item.topFt) / maxDepth) * 280;
          const y2 = 36 + (Math.max(item.shoeFt, item.topFt + 100) / maxDepth) * 280;
          const width = Math.max(44, 170 - index * 28);
          const x = 178 - width / 2;
          return (
            <g key={`${item.name}-${index}`}>
              <rect
                x={x}
                y={y1}
                width={width}
                height={Math.max(18, y2 - y1)}
                rx="8"
                fill="none"
                stroke={colors[index % colors.length]}
                strokeWidth="7"
              />
              <text x="270" y={Math.min(y2, 322)}>{item.name}</text>
              <text x="270" y={Math.min(y2 + 14, 340)}>{item.od} / {item.status}</text>
            </g>
          );
        })}
        {currentDepth > 0 && (
          <g className="current-depth-marker">
            <line x1="68" x2="306" y1={36 + (currentDepth / maxDepth) * 280} y2={36 + (currentDepth / maxDepth) * 280} />
            <text x="188" y={32 + (currentDepth / maxDepth) * 280}>Current MD</text>
          </g>
        )}
      </svg>
    </div>
  );
}

function initialReportForm(): ReportForm {
  return {
    reportDate: currentDateInputValue(),
    reportNo: "MR-DRAFT-001",
    well: "",
    rig: "",
    operator: "Monday Report",
    phase: "Morning operations",
    holeSize: "",
    mdFt: "",
    tvdFt: "",
    mudWeight: "",
    presentOps: "",
    nextOps: "",
    safety: "",
    risks: "",
    casingProgram: defaultCasingProgram,
    operationsLog: defaultOperationsLog
  };
}

function currentDateInputValue(): string {
  return new Date().toISOString().slice(0, 10);
}

function parseCasingProgram(value: string): CasingInterval[] {
  const parsed = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [name, od, top, shoe, status] = line.split("|").map((part) => part.trim());
      return {
        name: name || "Casing",
        od: od || "OD not set",
        topFt: parseDepth(top),
        shoeFt: parseDepth(shoe),
        status: status || "Planned"
      };
    })
    .filter((item) => item.shoeFt > 0);

  return parsed.length > 0 ? parsed : parseCasingProgram(defaultCasingProgram);
}

function parseOperationsLog(value: string): ActivitySegment[] {
  const parsed = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [time, ...rest] = line.split("|");
      return {
        time: time.trim() || "24 hr",
        description: rest.join("|").trim() || line
      };
    });

  return parsed.length > 0 ? parsed : parseOperationsLog(defaultOperationsLog);
}

function parseDepth(value: string | undefined): number {
  if (!value) {
    return 0;
  }
  const parsed = Number.parseFloat(value.replace(/,/g, "").replace(/[^\d.]/g, ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatDepth(value: string): string {
  const depth = parseDepth(value);
  return depth > 0 ? `${depth.toLocaleString()} ft` : "Not entered";
}

function buildExecutiveSummary(form: ReportForm): string {
  const well = form.well.trim() || "the active well";
  const phase = form.phase.trim() || "the current operation";
  const md = formatDepth(form.mdFt);
  const present = form.presentOps.trim() || "No present operations have been entered yet.";
  return `${well} is in ${phase} at ${md}. ${present} Monday Report should verify casing status, timeline accuracy, safety barriers, and source citations before client issue.`;
}

function buildStandardReportSections(
  form: ReportForm,
  casing: CasingInterval[],
  activities: ActivitySegment[]
): StandardReportSection[] {
  return [
    {
      title: "Well / job information",
      status: form.well.trim() && form.rig.trim() ? "ready" : "needs input",
      detail: `${form.well || "Well not entered"} | ${form.rig || "Rig not entered"} | ${form.operator || "Operator not entered"}`
    },
    {
      title: "Present operations",
      status: form.presentOps.trim() ? "drafted" : "needs input",
      detail: fallbackText(form.presentOps, "Enter the current operation or use AI draft.")
    },
    {
      title: "Drilling parameters",
      status: form.mdFt.trim() || form.mudWeight.trim() ? "drafted" : "needs input",
      detail: `Hole ${form.holeSize || "not entered"}, MD ${formatDepth(form.mdFt)}, TVD ${formatDepth(form.tvdFt)}, mud ${form.mudWeight || "not entered"}.`
    },
    {
      title: "Mud, BHA, survey, and bit",
      status: "source-confirm",
      detail: "Confirm mud properties, BHA, bit run, survey trend, MWD/LWD/RSS status, and surface parameters from the source report."
    },
    {
      title: "Casing and well schematic",
      status: casing.length > 0 ? "rendered" : "needs input",
      detail: `${casing.length} string(s) plotted with current depth, shoe depths, and status labels.`
    },
    {
      title: "Time breakdown and approvals",
      status: activities.length > 0 ? "drafted" : "needs input",
      detail: `${activities.length} activity segment(s) captured. Validation, citation, and approval checks remain required before client issue.`
    }
  ];
}

function buildAiExecutionPlan(
  form: ReportForm,
  casing: CasingInterval[],
  activities: ActivitySegment[]
): AiExecutionStep[] {
  return [
    {
      step: "Plan",
      status: "ready",
      detail: "Map the source report into well/job info, operations, drilling parameters, mud/BHA/survey, casing, time, risk, and approval sections."
    },
    {
      step: "Draft",
      status: form.presentOps.trim() ? "ready" : "use AI draft",
      detail: "Generate normal daily-report wording while preserving the original field order and making gaps visible."
    },
    {
      step: "Draw",
      status: casing.length > 0 ? "ready" : "needs casing",
      detail: "Render casing strings, shoe depths, current MD, and risk markers for the morning handover."
    },
    {
      step: "Execute",
      status: activities.length > 0 ? "approval-gated" : "needs timeline",
      detail: "Export the branded report package after timeline review, source citations, and client issue checks are complete."
    }
  ];
}

function buildClientIssueChecklist(
  form: ReportForm,
  casing: CasingInterval[],
  activities: ActivitySegment[]
): string[] {
  return [
    form.well.trim() ? "Well and report identifiers are present." : "Add well and report identifiers.",
    casing.length > 0 ? "Casing schematic has at least one string." : "Add casing strings before issue.",
    activities.length > 0 ? "24 hr activity timeline is populated." : "Add the 24 hr activity timeline.",
    form.safety.trim() ? "Safety and well-control notes are included." : "Confirm safety and well-control notes.",
    "Confirm mud, BHA, survey, bit, and drilling parameters against source evidence.",
    "Attach citations and close validation items before official PDF/XLSX export."
  ];
}

function buildStudioMetrics(
  form: ReportForm,
  casing: CasingInterval[],
  activities: ActivitySegment[],
  clientChecks: string[]
): StudioMetric[] {
  const requiredFields: Array<keyof ReportForm> = [
    "reportDate",
    "reportNo",
    "well",
    "rig",
    "phase",
    "holeSize",
    "mdFt",
    "mudWeight",
    "presentOps",
    "nextOps",
    "safety",
    "risks",
  ];
  const completeFields = requiredFields.filter((field) => form[field].trim()).length;
  const completion = Math.round((completeFields / requiredFields.length) * 100);
  const blockers = clientChecks.filter((item) => item.startsWith("Add") || item.startsWith("Confirm")).length;
  return [
    {
      label: "Format",
      value: "MR-DDR-2",
      detail: "Normal daily-report structure with original casing/timeline compatibility.",
      tone: "info",
    },
    {
      label: "Completeness",
      value: `${completion}%`,
      detail: `${completeFields}/${requiredFields.length} primary fields populated.`,
      tone: completion >= 85 ? "good" : completion >= 55 ? "warning" : "danger",
    },
    {
      label: "Schematic",
      value: `${casing.length} strings`,
      detail: `${activities.length} timeline segment(s), current MD ${formatDepth(form.mdFt)}.`,
      tone: casing.length >= 4 ? "good" : "warning",
    },
    {
      label: "AI engine",
      value: "plan + execute",
      detail: "Drafting, schematic, audit, and export commands are exposed in chat.",
      tone: "good",
    },
    {
      label: "Gate",
      value: blockers === 0 ? "issue-ready" : `${blockers} blocker(s)`,
      detail: "Client issue checklist tracks missing identifiers, safety, casing, and evidence.",
      tone: blockers === 0 ? "good" : "warning",
    },
  ];
}

function buildControlMatrix(
  form: ReportForm,
  casing: CasingInterval[],
  activities: ActivitySegment[],
  clientChecks: string[]
): ControlMatrixItem[] {
  const safetyReady = Boolean(form.safety.trim());
  const depthReady = parseDepth(form.mdFt) > 0 && parseDepth(form.tvdFt) > 0;
  return [
    {
      label: "Trajectory",
      value: depthReady ? "tracked" : "needs depth",
      detail: `MD ${formatDepth(form.mdFt)} / TVD ${formatDepth(form.tvdFt)}.`,
    },
    {
      label: "Hydraulics",
      value: form.mudWeight.trim() ? "drafted" : "needs mud",
      detail: `Mud ${form.mudWeight || "not entered"}; confirm flow, SPP, ECD, and rheology from source.`,
    },
    {
      label: "Well control",
      value: safetyReady ? "noted" : "needs note",
      detail: safetyReady ? "Safety and barrier notes are present." : "Confirm BOP, pressure-control, and handover barriers.",
    },
    {
      label: "Schematic",
      value: casing.length > 0 ? "rendered" : "needs casing",
      detail: `${casing.length} casing string(s) with shoe-depth context.`,
    },
    {
      label: "Timeline",
      value: `${activities.length} blocks`,
      detail: "24 hr activity blocks are ready for source review.",
    },
    {
      label: "Issue gate",
      value: clientChecks.some((item) => item.startsWith("Add") || item.startsWith("Confirm")) ? "review" : "ready",
      detail: "Export only after citations and validation tasks are complete.",
    },
  ];
}

function fallbackText(value: string, fallback: string): string {
  return value.trim() || fallback;
}

function safeFilePart(value: string): string {
  const safe = value.trim().replace(/[^a-z0-9_-]+/gi, "_").replace(/^_+|_+$/g, "");
  return safe || "morning_report";
}

function renderMarkdownReport(
  form: ReportForm,
  summary: string,
  casing: CasingInterval[],
  activities: ActivitySegment[],
  standardSections: StandardReportSection[],
  aiPlan: AiExecutionStep[],
  clientChecks: string[]
): string {
  const casingRows = casing
    .map((item) => `- ${item.name}: ${item.od}, ${item.topFt.toLocaleString()} to ${item.shoeFt.toLocaleString()} ft, ${item.status}`)
    .join("\n");
  const activityRows = activities.map((item) => `- ${item.time}: ${item.description}`).join("\n");
  const standardRows = standardSections
    .map((item) => `- ${item.title}: ${item.status} - ${item.detail}`)
    .join("\n");
  const aiPlanRows = aiPlan.map((item) => `- ${item.step}: ${item.status} - ${item.detail}`).join("\n");
  const checklistRows = clientChecks.map((item) => `- ${item}`).join("\n");
  return [
    "# Monday Report Morning Drilling Report",
    "",
    `Date: ${form.reportDate}`,
    `Report: ${form.reportNo}`,
    `Well: ${form.well}`,
    `Rig: ${form.rig}`,
    `Operator: ${form.operator}`,
    `Phase: ${form.phase}`,
    `Depth: MD ${formatDepth(form.mdFt)}, TVD ${formatDepth(form.tvdFt)}`,
    "",
    "## Executive Summary",
    summary,
    "",
    "## Standard Daily Report Format",
    standardRows,
    "",
    "## Present Operations",
    fallbackText(form.presentOps, "No present operations entered."),
    "",
    "## Next 24 Hr Plan",
    fallbackText(form.nextOps, "No next plan entered."),
    "",
    "## Safety And Well Control",
    fallbackText(form.safety, "No safety notes entered."),
    "",
    "## Risks And AI Watchlist",
    fallbackText(form.risks, "No risk watchlist entered."),
    "",
    "## Casing Program",
    casingRows,
    "",
    "## 24 Hr Activity Timeline",
    activityRows,
    "",
    "## AI Plan And Execution",
    aiPlanRows,
    "",
    "## Client Issue Checklist",
    checklistRows,
    ""
  ].join("\n");
}
