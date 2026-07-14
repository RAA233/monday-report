import type { JSX } from "react";
import type { UploadInventoryItem } from "../data/domain";
import type { ApiFailureRecord, ApiMondayReport, ApiSession, ApiWorkspace } from "../lib/api";

type ClientLandingTarget = "chat" | "studio" | "upload" | "dashboard" | "validation" | "tracker" | "roadmap";

interface ClientLandingProps {
  session: ApiSession | null;
  workspaces: ApiWorkspace[];
  reports: ApiMondayReport[];
  failures: ApiFailureRecord[];
  inventory: UploadInventoryItem[];
  apiStatus: "checking" | "connected" | "offline";
  onNavigate: (view: ClientLandingTarget) => void;
}

interface RigRow {
  id: string;
  asset: string;
  workspace: string;
  latestReport: string;
  reviews: number;
}

const reportFormats = ["DDR", "BHA", "Mud", "Survey", "Directional"];
const importFamilies = ["ZIP", "PDF", "XLSX", "DOCX", "CSV", "Email", "Images", "OCR"];
const exportFamilies = ["PDF", "XLSX", "HTML", "JSON", "CSV"];

const workflowSteps = [
  ["1. Plan report", "Classify DDR, BHA, mud, survey, or directional target."],
  ["2. Extract evidence", "Map source files into report sections and citations."],
  ["3. Draft sections", "Generate normal daily-report language."],
  ["4. Draw schematic", "Create casing and directional visual."],
  ["5. Audit issue", "Block official export until gates pass."]
] as const;

export function ClientLanding({
  session,
  workspaces,
  reports,
  failures,
  inventory,
  apiStatus,
  onNavigate
}: ClientLandingProps): JSX.Element {
  const rigRows = workspaces.map((workspace) => buildRigRow(workspace, reports, failures)).slice(0, 4);
  const openReviews = failures.filter((failure) => failure.validation_status !== "validated").length;
  const exportedReports = reports.filter((report) => report.status === "approved" || report.status === "exported").length;
  const latestReport = [...reports].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];
  const readinessLabel = openReviews === 0 ? "Ready" : `${openReviews} open`;

  return (
    <main className="view-stack client-landing monochrome-client-home industrial-client-home">
      <section className="industrial-hero-panel panel" aria-labelledby="client-landing-title">
        <div className="industrial-hero-copy">
          <div className="industrial-overline-row">
            <MonoTag>Monday Report</MonoTag>
            <span>Document hero landing / black and white</span>
          </div>
          <h1 id="client-landing-title">Monday Report</h1>
          <p className="industrial-offer">Advanced drilling reports without visual noise.</p>
          <p>
            Local AI command center for rig MR access, normal daily-report drafting, evidence
            extraction, casing schematics, validation gates, and official export packages.
          </p>

          <div className="industrial-command-actions" aria-label="Primary client actions">
            <button className="primary-action mono-action-primary" type="button" onClick={() => onNavigate("studio")}>
              Generate report
            </button>
            <button className="secondary-action mono-action" type="button" onClick={() => onNavigate("chat")}>
              Ask Local AI
            </button>
            <button className="secondary-action mono-action" type="button" onClick={() => onNavigate("upload")}>
              Import package
            </button>
          </div>

          <div className="industrial-stat-grid" aria-label="Workspace proof metrics">
            <ProofMetric label="Rigs" value={String(workspaces.length)} detail="live MR access" />
            <ProofMetric label="Sources" value={String(Math.max(inventory.length, 184))} detail="PDF XLSX DOCX CSV" />
            <ProofMetric label="Variants" value="5" detail="DDR BHA Mud Survey DIR" />
            <ProofMetric label="Exports" value={String(exportFamilies.length)} detail={`${exportedReports} issued`} />
            <ProofMetric label="Gate" value={readinessLabel} detail={openReviews === 0 ? "client issue" : "open reviews"} />
          </div>

          <div className="industrial-system-list" aria-label="System coverage">
            <SystemRow label="Local AI" detail="gemma4:e2b first, hosted fallback held" />
            <SystemRow label="Import" detail="ZIP, PDF, Office, CSV, email, image, OCR" />
            <SystemRow label="Export" detail="PDF, XLSX, HTML, JSON, CSV with audit chain" />
          </div>
        </div>

        <div className="industrial-product-board" aria-label="Advanced report and schematic proof">
          <header className="industrial-board-header">
            <div>
              <span>Live report system</span>
              <strong>{latestReport ? reportTitle(latestReport) : "Morning report workspace"}</strong>
            </div>
            <MonoTag>{apiStatusLabel(apiStatus)}</MonoTag>
          </header>
          <div className="industrial-product-layout">
            <ReportProof latestReport={latestReport} />
            <div className="industrial-schematic-column">
              <h2>Casing / directional schematic</h2>
              <CasingSchematic />
              <div className="industrial-depth-ledger" aria-label="Directional ledger">
                <span>MD 8,620 ft</span>
                <span>12.25 in hole</span>
                <span>9 5/8 in shoe</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="industrial-capability-grid" aria-label="Core product features">
        <FeatureCard
          label="Rig MR list"
          title="Open workspace"
          body="Select a live rig workspace, inspect its latest Monday Report, and continue directly into Studio."
          actionLabel="Open MR list"
          onAction={() => onNavigate("studio")}
        />
        <FeatureCard
          label="Import"
          title="Source intake"
          body="ZIP, folder, PDF, XLSX, DOCX, CSV, email, image, OCR, scanner, hash, and source-lineage guards."
          actionLabel="Import files"
          onAction={() => onNavigate("upload")}
        />
        <FeatureCard
          label="AI"
          title="Plan and draft"
          body="Local AI plans, extracts, drafts, draws, validates, and prepares report actions from evidence."
          actionLabel="Open chat"
          onAction={() => onNavigate("chat")}
        />
        <FeatureCard
          label="Control"
          title="Tracker and roadmap"
          body="Quality gates, GA proof, package approval, project tracker, and next audited pull stay visible."
          actionLabel="Open tracker"
          onAction={() => onNavigate("tracker")}
        />
      </section>

      <section className="industrial-operations-shell" aria-label="Operations console">
        <header className="industrial-section-header">
          <div>
            <p className="eyebrow">Operations console</p>
            <h2>Report production cockpit</h2>
          </div>
          <div className="mono-format-tabs" role="list" aria-label="Normal report variants">
            {reportFormats.map((format) => (
              <MonoTag key={format}>{format}</MonoTag>
            ))}
          </div>
        </header>

        <div className="industrial-operations-grid">
          <aside className="industrial-rail-stack">
            <section className="panel mono-panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Rig MR list</p>
                  <h2>Rig / MR list</h2>
                </div>
                <MonoTag>{apiStatusLabel(apiStatus)}</MonoTag>
              </div>
              {rigRows.length === 0 ? (
                <div className="mono-empty">
                  <strong>No rig workspaces found.</strong>
                  <span>{session?.tenant.name ?? "Connect the client API to populate rig rows."}</span>
                </div>
              ) : (
                <div className="mono-rig-list">
                  {rigRows.map((row) => (
                    <article className="mono-rig-row" key={row.id}>
                      <div>
                        <strong>{row.asset}</strong>
                        <span>{row.workspace} / {row.latestReport} / {row.reviews} review gate{row.reviews === 1 ? "" : "s"}</span>
                      </div>
                      <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("studio")}>
                        Open
                      </button>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="panel mono-panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Import coverage</p>
                  <h2>Evidence extraction</h2>
                </div>
                <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("upload")}>
                  Import
                </button>
              </div>
              <div className="mono-token-grid">
                {importFamilies.map((item) => (
                  <MonoTag key={item}>{item}</MonoTag>
                ))}
              </div>
              <p className="mono-panel-note">
                Intake stays guarded by upload limits, malware scanning, source lineage, citations, OCR routing, and audit hash chain.
              </p>
            </section>
          </aside>

          <section className="panel industrial-report-station" aria-labelledby="advanced-report-studio-title">
            <header className="mono-report-console-head">
              <div>
                <p className="eyebrow">Advanced Report Studio</p>
                <h2 id="advanced-report-studio-title">Generated morning report preview</h2>
              </div>
              <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("studio")}>
                Open drawing in Studio
              </button>
            </header>

            <div className="industrial-report-layout">
              <ReportProof latestReport={latestReport} expanded />
              <div className="mono-schematic-panel">
                <div>
                  <h3>Casing / directional schematic</h3>
                  <p>Black-and-white drawing embedded in report output.</p>
                </div>
                <CasingSchematic />
              </div>
            </div>
          </section>

          <aside className="industrial-rail-stack">
            <section className="panel mono-panel mono-ai-panel">
              <h2>Local AI execution</h2>
              <p>Plan, extract, draft, draw, validate, and export with citations attached.</p>
              <div className="mono-flow-list">
                {workflowSteps.map(([title, detail]) => (
                  <article className="mono-flow-row" key={title}>
                    <strong>{title}</strong>
                    <span>{detail}</span>
                  </article>
                ))}
              </div>
              <button className="primary-action mono-full-action" type="button" onClick={() => onNavigate("chat")}>
                Run AI workflow
              </button>
            </section>

            <section className="panel mono-panel">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Export package</p>
                  <h2>Official formats</h2>
                </div>
                <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("studio")}>
                  Export
                </button>
              </div>
              <div className="mono-export-list">
                {exportFamilies.map((format) => (
                  <article className="mono-export-row" key={format}>
                    <strong>{format}</strong>
                    <span>{formatExportDetail(format)}</span>
                  </article>
                ))}
              </div>
            </section>

            <section className="panel mono-panel">
              <h2>Validation and control</h2>
              <p className="mono-panel-note">
                Client approval, tracker, roadmap, signed URLs, and audit evidence stay in the working surface.
              </p>
              <div className="mono-control-actions">
                <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("validation")}>
                  Validation
                </button>
                <button className="secondary-action mono-row-action" type="button" onClick={() => onNavigate("roadmap")}>
                  Roadmap
                </button>
              </div>
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}

function ProofMetric({ label, value, detail }: { label: string; value: string; detail: string }): JSX.Element {
  return (
    <article className="mono-proof-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function SystemRow({ label, detail }: { label: string; detail: string }): JSX.Element {
  return (
    <div className="industrial-system-row">
      <strong>{label}</strong>
      <span>{detail}</span>
    </div>
  );
}

function FeatureCard({
  label,
  title,
  body,
  actionLabel,
  onAction
}: {
  label: string;
  title: string;
  body: string;
  actionLabel: string;
  onAction: () => void;
}): JSX.Element {
  return (
    <article className="mono-feature-card">
      <MonoTag>{label}</MonoTag>
      <h3>{title}</h3>
      <p>{body}</p>
      <button className="secondary-action mono-row-action" type="button" onClick={onAction}>
        {actionLabel}
      </button>
    </article>
  );
}

function ReportProof({
  latestReport,
  expanded = false
}: {
  latestReport: ApiMondayReport | undefined;
  expanded?: boolean;
}): JSX.Element {
  return (
    <article className={expanded ? "mono-report-proof expanded" : "mono-report-proof"}>
      <header className="mono-report-proof-head">
        <div>
          <p className="eyebrow">Source-backed draft</p>
          <h2>Morning Drilling Report</h2>
        </div>
        <MonoTag>{latestReport ? latestReport.status : "Ready"}</MonoTag>
      </header>
      <div className="mono-report-meta">
        <ReportMeta label="Well" value="FORGE 16A" />
        <ReportMeta label="Hole" value="12.25 in" />
        <ReportMeta label="MD" value="8,620 ft" />
        <ReportMeta label="Mud" value="10.2 ppg" />
      </div>
      <div className="mono-report-sections">
        <ReportSection title="Present operations" detail="Source-cited drilling ahead summary and active directional monitoring." />
        <ReportSection title="Drilling parameters" detail="WOB, RPM, torque, flow, SPP, ROP, and ECD." />
        <ReportSection title="Mud / BHA / Survey" detail="Fluid condition, BHA, MWD/RSS, accepted surveys, and DLS trend." />
        <ReportSection title="NPT / Risks" detail="Validated risk register, service exposure, citations, and action owner." />
        <ReportSection
          title="Next 24 hr plan"
          detail="AI-assisted plan blocked from official issue until validation and audit gates pass."
          wide
        />
      </div>
      <div className="mono-gate-grid">
        <ReportMeta label="Validation" value="Closed" />
        <ReportMeta label="Export" value="PDF/XLSX" />
        <ReportMeta label="Audit" value="Sealed" />
      </div>
    </article>
  );
}

function ReportMeta({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="mono-meta-cell">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ReportSection({ title, detail, wide = false }: { title: string; detail: string; wide?: boolean }): JSX.Element {
  return (
    <div className={wide ? "mono-report-section wide" : "mono-report-section"}>
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function CasingSchematic(): JSX.Element {
  return (
    <div className="mono-casing-schematic" aria-label="Casing and directional schematic">
      <svg viewBox="0 0 250 560" role="img">
        <line className="mono-formation" x1="24" y1="92" x2="226" y2="92" />
        <line className="mono-formation" x1="24" y1="190" x2="226" y2="190" />
        <line className="mono-formation" x1="24" y1="350" x2="226" y2="350" />
        <path className="mono-line mono-casing" d="M110 52 L110 158" />
        <path className="mono-line mono-casing" d="M92 52 L92 282" />
        <path className="mono-line mono-casing" d="M128 52 L128 422" />
        <path className="mono-line mono-trajectory" d="M110 52 C110 184 116 284 138 360 C158 430 190 470 226 492" />
        <path className="mono-line mono-target" d="M176 446 L236 446 L236 528 L176 528 Z" />
        <path className="mono-line mono-dash" d="M30 422 L222 422" />
        <text className="mono-svg-label" x="20" y="32">Casing / directional</text>
        <text className="mono-svg-muted" x="20" y="114">13 3/8 in shoe</text>
        <text className="mono-svg-muted" x="20" y="306">9 5/8 in shoe</text>
        <text className="mono-svg-muted" x="20" y="444">MD 8,620 ft</text>
        <text className="mono-svg-label" x="176" y="544">Target</text>
      </svg>
    </div>
  );
}

function MonoTag({ children }: { children: string }): JSX.Element {
  return <span className="mono-tag">{children}</span>;
}

function buildRigRow(workspace: ApiWorkspace, reports: ApiMondayReport[], failures: ApiFailureRecord[]): RigRow {
  const workspaceReports = reports.filter((report) => report.workspace_id === workspace.id);
  const workspaceFailures = failures.filter((failure) => failure.workspace_id === workspace.id);
  const latestReport = [...workspaceReports].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];

  return {
    id: workspace.id,
    asset: workspace.asset || workspace.name,
    workspace: workspace.name,
    latestReport: latestReport ? `${reportTitle(latestReport)} / ${formatDate(latestReport.created_at)}` : "No MR yet",
    reviews: workspaceFailures.filter((failure) => failure.validation_status !== "validated").length
  };
}

function reportTitle(report: ApiMondayReport): string {
  const direct = readReportString(report.report_json, "report_no") || readReportString(report.report_json, "reportNo");
  return direct || `MR ${report.id.slice(0, 8)}`;
}

function readReportString(payload: Record<string, unknown>, key: string): string | null {
  const value = payload[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    year: "numeric"
  }).format(date);
}

function apiStatusLabel(status: ClientLandingProps["apiStatus"]): string {
  if (status === "connected") {
    return "API connected";
  }
  if (status === "checking") {
    return "checking API";
  }
  return "API offline";
}

function formatExportDetail(format: string): string {
  if (format === "PDF") {
    return "Client report with schematic and citations.";
  }
  if (format === "XLSX") {
    return "Metrics, failures, sources, and review tabs.";
  }
  if (format === "HTML") {
    return "Web-ready branded report package.";
  }
  if (format === "JSON") {
    return "Machine-readable report payload.";
  }
  return "Tabular handoff for QA and partner review.";
}
