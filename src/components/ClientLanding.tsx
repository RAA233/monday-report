import type { JSX } from "react";
import {
  Archive,
  Bot,
  ClipboardCheck,
  Download,
  FileArchive,
  FileJson,
  FileSpreadsheet,
  FileText,
  FolderUp,
  Gauge,
  HardHat,
  Image,
  ListChecks,
  Mail,
  MessageSquareText,
  PackageCheck,
  ShieldCheck,
  UploadCloud
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { UploadInventoryItem } from "../data/domain";
import type { ApiFailureRecord, ApiMondayReport, ApiSession, ApiWorkspace } from "../lib/api";
import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";

type ClientLandingTarget = "chat" | "studio" | "upload" | "dashboard" | "validation" | "roadmap";

interface ClientLandingProps {
  session: ApiSession | null;
  workspaces: ApiWorkspace[];
  reports: ApiMondayReport[];
  failures: ApiFailureRecord[];
  inventory: UploadInventoryItem[];
  apiStatus: "checking" | "connected" | "offline";
  onNavigate: (view: ClientLandingTarget) => void;
}

interface FormatCapability {
  label: string;
  tokens: string;
  detail: string;
  icon: LucideIcon;
}

interface CommandAction {
  label: string;
  detail: string;
  view: ClientLandingTarget;
  icon: LucideIcon;
  tone: "primary" | "standard";
}

const importCapabilities: FormatCapability[] = [
  {
    label: "ZIP archives",
    tokens: ".zip",
    detail: "Safe expansion, child-file hashing, malware check, and queue audit.",
    icon: FileArchive
  },
  {
    label: "Folders",
    tokens: "directory",
    detail: "Browser folder intake keeps relative paths for rig report packs.",
    icon: FolderUp
  },
  {
    label: "PDF reports",
    tokens: ".pdf",
    detail: "Text, native table rows, DDR profile fields, and OCR routing.",
    icon: FileText
  },
  {
    label: "Excel sheets",
    tokens: ".xlsx .xls",
    detail: "Workbook and sheet locators support source-backed citations.",
    icon: FileSpreadsheet
  },
  {
    label: "Word docs",
    tokens: ".docx .doc",
    detail: "Sections and paragraphs become typed evidence chunks.",
    icon: FileText
  },
  {
    label: "Emails",
    tokens: ".eml .msg",
    detail: "Subject and message evidence routes into the review queue.",
    icon: Mail
  },
  {
    label: "Images",
    tokens: ".png .jpg .tiff",
    detail: "Scanned pages and photos route through the OCR path.",
    icon: Image
  },
  {
    label: "Flat files",
    tokens: ".csv .txt .log",
    detail: "Rows and lines are chunked with deterministic source locators.",
    icon: FileJson
  }
];

const exportCapabilities: FormatCapability[] = [
  {
    label: "JSON",
    tokens: "official export",
    detail: "Machine-readable report data, validation posture, and source coverage.",
    icon: FileJson
  },
  {
    label: "CSV",
    tokens: "official export",
    detail: "Tabular summary for partner review and downstream QA.",
    icon: FileSpreadsheet
  },
  {
    label: "HTML",
    tokens: "official export",
    detail: "Branded web-ready report with operations sections and citations.",
    icon: FileText
  },
  {
    label: "PDF",
    tokens: "official export",
    detail: "Client-facing report package with schematic and timeline.",
    icon: Download
  },
  {
    label: "XLSX",
    tokens: "official export",
    detail: "Workbook package for drilling, validation, and source tabs.",
    icon: FileSpreadsheet
  }
];

const commandActions: CommandAction[] = [
  {
    label: "Ask Local AI",
    detail: "Open chat for source-backed plans, summaries, and report actions.",
    view: "chat",
    icon: MessageSquareText,
    tone: "primary"
  },
  {
    label: "Draft morning report",
    detail: "Open Report Studio with DDR, BHA, mud, and survey variants.",
    view: "studio",
    icon: Bot,
    tone: "primary"
  },
  {
    label: "Import rig package",
    detail: "Upload ZIPs, folders, PDFs, sheets, docs, email, images, and logs.",
    view: "upload",
    icon: UploadCloud,
    tone: "standard"
  },
  {
    label: "Review issues",
    detail: "Clear validation tasks before official report exports.",
    view: "validation",
    icon: ClipboardCheck,
    tone: "standard"
  },
  {
    label: "Open dashboard",
    detail: "Inspect failures, NPT, confidence, and risk distribution.",
    view: "dashboard",
    icon: Gauge,
    tone: "standard"
  },
  {
    label: "Roadmap board",
    detail: "Track current slice, audited pull, GA proof, and package gate.",
    view: "roadmap",
    icon: ListChecks,
    tone: "standard"
  }
];

export function ClientLanding({
  session,
  workspaces,
  reports,
  failures,
  inventory,
  apiStatus,
  onNavigate
}: ClientLandingProps): JSX.Element {
  const rigRows = workspaces.map((workspace) => buildRigRow(workspace, reports, failures));
  const reportRows = [...reports]
    .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
    .slice(0, 8);
  const openReviews = failures.filter((failure) => failure.validation_status !== "validated").length;
  const exportedReports = reports.filter((report) => report.status === "approved" || report.status === "exported").length;
  const latestReport = reportRows[0] ?? null;

  return (
    <main className="view-stack client-landing">
      <section className="workspace-title client-title" aria-labelledby="client-landing-title">
        <div>
          <p className="eyebrow">Client landing</p>
          <h1 id="client-landing-title">Rigs and Monday Reports</h1>
          <p>
            Start from the live rig workspace list, open the MR list, import approved report packs,
            and export official Monday Report packages in every supported format.
          </p>
        </div>
        <div className="client-title-status">
          <Badge tone={apiStatusTone(apiStatus)}>{apiStatusLabel(apiStatus)}</Badge>
          <span>{session?.tenant.name ?? "Monday Report workspace"}</span>
        </div>
      </section>

      <section className="client-command-grid" aria-label="Client command actions">
        {commandActions.map((action) => {
          const Icon = action.icon;
          return (
            <button
              className={`client-command-card client-command-${action.tone}`}
              key={action.label}
              type="button"
              onClick={() => onNavigate(action.view)}
            >
              <span className="stage-icon" aria-hidden="true">
                <Icon size={18} />
              </span>
              <span>
                <strong>{action.label}</strong>
                <small>{action.detail}</small>
              </span>
            </button>
          );
        })}
      </section>

      <div className="metric-grid client-metric-grid">
        <MetricCard icon={HardHat} label="Rig workspaces" value={String(workspaces.length)} detail="live API assets" tone="blue" />
        <MetricCard icon={PackageCheck} label="MR list" value={String(reports.length)} detail={`${exportedReports} approved or exported`} tone="green" />
        <MetricCard icon={ShieldCheck} label="Open reviews" value={String(openReviews)} detail="must clear before issue" tone={openReviews > 0 ? "amber" : "green"} />
        <MetricCard icon={Archive} label="Files staged" value={String(inventory.length)} detail="current import basket" tone="blue" />
      </div>

      <section className="panel client-rig-panel" aria-labelledby="rig-mr-list-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Rig MR list</p>
            <h2 id="rig-mr-list-title">Rig workspace access</h2>
          </div>
          <Badge tone={rigRows.length > 0 ? "good" : "neutral"}>{rigRows.length} rig rows</Badge>
        </div>
        {rigRows.length === 0 ? (
          <div className="empty-state">
            <HardHat size={28} aria-hidden="true" />
            <p>No rig workspaces are available from the API yet.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rig / asset</th>
                  <th>Campaign</th>
                  <th>Failures</th>
                  <th>MRs</th>
                  <th>Latest MR</th>
                  <th>Reviews</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {rigRows.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <div className="stacked-cell">
                        <strong>{row.asset}</strong>
                        <span>{row.workspace}</span>
                      </div>
                    </td>
                    <td>{row.campaign}</td>
                    <td>{row.failures}</td>
                    <td>{row.reports}</td>
                    <td>{row.latestReport}</td>
                    <td>
                      <Badge tone={row.openReviews > 0 ? "warning" : "good"}>{row.openReviews} open</Badge>
                    </td>
                    <td>
                      <button className="secondary-action" type="button" onClick={() => onNavigate("studio")}>
                        Open studio
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="client-lower-grid" aria-label="MR list and format coverage">
        <article className="panel client-mr-panel" aria-labelledby="latest-mr-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">MR access</p>
              <h2 id="latest-mr-title">Latest Monday Reports</h2>
            </div>
            <Badge tone={latestReport ? "good" : "neutral"}>{latestReport ? latestReport.status : "empty"}</Badge>
          </div>
          {reportRows.length === 0 ? (
            <div className="empty-state">
              <FileText size={28} aria-hidden="true" />
              <p>No Monday Reports have been created for the current client workspace list.</p>
            </div>
          ) : (
            <div className="client-mr-list">
              {reportRows.map((report) => (
                <article className="client-mr-row" key={report.id}>
                  <div>
                    <strong>{reportTitle(report)}</strong>
                    <span>{workspaceLabel(report.workspace_id, workspaces)}</span>
                  </div>
                  <span>{formatDate(report.period_start)} to {formatDate(report.period_end)}</span>
                  <Badge tone={reportStatusTone(report.status)}>{report.status}</Badge>
                </article>
              ))}
            </div>
          )}
        </article>

        <article className="panel client-export-panel" aria-labelledby="export-format-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Export coverage</p>
              <h2 id="export-format-title">Official formats</h2>
            </div>
            <Badge tone="good">{exportCapabilities.length} formats</Badge>
          </div>
          <FormatGrid items={exportCapabilities} />
        </article>
      </section>

      <section className="panel client-import-panel" aria-labelledby="import-format-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Import coverage</p>
            <h2 id="import-format-title">Supported report intake</h2>
          </div>
          <Badge tone="info">{importCapabilities.length} families</Badge>
        </div>
        <FormatGrid items={importCapabilities} />
      </section>
    </main>
  );
}

function FormatGrid({ items }: { items: FormatCapability[] }): JSX.Element {
  return (
    <div className="client-format-grid">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <article className="client-format-row" key={item.label}>
            <div className="stage-icon" aria-hidden="true">
              <Icon size={17} />
            </div>
            <div>
              <strong>{item.label}</strong>
              <code>{item.tokens}</code>
              <p>{item.detail}</p>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function buildRigRow(workspace: ApiWorkspace, reports: ApiMondayReport[], failures: ApiFailureRecord[]) {
  const workspaceReports = reports.filter((report) => report.workspace_id === workspace.id);
  const workspaceFailures = failures.filter((failure) => failure.workspace_id === workspace.id);
  const latestReport = [...workspaceReports].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];

  return {
    id: workspace.id,
    asset: workspace.asset || workspace.name,
    workspace: workspace.name,
    campaign: workspace.campaign || "Not assigned",
    failures: workspaceFailures.length,
    reports: workspaceReports.length,
    latestReport: latestReport ? `${reportTitle(latestReport)} / ${formatDate(latestReport.created_at)}` : "No MR yet",
    openReviews: workspaceFailures.filter((failure) => failure.validation_status !== "validated").length
  };
}

function workspaceLabel(workspaceId: string, workspaces: ApiWorkspace[]): string {
  const workspace = workspaces.find((item) => item.id === workspaceId);
  return workspace ? `${workspace.asset || workspace.name} / ${workspace.name}` : workspaceId.slice(0, 8);
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

function apiStatusTone(status: ClientLandingProps["apiStatus"]): "neutral" | "good" | "warning" | "danger" {
  if (status === "connected") {
    return "good";
  }
  if (status === "checking") {
    return "warning";
  }
  return "danger";
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

function reportStatusTone(status: ApiMondayReport["status"]): "neutral" | "good" | "warning" | "info" {
  if (status === "approved" || status === "exported") {
    return "good";
  }
  if (status === "review") {
    return "warning";
  }
  return "info";
}
