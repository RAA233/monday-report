import { useEffect, useMemo, useState } from "react";
import type { JSX } from "react";
import {
  ClipboardCheck,
  Database,
  FilePenLine,
  Gauge,
  LayoutDashboard,
  MessageSquareText,
  SearchCheck,
  ShieldCheck,
  UploadCloud
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { ArchitectureView } from "./components/ArchitectureView";
import { Badge } from "./components/Badge";
import { ChatAnalyst } from "./components/ChatAnalyst";
import { Dashboard } from "./components/Dashboard";
import { FailureExplorer } from "./components/FailureExplorer";
import { SecurityStrip } from "./components/PipelineBoard";
import { ProjectTracker } from "./components/ProjectTracker";
import { ReportStudio } from "./components/ReportStudio";
import { UploadPanel } from "./components/UploadPanel";
import { ValidationQueue } from "./components/ValidationQueue";
import {
  defaultFilters,
  type FailureEvent,
  type FilterState,
  type UploadInventoryItem,
  type ValidationStatus
} from "./data/domain";
import {
  getFailures,
  getSession,
  getWorkspaces,
  type ApiCitation,
  type ApiFailureRecord,
  type ApiSession
} from "./lib/api";
import { summarizeMetrics } from "./lib/analytics";

type ViewKey =
  | "dashboard"
  | "upload"
  | "chat"
  | "studio"
  | "explorer"
  | "validation"
  | "tracker"
  | "architecture";

const navItems: Array<{
  key: ViewKey;
  label: string;
  icon: LucideIcon;
}> = [
  { key: "chat", label: "Local AI Chat", icon: MessageSquareText },
  { key: "studio", label: "Report Studio", icon: FilePenLine },
  { key: "upload", label: "Upload", icon: UploadCloud },
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "explorer", label: "Explorer", icon: SearchCheck },
  { key: "validation", label: "Validation", icon: ClipboardCheck },
  { key: "tracker", label: "Tracker", icon: Gauge },
  { key: "architecture", label: "Architecture", icon: Database }
];

export function App(): JSX.Element {
  const [activeView, setActiveView] = useState<ViewKey>("chat");
  const [events, setEvents] = useState<FailureEvent[]>([]);
  const [filters, setFilters] = useState<FilterState>(defaultFilters);
  const [inventory, setInventory] = useState<UploadInventoryItem[]>([]);
  const [apiSession, setApiSession] = useState<ApiSession | null>(null);
  const [apiWorkspaceId, setApiWorkspaceId] = useState<string | null>(null);
  const [apiStatus, setApiStatus] = useState<"checking" | "connected" | "offline">("checking");
  const metrics = useMemo(() => summarizeMetrics(events), [events]);

  useEffect(() => {
    let isMounted = true;

    async function loadApiContext(): Promise<void> {
      try {
        const [session, workspaces, failures] = await Promise.all([
          getSession(),
          getWorkspaces(),
          getFailures()
        ]);
        if (!isMounted) {
          return;
        }
        setApiSession(session);
        setApiWorkspaceId(workspaces[0]?.id ?? null);
        setEvents(failures.map(mapFailureRecord));
        setApiStatus("connected");
      } catch {
        if (isMounted) {
          setApiStatus("offline");
        }
      }
    }

    void loadApiContext();

    return () => {
      isMounted = false;
    };
  }, []);

  function updateValidationStatus(eventId: string, status: ValidationStatus): void {
    setEvents((current) =>
      current.map((event) => (event.id === eventId ? { ...event, validationStatus: status } : event))
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={24} />
          </div>
          <div>
            <strong>Monday</strong>
            <span>Report</span>
          </div>
        </div>

        <nav className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = item.key === activeView;
            return (
              <button
                key={item.key}
                className={isActive ? "is-active" : ""}
                type="button"
                onClick={() => setActiveView(item.key)}
                aria-current={isActive ? "page" : undefined}
              >
                <Icon size={18} aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </nav>

        <section className="tenant-card" aria-label="Tenant status">
          <span>Tenant</span>
          <strong>{apiSession?.tenant.name ?? "Not connected"}</strong>
          <Badge tone="good">isolated</Badge>
        </section>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <div>
            <p>Local AI workspace</p>
            <strong>
              {apiSession?.tenant.name ?? "Monday Report"} / chat-first rig intelligence
            </strong>
          </div>
          <div className="topbar-metrics" aria-label="Workspace summary">
            <span>{apiStatus === "connected" ? "API connected" : apiStatus === "checking" ? "checking API" : "local fallback"}</span>
            <span>{events.length} events</span>
            <span>{metrics.validationBacklog} reviews</span>
            <span>{inventory.length} files staged</span>
          </div>
        </header>

        <SecurityStrip />

        {apiStatus === "connected" && events.length === 0 && (
          <section className="empty-state" aria-live="polite">
            <strong>No extracted failures yet.</strong>
            <p>Upload and process client-approved evidence to populate the workspace.</p>
          </section>
        )}

        {activeView === "dashboard" && <Dashboard events={events} />}
        {activeView === "upload" && (
          <UploadPanel
            inventory={inventory}
            onInventoryChange={setInventory}
            workspaceId={apiWorkspaceId ?? undefined}
          />
        )}
        {activeView === "chat" && (
          <ChatAnalyst
            events={events}
            filters={filters}
            workspaceId={apiWorkspaceId ?? undefined}
          />
        )}
        {activeView === "studio" && <ReportStudio />}
        {activeView === "explorer" && (
          <FailureExplorer events={events} filters={filters} onFiltersChange={setFilters} />
        )}
        {activeView === "validation" && (
          <ValidationQueue events={events} onStatusChange={updateValidationStatus} />
        )}
        {activeView === "tracker" && <ProjectTracker />}
        {activeView === "architecture" && <ArchitectureView />}
      </div>
    </div>
  );
}

function mapFailureRecord(record: ApiFailureRecord): FailureEvent {
  return {
    id: record.id,
    eventType: record.event_type,
    eventDate: "Unspecified",
    well: "Unspecified",
    rig: "Unspecified",
    section: "Unspecified",
    holeSizeIn: 0,
    depthMdFt: 0,
    formation: "Unspecified",
    company: record.company || "Unspecified",
    toolType: record.tool_type || "Unspecified",
    toolName: "Unspecified",
    toolSerial: record.tool_serial || "Unspecified",
    summary: record.summary,
    rootCause: "Not extracted",
    recommendation: "Review source citations before action.",
    nptHours: record.npt_hours,
    costImpactUsd: 0,
    severity: record.severity,
    confidence: record.confidence,
    validationStatus: mapValidationStatus(record.validation_status),
    citations: record.citations.map(mapCitation)
  };
}

function mapValidationStatus(status: ApiFailureRecord["validation_status"]): ValidationStatus {
  if (status === "validated" || status === "rejected" || status === "conflict") {
    return status;
  }
  return "needs_review";
}

function mapCitation(citation: ApiCitation): FailureEvent["citations"][number] {
  const locator = citation.locator ?? {};
  const page = typeof locator.page === "number" ? locator.page : undefined;
  const row = typeof locator.row === "number" ? locator.row : undefined;
  const sheet = typeof locator.sheet === "string" ? locator.sheet : undefined;
  const file =
    typeof locator.file_path === "string"
      ? locator.file_path
      : citation.file_id
        ? `file:${citation.file_id}`
        : "Source file";

  return {
    id: citation.id,
    file,
    page,
    sheet,
    row,
    snippet: citation.snippet
  };
}
