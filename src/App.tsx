import { useEffect, useMemo, useState } from "react";
import type { JSX } from "react";
import {
  ClipboardCheck,
  Database,
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
import { UploadPanel } from "./components/UploadPanel";
import { ValidationQueue } from "./components/ValidationQueue";
import {
  defaultFilters,
  sampleFailures,
  type FailureEvent,
  type FilterState,
  type UploadInventoryItem,
  type ValidationStatus
} from "./data/domain";
import { getSession, getWorkspaces, type ApiSession } from "./lib/api";
import { summarizeMetrics } from "./lib/analytics";

type ViewKey = "dashboard" | "upload" | "chat" | "explorer" | "validation" | "tracker" | "architecture";

const navItems: Array<{
  key: ViewKey;
  label: string;
  icon: LucideIcon;
}> = [
  { key: "chat", label: "Local AI Chat", icon: MessageSquareText },
  { key: "upload", label: "Upload", icon: UploadCloud },
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "explorer", label: "Explorer", icon: SearchCheck },
  { key: "validation", label: "Validation", icon: ClipboardCheck },
  { key: "tracker", label: "Tracker", icon: Gauge },
  { key: "architecture", label: "Architecture", icon: Database }
];

export function App(): JSX.Element {
  const [activeView, setActiveView] = useState<ViewKey>("chat");
  const [events, setEvents] = useState<FailureEvent[]>(sampleFailures);
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
        const [session, workspaces] = await Promise.all([getSession(), getWorkspaces()]);
        if (!isMounted) {
          return;
        }
        setApiSession(session);
        setApiWorkspaceId(workspaces[0]?.id ?? null);
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
          <strong>NorthStar Drilling</strong>
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
