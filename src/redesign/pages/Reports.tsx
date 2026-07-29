import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createMondayReport, getMondayReports, type ApiMondayReport } from "../../lib/api";
import {
  EmptyState,
  ErrorState,
  Frame,
  GridCell,
  GridRow,
  GridTable,
  PageHeader,
  Skeleton,
  Tag
} from "../components/primitives";
import { exportGateMessage, useLoadable, useWorkspace } from "../lib/workspace";

/**
 * Monday reports.
 *
 * The gate column is the same open-validation count the Exports view enforces and
 * the sidebar badge shows — one source of truth, so a report can never look clear
 * here and be refused there.
 */
const TEMPLATE = "130px 1.2fr auto auto 0.7fr 0.7fr auto";

const STATUS_TONE: Record<ApiMondayReport["status"], "accent" | "neutral" | "outline"> = {
  draft: "outline",
  review: "neutral",
  approved: "accent",
  exported: "accent"
};

function isoDay(value: string): string {
  // Server dates are ISO; show the date part without inventing a locale format.
  return value.slice(0, 10);
}

/**
 * Report ids are server-generated UUIDs. The column shows a marked abbreviation
 * and carries the full value in `title` — a shortened identifier, never a
 * different one, and never a label the backend does not use.
 */
function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

export function Reports() {
  const navigate = useNavigate();
  const { activeWorkspace, openValidationTasks, readOnly, showToast, apiStatus } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!workspaceId) return [] as ApiMondayReport[];
    return getMondayReports(workspaceId);
  }, [workspaceId]);

  const { value, reload } = useLoadable(load, [workspaceId]);

  const gateLabel = openValidationTasks === 0 ? "Clear" : `${openValidationTasks} open`;

  async function createReport() {
    if (!workspaceId || readOnly || creating) return;
    setCreating(true);
    try {
      // A Monday week: today back to the previous Monday is not derivable without
      // guessing intent, so the period is the current ISO week containing today.
      const now = new Date();
      const day = (now.getUTCDay() + 6) % 7; // 0 = Monday
      const monday = new Date(now);
      monday.setUTCDate(now.getUTCDate() - day);
      const sunday = new Date(monday);
      sunday.setUTCDate(monday.getUTCDate() + 6);
      const report = await createMondayReport({
        workspaceId,
        periodStart: monday.toISOString().slice(0, 10),
        periodEnd: sunday.toISOString().slice(0, 10)
      });
      showToast(
        "Report created",
        `${report.id} opened as a ${report.status} for ${isoDay(report.period_start)} – ${isoDay(
          report.period_end
        )} and appended to the audit chain.`
      );
      reload();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "The request did not complete.";
      showToast("Not created", `The report was not created. ${message}`);
    } finally {
      setCreating(false);
    }
  }

  const newReportButton = (
    <button
      type="button"
      className="btn btn-primary"
      onClick={() => void createReport()}
      disabled={readOnly || creating || !workspaceId}
    >
      {creating ? "Creating…" : "New Monday report"}
    </button>
  );

  return (
    <>
      <PageHeader
        kicker={activeWorkspace?.name ?? "No workspace"}
        title="Monday reports"
        lede="Weekly reports move draft → review → approved → exported. Official export stays blocked while validation tasks are open."
        actions={newReportButton}
      />

      {value.state === "loading" ? <Skeleton rows={3} label="Loading Monday reports" /> : null}

      {value.state === "error" ? (
        <ErrorState
          title="Report list failed to load"
          message={`${value.message} The list is unavailable — retry, or check that the backend is running.`}
          onRetry={reload}
        />
      ) : null}

      {value.state === "ready" && value.data.length === 0 ? (
        <EmptyState
          title="No Monday reports yet"
          body={
            apiStatus === "connected"
              ? "Create the first report for this workspace, or build a source-backed draft in the Studio once evidence is processed."
              : "The workspace API is unreachable, so no report list could be read. This is not a confirmation that the workspace is empty."
          }
          action={newReportButton}
        />
      ) : null}

      {value.state === "ready" && value.data.length > 0 ? (
        <>
          <Frame style={{ padding: "4px 18px 12px" }}>
            <GridTable
              label="Monday reports"
              template={TEMPLATE}
              minWidth={760}
              columns={["Report", "Period", "Status", "Validation gate", "Exports", "Created", ""]}
            >
              {value.data.map((report) => (
                <GridRow template={TEMPLATE} key={report.id}>
                  <GridCell style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>
                    <span title={report.id}>{shortId(report.id)}</span>
                  </GridCell>
                  <GridCell style={{ fontSize: 13.5 }}>
                    {isoDay(report.period_start)} – {isoDay(report.period_end)}
                  </GridCell>
                  <GridCell>
                    <Tag tone={STATUS_TONE[report.status]}>{report.status}</Tag>
                  </GridCell>
                  <GridCell>
                    <Tag tone={openValidationTasks > 0 ? "critical" : "outline"}>{gateLabel}</Tag>
                  </GridCell>
                  <GridCell>
                    <span className="text-muted" style={{ fontSize: 13 }}>
                      {report.status === "exported" ? "Exported" : "—"}
                    </span>
                  </GridCell>
                  <GridCell>
                    <span className="text-muted" style={{ fontSize: 13 }}>
                      {isoDay(report.created_at)}
                    </span>
                  </GridCell>
                  <GridCell style={{ textAlign: "end" }}>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => navigate(`/app/reports/${encodeURIComponent(report.id)}/draft`)}
                    >
                      Open
                    </button>
                  </GridCell>
                </GridRow>
              ))}
            </GridTable>
          </Frame>

          <p className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
            Status chain: draft → review → approved → exported. Every transition and export is appended
            to the audit chain.
          </p>

          {openValidationTasks > 0 ? (
            <p role="status" style={{ fontSize: 12.5, margin: 0, color: "var(--color-accent-800)" }}>
              {exportGateMessage(openValidationTasks)}
            </p>
          ) : null}
        </>
      ) : null}
    </>
  );
}
