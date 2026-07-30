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
import {
  apiUnreadReason,
  errorText,
  exportGateMessage,
  gateIsClear,
  gateIsClosed,
  gateLabel,
  useLoadable,
  useWorkspace
} from "../lib/workspace";

/**
 * Monday reports.
 *
 * The gate column shows the BACKEND's gate for this workspace (the same figure the
 * export route enforces), so a report cannot look clear here and be refused there.
 * It is deliberately NOT the sidebar badge, which counts the tenant-wide review
 * queue: those are different populations and the columns are labelled accordingly.
 */
// Definite widths, not `auto`: `.mr-table-head` and `.mr-table-row` are separate
// grid containers, so an `auto` track sizes to that ROW's content and the header
// stopped lining up with the cells beneath it.
const TEMPLATE = "130px 1.2fr 96px 112px 0.7fr 0.7fr 84px";

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
  const { activeWorkspace, gate, readOnly, can, showToast, apiStatus } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;
  const [creating, setCreating] = useState(false);
  // POST /monday-reports is gated on generate_reports by the backend.
  const canCreate = can("generate_reports");

  const load = useCallback(async () => {
    if (!workspaceId) return [] as ApiMondayReport[];
    return getMondayReports(workspaceId);
  }, [workspaceId]);

  const { value, reload } = useLoadable(load, [workspaceId]);

  // The gate label comes from the backend's own gate report, never a client
  // re-derivation: only "ready" can say clear or give a count.
  const gateText = gateLabel(gate);
  const gateIsGood = gateIsClear(gate);
  /**
   * `critical` is the design system's reserved solid inverted treatment, so it is
   * spent only on a gate the backend reported CLOSED. An unread gate (loading,
   * unauthorized, error, unavailable) is neutral — the same rule the Exports banner
   * follows — otherwise every row paints as a breach on first load, and permanently
   * for a session that may export but may not read the queue.
   */
  const gateTone = gate.state !== "ready" ? "neutral" : gateIsGood ? "outline" : "critical";
  // `load()` returns [] WITHOUT calling the API when no workspace is resolved, so an
  // empty array is not evidence that the workspace has no reports.
  const listWasRead = value.state === "ready" && workspaceId !== null;
  const unreadReason = apiUnreadReason(apiStatus) ?? "No workspace is resolved";

  async function createReport() {
    if (!workspaceId || readOnly || !canCreate || creating) return;
    setCreating(true);
    try {
      // The ISO week containing today, computed in UTC throughout so the derived
      // period does not shift by a day for operators west of UTC.
      const now = new Date();
      const monday = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - ((now.getUTCDay() + 6) % 7))
      );
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
      showToast("Not created", `The report was not created. ${errorText(caught)}`);
    } finally {
      setCreating(false);
    }
  }

  const newReportButton = (
    <button
      type="button"
      className="btn btn-primary"
      onClick={() => void createReport()}
      disabled={readOnly || !canCreate || creating || !workspaceId}
      title={
        !readOnly && !canCreate
          ? "This session lacks the generate_reports permission."
          : undefined
      }
    >
      {creating ? "Creating…" : "New Monday report"}
    </button>
  );

  return (
    <>
      <PageHeader
        kicker={activeWorkspace?.name ?? "No workspace"}
        title="Monday reports"
        lede="A report opens as a draft, or directly as review when the workspace already has open validation tasks; a refused export also moves it to review, and a completed export marks it exported. Official export stays blocked while validation tasks are open."
        actions={newReportButton}
      />

      {!readOnly && !canCreate ? (
        // Visible, not only in a `title=`: a disabled button is not hoverable in most
        // browsers and is skipped by keyboard focus, so the reason was unreachable.
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          This session lacks <strong>generate_reports</strong>, so new Monday reports cannot be
          created here. The backend refuses the create route without it.
        </p>
      ) : null}

      {value.state === "loading" ? <Skeleton rows={3} label="Loading Monday reports" /> : null}

      {value.state === "error" ? (
        <ErrorState
          title="Report list failed to load"
          message={`${value.message} The list is unavailable — retry, or check that the backend is running.`}
          onRetry={reload}
        />
      ) : null}

      {value.state === "ready" && !listWasRead ? (
        <EmptyState
          title="Report list not read"
          body={`${unreadReason}, so no report list could be read. This is not a confirmation that the workspace is empty.`}
        />
      ) : null}

      {listWasRead && value.data.length === 0 ? (
        <EmptyState
          title="No Monday reports yet"
          body="Create the first report for this workspace, or build a source-backed draft in the Studio once evidence is processed."
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
                    <Tag tone={gateTone} style={{ whiteSpace: "nowrap" }}>
                      {gateText}
                    </Tag>
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
                    {/* Every row repeats "Open", so the name identifies the report. */}
                    <button
                      type="button"
                      className="btn btn-ghost"
                      aria-label={`Open report ${shortId(report.id)} for ${isoDay(report.period_start)} to ${isoDay(report.period_end)}`}
                      onClick={() => navigate(`/app/reports/${encodeURIComponent(report.id)}/draft`)}
                    >
                      Open
                    </button>
                  </GridCell>
                </GridRow>
              ))}
            </GridTable>
          </Frame>

          {/* Only the transitions that exist. Creation is itself conditional: the backend
              opens a report as `review` when the workspace already has open validation
              tasks, and as `draft` otherwise. A gate-refused export also sets `review`; a
              completed export sets `exported`. `approved` is a schema value that no route
              writes, so advertising an approval step would describe a workflow the backend
              does not have. */}
          <p className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
            Recorded status: a report opens as a draft, or directly as review when the workspace
            already has open validation tasks. A refused export also moves one to review, and a
            completed export marks it exported. There is no approval step in this increment. Every
            report creation and export is appended to the audit chain.
          </p>

          {gateIsClosed(gate) && gate.state === "ready" ? (
            <p role="status" style={{ fontSize: 12.5, margin: 0, color: "var(--color-accent-800)" }}>
              {exportGateMessage(gate.openTasks)}
            </p>
          ) : null}
        </>
      ) : null}
    </>
  );
}
