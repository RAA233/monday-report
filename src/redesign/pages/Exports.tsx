import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  createReportExportSignedUrl,
  exportMondayReport,
  getMondayReports,
  type ApiMondayReport,
  type ApiReportExport
} from "../../lib/api";
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
  exportGateMessage,
  gateIsClosed,
  newestReport,
  useLoadable,
  useWorkspace,
  type GateState
} from "../lib/workspace";

/**
 * Exports.
 *
 * The gate here is not a client-side courtesy. `POST /monday-reports/{id}/exports`
 * answers 409 while any validation task is open, and this view surfaces that
 * refusal verbatim through the committed gate copy. The button is also disabled
 * while the gate is closed, so the two agree — but the backend remains the
 * authority, and a 409 arriving anyway is displayed rather than swallowed.
 *
 * Storage URIs are never rendered. Access is only ever a freshly minted expiring
 * signed URL, and each issuance is audit-logged server-side.
 */
const FORMATS: Array<{ format: ApiReportExport["format"]; label: string; detail: string }> = [
  { format: "pdf", label: "PDF", detail: "Issue-ready report document for client handoff." },
  { format: "xlsx", label: "XLSX", detail: "Workbook of report tables for operator systems." },
  { format: "html", label: "HTML", detail: "Self-contained rendering for review in a browser." },
  { format: "json", label: "JSON", detail: "Full report payload for downstream integration." },
  { format: "csv", label: "CSV", detail: "Flat record extract for spreadsheets and pipelines." }
];

const TEMPLATE = "130px 70px 90px 150px 110px 1fr";

interface Issued extends ApiReportExport {
  signedUrl?: string;
  expiresAt?: string;
}

/**
 * The gate banner. Five states, and only one of them says "clear".
 *
 * `unauthorized` and `error` are explicitly NOT gate verdicts: they say the gate
 * was not read and that the backend still enforces it. Neither is presented as an
 * empty queue.
 */
function GateBanner({ gate, onRetry }: { gate: GateState; onRetry: () => void }) {
  // An unread gate is NOT a breach: it is styled neutrally, never like a closed gate.
  const frame = (accent: boolean) => ({
    display: "flex" as const,
    gap: 12,
    alignItems: "baseline" as const,
    flexWrap: "wrap" as const,
    border: `1px solid ${accent ? "var(--color-accent)" : "var(--color-text)"}`,
    padding: "12px 16px"
  });
  const heading = (accent: boolean) => ({
    fontFamily: "var(--font-heading)",
    textTransform: "uppercase" as const,
    letterSpacing: "0.05em",
    fontSize: 13,
    ...(accent ? { color: "var(--color-accent-700)" } : {})
  });

  if (gate.state === "ready" && !gate.clear) {
    return (
      <div role="status" style={frame(false)}>
        <strong style={heading(false)}>Export gate closed</strong>
        <span style={{ fontSize: 13 }}>{exportGateMessage(gate.openTasks)}</span>
        <Link className="btn btn-ghost" to="/app/validation" style={{ minHeight: 0, padding: "0 4px" }}>
          Open the queue →
        </Link>
      </div>
    );
  }
  if (gate.state === "ready") {
    return (
      <div role="status" style={frame(true)}>
        <strong style={heading(true)}>Export gate clear</strong>
        <span style={{ fontSize: 13 }}>
          The backend reports no unresolved validation tasks for this report's workspace — official
          exports are unlocked.
        </span>
      </div>
    );
  }
  if (gate.state === "loading") {
    return (
      <div role="status" style={frame(false)}>
        <strong style={heading(false)}>Checking the export gate</strong>
        <span style={{ fontSize: 13 }}>Reading the gate from the backend…</span>
      </div>
    );
  }
  if (gate.state === "unauthorized") {
    return (
      <div role="status" style={frame(false)}>
        <strong style={heading(false)}>Export gate not visible</strong>
        <span style={{ fontSize: 13 }}>
          This session may not read the validation gate, so it is not shown here. That is not a
          statement that the queue is empty — the backend enforces the gate on every export and will
          refuse with the open-task count if any remain.
        </span>
      </div>
    );
  }
  if (gate.state === "error") {
    return (
      <div role="status" style={frame(false)}>
        <strong style={heading(false)}>Export gate unknown</strong>
        <span style={{ fontSize: 13 }}>
          The gate could not be read, so it cannot be shown. This is not a statement that the queue is
          empty — the backend still enforces it on every export.
        </span>
        <button type="button" className="btn btn-ghost" style={{ minHeight: 0, padding: "0 4px" }} onClick={onRetry}>
          Retry
        </button>
      </div>
    );
  }
  return (
    <div role="status" style={frame(false)}>
      <strong style={heading(false)}>Export gate unavailable</strong>
      <span style={{ fontSize: 13 }}>
        No workspace is resolved, so there is no gate to evaluate and nothing to export.
      </span>
    </div>
  );
}

function shortSha(sha: string): string {
  return sha.slice(0, 12);
}

/** Marked abbreviation of a server-generated UUID; the full value goes in `title`. */
function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * A 409 alone does not mean the validation gate. The export route answers 409 with
 * "Report has unresolved validation tasks" for the gate, but also with
 * "Signing secret is required in client data mode" for an unrelated cause — so the
 * detail, not the status, decides. Anything else is shown verbatim rather than
 * mislabelled as a gate refusal.
 */
function isGateRefusal(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.message.includes("409") &&
    /unresolved validation task/i.test(error.message)
  );
}

export function Exports() {
  const { activeWorkspace, gate, reloadGate, reloadValidationTasks, readOnly, can, showToast, apiStatus } =
    useWorkspace();
  const [searchParams] = useSearchParams();
  const workspaceId = activeWorkspace?.id ?? null;
  const workspaceIdRef = useRef(workspaceId);
  workspaceIdRef.current = workspaceId;

  const [issued, setIssued] = useState<Issued[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [minting, setMinting] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Record<string, { tone: "ok" | "bad"; text: string }>>({});

  // Issued rows and per-format status belong to one workspace. Carrying them across
  // a switch would attribute another workspace's exports to this one.
  useEffect(() => {
    setIssued([]);
    setStatuses({});
    setBusy(null);
    setMinting(null);
  }, [workspaceId]);

  const loadReports = useCallback(async () => {
    if (!workspaceId) return [] as ApiMondayReport[];
    return getMondayReports(workspaceId);
  }, [workspaceId]);

  const { value: reports, reload } = useLoadable(loadReports, [workspaceId]);

  // The report to export. When a caller names one (the Studio links here with
  // ?report=<id>), THAT report is the target — silently exporting whichever is
  // newest would issue a different report than the one the operator was drafting.
  // The id is only honoured if it is actually in this workspace's list.
  const requestedReportId = searchParams.get("report");
  const requested =
    reports.state === "ready" && requestedReportId
      ? (reports.data.find((report) => report.id === requestedReportId) ?? null)
      : null;
  const target = reports.state === "ready" ? (requested ?? newestReport(reports.data)) : null;
  const requestedButMissing = Boolean(requestedReportId) && reports.state === "ready" && !requested;

  // The two routes require DIFFERENT permissions; the backend checks them
  // separately, so the UI must not collapse them into one capability.
  //   POST /monday-reports/{id}/exports/{fmt}  -> issue_client_reports
  //   POST /report-exports/{id}/signed-url     -> export_evidence
  const canIssueExport = can("issue_client_reports");
  const canFetchEvidence = can("export_evidence");

  // Only the backend's own "clear" enables the buttons. When the gate could not be
  // READ (unauthorized/error) the buttons stay enabled for a permitted user — the
  // backend still enforces the gate and answers 409, which is surfaced verbatim —
  // because a session that may export but may not read the queue must not be
  // stranded, and the banner says plainly that the gate is not being shown.
  const gateBlocksExport = gateIsClosed(gate);
  // Read inside async handlers: the captured render-time `gate` is stale by the
  // time an awaited request rejects.
  const gateRef = useRef(gate);
  gateRef.current = gate;
  const exportsBlocked = readOnly || !canIssueExport || gateBlocksExport;

  async function runExport(format: ApiReportExport["format"]) {
    if (!target || exportsBlocked || busy) return;
    // Captured so a resolution arriving after a workspace switch cannot attribute
    // this export, its toast, or its status text to the new workspace.
    const forWorkspace = workspaceId;
    const forReport = target.id;
    setBusy(format);
    setStatuses((current) => ({ ...current, [format]: { tone: "ok", text: `Creating ${format.toUpperCase()} export…` } }));
    try {
      const result = await exportMondayReport(forReport, format);
      if (forWorkspace !== workspaceIdRef.current) return;
      setIssued((current) => [...current.filter((item) => item.id !== result.id), result]);
      setStatuses((current) => ({
        ...current,
        [format]: {
          tone: "ok",
          text: `${format.toUpperCase()} ready · ${sizeLabel(result.byte_size)} · SHA ${shortSha(result.sha256)}`
        }
      }));
      // The backend sets the report to "exported"; re-read so the panel does not
      // keep showing the pre-export status.
      reload();
      showToast(
        "Export ready",
        `${shortId(forReport)} ${format.toUpperCase()} export written, checksummed, and appended to the audit chain. Fetch it with an expiring signed URL.`
      );
    } catch (caught) {
      if (forWorkspace !== workspaceIdRef.current) return;
      let text: string;
      if (isGateRefusal(caught)) {
        // The backend refused on the gate. Re-read the gate and the queue rather
        // than interpolating a number we may not have (which once produced
        // "Resolve 0 validation task(s)…").
        reloadGate();
        reloadValidationTasks();
        // The refusal itself mutates the report (status -> "review" plus a
        // validation block), so the panel's status line is stale until re-read.
        reload();
        const live = gateRef.current;
        text =
          live.state === "ready" && live.openTasks > 0
            ? exportGateMessage(live.openTasks)
            : "Export refused: the backend reports unresolved validation tasks for this report. Re-reading the gate — open Validation to resolve them.";
      } else {
        text =
          caught instanceof Error && caught.message
            ? `Export refused. ${caught.message}`
            : "Export refused. The workspace API did not answer.";
      }
      setStatuses((current) => ({ ...current, [format]: { tone: "bad", text } }));
    } finally {
      // Clear unconditionally: the reset effect also clears `busy`, and guarding on
      // workspace identity could leave a format pinned as "Exporting…" forever.
      setBusy((current) => (current === format ? null : current));
    }
  }

  async function mintUrl(item: Issued) {
    // Guard the in-flight request: a second click would mint a second token and
    // append a second audit event for one user intent.
    if (readOnly || !canFetchEvidence || minting) return;
    const forWorkspace = workspaceIdRef.current;
    setMinting(item.id);
    try {
      const signed = await createReportExportSignedUrl(item.id);
      // A workspace switch clears `issued`; without this the late response would
      // re-add the row under the new workspace.
      if (forWorkspace !== workspaceIdRef.current) return;
      setIssued((current) =>
        current.map((row) =>
          row.id === item.id ? { ...row, signedUrl: signed.url, expiresAt: signed.expires_at } : row
        )
      );
      showToast(
        "Signed URL issued",
        `A short-lived reference for the ${item.format.toUpperCase()} export was issued and audit-logged. It expires at ${signed.expires_at}.`
      );
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "The request did not complete.";
      showToast("No URL issued", `A signed reference was not issued. ${message}`);
    } finally {
      setMinting((current) => (current === item.id ? null : current));
    }
  }

  return (
    <>
      <PageHeader
        kicker="Controlled handoff"
        title="Exports"
        lede="Official exports are validation-gated, checksummed, audit-logged, and fetched only through expiring signed URLs."
      />

      <GateBanner gate={gate} onRetry={reloadGate} />

      {!readOnly && !canIssueExport ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          This session lacks <strong>issue_client_reports</strong>, so official exports stay disabled.
          The backend refuses the export route without it.
        </p>
      ) : null}

      {!readOnly && canIssueExport && !canFetchEvidence ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          This session can create exports but lacks <strong>export_evidence</strong>, so signed
          references cannot be issued from here.
        </p>
      ) : null}

      {requestedButMissing ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-text)", padding: "10px 14px", margin: 0 }}
        >
          The report named in the link is not in this workspace's report list, so it is not the target
          below. Check the workspace selector before exporting.
        </p>
      ) : null}

      {reports.state === "loading" ? <Skeleton rows={2} label="Loading reports" /> : null}

      {reports.state === "error" ? (
        <ErrorState
          title="Reports failed to load"
          message={`${reports.message} Without the report list there is nothing to export.`}
          onRetry={reload}
        />
      ) : null}

      {reports.state === "ready" && !target ? (
        <EmptyState
          title="No report to export"
          body={
            apiStatus === "connected"
              ? "This workspace has no Monday report yet. Create one first — exports are always issued against a report."
              : "The workspace API is unreachable, so the report list could not be read."
          }
          action={
            <Link className="btn btn-primary" to="/app/reports">
              Go to Monday reports
            </Link>
          }
        />
      ) : null}

      {target ? (
        <Frame as="section" style={{ padding: 18 }}>
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            New export — <span title={target.id}>{shortId(target.id)}</span>
          </h2>
          <p className="text-muted" style={{ fontSize: 12.5, margin: "6px 0 0" }}>
            {requested
              ? "This is the report you arrived from."
              : "No report was named, so this is the newest report in the workspace."}{" "}
            Five official formats. Each export records byte size and SHA-256, and appends to the audit
            chain. Report status: {target.status}.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(min(200px,100%),1fr))",
              gap: 14,
              marginTop: 14
            }}
          >
            {FORMATS.map((entry) => {
              const status = statuses[entry.format];
              return (
                <div
                  key={entry.format}
                  style={{
                    border: "1px solid var(--color-divider)",
                    padding: 13,
                    display: "grid",
                    gap: 8,
                    alignContent: "start"
                  }}
                >
                  <strong style={{ fontFamily: "var(--font-heading)", fontSize: 17, letterSpacing: "0.03em" }}>
                    {entry.label}
                  </strong>
                  <span style={{ fontSize: 12, lineHeight: 1.45, color: "var(--color-neutral-700)" }}>
                    {entry.detail}
                  </span>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => void runExport(entry.format)}
                    disabled={exportsBlocked || busy !== null}
                  >
                    {busy === entry.format ? "Exporting…" : `Export ${entry.label}`}
                  </button>
                  {status ? (
                    <span
                      role="status"
                      style={{
                        fontSize: 11.5,
                        lineHeight: 1.45,
                        border: "1px solid var(--color-divider)",
                        padding: "6px 8px",
                        fontFamily: "var(--font-heading)",
                        color: status.tone === "bad" ? "var(--color-accent-800)" : "var(--color-text)"
                      }}
                    >
                      {status.text}
                    </span>
                  ) : null}
                </div>
              );
            })}
          </div>
        </Frame>
      ) : null}

      <Frame as="section" style={{ padding: "4px 18px 12px" }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: "14px 0 0" }}>
          Issued exports
        </h2>
        {issued.length === 0 ? (
          <p className="text-muted" style={{ fontSize: 12.5, margin: "10px 0" }}>
            No export has been issued from this session. Exports issued earlier are recorded in the
            audit chain rather than listed here.
          </p>
        ) : (
          <GridTable
            label="Issued exports"
            template={TEMPLATE}
            minWidth={700}
            columns={["Report", "Format", "Size", "SHA-256", "Created", "Access"]}
          >
            {issued.map((item) => (
              <GridRow template={TEMPLATE} key={item.id}>
                <GridCell style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>
                  <span title={item.report_id}>{shortId(item.report_id)}</span>
                </GridCell>
                <GridCell>
                  <Tag tone="neutral">{item.format}</Tag>
                </GridCell>
                <GridCell style={{ fontSize: 13.5 }}>{sizeLabel(item.byte_size)}</GridCell>
                <GridCell style={{ fontFamily: "var(--font-heading)", color: "var(--color-accent-700)", fontSize: 13 }}>
                  {shortSha(item.sha256)}…
                </GridCell>
                <GridCell>
                  <span className="text-muted" style={{ fontSize: 13 }}>
                    {item.created_at.slice(0, 10)}
                  </span>
                </GridCell>
                <GridCell>
                  {/* A minted reference EXPIRES, so the mint action must remain
                      available afterwards — otherwise the row's only affordance
                      becomes a link that has already died. */}
                  <span style={{ display: "grid", gap: 4, justifyItems: "start" }}>
                    {item.signedUrl ? (
                      <a
                        className="btn btn-ghost"
                        href={item.signedUrl}
                        target="_blank"
                        rel="noreferrer"
                        style={{ minHeight: 0, whiteSpace: "normal", textAlign: "start" }}
                        aria-label={`Open the signed reference for the ${item.format.toUpperCase()} export of report ${shortId(item.report_id)}, expires ${item.expiresAt}`}
                      >
                        Open signed reference (expires {item.expiresAt})
                      </a>
                    ) : null}
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => void mintUrl(item)}
                      disabled={readOnly || !canFetchEvidence || minting !== null}
                      // Rows repeat this label, so the name states which export.
                      aria-label={`${item.signedUrl ? "Issue a fresh signed URL" : "Get a signed URL"} for the ${item.format.toUpperCase()} export of report ${shortId(item.report_id)}`}
                    >
                      {minting === item.id
                        ? "Issuing…"
                        : item.signedUrl
                          ? "Issue a fresh URL"
                          : "Get signed URL"}
                    </button>
                  </span>
                </GridCell>
              </GridRow>
            ))}
          </GridTable>
        )}
        <p className="text-muted" style={{ fontSize: 12, margin: "10px 0 2px" }}>
          Storage paths are never exposed — access is only ever through short-lived signed URLs, and
          every issuance is audit-logged.
        </p>
      </Frame>
    </>
  );
}
