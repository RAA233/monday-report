import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
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
import { exportGateMessage, useLoadable, useWorkspace } from "../lib/workspace";

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

function isGateRefusal(error: unknown): boolean {
  return error instanceof Error && error.message.includes("409");
}

export function Exports() {
  const { activeWorkspace, openValidationTasks, readOnly, showToast, apiStatus } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;

  const [issued, setIssued] = useState<Issued[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Record<string, { tone: "ok" | "bad"; text: string }>>({});

  const loadReports = useCallback(async () => {
    if (!workspaceId) return [] as ApiMondayReport[];
    return getMondayReports(workspaceId);
  }, [workspaceId]);

  const { value: reports, reload } = useLoadable(loadReports, [workspaceId]);

  // Export the newest report in the workspace — the one the Studio drafts against.
  const target =
    reports.state === "ready" && reports.data.length > 0 ? reports.data[reports.data.length - 1] : null;

  const gateClosed = openValidationTasks > 0;

  async function runExport(format: ApiReportExport["format"]) {
    if (!target || readOnly || busy) return;
    setBusy(format);
    setStatuses((current) => ({ ...current, [format]: { tone: "ok", text: `Creating ${format.toUpperCase()} export…` } }));
    try {
      const result = await exportMondayReport(target.id, format);
      setIssued((current) => [...current.filter((item) => item.id !== result.id), result]);
      setStatuses((current) => ({
        ...current,
        [format]: {
          tone: "ok",
          text: `${format.toUpperCase()} ready · ${sizeLabel(result.byte_size)} · SHA ${shortSha(result.sha256)}`
        }
      }));
      showToast(
        "Export ready",
        `${target.id} ${format.toUpperCase()} export written, checksummed, and appended to the audit chain. Fetch it with an expiring signed URL.`
      );
    } catch (caught) {
      const text = isGateRefusal(caught)
        ? exportGateMessage(openValidationTasks)
        : caught instanceof Error && caught.message
          ? `Export refused. ${caught.message}`
          : "Export refused. The workspace API did not answer.";
      setStatuses((current) => ({ ...current, [format]: { tone: "bad", text } }));
    } finally {
      setBusy(null);
    }
  }

  async function mintUrl(item: Issued) {
    if (readOnly) return;
    try {
      const signed = await createReportExportSignedUrl(item.id);
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
    }
  }

  return (
    <>
      <PageHeader
        kicker="Controlled handoff"
        title="Exports"
        lede="Official exports are validation-gated, checksummed, audit-logged, and fetched only through expiring signed URLs."
      />

      {gateClosed ? (
        <div
          role="status"
          style={{
            display: "flex",
            gap: 12,
            alignItems: "baseline",
            flexWrap: "wrap",
            border: "1px solid var(--color-text)",
            padding: "12px 16px"
          }}
        >
          <strong
            style={{
              fontFamily: "var(--font-heading)",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              fontSize: 13
            }}
          >
            Export gate closed
          </strong>
          <span style={{ fontSize: 13 }}>{exportGateMessage(openValidationTasks)}</span>
          <Link className="btn btn-ghost" to="/app/validation" style={{ minHeight: 0, padding: "0 4px" }}>
            Open the queue →
          </Link>
        </div>
      ) : (
        <div
          role="status"
          style={{
            display: "flex",
            gap: 12,
            alignItems: "baseline",
            flexWrap: "wrap",
            border: "1px solid var(--color-accent)",
            padding: "12px 16px"
          }}
        >
          <strong
            style={{
              fontFamily: "var(--font-heading)",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              fontSize: 13,
              color: "var(--color-accent-700)"
            }}
          >
            Export gate clear
          </strong>
          <span style={{ fontSize: 13 }}>
            No validation tasks are open — official exports of the current report are unlocked.
          </span>
        </div>
      )}

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
                    disabled={readOnly || gateClosed || busy !== null}
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
                  {item.signedUrl ? (
                    <a
                      className="btn btn-ghost"
                      href={item.signedUrl}
                      target="_blank"
                      rel="noreferrer"
                      style={{ minHeight: 0 }}
                    >
                      Open signed reference (expires {item.expiresAt})
                    </a>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => void mintUrl(item)}
                      disabled={readOnly}
                    >
                      Get signed URL
                    </button>
                  )}
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
