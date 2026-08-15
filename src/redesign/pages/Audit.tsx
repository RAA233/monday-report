import type { ApiAuditIntegrityStatus } from "../../lib/api";
import {
  Cells,
  EmptyState,
  ErrorState,
  Frame,
  PageHeader,
  Skeleton,
  Tag,
  useRetryPresence
} from "../components/primitives";
import { apiUnreadReason, useWorkspace } from "../lib/workspace";

/**
 * Audit chain.
 *
 * Both reads are the provider's shared, permission-gated snapshots
 * (view_audit_history): the integrity verdict from `GET /audit-logs/integrity`
 * and the newest entries from `GET /audit-logs`.
 *
 * `integrity_state` is the display authority. The backward-compatible `status`
 * field reports LINKAGE only — "sealed" means the hash chain links, keyed OR
 * unkeyed — so this view never presents a legacy or mixed chain as keyed, and
 * never uses the word "secure" for a chain that merely links. Redacted metadata
 * values are shown as their recorded digest, never reconstructed.
 */
export function integrityStateLabel(state: ApiAuditIntegrityStatus["integrity_state"]): string {
  switch (state) {
    case "keyed_valid":
      return "Verified";
    case "mixed_valid":
      return "Partly sealed";
    case "legacy_valid":
      return "Linked, not sealed";
    case "key_unavailable":
      return "Seal key unavailable";
    case "broken":
      return "Break detected";
    case "empty":
      return "No entries yet";
    default:
      return "Unknown";
  }
}

function integrityTone(state: ApiAuditIntegrityStatus["integrity_state"]): "accent" | "neutral" | "outline" | "critical" {
  switch (state) {
    case "keyed_valid":
      return "accent";
    case "mixed_valid":
    case "legacy_valid":
      return "neutral";
    case "key_unavailable":
    case "broken":
      return "critical";
    default:
      return "outline";
  }
}

function formatValue(value: unknown): string {
  if (
    value &&
    typeof value === "object" &&
    (value as { redacted?: unknown }).redacted === true &&
    typeof (value as { sha256?: unknown }).sha256 === "string"
  ) {
    return `redacted ${(value as { sha256: string }).sha256.slice(0, 10)}`;
  }
  if (Array.isArray(value)) return `${value.length} item(s)`;
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatMetadata(metadata: Record<string, unknown>): string {
  const entries = Object.entries(metadata);
  if (entries.length === 0) return "No details recorded.";
  return entries.map(([key, value]) => `${key}: ${formatValue(value)}`).join(" · ");
}

export function Audit() {
  const { apiStatus, auditIntegrity, auditLogs, reloadAuditLogs } = useWorkspace();
  const logsRetry = useRetryPresence(auditLogs.state);

  const integrity = auditIntegrity.state === "ready" ? auditIntegrity.data : null;
  const logs = auditLogs.state === "ready" ? auditLogs.data : null;

  return (
    <>
      <PageHeader
        kicker="Trust"
        title="Report integrity"
        lede="This workspace's activity record — every upload, decision, draft, correction and export lands here, and entries are only ever added, never changed or removed. The integrity result below is Monday Report's own; this page recomputes nothing."
        actions={
          integrity ? (
            <Tag
              tone={integrityTone(integrity.integrity_state ?? null)}
              data-integrity-state={integrity.integrity_state ?? "unknown"}
              style={{ fontSize: 13, padding: "6px 12px" }}
            >
              {integrityStateLabel(integrity.integrity_state ?? null)}
            </Tag>
          ) : (
            <Tag tone="outline" style={{ fontSize: 13, padding: "6px 12px" }}>
              {auditIntegrity.state === "loading" ? "Checking…" : "Integrity not read"}
            </Tag>
          )
        }
      />

      {auditIntegrity.state === "loading" ? <Skeleton rows={1} label="Reading the integrity result" /> : null}

      {auditIntegrity.state === "unauthorized" ? (
        <ErrorState
          title="Report integrity record not available here"
          message="This session doesn't have report-integrity access, so neither the integrity result nor the entries can be shown here. This doesn't say anything about the record's state — ask a workspace admin for report-integrity access."
        />
      ) : null}

      {auditIntegrity.state === "error" ? (
        <ErrorState
          title="Integrity result not read"
          message={`${auditIntegrity.message} This doesn't say the record is intact or broken — it just wasn't read.`}
        />
      ) : null}

      {integrity ? (
        <>
          <Cells
            label="Report integrity"
            min={130}
            items={[
              {
                label: "Integrity",
                value: integrityStateLabel(integrity.integrity_state ?? null),
                detail:
                  integrity.integrity_state === "keyed_valid"
                    ? "Every entry is cryptographically sealed and verifies"
                    : integrity.integrity_state === "mixed_valid" ||
                        integrity.integrity_state === "legacy_valid"
                      ? "Newer entries are sealed; older entries are hashed only and don't have the same protection against tampering"
                      : "See the detail below",
                ok:
                  integrity.integrity_state === "keyed_valid"
                    ? true
                    : integrity.integrity_state === "broken" ||
                        integrity.integrity_state === "key_unavailable"
                      ? false
                      : undefined
              },
              { label: "Entries", value: String(integrity.total_events) },
              {
                label: "Sealed",
                value: String(integrity.keyed_event_count ?? 0),
                detail: "Cryptographically sealed entries"
              },
              {
                label: "Hashed",
                value: String(integrity.legacy_event_count ?? integrity.legacy_events),
                detail: "Hashed but not sealed"
              },
              {
                label: "Breaks",
                value: String(integrity.broken_events),
                ok: integrity.broken_events === 0,
                detail: integrity.first_broken_event_id
                  ? `First break: ${integrity.first_broken_event_id.slice(0, 8)}…`
                  : "No break detected"
              },
              {
                label: "Active seal",
                value: integrity.active_key_id
                  ? `${integrity.active_key_id} v${integrity.active_key_version ?? "?"}`
                  : "None",
                detail: integrity.active_key_id
                  ? "New entries are sealed with this key"
                  : "No active seal key is configured"
              }
            ]}
          />
          <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "90ch" }}>
            Details: {integrity.detail}
          </p>
        </>
      ) : null}

      <Frame as="section" aria-label="Recent activity entries" style={{ padding: 18, display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            Recent entries
          </h2>
          <button
            type="button"
            className="btn btn-ghost"
            style={{ minHeight: 0, padding: "2px 6px", fontSize: 12 }}
            onClick={() => {
              if (logsRetry.retrying) return;
              reloadAuditLogs();
            }}
            disabled={apiStatus !== "connected" || auditLogs.state === "unauthorized"}
            aria-disabled={logsRetry.retrying || undefined}
          >
            Re-read the record
          </button>
        </div>

        {auditLogs.state === "loading" ? <Skeleton rows={3} label="Loading entries" /> : null}

        {auditLogs.state === "unauthorized" ? (
          <p role="status" style={{ fontSize: 13, margin: 0 }}>
            This session doesn't have <strong>report-integrity access</strong>, so the entries
            can't be shown here.
          </p>
        ) : null}

        {logsRetry.show ? (
          <ErrorState
            title="Entries not read"
            message={
              logsRetry.retrying
                ? "The record is being read again."
                : `${auditLogs.state === "error" ? auditLogs.message : ""} This doesn't mean the record is empty.`
            }
            onRetry={apiStatus === "connected" ? reloadAuditLogs : undefined}
            retrying={logsRetry.retrying}
          />
        ) : null}

        {logs && logs.length === 0 ? (
          <EmptyState
            title="No entries yet"
            body="This workspace's activity record was read and holds no entries yet. Every recorded action adds one."
          />
        ) : null}

        {logs && logs.length > 0 ? (
          <>
            <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
              Newest {logs.length} entr{logs.length === 1 ? "y" : "ies"} (this list is capped at the
              newest 200). Redacted values show only their recorded fingerprint — the original can't
              be recovered here.
            </p>
            <div style={{ display: "grid", gap: 8 }}>
              {logs.map((entry) => (
                <article
                  key={entry.id}
                  style={{ border: "1px solid var(--color-divider)", padding: "9px 12px", display: "grid", gap: 4, fontSize: 12.5 }}
                >
                  <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                    <strong style={{ fontFamily: "var(--font-heading)" }}>{entry.action}</strong>
                    <span className="text-muted" style={{ fontSize: 11.5 }}>
                      {entry.resource_type}
                      {entry.resource_id ? ` · ${entry.resource_id.slice(0, 8)}…` : ""} ·{" "}
                      {new Date(entry.created_at).toLocaleString()}
                    </span>
                    <span style={{ marginInlineStart: "auto", display: "flex", gap: 6 }}>
                      {entry.integrity_version === 2 ? (
                        <Tag tone="accent">Sealed{entry.key_id ? ` · ${entry.key_id}` : ""}</Tag>
                      ) : entry.entry_hash ? (
                        <Tag tone="outline">Hashed</Tag>
                      ) : (
                        <Tag tone="neutral">No hash</Tag>
                      )}
                    </span>
                  </div>
                  <span className="text-muted" style={{ lineHeight: 1.5, overflowWrap: "anywhere" }}>
                    {formatMetadata(entry.metadata)}
                  </span>
                </article>
              ))}
            </div>
          </>
        ) : null}
      </Frame>
    </>
  );
}
