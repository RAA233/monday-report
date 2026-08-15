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
      return "keyed (HMAC)";
    case "mixed_valid":
      return "mixed — keyed suffix, unkeyed history";
    case "legacy_valid":
      return "legacy — unkeyed";
    case "key_unavailable":
      return "key unavailable";
    case "broken":
      return "broken";
    case "empty":
      return "empty";
    default:
      return "unknown";
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
  if (entries.length === 0) return "No metadata recorded.";
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
        lede="The tenant's append-only, hash-chained audit log: every upload, decision, draft, correction and export lands here. The integrity verdict below is the backend's own — this view recomputes nothing."
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

      {auditIntegrity.state === "loading" ? <Skeleton rows={1} label="Reading the integrity verdict" /> : null}

      {auditIntegrity.state === "unauthorized" ? (
        <ErrorState
          title="Audit history not visible to this session"
          message="This session lacks the view_audit_history permission, so neither the integrity verdict nor the entries can be read here. This is not a statement about the chain's state — ask a workspace admin for audit access."
        />
      ) : null}

      {auditIntegrity.state === "error" ? (
        <ErrorState
          title="Integrity verdict not read"
          message={`${auditIntegrity.message} This is not a statement that the chain is intact or broken — it was not read.`}
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
                    ? "Every event verifies under the active HMAC key"
                    : integrity.integrity_state === "mixed_valid" ||
                        integrity.integrity_state === "legacy_valid"
                      ? "The chain links, but unkeyed history is not tamper-evident against a writer who can recompute hashes"
                      : "See the backend detail below",
                ok:
                  integrity.integrity_state === "keyed_valid"
                    ? true
                    : integrity.integrity_state === "broken" ||
                        integrity.integrity_state === "key_unavailable"
                      ? false
                      : undefined
              },
              { label: "Events", value: String(integrity.total_events) },
              {
                label: "Keyed",
                value: String(integrity.keyed_event_count ?? 0),
                detail: "HMAC-signed events"
              },
              {
                label: "Legacy",
                value: String(integrity.legacy_event_count ?? integrity.legacy_events),
                detail: "Unkeyed SHA-256 events"
              },
              {
                label: "Broken",
                value: String(integrity.broken_events),
                ok: integrity.broken_events === 0,
                detail: integrity.first_broken_event_id
                  ? `First broken: ${integrity.first_broken_event_id.slice(0, 8)}…`
                  : "No break detected"
              },
              {
                label: "Active key",
                value: integrity.active_key_id
                  ? `${integrity.active_key_id} v${integrity.active_key_version ?? "?"}`
                  : "None",
                detail: integrity.active_key_id
                  ? "New events sign under this key"
                  : "No active audit key is configured"
              }
            ]}
          />
          <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "90ch" }}>
            Backend detail: {integrity.detail}
          </p>
        </>
      ) : null}

      <Frame as="section" aria-label="Recent audit entries" style={{ padding: 18, display: "grid", gap: 12 }}>
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
            Re-read the log
          </button>
        </div>

        {auditLogs.state === "loading" ? <Skeleton rows={3} label="Loading audit entries" /> : null}

        {auditLogs.state === "unauthorized" ? (
          <p role="status" style={{ fontSize: 13, margin: 0 }}>
            This session lacks the <strong>view_audit_history</strong> permission, so the entries
            cannot be read here.
          </p>
        ) : null}

        {logsRetry.show ? (
          <ErrorState
            title="Entries not read"
            message={
              logsRetry.retrying
                ? "The log is being read again."
                : `${auditLogs.state === "error" ? auditLogs.message : ""} This is not a statement that the log is empty.`
            }
            onRetry={apiStatus === "connected" ? reloadAuditLogs : undefined}
            retrying={logsRetry.retrying}
          />
        ) : null}

        {logs && logs.length === 0 ? (
          <EmptyState
            title="No audit entries"
            body="The tenant audit log was read and holds no entries yet. Every audited action appends one."
          />
        ) : null}

        {logs && logs.length > 0 ? (
          <>
            <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
              Newest {logs.length} entr{logs.length === 1 ? "y" : "ies"} (the API caps this read at
              200). Redacted metadata values show their recorded digest — the original value is not
              retrievable here.
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
                        <Tag tone="accent">keyed{entry.key_id ? ` · ${entry.key_id}` : ""}</Tag>
                      ) : entry.entry_hash ? (
                        <Tag tone="outline">legacy hash</Tag>
                      ) : (
                        <Tag tone="neutral">unhashed</Tag>
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
