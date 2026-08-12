import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ApiFailureRecord } from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import {
  EmptyState,
  ErrorState,
  Frame,
  GridCell,
  GridRow,
  GridTable,
  PageHeader,
  Skeleton,
  Tag,
  useRetryPresence
} from "../components/primitives";
import { apiUnreadReason, useWorkspace } from "../lib/workspace";

/**
 * Failure explorer.
 *
 * One shared read — the provider's `GET /failures` snapshot (gated on
 * view_source_documents) — filtered entirely client-side, so refining a filter
 * never issues another request. Every row is an extracted failure record with
 * its confidence and validation state; where a citation exists its locator is
 * shown, and where none does the row says so instead of borrowing one.
 */
const TEMPLATE = "1.6fr 1.1fr 0.7fr 0.7fr 0.9fr 1.3fr";

const SEVERITIES = ["All severities", "Critical", "High", "Medium", "Low"] as const;
const VALIDATION_STATES = [
  ["all", "All validation"],
  ["open", "Open"],
  ["validated", "Validated"],
  ["rejected", "Rejected"],
  ["conflict", "Conflict"]
] as const;

export function Failures() {
  const { activeWorkspace, apiStatus, failures, reloadFailures } = useWorkspace();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>("All severities");
  const [validation, setValidation] = useState<string>("all");

  const retry = useRetryPresence(failures.state);
  const all = failures.state === "ready" ? failures.data : null;

  const filtered = useMemo(() => {
    if (!all) return [];
    const needle = query.trim().toLowerCase();
    return all.filter((failure) => {
      if (severity !== "All severities" && failure.severity !== severity) return false;
      if (validation !== "all" && failure.validation_status !== validation) return false;
      if (!needle) return true;
      const haystack = [
        failure.event_type,
        failure.summary,
        failure.company,
        failure.tool_type,
        failure.tool_serial
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [all, query, severity, validation]);

  const filtersActive =
    query.trim().length > 0 || severity !== "All severities" || validation !== "all";

  return (
    <>
      <PageHeader
        kicker={`Investigation · ${activeWorkspace?.name ?? "no workspace"}`}
        title="Failure explorer"
        lede="Every extracted failure event in the tenant, with its severity, NPT, extraction confidence and validation state. Filters run over the list already read — refining one issues no further request."
        actions={
          <Tag tone="outline" style={{ fontSize: 13, padding: "6px 12px" }}>
            {all ? `${filtered.length} of ${all.length} shown` : "Not read"}
          </Tag>
        }
      />

      <Frame as="section" aria-label="Failure filters" style={{ padding: 14 }}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
          <div className="field" style={{ minWidth: 240, flex: "1 1 240px" }}>
            <label htmlFor="fx-query">Search</label>
            <input
              id="fx-query"
              className="input"
              placeholder="Event, summary, company, tool, serial"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="field" style={{ width: 160 }}>
            <label htmlFor="fx-severity">Severity</label>
            <select
              id="fx-severity"
              className="input"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as (typeof SEVERITIES)[number])}
            >
              {SEVERITIES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
          <div className="field" style={{ width: 160 }}>
            <label htmlFor="fx-validation">Validation</label>
            <select
              id="fx-validation"
              className="input"
              value={validation}
              onChange={(event) => setValidation(event.target.value)}
            >
              {VALIDATION_STATES.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Frame>

      {failures.state === "loading" ? <Skeleton rows={3} label="Loading failure records" /> : null}

      {failures.state === "unauthorized" ? (
        <ErrorState
          title="Failures not visible to this session"
          message="This session lacks the view_source_documents permission, so the failure list cannot be read here. This is not a statement that no failures exist — ask a workspace admin for source-document access."
        />
      ) : null}

      {retry.show ? (
        <ErrorState
          title="Failure list not read"
          message={
            retry.retrying
              ? "The list is being read again."
              : `${failures.state === "error" ? failures.message : ""} This is not a statement that no failures exist.`
          }
          onRetry={apiStatus === "connected" ? reloadFailures : undefined}
          retrying={retry.retrying}
        />
      ) : null}

      {all && all.length === 0 ? (
        <EmptyState
          title="No failure records"
          body="The tenant failure list was read and is empty. Failure records are extracted from uploaded reports by the worker's deterministic extractor."
          action={
            <Link className="btn btn-primary" to="/app/upload">
              Go to upload
            </Link>
          }
        />
      ) : null}

      {all && all.length > 0 && filtered.length === 0 ? (
        <EmptyState
          title="No failure matches these filters"
          body={`${all.length} failure record(s) were read; none matches the current filters. This is a filter result, not a statement about the workspace.`}
        />
      ) : null}

      {filtered.length > 0 ? (
        <GridTable
          label="Extracted failure events"
          columns={["Event", "Company / tool", "NPT", "Confidence", "Validation", "Source"]}
          template={TEMPLATE}
          minWidth={860}
        >
          {filtered.map((failure) => (
            <GridRow template={TEMPLATE} key={failure.id}>
              <GridCell style={{ minWidth: 0 }}>
                <span style={{ display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <Tag tone={failure.severity === "Critical" || failure.severity === "High" ? "critical" : "outline"}>
                      {failure.severity}
                    </Tag>
                    <strong style={{ fontFamily: "var(--font-heading)" }}>{failure.event_type}</strong>
                  </span>
                  <span className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.45, overflowWrap: "anywhere" }}>
                    {failure.summary}
                  </span>
                </span>
              </GridCell>
              <GridCell style={{ minWidth: 0 }}>
                <span style={{ display: "grid", gap: 2 }}>
                  <strong>{failure.company || "—"}</strong>
                  <span className="text-muted" style={{ fontSize: 11.5 }}>
                    {[failure.tool_type, failure.tool_serial].filter(Boolean).join(" · ") || "—"}
                  </span>
                </span>
              </GridCell>
              <GridCell>{failure.npt_hours.toFixed(1)} h</GridCell>
              <GridCell>{Math.round(failure.confidence * 100)}%</GridCell>
              <GridCell>
                <Tag
                  tone={
                    failure.validation_status === "validated"
                      ? "accent"
                      : failure.validation_status === "open" || failure.validation_status === "conflict"
                        ? "neutral"
                        : "outline"
                  }
                >
                  {failure.validation_status}
                </Tag>
              </GridCell>
              <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                {failure.citations[0]
                  ? `${formatSourceCitation(failure.citations[0].locator_type, failure.citations[0].locator)} · ${Math.round(failure.citations[0].confidence * 100)}%`
                  : "No citation attached"}
              </GridCell>
            </GridRow>
          ))}
        </GridTable>
      ) : null}

      {all && filtersActive && filtered.length > 0 ? (
        <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
          Filters applied client-side over the {all.length} record(s) already read.
        </p>
      ) : null}
    </>
  );
}
