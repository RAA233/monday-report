import { useMemo, useState } from "react";
import {
  createBenchmarkMeasurement,
  dismissBenchmarkDiagnostic,
  updateBenchmarkValue,
  type ApiAnomalyEvent,
  type ApiDiagnosticAction
} from "../../lib/api";
import {
  Cells,
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
import {
  apiUnreadReason,
  errorText,
  isBackendRefusal,
  useWorkspace
} from "../lib/workspace";

/**
 * Benchmarking.
 *
 * The read is the provider's shared `GET /workspaces/{id}/benchmarking` snapshot
 * (view_benchmarks). The three mutations are gated on the PAYLOAD's own
 * permissions map — the backend's benchmark permission set for this session —
 * so a control is disabled exactly when the route would refuse it, and the
 * blocked state names the missing permission:
 *
 *   record measurement   POST …/benchmarking/measurements   review_anomalies
 *   dismiss diagnostic   PATCH …/diagnostics/{id}/dismiss   dismiss_anomalies
 *   adjust benchmark     PATCH /benchmarking/values/{id}    manage_benchmark_config
 *
 * Mutation failures keep the repository's honesty rule: only a proven 4xx may
 * claim "not recorded"; anything else reports the outcome as unknown, warns the
 * change may have landed, and offers a re-read.
 */
const COMPARISON_TEMPLATE = "1.2fr 1fr 0.9fr 0.9fr 1fr 1.2fr 1fr";
const VALUES_TEMPLATE = "1.2fr 1fr 0.8fr 0.9fr 0.9fr";

function num(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "Missing";
  return value.toLocaleString(undefined, { maximumFractionDigits: 1 });
}

export function Benchmarking() {
  const {
    activeWorkspace,
    apiStatus,
    benchmarking,
    reloadBenchmarking,
    readOnly,
    showToast
  } = useWorkspace();

  const [measurementValue, setMeasurementValue] = useState("");
  const [measurementSource, setMeasurementSource] = useState("Daily drilling record");
  const [dismissReasons, setDismissReasons] = useState<Record<string, string>>({});
  const [adjustId, setAdjustId] = useState("");
  const [adjustValue, setAdjustValue] = useState("");
  const [adjustReason, setAdjustReason] = useState("");
  const [mutating, setMutating] = useState(false);

  const status = benchmarking.state === "ready" ? benchmarking.data : null;
  const perms = status?.permissions ?? {};
  const permits = (permission: string) => perms[permission] === true;
  const retry = useRetryPresence(benchmarking.state);

  const gordon = status?.gordon_average_benchmark;
  const noble = status?.noble_top_quartile_benchmark;
  const criticalThreshold = typeof gordon === "number" ? gordon * 0.85 : null;

  const activeAnomalies = status?.active_anomalies ?? [];

  const measurementBlocked = readOnly || !permits("review_anomalies");
  const dismissBlocked = readOnly || !permits("dismiss_anomalies");
  const adjustBlocked = readOnly || !permits("manage_benchmark_config");

  const adjustTarget = useMemo(
    () => status?.benchmark_values.find((value) => value.id === adjustId) ?? null,
    [status, adjustId]
  );

  async function recordMeasurement() {
    if (measurementBlocked || mutating || !activeWorkspace) return;
    const value = Number.parseFloat(measurementValue);
    if (!Number.isFinite(value)) {
      showToast("Value required", "Enter a numeric ft/day value before recording a measurement.");
      return;
    }
    setMutating(true);
    try {
      await createBenchmarkMeasurement({
        workspaceId: activeWorkspace.id,
        metric: "feet_drilled_per_day",
        value,
        unit: "ft/day",
        dataSource: measurementSource.trim() || "Daily drilling record",
        confidenceStatus: "manual",
        sourceType: "daily_drilling_record",
        sourceIdentifier: measurementSource.trim() || "manual-ddr-entry",
        datasetVersion: "workspace-current"
      });
      setMeasurementValue("");
      showToast(
        "Measurement recorded",
        "The measurement was recorded, anomaly rules were evaluated, and the action was added to the report integrity record."
      );
      reloadBenchmarking();
    } catch (caught) {
      const refused = isBackendRefusal(caught);
      showToast(
        refused ? "Not recorded" : "Outcome unknown",
        refused
          ? `The measurement was not recorded. ${errorText(caught)}`
          : `The request did not complete, so whether the measurement reached Monday Report is unknown — it may have landed. Re-read the benchmarking status before recording it again. ${errorText(caught)}`
      );
    } finally {
      setMutating(false);
    }
  }

  async function dismissDiagnostic(anomaly: ApiAnomalyEvent, action: ApiDiagnosticAction) {
    if (dismissBlocked || mutating) return;
    const reason = dismissReasons[action.id]?.trim();
    if (!reason) {
      showToast("Reason required", "Dismissing a diagnostic recommendation needs a written reason for the report integrity record.");
      return;
    }
    setMutating(true);
    try {
      await dismissBenchmarkDiagnostic({ anomalyId: anomaly.id, actionId: action.id, reason });
      showToast(
        "Dismissed",
        `The ${action.module} recommendation was dismissed with your reason and added to the report integrity record.`
      );
      reloadBenchmarking();
    } catch (caught) {
      const refused = isBackendRefusal(caught);
      showToast(
        refused ? "Not recorded" : "Outcome unknown",
        refused
          ? `The dismissal was not recorded. ${errorText(caught)}`
          : `The request did not complete, so whether the dismissal reached Monday Report is unknown — it may have landed. Re-read the benchmarking status before dismissing again. ${errorText(caught)}`
      );
    } finally {
      setMutating(false);
    }
  }

  async function adjustBenchmark() {
    if (adjustBlocked || mutating) return;
    if (!adjustTarget) {
      showToast("Benchmark required", "Choose which approved benchmark value to adjust.");
      return;
    }
    const value = Number.parseFloat(adjustValue);
    if (!Number.isFinite(value)) {
      showToast("Value required", "Enter a numeric replacement value for the benchmark.");
      return;
    }
    const reason = adjustReason.trim();
    if (!reason) {
      showToast("Reason required", "Adjusting an approved benchmark needs a written reason for the report integrity record.");
      return;
    }
    setMutating(true);
    try {
      await updateBenchmarkValue({ benchmarkId: adjustTarget.id, value, reason });
      setAdjustValue("");
      setAdjustReason("");
      showToast(
        "Benchmark adjusted",
        `${adjustTarget.benchmark_name} was updated with your reason and added to the report integrity record.`
      );
      reloadBenchmarking();
    } catch (caught) {
      const refused = isBackendRefusal(caught);
      showToast(
        refused ? "Not recorded" : "Outcome unknown",
        refused
          ? `The benchmark was not changed. ${errorText(caught)}`
          : `The request did not complete, so whether the change reached Monday Report is unknown — it may have landed. Re-read the benchmarking status before adjusting again. ${errorText(caught)}`
      );
    } finally {
      setMutating(false);
    }
  }

  return (
    <>
      <PageHeader
        kicker={`Review · ${activeWorkspace?.name ?? "no workspace"}`}
        title="Benchmarking"
        lede="Current drilling performance against this workspace's approved benchmark configuration. Every change here — a recorded measurement, a dismissed diagnostic, an adjusted benchmark — is added to the tamper-evident report integrity record with your reason."
        actions={
          <Tag
            tone={activeAnomalies.some((item) => item.severity === "Critical") ? "critical" : "outline"}
            style={{ fontSize: 13, padding: "6px 12px" }}
          >
            {status
              ? `${activeAnomalies.length} active anomal${activeAnomalies.length === 1 ? "y" : "ies"}`
              : "Not read"}
          </Tag>
        }
      />

      {benchmarking.state === "loading" ? <Skeleton rows={4} label="Loading benchmarking status" /> : null}

      {benchmarking.state === "unauthorized" ? (
        <ErrorState
          title="Benchmarking not visible to this session"
          message="This session does not have benchmark access, so the benchmarking status cannot be read here. This is not a statement that no benchmarks or anomalies exist — ask a workspace admin for benchmark access."
        />
      ) : null}

      {retry.show ? (
        <ErrorState
          title="Benchmarking status not read"
          message={
            retry.retrying
              ? "The status is being read again."
              : `${benchmarking.state === "error" ? benchmarking.message : ""} This is not a statement that no benchmarks or anomalies exist.`
          }
          onRetry={apiStatus === "connected" ? reloadBenchmarking : undefined}
          retrying={retry.retrying}
        />
      ) : null}

      {status ? (
        <>
          <Cells
            label="Benchmark status"
            min={140}
            items={[
              {
                label: "Current ft/day",
                value: num(status.current_ft_per_day),
                detail: "Latest workspace measurement"
              },
              {
                label: "Seven-day average",
                value: num(status.seven_day_average_ft_per_day),
                detail: "Normalized ft/day trend"
              },
              { label: "Gordon average", value: num(gordon), detail: "Approved average benchmark" },
              {
                label: "Noble top quartile",
                value: num(noble),
                detail: "Performance gap benchmark"
              },
              {
                label: "Critical threshold",
                value: num(criticalThreshold),
                detail: "Gordon × 85%, from the approved rule set"
              }
            ]}
          />

          <Frame as="section" aria-label="Record a measurement" style={{ padding: 18, display: "grid", gap: 12 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Record daily drilling-rate measurement
            </h2>
            {measurementBlocked ? (
              <p role="status" className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
                {readOnly
                  ? `${apiUnreadReason(apiStatus) ?? "The workspace is not resolved"}, so no measurement can be recorded.`
                  : "This session does not have permission to record measurements."}
              </p>
            ) : (
              <p className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
                Recording evaluates the approved anomaly rules against the new reading and adds the
                action to the report integrity record.
              </p>
            )}
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
              <div className="field" style={{ width: 140 }}>
                <label htmlFor="bm-value">ft/day</label>
                <input
                  id="bm-value"
                  className="input"
                  inputMode="decimal"
                  placeholder="e.g. 430"
                  value={measurementValue}
                  onChange={(event) => setMeasurementValue(event.target.value)}
                  disabled={measurementBlocked}
                />
              </div>
              <div className="field" style={{ minWidth: 220 }}>
                <label htmlFor="bm-source">Source</label>
                <input
                  id="bm-source"
                  className="input"
                  value={measurementSource}
                  onChange={(event) => setMeasurementSource(event.target.value)}
                  disabled={measurementBlocked}
                />
              </div>
              <button
                type="button"
                className="btn btn-primary"
                data-perm="review_anomalies"
                onClick={() => void recordMeasurement()}
                disabled={measurementBlocked}
                aria-disabled={mutating || undefined}
              >
                {mutating ? "Recording…" : "Record measurement"}
              </button>
            </div>
          </Frame>

          <Frame as="section" aria-label="Metric comparisons" style={{ padding: 18, display: "grid", gap: 12 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Metric comparisons
            </h2>
            {status.comparisons.length > 0 ? (
              <GridTable
                label="Benchmark comparisons"
                columns={["Metric", "Benchmark", "Current", "Reference", "Variance", "Status", "Evidence"]}
                template={COMPARISON_TEMPLATE}
                minWidth={760}
              >
                {status.comparisons.map((item) => (
                  <GridRow template={COMPARISON_TEMPLATE} key={`${item.metric}-${item.benchmark_name}`}>
                    <GridCell>{item.metric.replace(/_/g, " ")}</GridCell>
                    <GridCell>{item.benchmark_name}</GridCell>
                    <GridCell>
                      {num(item.current_value)} {item.current_unit}
                    </GridCell>
                    <GridCell>
                      {num(item.benchmark_value)} {item.benchmark_unit}
                    </GridCell>
                    <GridCell>
                      {num(item.absolute_variance)} / {num(item.percentage_variance)}%
                    </GridCell>
                    <GridCell>
                      <Tag
                        tone={
                          item.performance_status === "Critical deviation"
                            ? "critical"
                            : item.performance_status === "Below benchmark" ||
                                item.performance_status === "Stale data"
                              ? "neutral"
                              : item.performance_status === "Insufficient data"
                                ? "outline"
                                : "accent"
                        }
                      >
                        {item.performance_status}
                      </Tag>
                    </GridCell>
                    <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                      {item.supporting_source}
                    </GridCell>
                  </GridRow>
                ))}
              </GridTable>
            ) : (
              <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                The status was read and carries no comparisons yet — record a measurement to produce
                one.
              </p>
            )}
          </Frame>

          <Frame as="section" aria-label="Active anomalies" style={{ padding: 18, display: "grid", gap: 12 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Active anomalies
            </h2>
            {activeAnomalies.length === 0 ? (
              <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                The status was read and reports no active benchmark anomalies. Missing or stale
                measurements remain visible in the comparisons above.
              </p>
            ) : (
              activeAnomalies.map((anomaly) => (
                <div
                  key={anomaly.id}
                  style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 10 }}
                >
                  <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                    <Tag tone={anomaly.severity === "Critical" ? "critical" : "neutral"}>{anomaly.severity}</Tag>
                    <strong style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>{anomaly.summary}</strong>
                  </div>
                  <p style={{ fontSize: 12.5, margin: 0 }}>
                    Threshold {anomaly.threshold_value} {anomaly.threshold_unit}; current{" "}
                    {anomaly.current_value} {anomaly.unit}. Rule: {anomaly.rule_name}.
                  </p>
                  {anomaly.diagnostic_actions.map((action) => (
                    <div
                      key={action.id}
                      style={{ borderInlineStart: "2px solid var(--color-divider)", paddingInlineStart: 12, display: "grid", gap: 6 }}
                    >
                      <span style={{ fontSize: 12.5 }}>
                        <strong>{action.module}</strong> · {action.status} — {action.reason}
                        {action.dismissal_reason ? ` (dismissed: ${action.dismissal_reason})` : ""}
                      </span>
                      {action.status !== "Dismissed" ? (
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "end" }}>
                          <div className="field" style={{ minWidth: 240, flex: "1 1 240px" }}>
                            <label htmlFor={`dismiss-${action.id}`}>Dismissal reason</label>
                            <input
                              id={`dismiss-${action.id}`}
                              className="input"
                              value={dismissReasons[action.id] ?? ""}
                              placeholder="Required — recorded in the report integrity record."
                              onChange={(event) =>
                                setDismissReasons((current) => ({
                                  ...current,
                                  [action.id]: event.target.value
                                }))
                              }
                              disabled={dismissBlocked}
                            />
                          </div>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            data-perm="dismiss_anomalies"
                            aria-label={`Dismiss ${action.module} recommendation`}
                            onClick={() => void dismissDiagnostic(anomaly, action)}
                            disabled={dismissBlocked}
                            aria-disabled={mutating || undefined}
                          >
                            Dismiss
                          </button>
                        </div>
                      ) : null}
                    </div>
                  ))}
                  {dismissBlocked && anomaly.diagnostic_actions.some((action) => action.status !== "Dismissed") ? (
                    <p role="status" className="text-muted" style={{ fontSize: 12, margin: 0 }}>
                      {readOnly
                        ? `${apiUnreadReason(apiStatus) ?? "The workspace is not resolved"}, so no dismissal can be recorded.`
                        : "This session does not have permission to dismiss diagnostics."}
                    </p>
                  ) : null}
                </div>
              ))
            )}
          </Frame>

          {status.ai_interpretation.length > 0 ? (
            <Frame as="section" aria-label="AI interpretation" style={{ padding: 18, display: "grid", gap: 10 }}>
              <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
                AI interpretation — review required
              </h2>
              <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
                Statements below are categorized AI output over the benchmark evidence. None is
                accepted until a reviewer approves it; this view records no approvals.
              </p>
              {status.ai_interpretation.map((statement) => (
                <div
                  key={`${statement.category}-${statement.text}`}
                  style={{ border: "1px solid var(--color-divider)", padding: "8px 12px", fontSize: 12.5, display: "grid", gap: 3 }}
                >
                  <span style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Tag tone="outline">{statement.category}</Tag>
                    <Tag tone={statement.review_status === "accepted" ? "accent" : "neutral"}>
                      {statement.review_status.replace(/_/g, " ")}
                    </Tag>
                  </span>
                  <span style={{ lineHeight: 1.5 }}>{statement.text}</span>
                </div>
              ))}
            </Frame>
          ) : null}

          <Frame as="section" aria-label="Approved benchmark configuration" style={{ padding: 18, display: "grid", gap: 12 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Approved benchmark configuration
            </h2>
            {status.benchmark_values.length > 0 ? (
              <GridTable
                label="Benchmark values"
                columns={["Benchmark", "Metric", "Value", "Dataset", "Approval"]}
                template={VALUES_TEMPLATE}
                minWidth={640}
              >
                {status.benchmark_values.map((value) => (
                  <GridRow template={VALUES_TEMPLATE} key={value.id}>
                    <GridCell>{value.benchmark_name}</GridCell>
                    <GridCell>{value.metric.replace(/_/g, " ")}</GridCell>
                    <GridCell>
                      {num(value.value)} {value.unit}
                    </GridCell>
                    <GridCell>{value.dataset_version}</GridCell>
                    <GridCell>
                      <Tag tone={value.approval_status === "approved" ? "accent" : "outline"}>
                        {value.approval_status}
                      </Tag>
                    </GridCell>
                  </GridRow>
                ))}
              </GridTable>
            ) : (
              <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                The status was read and carries no benchmark values.
              </p>
            )}

            <div style={{ display: "grid", gap: 8 }}>
              <h3 style={{ fontSize: 14, letterSpacing: "0.04em", textTransform: "uppercase", margin: 0 }}>
                Adjust a benchmark value
              </h3>
              {adjustBlocked ? (
                <p role="status" className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
                  {readOnly
                    ? `${apiUnreadReason(apiStatus) ?? "The workspace is not resolved"}, so no benchmark can be adjusted.`
                    : "This session does not have permission to adjust approved benchmarks."}
                </p>
              ) : (
                <p className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
                  Changing an approved benchmark requires a written reason and is added to the
                  report integrity record.
                </p>
              )}
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
                <div className="field" style={{ minWidth: 220 }}>
                  <label htmlFor="bm-adjust-id">Benchmark</label>
                  <select
                    id="bm-adjust-id"
                    className="input"
                    value={adjustId}
                    onChange={(event) => setAdjustId(event.target.value)}
                    disabled={adjustBlocked}
                  >
                    <option value="">Choose a benchmark…</option>
                    {status.benchmark_values.map((value) => (
                      <option key={value.id} value={value.id}>
                        {value.benchmark_name} ({num(value.value)} {value.unit})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field" style={{ width: 140 }}>
                  <label htmlFor="bm-adjust-value">New value</label>
                  <input
                    id="bm-adjust-value"
                    className="input"
                    inputMode="decimal"
                    value={adjustValue}
                    onChange={(event) => setAdjustValue(event.target.value)}
                    disabled={adjustBlocked}
                  />
                </div>
                <div className="field" style={{ minWidth: 260, flex: "1 1 260px" }}>
                  <label htmlFor="bm-adjust-reason">Reason</label>
                  <input
                    id="bm-adjust-reason"
                    className="input"
                    placeholder="Required — recorded in the report integrity record."
                    value={adjustReason}
                    onChange={(event) => setAdjustReason(event.target.value)}
                    disabled={adjustBlocked}
                  />
                </div>
                <button
                  type="button"
                  className="btn btn-secondary"
                  data-perm="manage_benchmark_config"
                  onClick={() => void adjustBenchmark()}
                  disabled={adjustBlocked}
                  aria-disabled={mutating || undefined}
                >
                  Adjust benchmark
                </button>
              </div>
            </div>
          </Frame>

          <Frame as="section" aria-label="Evidence scope" style={{ padding: 18, display: "grid", gap: 10 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Evidence scope
            </h2>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(min(240px,100%),1fr))",
                gap: 16,
                fontSize: 12.5
              }}
            >
              <EvidenceList title="Benchmark sources" items={status.supporting_evidence_references} />
              <EvidenceList title="Likely contributors" items={status.likely_operational_contributors} />
              <EvidenceList
                title="Recommended diagnostics"
                items={status.recommended_diagnostic_actions.map(
                  (action) => `${action.module}: ${action.status} — ${action.reason}`
                )}
              />
            </div>
          </Frame>
        </>
      ) : null}
    </>
  );
}

function EvidenceList({ title, items }: { title: string; items: string[] }) {
  return (
    <div style={{ borderInlineStart: "1px solid var(--color-divider)", paddingInlineStart: 14 }}>
      <strong style={{ fontFamily: "var(--font-heading)", textTransform: "uppercase", letterSpacing: "0.04em", fontSize: 12 }}>
        {title}
      </strong>
      <ul style={{ margin: "6px 0 0", paddingInlineStart: 16, lineHeight: 1.6 }}>
        {(items.length > 0 ? items : ["No item recorded yet."]).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
