import { useEffect, useMemo, useState } from "react";
import type { JSX } from "react";
import {
  AlertTriangle,
  BarChart3,
  Calculator,
  CheckCircle2,
  FileDown,
  Gauge,
  GitCompareArrows,
  LineChart,
  ShieldCheck,
  SlidersHorizontal,
  Wrench
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Badge } from "./Badge";
import {
  createBenchmarkMeasurement,
  dismissBenchmarkDiagnostic,
  getWorkspaceBenchmarking,
  type ApiAnomalyEvent,
  type ApiBenchmarkComparison,
  type ApiBenchmarkingStatus,
  type ApiDiagnosticAction
} from "../lib/api";

interface BenchmarkingModuleProps {
  workspaceId?: string;
}

export function BenchmarkingModule({ workspaceId }: BenchmarkingModuleProps): JSX.Element {
  const [status, setStatus] = useState<ApiBenchmarkingStatus | null>(null);
  const [loadState, setLoadState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [message, setMessage] = useState("Benchmarking uses approved operator and market datasets.");
  const [measurementValue, setMeasurementValue] = useState("");
  const [measurementSource, setMeasurementSource] = useState("Daily drilling record");
  const [dismissState, setDismissState] = useState<Record<string, string>>({});

  useEffect(() => {
    void refreshBenchmarking();
  }, [workspaceId]);

  const ftDayComparisons = useMemo(
    () => status?.comparisons.filter((item) => item.metric === "feet_drilled_per_day") ?? [],
    [status]
  );

  async function refreshBenchmarking(): Promise<void> {
    if (!workspaceId) {
      setLoadState("error");
      setMessage("Connect to a workspace before loading Benchmarking.");
      return;
    }
    setLoadState("loading");
    try {
      const next = await getWorkspaceBenchmarking(workspaceId);
      setStatus(next);
      setLoadState("ready");
      setMessage("Benchmark status loaded from approved configuration and workspace measurements.");
    } catch (error) {
      setLoadState("error");
      setMessage(error instanceof Error ? error.message : "Benchmarking failed to load.");
    }
  }

  async function submitMeasurement(): Promise<void> {
    if (!workspaceId) {
      return;
    }
    const value = Number.parseFloat(measurementValue);
    if (!Number.isFinite(value)) {
      setMessage("Enter a valid ft/day value before recording a measurement.");
      return;
    }
    setLoadState("loading");
    try {
      const next = await createBenchmarkMeasurement({
        workspaceId,
        metric: "feet_drilled_per_day",
        value,
        unit: "ft/day",
        dataSource: measurementSource || "Daily drilling record",
        confidenceStatus: "manual",
        sourceType: "daily_drilling_record",
        sourceIdentifier: measurementSource || "manual-ddr-entry",
        datasetVersion: "workspace-current"
      });
      setStatus(next);
      setMeasurementValue("");
      setLoadState("ready");
      setMessage("Measurement recorded, anomaly rules evaluated, and audit trail updated.");
    } catch (error) {
      setLoadState("error");
      setMessage(error instanceof Error ? error.message : "Measurement failed.");
    }
  }

  async function dismissAction(anomaly: ApiAnomalyEvent, action: ApiDiagnosticAction): Promise<void> {
    const reason = dismissState[action.id]?.trim();
    if (!reason) {
      setDismissState((current) => ({ ...current, [action.id]: "Reviewed by authorized user; no run required now." }));
      setMessage("Dismissal reason is required. A default reason was prepared for review.");
      return;
    }
    try {
      await dismissBenchmarkDiagnostic({ anomalyId: anomaly.id, actionId: action.id, reason });
      await refreshBenchmarking();
      setMessage(`${action.module} recommendation dismissed with an audit reason.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Dismissal failed.");
    }
  }

  const current = status?.current_ft_per_day;
  const gordon = status?.gordon_average_benchmark;
  const noble = status?.noble_top_quartile_benchmark;
  const critical = gordon ? gordon * 0.85 : null;

  return (
    <main className="benchmarking-module">
      <section className="workspace-title benchmarking-title">
        <div>
          <p className="eyebrow">Benchmarking</p>
          <h1>Market Benchmark</h1>
          <p>
            Compare current drilling performance against approved operator and market benchmarks,
            then route critical deviations into watchlist, diagnostics, audit, and evidence export.
          </p>
        </div>
        <Badge tone={status?.active_anomalies.some((item) => item.severity === "Critical") ? "danger" : "info"}>
          {status?.active_anomalies.length ?? 0} active
        </Badge>
      </section>

      <section className="benchmark-status-strip" aria-label="Benchmark status indicators">
        <BenchmarkStat icon={Gauge} label="Current ft/day" value={formatNumber(current)} detail="Latest workspace measurement" />
        <BenchmarkStat icon={LineChart} label="Seven-day average" value={formatNumber(status?.seven_day_average_ft_per_day)} detail="Normalized ft/day trend" />
        <BenchmarkStat icon={GitCompareArrows} label="Gordon average" value={formatNumber(gordon)} detail="Approved average benchmark" />
        <BenchmarkStat icon={ShieldCheck} label="Noble top quartile" value={formatNumber(noble)} detail="Performance gap benchmark" />
        <BenchmarkStat icon={AlertTriangle} label="Critical threshold" value={formatNumber(critical)} detail="Gordon x 85%" />
      </section>

      <section className="benchmark-command-panel" aria-label="Benchmark measurement controls">
        <div>
          <p className="eyebrow">Current reading</p>
          <h2>Record daily drilling-rate measurement</h2>
          <p>{message}</p>
        </div>
        <label>
          <span>ft/day</span>
          <input
            inputMode="decimal"
            placeholder="e.g. 430"
            value={measurementValue}
            onChange={(event) => setMeasurementValue(event.currentTarget.value)}
          />
        </label>
        <label>
          <span>Source</span>
          <input value={measurementSource} onChange={(event) => setMeasurementSource(event.currentTarget.value)} />
        </label>
        <button className="primary-action" type="button" onClick={() => void submitMeasurement()} disabled={loadState === "loading"}>
          <Calculator size={18} aria-hidden="true" />
          Record measurement
        </button>
        <button className="secondary-action" type="button" onClick={() => void refreshBenchmarking()}>
          <SlidersHorizontal size={18} aria-hidden="true" />
          Refresh
        </button>
      </section>

      <section className="benchmark-grid">
        <article className="benchmark-panel benchmark-visual-panel">
          <div className="benchmark-panel-heading">
            <div>
              <p className="eyebrow">Actual versus benchmark</p>
              <h2>Drilling-rate comparison</h2>
            </div>
            <BarChart3 size={20} aria-hidden="true" />
          </div>
          <ActualBenchmarkBars current={current} gordon={gordon} noble={noble} />
        </article>

        <article className="benchmark-panel">
          <div className="benchmark-panel-heading">
            <div>
              <p className="eyebrow">Seven-day trend</p>
              <h2>Performance movement</h2>
            </div>
            <LineChart size={20} aria-hidden="true" />
          </div>
          <TrendBars trend={status?.seven_day_trend ?? []} benchmark={gordon ?? noble ?? 1} />
        </article>
      </section>

      <section className="benchmark-panel">
        <div className="benchmark-panel-heading">
          <div>
            <p className="eyebrow">Variance table</p>
            <h2>Metric comparisons</h2>
          </div>
          <Badge tone="info">{status?.comparisons.length ?? 0} rows</Badge>
        </div>
        <div className="benchmark-table-wrap">
          <table className="benchmark-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Benchmark</th>
                <th>Current</th>
                <th>Benchmark</th>
                <th>Variance</th>
                <th>Status</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {(status?.comparisons ?? []).map((item) => (
                <BenchmarkRow key={`${item.metric}-${item.benchmark_name}`} item={item} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="benchmark-grid">
        <article className="benchmark-panel">
          <div className="benchmark-panel-heading">
            <div>
              <p className="eyebrow">Risks & Watchlist</p>
              <h2>Active anomalies</h2>
            </div>
            <AlertTriangle size={20} aria-hidden="true" />
          </div>
          <div className="benchmark-anomaly-list">
            {(status?.active_anomalies.length ?? 0) > 0 ? (
              status?.active_anomalies.map((anomaly) => (
                <AnomalyCard
                  key={anomaly.id}
                  anomaly={anomaly}
                  dismissState={dismissState}
                  setDismissState={setDismissState}
                  onDismiss={dismissAction}
                />
              ))
            ) : (
              <p className="benchmark-empty">No active benchmark anomalies. Missing or stale measurements remain visible in the variance table.</p>
            )}
          </div>
        </article>

        <article className="benchmark-panel">
          <div className="benchmark-panel-heading">
            <div>
              <p className="eyebrow">AI interpretation</p>
              <h2>Review-required statements</h2>
            </div>
            <CheckCircle2 size={20} aria-hidden="true" />
          </div>
          <div className="benchmark-ai-list">
            {(status?.ai_interpretation ?? []).map((statement) => (
              <article key={`${statement.category}-${statement.text}`}>
                <span>{statement.category}</span>
                <strong>{statement.review_status.replace("_", " ")}</strong>
                <p>{statement.text}</p>
              </article>
            ))}
          </div>
        </article>
      </section>

      <section className="benchmark-panel">
        <div className="benchmark-panel-heading">
          <div>
            <p className="eyebrow">Evidence export scope</p>
            <h2>Management of Change package inputs</h2>
          </div>
          <FileDown size={20} aria-hidden="true" />
        </div>
        <div className="benchmark-evidence-grid">
          <EvidenceList title="Benchmark sources" items={status?.supporting_evidence_references ?? []} />
          <EvidenceList title="Likely contributors" items={status?.likely_operational_contributors ?? []} />
          <EvidenceList title="Approved configuration" items={(status?.benchmark_values ?? []).map((item) => `${item.benchmark_name}: ${item.value} ${item.unit} (${item.dataset_version})`)} />
        </div>
      </section>
    </main>
  );
}

function BenchmarkStat({
  icon: Icon,
  label,
  value,
  detail
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
}): JSX.Element {
  return (
    <article>
      <Icon size={18} aria-hidden="true" />
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

function ActualBenchmarkBars({ current, gordon, noble }: { current?: number | null; gordon?: number | null; noble?: number | null }): JSX.Element {
  const max = Math.max(current ?? 0, gordon ?? 0, noble ?? 0, 1);
  const rows = [
    { label: "Current", value: current, className: "current" },
    { label: "Gordon", value: gordon, className: "gordon" },
    { label: "Noble", value: noble, className: "noble" }
  ];
  return (
    <div className="benchmark-bars">
      {rows.map((row) => (
        <div key={row.label} className={`benchmark-bar-row ${row.className}`}>
          <span>{row.label}</span>
          <div>
            <i style={{ width: `${Math.max(((row.value ?? 0) / max) * 100, row.value ? 8 : 0)}%` }} />
          </div>
          <strong>{formatNumber(row.value)}</strong>
        </div>
      ))}
    </div>
  );
}

function TrendBars({ trend, benchmark }: { trend: ApiBenchmarkingStatus["seven_day_trend"]; benchmark: number }): JSX.Element {
  if (!trend.length) {
    return <p className="benchmark-empty">No seven-day measurements have been recorded yet.</p>;
  }
  const max = Math.max(...trend.map((item) => item.value), benchmark, 1);
  return (
    <div className="benchmark-trend" aria-label="Seven-day performance trend">
      {trend.map((item) => (
        <div key={`${item.timestamp}-${item.value}`}>
          <i style={{ height: `${Math.max((item.value / max) * 100, 8)}%` }} />
          <span>{Math.round(item.value)}</span>
        </div>
      ))}
    </div>
  );
}

function BenchmarkRow({ item }: { item: ApiBenchmarkComparison }): JSX.Element {
  return (
    <tr>
      <td>{item.metric.replace(/_/g, " ")}</td>
      <td>{item.benchmark_name}</td>
      <td>{formatNumber(item.current_value)} {item.current_unit}</td>
      <td>{formatNumber(item.benchmark_value)} {item.benchmark_unit}</td>
      <td>{formatNumber(item.absolute_variance)} / {formatNumber(item.percentage_variance)}%</td>
      <td><span className={`benchmark-status-pill ${statusClass(item.performance_status)}`}>{item.performance_status}</span></td>
      <td>{item.supporting_source}</td>
    </tr>
  );
}

function AnomalyCard({
  anomaly,
  dismissState,
  setDismissState,
  onDismiss
}: {
  anomaly: ApiAnomalyEvent;
  dismissState: Record<string, string>;
  setDismissState: (value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)) => void;
  onDismiss: (anomaly: ApiAnomalyEvent, action: ApiDiagnosticAction) => Promise<void>;
}): JSX.Element {
  return (
    <article className={`benchmark-anomaly-card anomaly-${anomaly.severity.toLowerCase()}`}>
      <div>
        <span>{anomaly.severity}</span>
        <strong>{anomaly.summary}</strong>
        <p>
          Threshold {anomaly.threshold_value} {anomaly.threshold_unit}; current {anomaly.current_value} {anomaly.unit}.
        </p>
      </div>
      <div className="diagnostic-action-list">
        {anomaly.diagnostic_actions.map((action) => (
          <section key={action.id}>
            <Wrench size={16} aria-hidden="true" />
            <div>
              <strong>{action.module}</strong>
              <span>{action.status}</span>
              <p>{action.reason}</p>
              {action.status !== "Dismissed" && (
                <div className="diagnostic-dismiss-row">
                  <input
                    aria-label={`Dismissal reason for ${action.module}`}
                    value={dismissState[action.id] ?? ""}
                    placeholder="Dismissal reason"
                    onChange={(event) =>
                      setDismissState((current) => ({ ...current, [action.id]: event.currentTarget.value }))
                    }
                  />
                  <button className="secondary-action" type="button" onClick={() => void onDismiss(anomaly, action)}>
                    Dismiss
                  </button>
                </div>
              )}
            </div>
          </section>
        ))}
      </div>
    </article>
  );
}

function EvidenceList({ title, items }: { title: string; items: string[] }): JSX.Element {
  return (
    <article>
      <strong>{title}</strong>
      <ul>
        {(items.length ? items : ["No evidence item recorded yet."]).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </article>
  );
}

function formatNumber(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "Missing";
  }
  return value.toLocaleString(undefined, { maximumFractionDigits: 1 });
}

function statusClass(status: string): string {
  if (status === "Critical deviation") {
    return "critical";
  }
  if (status === "Below benchmark" || status === "Stale data") {
    return "warning";
  }
  if (status === "Above benchmark" || status === "Within expected range") {
    return "good";
  }
  return "neutral";
}
