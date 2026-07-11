import {
  Activity,
  AlertTriangle,
  BadgeDollarSign,
  BarChart3,
  Clock3,
  Database,
  Gauge,
  ShieldAlert
} from "lucide-react";
import type { CSSProperties, JSX } from "react";
import type { FailureEvent } from "../data/domain";
import {
  companyRisk,
  formatHours,
  formatPercent,
  formatUsd,
  summarizeMetrics,
  toolRisk
} from "../lib/analytics";
import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";

interface DashboardProps {
  events: FailureEvent[];
}

export function Dashboard({ events }: DashboardProps): JSX.Element {
  const metrics = summarizeMetrics(events);
  const companyRisks = companyRisk(events);
  const toolRisks = toolRisk(events);
  const maxNpt = Math.max(...events.map((event) => event.nptHours), 1);

  return (
    <main className="view-stack">
      <section className="workspace-title" aria-labelledby="dashboard-title">
        <div>
          <p className="eyebrow">Executive overview</p>
          <h1 id="dashboard-title">Monday Report intelligence</h1>
          <p>
            Failure, NPT, company, tool, risk, and validation signals from indexed Monday Report
            evidence.
          </p>
        </div>
        <Badge tone="good">source-backed</Badge>
      </section>

      <div className="metric-grid">
        <MetricCard
          icon={AlertTriangle}
          label="Total failures"
          value={String(metrics.totalFailures)}
          detail={`${metrics.criticalAndHigh} high or critical`}
          tone="red"
        />
        <MetricCard
          icon={Clock3}
          label="NPT exposure"
          value={formatHours(metrics.totalNptHours)}
          detail="validated plus pending"
          tone="amber"
        />
        <MetricCard
          icon={BadgeDollarSign}
          label="Cost impact"
          value={formatUsd(metrics.costImpactUsd)}
          detail="rig-spread estimate"
          tone="green"
        />
        <MetricCard
          icon={ShieldAlert}
          label="Validation backlog"
          value={String(metrics.validationBacklog)}
          detail={`${metrics.repeatedToolSerials} repeated serial signal`}
          tone="blue"
        />
      </div>

      <section className="insight-grid">
        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Trend</p>
              <h2>NPT by event</h2>
            </div>
            <BarChart3 size={20} aria-hidden="true" />
          </div>
          <div className="bar-list">
            {events.map((event) => (
              <div className="bar-row" key={event.id}>
                <span>{event.eventType}</span>
                <div className="bar-track" aria-hidden="true">
                  <div style={{ width: `${Math.max((event.nptHours / maxNpt) * 100, 6)}%` }} />
                </div>
                <strong>{formatHours(event.nptHours)}</strong>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Risk</p>
              <h2>Company risk score</h2>
            </div>
            <Gauge size={20} aria-hidden="true" />
          </div>
          <RiskList items={companyRisks.slice(0, 5)} />
        </article>
      </section>

      <section className="insight-grid">
        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Reliability</p>
              <h2>Tool serial risk</h2>
            </div>
            <Activity size={20} aria-hidden="true" />
          </div>
          <RiskList items={toolRisks.slice(0, 5)} />
        </article>

        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Data quality</p>
              <h2>Extraction confidence</h2>
            </div>
            <Database size={20} aria-hidden="true" />
          </div>
          <div className="confidence-dial" aria-label={`Average confidence ${formatPercent(metrics.averageConfidence)}`}>
            <div style={{ "--confidence": `${metrics.averageConfidence * 100}%` } as CSSProperties}>
              <strong>{formatPercent(metrics.averageConfidence)}</strong>
              <span>average confidence</span>
            </div>
          </div>
          <p className="panel-note">
            Conflicts and low-confidence events stay visible instead of being hidden from the
            dashboard.
          </p>
        </article>
      </section>
    </main>
  );
}

interface RiskListProps {
  items: Array<{ label: string; score: number; drivers: string[] }>;
}

function RiskList({ items }: RiskListProps): JSX.Element {
  return (
    <div className="risk-list">
      {items.map((item) => (
        <div className="risk-row" key={item.label}>
          <div>
            <strong>{item.label}</strong>
            <span>{item.drivers.join(" / ")}</span>
          </div>
          <div className="risk-meter" aria-label={`${item.label} risk score ${Math.round(item.score)}`}>
            <div style={{ width: `${item.score}%` }} />
          </div>
          <Badge tone={item.score > 75 ? "danger" : item.score > 58 ? "warning" : "neutral"}>
            {Math.round(item.score)}
          </Badge>
        </div>
      ))}
    </div>
  );
}
