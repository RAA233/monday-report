import {
  CalendarClock,
  CheckCircle2,
  CircuitBoard,
  DatabaseZap,
  FileText,
  GitPullRequest,
  PackageCheck,
  Radar,
  ShieldCheck,
  TriangleAlert
} from "lucide-react";
import type { JSX } from "react";
import {
  capabilitySignals,
  releaseGates,
  roadmapLanes,
  roadmapRisks,
  type RoadmapStatus,
  type RoadmapTone
} from "../data/productRoadmap";
import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";

export function ProductRoadmap(): JSX.Element {
  const itemCount = roadmapLanes.reduce((total, lane) => total + lane.items.length, 0);
  const activeCount = roadmapLanes.reduce(
    (total, lane) => total + lane.items.filter((item) => item.status === "active").length,
    0
  );
  const queuedCount = roadmapLanes.reduce(
    (total, lane) => total + lane.items.filter((item) => item.status === "queued").length,
    0
  );
  const guardedCount = releaseGates.filter((gate) => gate.status === "complete" || gate.status === "active").length;

  return (
    <main className="view-stack roadmap-view">
      <section className="workspace-title roadmap-title" aria-labelledby="roadmap-title">
        <div>
          <p className="eyebrow">Execution roadmap</p>
          <h1 id="roadmap-title">Product roadmap</h1>
          <p>Client-grade path for Monday Report: local AI, advanced report drafting, import/export proof, security hardening, and controlled pilot dispatch.</p>
        </div>
        <Badge tone="info">client pilot path</Badge>
      </section>

      <div className="metric-grid">
        <MetricCard icon={Radar} label="Roadmap items" value={String(itemCount)} detail="tracked work packages" tone="blue" />
        <MetricCard icon={CircuitBoard} label="Active build" value={String(activeCount)} detail="in execution" tone="green" />
        <MetricCard icon={CalendarClock} label="Queued next" value={String(queuedCount)} detail="ready for phase pull" tone="amber" />
        <MetricCard icon={ShieldCheck} label="Guarded gates" value={`${guardedCount}/${releaseGates.length}`} detail="covered by audit evidence" tone="green" />
      </div>

      <section className="roadmap-signal-grid" aria-label="Roadmap capability signals">
        {capabilitySignals.map((signal) => (
          <article className={`roadmap-signal-card roadmap-signal-${signal.tone}`} key={signal.id}>
            <div>
              <span>{signal.label}</span>
              <Badge tone={signalTone(signal.tone)}>{signal.tone}</Badge>
            </div>
            <strong>{signal.value}</strong>
            <p>{signal.detail}</p>
          </article>
        ))}
      </section>

      <section className="panel roadmap-board" aria-labelledby="roadmap-board-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Now to pilot</p>
            <h2 id="roadmap-board-title">Delivery lanes</h2>
          </div>
          <Badge tone="good">{roadmapLanes.length} lanes</Badge>
        </div>
        <div className="roadmap-lanes">
          {roadmapLanes.map((lane) => (
            <article className="roadmap-lane" key={lane.id}>
              <header className="roadmap-lane-header">
                <div>
                  <span>{lane.label}</span>
                  <p>{lane.intent}</p>
                </div>
                <Badge tone={statusTone(lane.status)}>{lane.status.replace("_", " ")}</Badge>
              </header>
              <div className="roadmap-item-stack">
                {lane.items.map((item) => (
                  <article className={`roadmap-item roadmap-item-${item.status}`} key={item.id}>
                    <div className="roadmap-item-title">
                      <FileText size={17} aria-hidden="true" />
                      <h3>{item.title}</h3>
                      <Badge tone={statusTone(item.status)}>{item.status}</Badge>
                    </div>
                    <div className="roadmap-fact-grid">
                      <RoadmapFact label="Owner" value={item.owner} />
                      <RoadmapFact label="Gate" value={item.gate} />
                    </div>
                    <p>{item.evidence}</p>
                    <strong>{item.next}</strong>
                  </article>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="roadmap-bottom-grid">
        <article className="panel" aria-labelledby="release-train-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Dispatch control</p>
              <h2 id="release-train-title">Release train</h2>
            </div>
            <PackageCheck size={20} aria-hidden="true" />
          </div>
          <div className="release-train">
            {releaseGates.map((gate, index) => (
              <article className={`release-gate release-gate-${gate.status}`} key={gate.id}>
                <div className="release-gate-index">{index + 1}</div>
                <div>
                  <h3>{gate.label}</h3>
                  <Badge tone={statusTone(gate.status)}>{gate.status}</Badge>
                </div>
                <code>{gate.command}</code>
                <p>{gate.evidence}</p>
              </article>
            ))}
          </div>
        </article>

        <article className="panel" aria-labelledby="roadmap-risk-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Audit posture</p>
              <h2 id="roadmap-risk-title">Roadmap risk controls</h2>
            </div>
            <TriangleAlert size={20} aria-hidden="true" />
          </div>
          <div className="roadmap-risk-list">
            {roadmapRisks.map((risk) => (
              <article className={`roadmap-risk roadmap-risk-${risk.severity}`} key={risk.id}>
                <div>
                  <strong>{risk.risk}</strong>
                  <Badge tone={risk.severity === "high" ? "danger" : "warning"}>{risk.severity}</Badge>
                </div>
                <p>{risk.control}</p>
                <span>{risk.owner}</span>
              </article>
            ))}
          </div>
        </article>
      </section>

      <section className="panel" aria-labelledby="roadmap-dependency-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">System dependencies</p>
            <h2 id="roadmap-dependency-title">Capability map</h2>
          </div>
          <GitPullRequest size={20} aria-hidden="true" />
        </div>
        <div className="capability-dependency-grid">
          <RoadmapCapability icon={<DatabaseZap size={18} />} label="Ingest" detail="ZIP, PDF, Office, CSV, email, image, OCR route, and source hash." />
          <RoadmapCapability icon={<CircuitBoard size={18} />} label="Extract" detail="Classify, chunk, cite, score confidence, and create validation tasks." />
          <RoadmapCapability icon={<CheckCircle2 size={18} />} label="Validate" detail="Reviewer approval blocks report dispatch until source claims are checked." />
          <RoadmapCapability icon={<FileText size={18} />} label="Author" detail="Morning report studio with AI plan, normal sections, and branded drafts." />
          <RoadmapCapability icon={<Radar size={18} />} label="Visualize" detail="Casing rows, well schematic, timeline, status graphs, and evidence screenshots." />
          <RoadmapCapability icon={<PackageCheck size={18} />} label="Dispatch" detail="Signed exports, partner ZIP, client approval ledger, and pilot scope." />
        </div>
      </section>
    </main>
  );
}

function RoadmapFact({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RoadmapCapability({
  icon,
  label,
  detail
}: {
  icon: JSX.Element;
  label: string;
  detail: string;
}): JSX.Element {
  return (
    <article className="roadmap-capability">
      <div className="stage-icon" aria-hidden="true">
        {icon}
      </div>
      <div>
        <strong>{label}</strong>
        <p>{detail}</p>
      </div>
    </article>
  );
}

function statusTone(status: RoadmapStatus): "neutral" | "good" | "warning" | "danger" | "info" {
  if (status === "complete") {
    return "good";
  }
  if (status === "active") {
    return "info";
  }
  if (status === "watch") {
    return "warning";
  }
  return "neutral";
}

function signalTone(tone: RoadmapTone): "neutral" | "good" | "warning" | "danger" | "info" {
  return tone;
}
