import { Activity, CheckCircle2, CircleDashed, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import type { JSX } from "react";
import {
  auditEvents,
  clearTrackerLanes,
  getTrackerSummary,
  projectPhases,
  testGates,
  type GateStatus,
  type PhaseStatus
} from "../data/projectTracker";
import {
  getAuditIntegrity,
  getAuditLogs,
  getClientDataReadiness,
  getDocuments,
  getFailures,
  getLocalAiStatus,
  getProcessingJobs,
  getRuntimeBackends,
  type ApiAuditLog,
  type ApiAuditIntegrityStatus,
  type ApiClientDataReadiness,
  type ApiClientDataReadinessCheck,
  type ApiFailureRecord,
  type ApiLocalAiStatus,
  type ApiParsedDocument,
  type ApiProcessingJob,
  type ApiRuntimeBackendStatus
} from "../lib/api";
import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";

export function ProjectTracker(): JSX.Element {
  const summary = getTrackerSummary();
  const [liveAuditLogs, setLiveAuditLogs] = useState<ApiAuditLog[]>([]);
  const [auditIntegrity, setAuditIntegrity] = useState<ApiAuditIntegrityStatus | null>(null);
  const [processingJobs, setProcessingJobs] = useState<ApiProcessingJob[]>([]);
  const [parsedDocuments, setParsedDocuments] = useState<ApiParsedDocument[]>([]);
  const [failures, setFailures] = useState<ApiFailureRecord[]>([]);
  const [clientReadiness, setClientReadiness] = useState<ApiClientDataReadiness | null>(null);
  const [localAiStatus, setLocalAiStatus] = useState<ApiLocalAiStatus | null>(null);
  const [runtimeBackends, setRuntimeBackends] = useState<ApiRuntimeBackendStatus | null>(null);
  const [auditStatus, setAuditStatus] = useState<"loading" | "live" | "fallback">("loading");

  useEffect(() => {
    let isMounted = true;

    async function loadReadiness(): Promise<void> {
      try {
        const [readiness, aiStatus, backends] = await Promise.all([
          getClientDataReadiness(),
          getLocalAiStatus(),
          getRuntimeBackends()
        ]);
        if (!isMounted) {
          return;
        }
        setClientReadiness(readiness);
        setLocalAiStatus(aiStatus);
        setRuntimeBackends(backends);
      } catch {
        return;
      }
    }

    async function loadAuditLogs(): Promise<void> {
      try {
        const [logs, integrity, jobs, documents, failureRecords] = await Promise.all([
          getAuditLogs(12),
          getAuditIntegrity(),
          getProcessingJobs(),
          getDocuments(),
          getFailures()
        ]);
        if (!isMounted) {
          return;
        }
        setLiveAuditLogs(logs);
        setAuditIntegrity(integrity);
        setProcessingJobs(jobs);
        setParsedDocuments(documents);
        setFailures(failureRecords);
        setAuditStatus("live");
      } catch {
        if (isMounted) {
          setAuditStatus("fallback");
        }
      }
    }

    void loadReadiness();
    void loadAuditLogs();

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <main className="view-stack">
      <section className="workspace-title" aria-labelledby="tracker-title">
        <div>
          <p className="eyebrow">Execution control</p>
          <h1 id="tracker-title">Project tracker</h1>
          <p>Phase status, verification gates, and audit posture for Monday Report MVP execution.</p>
        </div>
        <Badge tone="info">phase-gated</Badge>
      </section>

      <div className="metric-grid">
        <MetricCard icon={CheckCircle2} label="Complete phases" value={String(summary.complete)} detail="accepted slices" tone="green" />
        <MetricCard icon={Activity} label="Active phases" value={String(summary.active)} detail="currently executing" tone="blue" />
        <MetricCard icon={CircleDashed} label="Pending phases" value={String(summary.pending)} detail="planned next" tone="amber" />
        <MetricCard icon={TriangleAlert} label="Blocked phases" value={String(summary.blocked)} detail="requires decision" tone="red" />
      </div>

      <section className="panel" aria-labelledby="clear-tracker-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Where we are</p>
            <h2 id="clear-tracker-title">Clear tracker</h2>
          </div>
          <Badge tone="info">operator view</Badge>
        </div>
        <div className="clear-tracker-grid">
          {clearTrackerLanes.map((lane) => (
            <article className="clear-tracker-card" key={lane.id}>
              <div>
                <strong>{lane.title}</strong>
                <Badge tone={gateTone(lane.status)}>{lane.status}</Badge>
              </div>
              <p>{lane.summary}</p>
              <ul>
                {lane.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section className="panel" aria-labelledby="client-readiness-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Client data</p>
            <h2 id="client-readiness-title">Real-client readiness</h2>
          </div>
          <Badge tone={clientReadiness?.ready ? "good" : "warning"}>
            {clientReadiness ? clientReadiness.status.replace("_", " ") : "loading"}
          </Badge>
        </div>
        {clientReadiness ? (
          <>
            <div className="job-health-strip" aria-label="Client data readiness summary">
              <span>mode: {clientReadiness.mode}</span>
              <span>{countReadiness(clientReadiness.checks, "pass")} pass</span>
              <span>{countReadiness(clientReadiness.checks, "warn")} warn</span>
              <span>{countReadiness(clientReadiness.checks, "fail")} fail</span>
            </div>
            {localAiStatus && (
              <div className="job-health-strip" aria-label="Local AI runtime summary">
                <span>runtime: {runtimeLabel(localAiStatus.runtime)}</span>
                <span>{localAiStatus.reachable ? "reachable" : "offline"}</span>
                <span>{localAiStatus.model_available ? "model ready" : "model missing"}</span>
                <span>fallback: {localAiStatus.hosted_fallback_enabled ? "enabled" : "disabled"}</span>
                <span>{localAiStatus.model ?? "model not pinned"}</span>
              </div>
            )}
            {runtimeBackends && (
              <div className="job-health-strip" aria-label="Runtime backend summary">
                <span>repo: {runtimeBackends.active_repository_backend}</span>
                <span>requested: {runtimeBackends.requested_repository_backend}</span>
                <span>queue: {runtimeBackends.active_queue_backend}</span>
                <span>requested: {runtimeBackends.requested_queue_backend}</span>
                <span>{runtimeBackends.database_url_configured ? "database URL set" : "database URL missing"}</span>
                <span>{runtimeBackends.redis_url_configured ? "Redis URL set" : "Redis URL missing"}</span>
                <Badge tone={runtimeBackends.repository_ready && runtimeBackends.queue_ready ? "good" : "warning"}>
                  {runtimeBackends.blocking_checks.length} blocker(s)
                </Badge>
              </div>
            )}
            <div className="readiness-grid">
              {clientReadiness.checks.map((check) => (
                <article className="readiness-check" key={check.id}>
                  <div>
                    <strong>{check.label}</strong>
                    <Badge tone={readinessTone(check.status)}>{check.status}</Badge>
                  </div>
                  <p>{check.detail}</p>
                  <span>{check.remediation}</span>
                </article>
              ))}
            </div>
          </>
        ) : (
          <p className="panel-note">Client-data readiness will appear when the API is reachable.</p>
        )}
      </section>

      <section className="panel" aria-labelledby="phase-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Phases</p>
            <h2 id="phase-title">Execution board</h2>
          </div>
          <Badge tone="good">{projectPhases.length} tracked</Badge>
        </div>
        <div className="tracker-phase-list">
          {projectPhases.map((phase) => {
            const Icon = phase.icon;
            return (
              <article className="tracker-phase" key={phase.id}>
                <div className="stage-icon" aria-hidden="true">
                  <Icon size={18} />
                </div>
                <div className="tracker-phase-main">
                  <div className="tracker-phase-title">
                    <div>
                      <span>{phase.id}</span>
                      <h3>{phase.name}</h3>
                    </div>
                    <Badge tone={phaseTone(phase.status)}>{phase.status.replace("_", " ")}</Badge>
                  </div>
                  <p>{phase.objective}</p>
                  <div className="tracker-meta-grid">
                    <TrackerFact label="Owner" value={phase.owner} />
                    <TrackerFact label="Evidence" value={phase.evidence} />
                    <TrackerFact label="Next" value={phase.nextAction} />
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="insight-grid">
        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Quality gates</p>
              <h2>Phase test matrix</h2>
            </div>
            <ShieldCheck size={20} aria-hidden="true" />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Gate</th>
                  <th>Status</th>
                  <th>Command</th>
                  <th>Last result</th>
                </tr>
              </thead>
              <tbody>
                {testGates.map((gate) => (
                  <tr key={gate.id}>
                    <td>{gate.name}</td>
                    <td><Badge tone={gateTone(gate.status)}>{gate.status}</Badge></td>
                    <td><code>{gate.command}</code></td>
                    <td>{gate.lastResult}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <article className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Audit</p>
              <h2>Recent trail</h2>
            </div>
            <Badge tone={auditStatus === "live" ? "good" : auditStatus === "loading" ? "info" : "warning"}>
              {auditStatus === "live" ? "live API" : auditStatus}
            </Badge>
          </div>
          <div className="job-health-strip" aria-label="Processing job health">
            <span>{processingJobs.length} jobs</span>
            <span>{countJobs(processingJobs, "queued")} queued</span>
            <span>{countJobs(processingJobs, "complete")} complete</span>
            <span>{countJobs(processingJobs, "failed")} failed</span>
            <span>{parsedDocuments.length} docs</span>
            <span>{countChunks(parsedDocuments)} chunks</span>
            <span>{failures.length} failures</span>
          </div>
          {auditIntegrity && (
            <div className="job-health-strip" aria-label="Audit integrity health">
              <span>audit: {auditIntegrity.status}</span>
              <span>{auditIntegrity.hashed_events} sealed</span>
              <span>{auditIntegrity.legacy_events} legacy</span>
              <span>{auditIntegrity.broken_events} broken</span>
              <Badge tone={auditIntegrityTone(auditIntegrity.status)}>
                {auditIntegrity.status}
              </Badge>
            </div>
          )}
          <div className="audit-list">
            {liveAuditLogs.length > 0
              ? liveAuditLogs.map((event) => (
                  <div className="audit-row" key={event.id}>
                    <strong>{event.action}</strong>
                    <span>{event.resource_type} / {formatAuditTime(event.created_at)}</span>
                    <p>{formatAuditMetadata(event.metadata)}</p>
                  </div>
                ))
              : auditEvents.map((event) => (
                  <div className="audit-row" key={event.id}>
                    <strong>{event.event}</strong>
                    <span>{event.scope} / {event.timestamp}</span>
                    <p>{event.result}</p>
                  </div>
                ))}
          </div>
          <div className="audit-refresh-note">
            <RefreshCw size={15} aria-hidden="true" />
            <span>Refresh the Tracker tab after upload/chat actions to pull the latest audit trail.</span>
          </div>
        </article>
      </section>
    </main>
  );
}

function countJobs(jobs: ApiProcessingJob[], status: ApiProcessingJob["status"]): number {
  return jobs.filter((job) => job.status === status).length;
}

function countChunks(documents: ApiParsedDocument[]): number {
  return documents.reduce((total, document) => total + document.chunk_count, 0);
}

function countReadiness(checks: ApiClientDataReadinessCheck[], status: ApiClientDataReadinessCheck["status"]): number {
  return checks.filter((check) => check.status === status).length;
}

function formatAuditTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function formatAuditMetadata(metadata: Record<string, unknown>): string {
  const entries = Object.entries(metadata);
  if (entries.length === 0) {
    return "No metadata recorded.";
  }
  return entries
    .map(([key, value]) => `${key}: ${formatAuditValue(value)}`)
    .join(" / ");
}

function formatAuditValue(value: unknown): string {
  if (isRedactedAuditValue(value)) {
    return `redacted ${value.sha256.slice(0, 10)}`;
  }
  if (Array.isArray(value)) {
    return `${value.length} item(s)`;
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function isRedactedAuditValue(value: unknown): value is { redacted: true; sha256: string } {
  return Boolean(
    value &&
      typeof value === "object" &&
      "redacted" in value &&
      "sha256" in value &&
      (value as { redacted?: unknown }).redacted === true &&
      typeof (value as { sha256?: unknown }).sha256 === "string"
  );
}

interface TrackerFactProps {
  label: string;
  value: string;
}

function TrackerFact({ label, value }: TrackerFactProps): JSX.Element {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function phaseTone(status: PhaseStatus): "good" | "warning" | "danger" | "info" {
  if (status === "complete") {
    return "good";
  }
  if (status === "blocked") {
    return "danger";
  }
  if (status === "pending") {
    return "warning";
  }
  return "info";
}

function gateTone(status: GateStatus): "good" | "warning" | "info" {
  if (status === "pass") {
    return "good";
  }
  if (status === "watch") {
    return "warning";
  }
  return "info";
}

function readinessTone(status: ApiClientDataReadinessCheck["status"]): "good" | "warning" | "danger" {
  if (status === "pass") {
    return "good";
  }
  if (status === "fail") {
    return "danger";
  }
  return "warning";
}

function auditIntegrityTone(status: ApiAuditIntegrityStatus["status"]): "good" | "warning" | "danger" | "info" {
  if (status === "sealed") {
    return "good";
  }
  if (status === "broken") {
    return "danger";
  }
  if (status === "legacy") {
    return "warning";
  }
  return "info";
}

function runtimeLabel(runtime: ApiLocalAiStatus["runtime"]): string {
  if (runtime === "lm_studio") {
    return "LM Studio";
  }
  if (runtime === "ollama") {
    return "Ollama";
  }
  return "unconfigured";
}
