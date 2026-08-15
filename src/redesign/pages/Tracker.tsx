import {
  clearTrackerLanes,
  getTrackerSummary,
  projectPhases,
  testGates,
  type GateStatus,
  type PhaseStatus
} from "../../data/projectTracker";
import {
  Cells,
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
import { Navigate } from "react-router-dom";
import { integrityStateLabel } from "./Audit";
import { apiUnreadReason, useWorkspace } from "../lib/workspace";
import { SHOW_INTERNAL } from "../lib/build";

/**
 * Project tracker — ported from the v1 interface on the owner's instruction.
 *
 * Two kinds of content, and the page keeps them visually and verbally separate:
 *
 *   1. The execution narrative (phases, lanes, test gates) is the COMMITTED
 *      record in `src/data/projectTracker.ts` — a checked-in account of the
 *      program, not a live workspace read, and it is labelled as such.
 *   2. The live strip (audit-chain integrity, processing jobs) comes from the
 *      provider's shared, permission-gated API reads and renders the same four
 *      honest states as every other surface.
 */
const GATE_TEMPLATE = "1.4fr 0.6fr 1.4fr 1.2fr";

function phaseTone(status: PhaseStatus): "accent" | "neutral" | "outline" | "critical" {
  if (status === "complete") return "accent";
  if (status === "blocked") return "critical";
  if (status === "pending") return "neutral";
  return "outline";
}

function gateTone(status: GateStatus): "accent" | "neutral" | "outline" {
  if (status === "pass") return "accent";
  if (status === "watch") return "neutral";
  return "outline";
}

export function Tracker() {
  // Internal/program surface: hidden from the shipped customer build, retained in
  // the codebase (and the internal build) so its guards keep exercising it.
  if (!SHOW_INTERNAL) return <Navigate to="/app" replace />;

  const summary = getTrackerSummary();
  const { apiStatus, auditIntegrity, processingJobs, reloadProcessingJobs } = useWorkspace();
  const jobsRetry = useRetryPresence(processingJobs.state);

  return (
    <>
      <PageHeader
        kicker="Program"
        title="Project tracker"
        lede="Phase status, verification gates and audit posture for the Monday Report build. The narrative below is the committed record in src/data/projectTracker.ts — a checked-in account of the program, not a live workspace read. Only the live-status strip reads the API."
        actions={<Tag tone="outline">Committed record</Tag>}
      />

      <Frame as="section" aria-label="Live workspace status" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Live status — read from the API
        </h2>

        <div style={{ display: "grid", gap: 6 }}>
          <h3 style={{ fontSize: 13.5, letterSpacing: "0.04em", textTransform: "uppercase", margin: 0 }}>
            Audit chain
          </h3>
          {auditIntegrity.state === "ready" ? (
            <Cells
              label="Audit chain integrity"
              min={130}
              items={[
                {
                  label: "Integrity",
                  value: integrityStateLabel(auditIntegrity.data.integrity_state ?? null),
                  ok:
                    auditIntegrity.data.integrity_state === "keyed_valid"
                      ? true
                      : auditIntegrity.data.integrity_state === "broken" ||
                          auditIntegrity.data.integrity_state === "key_unavailable"
                        ? false
                        : undefined
                },
                { label: "Events", value: String(auditIntegrity.data.total_events) },
                {
                  label: "Broken",
                  value: String(auditIntegrity.data.broken_events),
                  ok: auditIntegrity.data.broken_events === 0
                }
              ]}
            />
          ) : auditIntegrity.state === "loading" ? (
            <Skeleton rows={1} label="Reading the audit integrity verdict" />
          ) : auditIntegrity.state === "unauthorized" ? (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              This session lacks the <strong>view_audit_history</strong> permission, so the audit
              posture was not read. This is not a statement about the chain's state.
            </p>
          ) : (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              {auditIntegrity.message} The audit posture was not read.
            </p>
          )}
        </div>

        <div style={{ display: "grid", gap: 6 }}>
          <h3 style={{ fontSize: 13.5, letterSpacing: "0.04em", textTransform: "uppercase", margin: 0 }}>
            Processing
          </h3>
          {processingJobs.state === "ready" ? (
            <Cells
              label="Processing job counts"
              min={110}
              items={[
                { label: "Jobs", value: String(processingJobs.data.length) },
                {
                  label: "Queued",
                  value: String(processingJobs.data.filter((job) => job.status === "queued").length)
                },
                {
                  label: "Complete",
                  value: String(processingJobs.data.filter((job) => job.status === "complete").length)
                },
                {
                  label: "Failed",
                  value: String(processingJobs.data.filter((job) => job.status === "failed").length),
                  ok: processingJobs.data.every((job) => job.status !== "failed")
                }
              ]}
            />
          ) : processingJobs.state === "loading" ? (
            <Skeleton rows={1} label="Reading the processing queue" />
          ) : processingJobs.state === "unauthorized" ? (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              This session lacks the <strong>view_processing_status</strong> permission, so the
              processing queue was not read. This is not a statement that it is empty.
            </p>
          ) : jobsRetry.show ? (
            <ErrorState
              title="Processing queue not read"
              message={
                jobsRetry.retrying
                  ? "The queue is being read again."
                  : `${processingJobs.state === "error" ? processingJobs.message : ""} This is not a statement that it is empty.`
              }
              onRetry={apiStatus === "connected" ? reloadProcessingJobs : undefined}
              retrying={jobsRetry.retrying}
            />
          ) : (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              {apiUnreadReason(apiStatus) ?? "The workspace is not resolved"}, so the processing
              queue was not read.
            </p>
          )}
        </div>
      </Frame>

      <Cells
        label="Committed phase summary"
        min={140}
        items={[
          { label: "Complete phases", value: String(summary.complete), detail: "Accepted slices" },
          { label: "Active phases", value: String(summary.active), detail: "Currently executing" },
          { label: "Pending phases", value: String(summary.pending), detail: "Planned next" },
          {
            label: "Blocked phases",
            value: String(summary.blocked),
            detail: "Requires a decision",
            ok: summary.blocked === 0
          }
        ]}
      />

      <Frame as="section" aria-label="Clear tracker" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Clear tracker
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(280px,100%),1fr))",
            gap: 14
          }}
        >
          {clearTrackerLanes.map((lane) => (
            <article
              key={lane.id}
              style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 8, alignContent: "start" }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap" }}>
                <strong style={{ fontFamily: "var(--font-heading)", fontSize: 14.5 }}>{lane.title}</strong>
                <Tag tone={gateTone(lane.status)}>{lane.status}</Tag>
              </div>
              <p style={{ fontSize: 12.5, lineHeight: 1.5, margin: 0 }}>{lane.summary}</p>
              <ul className="text-muted" style={{ fontSize: 12, lineHeight: 1.55, margin: 0, paddingInlineStart: 16 }}>
                {lane.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </Frame>

      <Frame as="section" aria-label="Execution board" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Execution board
        </h2>
        <div style={{ display: "grid", gap: 10 }}>
          {projectPhases.map((phase) => {
            const Icon = phase.icon;
            return (
              <article
                key={phase.id}
                style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 8 }}
              >
                <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignSelf: "center" }}>
                    <Icon size={15} strokeWidth={1.5} />
                  </span>
                  <span className="text-muted" style={{ fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase" }}>
                    {phase.id}
                  </span>
                  <strong style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>{phase.name}</strong>
                  <span style={{ marginInlineStart: "auto" }}>
                    <Tag tone={phaseTone(phase.status)}>{phase.status.replace(/_/g, " ")}</Tag>
                  </span>
                </div>
                <p style={{ fontSize: 12.5, lineHeight: 1.5, margin: 0 }}>{phase.objective}</p>
                <dl style={{ display: "flex", gap: 24, flexWrap: "wrap", margin: 0, fontSize: 12 }}>
                  <TrackerFact label="Owner" value={phase.owner} />
                  <TrackerFact label="Evidence" value={phase.evidence} />
                  <TrackerFact label="Next" value={phase.nextAction} />
                </dl>
              </article>
            );
          })}
        </div>
      </Frame>

      <Frame as="section" aria-label="Phase test matrix" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Phase test matrix
        </h2>
        <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "80ch" }}>
          Gate statuses and last results are part of the committed record — they describe the run
          recorded there, not a run this page performed.
        </p>
        <GridTable
          label="Test gates"
          columns={["Gate", "Status", "Command", "Last recorded result"]}
          template={GATE_TEMPLATE}
          minWidth={760}
        >
          {testGates.map((gate) => (
            <GridRow template={GATE_TEMPLATE} key={gate.id}>
              <GridCell>{gate.name}</GridCell>
              <GridCell>
                <Tag tone={gateTone(gate.status)}>{gate.status}</Tag>
              </GridCell>
              <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                <code style={{ fontSize: 11.5 }}>{gate.command}</code>
              </GridCell>
              <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>{gate.lastResult}</GridCell>
            </GridRow>
          ))}
        </GridTable>
      </Frame>
    </>
  );
}

function TrackerFact({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ minWidth: 0, maxWidth: "38ch" }}>
      <dt className="text-muted" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase" }}>
        {label}
      </dt>
      <dd style={{ margin: "2px 0 0", fontWeight: 500, overflowWrap: "anywhere" }}>{value}</dd>
    </div>
  );
}
