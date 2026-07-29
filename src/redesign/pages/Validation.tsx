import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getFailures, updateValidationTask, type ApiFailureRecord, type ApiValidationTask } from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import { EmptyState, ErrorState, Frame, PageHeader, Skeleton, Tag } from "../components/primitives";
import { isOpenValidationTask, useLoadable, useWorkspace } from "../lib/workspace";

/**
 * Validation queue.
 *
 * Decisions go through `PATCH /validation-tasks/{id}` — the same call the v1
 * interface makes — so a decision here really does resolve the task, really does
 * carry server-derived reviewer attribution, and really does move the export gate.
 * After a successful decision the shared open-task count reloads, which is what
 * unlocks Exports.
 *
 * Where a task points at an extracted failure the failure's own evidence is shown
 * beside it. When the task targets something else, the card says what the target is
 * instead of borrowing an unrelated record's citation.
 */
export function Validation() {
  const { validationTasks, reloadValidationTasks, openValidationTasks, readOnly, showToast, apiStatus, roles } =
    useWorkspace();

  const [busyId, setBusyId] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});

  const loadFailures = useCallback(async () => getFailures(), []);
  const { value: failures } = useLoadable(loadFailures, [apiStatus]);

  const failureById = useMemo(() => {
    const map = new Map<string, ApiFailureRecord>();
    if (failures.state === "ready") {
      for (const failure of failures.data) map.set(failure.id, failure);
    }
    return map;
  }, [failures]);

  const openTasks = useMemo(
    () => (validationTasks.state === "ready" ? validationTasks.data.filter(isOpenValidationTask) : []),
    [validationTasks]
  );

  async function decide(task: ApiValidationTask, status: "validated" | "rejected") {
    if (readOnly || busyId) return;
    const note = notes[task.id]?.trim();
    if (status === "rejected" && !note) {
      showToast("Reason required", "Rejecting a task needs a written resolution note for the record.");
      return;
    }
    setBusyId(task.id);
    try {
      const updated = await updateValidationTask({
        taskId: task.id,
        status,
        resolutionNote: note || undefined
      });
      const attribution = updated.reviewer_verified_at
        ? `verified reviewer ${updated.reviewer_user_id ?? "unknown"}`
        : `actor source ${updated.reviewer_actor_source ?? "unreported"} — not a verified reviewer`;
      showToast(
        status === "validated" ? "Validated" : "Rejected",
        `Decision recorded with ${attribution} and appended to the audit chain.`
      );
      reloadValidationTasks();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "The request did not complete.";
      showToast("Not recorded", `The decision was not recorded, so the gate is unchanged. ${message}`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <PageHeader
        kicker="Human-in-the-loop"
        title="Validation queue"
        lede="High-severity, low-confidence, and conflicting extractions wait here. Decisions carry verified-reviewer attribution and unlock the export gate."
        actions={
          <Tag tone={openValidationTasks > 0 ? "critical" : "outline"} style={{ fontSize: 13, padding: "6px 12px" }}>
            {openValidationTasks} open
          </Tag>
        }
      />

      {readOnly ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          {apiStatus === "connected" ? (
            <>
              This session has no validation permission — the queue is read-only. Decisions require the{" "}
              <strong>validator</strong> or <strong>admin</strong> role
              {roles.length > 0 ? <> (this session holds: {roles.join(", ")})</> : null}.
            </>
          ) : (
            <>The workspace API is unreachable, so no decision can be recorded and the queue is read-only.</>
          )}
        </p>
      ) : null}

      {validationTasks.state === "loading" ? <Skeleton rows={3} label="Loading the validation queue" /> : null}

      {validationTasks.state === "error" ? (
        <ErrorState
          title="Validation queue failed to load"
          message={`${validationTasks.message} The queue is unavailable, so the export gate cannot be evaluated here.`}
          onRetry={reloadValidationTasks}
        />
      ) : null}

      {validationTasks.state === "ready" && openTasks.length === 0 ? (
        <EmptyState
          title="All extracted events are resolved"
          body={
            validationTasks.data.length === 0
              ? "No validation tasks exist in this workspace yet. Tasks appear when extraction finds high-severity, low-confidence, or conflicting evidence."
              : "The export gate is clear. Official Monday Report exports are unlocked until new evidence raises tasks."
          }
          action={
            <Link className="btn btn-primary" to="/app/exports">
              Go to exports
            </Link>
          }
        />
      ) : null}

      {openTasks.length > 0 ? (
        <div style={{ display: "grid", gap: 16 }}>
          {openTasks.map((task) => {
            const failure = task.target_type === "failure" ? failureById.get(task.target_id) : undefined;
            const critical = task.priority === "critical";
            const conflict = task.status === "conflict";
            const citation = failure?.citations[0];

            return (
              <Frame
                as="article"
                key={task.id}
                style={{
                  padding: 18,
                  display: "grid",
                  gridTemplateColumns: "minmax(0,1fr) auto",
                  gap: 18,
                  alignItems: "start"
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
                    <Tag tone={critical ? "critical" : "outline"}>{task.priority}</Tag>
                    <h2 style={{ fontSize: 19, letterSpacing: "0.02em", textTransform: "uppercase", margin: 0 }}>
                      {failure ? failure.event_type : task.target_type.replace(/_/g, " ")}
                    </h2>
                    {conflict ? <Tag tone="neutral">conflict — sources disagree</Tag> : null}
                  </div>

                  <p className="text-muted" style={{ fontSize: 12, margin: "6px 0 0" }}>
                    {task.reason}
                  </p>

                  {failure ? (
                    <>
                      <p style={{ fontSize: 13.5, lineHeight: 1.55, margin: "10px 0 0" }}>{failure.summary}</p>
                      <dl style={{ display: "flex", gap: 24, flexWrap: "wrap", margin: "12px 0 0", fontSize: 12.5 }}>
                        <Detail label="Severity" value={failure.severity} />
                        <Detail label="Company" value={failure.company || "—"} />
                        <Detail
                          label="Tool"
                          value={[failure.tool_type, failure.tool_serial].filter(Boolean).join(" · ") || "—"}
                        />
                        <Detail label="NPT" value={`${failure.npt_hours.toFixed(1)} h`} />
                        <Detail label="Confidence" value={`${Math.round(failure.confidence * 100)}%`} />
                      </dl>
                      {citation ? (
                        <blockquote
                          style={{
                            margin: "12px 0 0",
                            borderInlineStart: "2px solid var(--color-accent)",
                            padding: "8px 14px",
                            fontSize: 12.5,
                            lineHeight: 1.5,
                            color: "var(--color-neutral-700)"
                          }}
                        >
                          “{citation.snippet}”
                          <cite
                            style={{
                              display: "block",
                              fontStyle: "normal",
                              fontSize: 11,
                              marginTop: 5,
                              color: "var(--color-accent-700)"
                            }}
                          >
                            {formatSourceCitation(citation.locator_type, citation.locator)} ·{" "}
                            {Math.round(citation.confidence * 100)}% confidence
                          </cite>
                        </blockquote>
                      ) : (
                        <p className="text-muted" style={{ fontSize: 12, margin: "12px 0 0" }}>
                          No citation is attached to this failure record.
                        </p>
                      )}
                    </>
                  ) : (
                    <p style={{ fontSize: 13, lineHeight: 1.55, margin: "10px 0 0" }}>
                      This task targets {task.target_type.replace(/_/g, " ")}{" "}
                      <code>{task.target_id}</code>. Its evidence is not part of the failure list, so no
                      extracted record is shown here.
                    </p>
                  )}

                  <div className="field" style={{ marginTop: 12, maxWidth: "60ch" }}>
                    <label htmlFor={`note-${task.id}`}>Resolution note</label>
                    <textarea
                      id={`note-${task.id}`}
                      className="input"
                      rows={2}
                      value={notes[task.id] ?? ""}
                      placeholder="Required to reject; recorded with the decision either way."
                      disabled={readOnly || busyId === task.id}
                      onChange={(event) =>
                        setNotes((current) => ({ ...current, [task.id]: event.target.value }))
                      }
                    />
                  </div>
                </div>

                <div style={{ display: "grid", gap: 8, alignContent: "start" }}>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => void decide(task, "validated")}
                    disabled={readOnly || busyId === task.id}
                  >
                    {busyId === task.id ? "Recording…" : "Validate"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => void decide(task, "rejected")}
                    disabled={readOnly || busyId === task.id}
                  >
                    Reject
                  </button>
                  <span className="text-muted" style={{ fontSize: 10.5, lineHeight: 1.45, maxWidth: 150 }}>
                    Recorded with reviewer attribution and appended to the audit chain.
                  </span>
                </div>
              </Frame>
            );
          })}
        </div>
      ) : null}
    </>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt
        className="text-muted"
        style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase" }}
      >
        {label}
      </dt>
      <dd style={{ margin: "2px 0 0", fontWeight: 500 }}>{value}</dd>
    </div>
  );
}
