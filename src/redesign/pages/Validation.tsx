import { useCallback, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { getFailures, updateValidationTask, type ApiFailureRecord, type ApiValidationTask } from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import {
  EmptyState,
  ErrorState,
  Frame,
  PageHeader,
  Skeleton,
  Tag,
  useRetryPresence
} from "../components/primitives";
import {
  apiUnreadReason,
  errorText,
  isOpenValidationTask,
  useLoadable,
  useWorkspace
} from "../lib/workspace";

/**
 * Validation queue.
 *
 * Decisions go through `PATCH /validation-tasks/{id}` — so a decision here really
 * does resolve the task and really does carry server-derived reviewer attribution.
 * It moves the EXPORT GATE only for the task types the gate counts:
 * `_open_validation_tasks_for_workspace` counts open tasks whose target is a
 * `failure` or an `anomaly_event` in that workspace, so an OCR `file` task is queue
 * work that no export waits on. After a successful decision the shared open-task
 * count reloads, which is what unlocks Exports for the counted types.
 *
 * Where a task points at an extracted failure the failure's own evidence is shown
 * beside it. When the task targets something else, the card says what the target is
 * instead of borrowing an unrelated record's citation.
 */
export function Validation() {
  const {
    validationTasks,
    reloadValidationTasks,
    openQueueTasks,
    readOnly,
    can,
    showToast,
    apiStatus,
    roles
  } = useWorkspace();

  const [busyId, setBusyId] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});

  // The backend gates PATCH /validation-tasks on resolve_validation.
  const canResolve = can("resolve_validation");
  const decisionsBlocked = readOnly || !canResolve;

  // Not read until the session resolves. Keyed on `apiStatus`, this used to fire once
  // against the unresolved "checking" state and again after the probe landed - two
  // reads, and on a refused route two audited refusals, for one navigation.
  //
  // It REJECTS rather than resolving to []: an empty array would reach `ready` and let
  // a card state that the target failure is absent from the list, which a read that
  // never happened does not establish.
  const loadFailures = useCallback(async () => {
    if (apiStatus !== "connected") {
      throw new Error(
        `${apiUnreadReason(apiStatus) ?? "The workspace is not resolved"}, so failure evidence was not read.`
      );
    }
    return getFailures();
  }, [apiStatus]);
  const { value: failures, reload: reloadFailures } = useLoadable(loadFailures, [apiStatus]);

  const failureById = useMemo(() => {
    const map = new Map<string, ApiFailureRecord>();
    if (failures.state === "ready") {
      for (const failure of failures.data) map.set(failure.id, failure);
    }
    return map;
  }, [failures]);

  // The last list that was actually read, held across a refetch. Without it, resolving a
  // task set the queue to `loading`, every card unmounted - including the button that had
  // focus - and focus fell to <body>, so a keyboard user lost their place in the queue
  // and a screen-reader user was told nothing about what had happened.
  const lastReadTasks = useRef<ApiValidationTask[] | null>(null);
  if (validationTasks.state === "ready") lastReadTasks.current = validationTasks.data;
  const visibleTasks =
    validationTasks.state === "ready"
      ? validationTasks.data
      : validationTasks.state === "loading"
        ? lastReadTasks.current
        : null;
  const openTasks = useMemo(
    (): ApiValidationTask[] => (visibleTasks ? visibleTasks.filter(isOpenValidationTask) : []),
    [visibleTasks]
  );
  const queueRetry = useRetryPresence(validationTasks.state);
  // The failure-evidence retry inside each card has the same self-deleting shape.
  const failuresRetry = useRetryPresence(failures.state);

  async function decide(task: ApiValidationTask, status: "validated" | "rejected") {
    if (decisionsBlocked || busyId) return;
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
      // Drop the decided task from the retained snapshot BEFORE the refetch. Retention
      // is what keeps the surrounding cards (and the keyboard user's place) on screen,
      // but it also kept THIS card on screen with its buttons live, so a second click
      // recorded a second audited decision for one operator intent.
      lastReadTasks.current =
        lastReadTasks.current?.filter((candidate) => candidate.id !== task.id) ?? null;
      reloadValidationTasks();
      // The resolved card is about to leave the list, taking the focused button with it.
      // Move focus to the page heading so the keyboard user lands somewhere meaningful
      // instead of on <body>, and the change is announced.
      document.querySelector<HTMLElement>("[data-page-heading]")?.focus();
    } catch (caught) {
      showToast(
        "Not recorded",
        `The decision was not recorded, so the gate is unchanged. ${errorText(caught)}`
      );
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <PageHeader
        kicker="Human-in-the-loop"
        title="Validation queue"
        lede="A high-severity extracted failure, a file that needed OCR before its text could be read, and a Critical benchmark anomaly each raise a task here. Decisions are recorded with server-derived reviewer attribution — verified-reviewer only when the session authenticates a per-user credential. The export gate counts only the failure- and anomaly-targeted tasks, so resolving one of those moves it; an OCR file task is queue work that export does not wait on."
        actions={
          <Tag
            tone={openQueueTasks === null ? "neutral" : openQueueTasks > 0 ? "critical" : "outline"}
            style={{ fontSize: 13, padding: "6px 12px" }}
          >
            {/* Never "0 open" for an unread queue: that is a positive claim the
                read did not establish. */}
            {openQueueTasks === null
              ? validationTasks.state === "loading"
                ? "Checking…"
                : "Queue not read"
              : `${openQueueTasks} open`}
          </Tag>
        }
      />

      {decisionsBlocked ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          {apiStatus === "checking" ? (
            <>Checking the workspace API — decisions are disabled until the session resolves.</>
          ) : apiStatus !== "connected" ? (
            <>
              {apiUnreadReason(apiStatus)}, so no decision can be recorded and the queue is read-only.
            </>
          ) : (
            <>
              This session lacks the <strong>resolve_validation</strong> permission, so the queue is
              read-only
              {roles.length > 0 ? <> (roles: {roles.join(", ")})</> : null}. The backend refuses the
              decision route without it.
            </>
          )}
        </p>
      ) : null}

      {validationTasks.state === "loading" && lastReadTasks.current === null ? (
        <Skeleton rows={3} label="Loading the validation queue" />
      ) : null}

      {validationTasks.state === "unauthorized" ? (
        <ErrorState
          title="Queue not visible to this session"
          message="This session lacks the view_validation_queue permission, so the validation queue cannot be read here. This is not a statement that the queue is empty, and retrying cannot change it — ask a workspace admin for validator access."
        />
      ) : null}

      {queueRetry.show ? (
        <ErrorState
          title="Validation queue failed to load"
          message={
            queueRetry.retrying
              ? "The queue is being read again."
              : `${validationTasks.state === "error" ? validationTasks.message : ""} The queue is unavailable, so it cannot be shown — this is not a statement that it is empty.`
          }
          // A queue-only retry cannot reconcile `apiStatus`: `loadValidationTasks` has no
          // connectivity guard, so a successful read would render live task cards under
          // the shell banner that says nothing can be read. While degraded the shell
          // carries the correct affordance for each state ("Retry connection" for
          // offline, "Check the session" for a refusal or a 503), so no second and
          // dishonest retry is offered here.
          onRetry={apiStatus === "connected" ? reloadValidationTasks : undefined}
          retrying={queueRetry.retrying}
        />
      ) : null}

      {validationTasks.state === "ready" && openTasks.length === 0 ? (
        <EmptyState
          title="All extracted events are resolved"
          body={
            validationTasks.data.length === 0
              ? "No validation tasks exist for this tenant yet. This queue is tenant-wide; a task is raised for a high-severity extracted failure, for a file that needed OCR, and for a Critical benchmark anomaly."
              : "Every task in the tenant queue is resolved. The export gate is evaluated per workspace on the Exports view."
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
            const cardTitle = failure ? failure.event_type : task.target_type.replace(/_/g, " ");

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
                      {cardTitle}
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
                  ) : task.target_type === "failure" && failures.state !== "ready" ? (
                    // Absence of a record and a failed read are different facts.
                    <p style={{ fontSize: 13, lineHeight: 1.55, margin: "10px 0 0" }}>
                      This task targets failure <code>{task.target_id}</code>, but the failure list{" "}
                      {failures.state === "loading" ? "is still loading" : "could not be read"}, so its
                      evidence is unavailable — this is not a statement that no record exists.
                      {failuresRetry.show ? (
                        <>
                          {" "}
                          <button
                            type="button"
                            className="btn btn-ghost"
                            style={{ minHeight: 0, padding: "0 4px", fontSize: 12 }}
                            onClick={() => {
                              if (failuresRetry.retrying) return;
                              reloadFailures();
                            }}
                            aria-disabled={failuresRetry.retrying || undefined}
                          >
                            {failuresRetry.retrying ? "Retrying…" : "Retry"}
                          </button>
                        </>
                      ) : null}
                    </p>
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
                      disabled={decisionsBlocked || busyId !== null}
                      onChange={(event) =>
                        setNotes((current) => ({ ...current, [task.id]: event.target.value }))
                      }
                    />
                  </div>
                </div>

                <div style={{ display: "grid", gap: 8, alignContent: "start" }}>
                  {/* Every card repeats these labels, so each name states its target.
                      Disabled across the WHOLE queue while any decision is in flight:
                      `decide()` refuses on `busyId` regardless of which card was
                      clicked, so leaving a sibling enabled made its click a silent
                      no-op — no toast, no status, no label change. */}
                  <button
                    type="button"
                    className="btn btn-primary"
                    // WCAG 2.5.3: the name must contain the VISIBLE text, which becomes
                    // "Recording…" while this decision is in flight.
                    aria-label={
                      busyId === task.id ? `Recording… Validate: ${cardTitle}` : `Validate: ${cardTitle}`
                    }
                    onClick={() => void decide(task, "validated")}
                    disabled={decisionsBlocked || busyId !== null}
                  >
                    {busyId === task.id ? "Recording…" : "Validate"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    aria-label={`Reject: ${cardTitle}`}
                    onClick={() => void decide(task, "rejected")}
                    disabled={decisionsBlocked || busyId !== null}
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
