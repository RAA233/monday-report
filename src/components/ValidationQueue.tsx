import { CheckCircle2, ClipboardCheck, ShieldAlert, XCircle } from "lucide-react";
import type { JSX } from "react";
import type { FailureEvent, ValidationStatus } from "../data/domain";
import { formatHours, formatPercent } from "../lib/analytics";
import { Badge } from "./Badge";

interface ValidationQueueProps {
  events: FailureEvent[];
  onStatusChange: (eventId: string, status: ValidationStatus) => void;
}

export function ValidationQueue({
  events,
  onStatusChange
}: ValidationQueueProps): JSX.Element {
  const tasks = events.filter(
    (event) => event.validationStatus === "needs_review" || event.validationStatus === "conflict"
  );

  return (
    <main className="view-stack">
      <section className="workspace-title" aria-labelledby="validation-title">
        <div>
          <p className="eyebrow">Human-in-the-loop</p>
          <h1 id="validation-title">Validation queue</h1>
          <p>Review high-severity, ambiguous, low-confidence, and conflicting extracted events.</p>
        </div>
        <Badge tone={tasks.length > 0 ? "warning" : "good"}>{tasks.length} open</Badge>
      </section>

      {tasks.length === 0 ? (
        <section className="empty-state">
          <ClipboardCheck size={30} aria-hidden="true" />
          <p>All extracted events are currently resolved.</p>
        </section>
      ) : (
        <section className="validation-list" aria-label="Validation tasks">
          {tasks.map((event) => (
            <article className="validation-task" key={event.id}>
              <div className="task-main">
                <div className="task-icon" aria-hidden="true">
                  <ShieldAlert size={20} />
                </div>
                <div>
                  <div className="task-title">
                    <h2>{event.eventType}</h2>
                    <Badge tone={event.validationStatus === "conflict" ? "danger" : "warning"}>
                      {event.validationStatus.replace("_", " ")}
                    </Badge>
                  </div>
                  <p>{event.summary}</p>
                  <dl className="task-facts">
                    <div>
                      <dt>Company</dt>
                      <dd>{event.company}</dd>
                    </div>
                    <div>
                      <dt>Tool</dt>
                      <dd>{event.toolSerial}</dd>
                    </div>
                    <div>
                      <dt>NPT</dt>
                      <dd>{formatHours(event.nptHours)}</dd>
                    </div>
                    <div>
                      <dt>Confidence</dt>
                      <dd>{formatPercent(event.confidence)}</dd>
                    </div>
                  </dl>
                  <blockquote>{event.citations[0]?.snippet}</blockquote>
                </div>
              </div>
              <div className="task-actions">
                <button
                  className="secondary-action"
                  type="button"
                  onClick={() => onStatusChange(event.id, "rejected")}
                >
                  <XCircle size={18} aria-hidden="true" />
                  Reject
                </button>
                <button
                  className="primary-action"
                  type="button"
                  onClick={() => onStatusChange(event.id, "validated")}
                >
                  <CheckCircle2 size={18} aria-hidden="true" />
                  Validate
                </button>
              </div>
            </article>
          ))}
        </section>
      )}
    </main>
  );
}
