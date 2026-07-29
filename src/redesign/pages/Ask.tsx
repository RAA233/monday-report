import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  askChat,
  getMondayReports,
  getWorkspaceBenchmarking,
  type ApiChatResponse
} from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import { Cells, ErrorState, Frame, PageHeader, Tag } from "../components/primitives";
import { useWorkspace } from "../lib/workspace";

/**
 * Ask — the chat-first home.
 *
 * Every enriched block below is a real field of `ApiChatResponse`: `workflow_steps`
 * is the runway, `insight_cards` the cell grid, `risk_register` the risk list,
 * `citations` the source list, `tool_actions` the follow-on commands. Nothing here
 * is synthesised client-side, so an answer can never display a citation or a
 * confidence the backend did not return.
 */

const COMMANDS = [
  {
    label: "Plan",
    detail: "Map evidence into DDR sections.",
    prompt: "Plan next morning report with source-backed sections and approval gates."
  },
  {
    label: "Extract",
    detail: "Focus the data model.",
    prompt: "Extract failures, NPT, tool attribution, and source gaps for this workspace."
  },
  {
    label: "Draft",
    detail: "Generate report language.",
    prompt: "Create draft report with executive summary, normal daily format, and next 24 hr plan."
  },
  {
    label: "Draw",
    detail: "Prepare schematics.",
    prompt: "Build casing schematic with hole sections, shoe depths, current MD, and risk markers."
  },
  {
    label: "Audit",
    detail: "Harden the package.",
    prompt: "Audit blockers, validation tasks, citations, export gate, and client issue checklist."
  }
];

const STARTERS = [
  "Which failures need validation before Monday Report?",
  "Draft a normal morning report from source evidence.",
  "Compare NPT by service company.",
  "Why is the drilling rate below benchmark?"
];

interface Turn {
  id: string;
  role: "user" | "assistant";
  text: string;
  answer?: ApiChatResponse;
}

const STEP_TONE: Record<string, string> = {
  blocked: "color-mix(in srgb, var(--color-accent) 14%, transparent)",
  active: "color-mix(in srgb, var(--color-accent) 8%, transparent)",
  complete: "var(--color-bg)",
  ready: "var(--color-bg)",
  watch: "var(--color-surface)"
};

export function Ask() {
  const navigate = useNavigate();
  const { activeWorkspace, apiStatus, session, openValidationTasks, localAi, auditIntegrity, readOnly } =
    useWorkspace();

  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [latestReport, setLatestReport] = useState<string | null>(null);
  const [rate, setRate] = useState<{ current: number | null; benchmark: number | null } | null>(null);
  const seq = useRef(0);

  const workspaceId = activeWorkspace?.id ?? null;

  // Snapshot reads. Each is independently tolerant: a cell that cannot be read
  // says so rather than showing a zero that looks like a measurement.
  useEffect(() => {
    if (!workspaceId) return;
    let cancelled = false;
    void getMondayReports(workspaceId)
      .then((reports) => {
        if (cancelled) return;
        const newest = reports[reports.length - 1];
        setLatestReport(newest ? `${newest.period_end} · ${newest.status}` : null);
      })
      .catch(() => {
        if (!cancelled) setLatestReport(null);
      });
    void getWorkspaceBenchmarking(workspaceId)
      .then((status) => {
        if (cancelled) return;
        setRate({
          current: status.current_ft_per_day ?? null,
          benchmark: status.gordon_average_benchmark ?? null
        });
      })
      .catch(() => {
        if (!cancelled) setRate(null);
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  const submit = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || busy) return;
      if (!workspaceId) {
        setError("No workspace is selected, so there is nothing to ask about.");
        return;
      }
      seq.current += 1;
      const id = `t${seq.current}`;
      setError(null);
      setInput("");
      setBusy(true);
      setTurns((current) => [...current, { id: `u-${id}`, role: "user", text: trimmed }]);

      void askChat(workspaceId, trimmed)
        .then((answer) => {
          setTurns((current) => [
            ...current,
            { id: `a-${id}`, role: "assistant", text: answer.answer, answer }
          ]);
        })
        .catch((caught: unknown) => {
          const message = caught instanceof Error ? caught.message : "";
          setTurns((current) => [
            ...current,
            {
              id: `a-${id}`,
              role: "assistant",
              text:
                "The workspace API did not answer, so this question was not processed. Nothing was drafted, extracted, or recorded." +
                (message ? ` (${message})` : "")
            }
          ]);
        })
        .finally(() => setBusy(false));
    },
    [busy, workspaceId]
  );

  const gateLabel = openValidationTasks === 0 ? "Clear" : `${openValidationTasks} open`;

  return (
    <section
      data-askgrid=""
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(0,1fr) minmax(min(280px,100%),320px)",
        gap: 24,
        alignItems: "start"
      }}
    >
      <div style={{ display: "grid", gap: 16, minWidth: 0 }}>
        <PageHeader
          kicker={
            [session?.tenant.name, activeWorkspace?.name, activeWorkspace?.asset]
              .filter(Boolean)
              .join(" · ") || "No workspace resolved"
          }
          title="Ask Monday Report"
          lede="Chat is the workflow: plan, extract, draft, draw, and audit from here. Every answer carries its citations, and official exports stay gated until validation clears."
        />

        <form
          style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: 10 }}
          onSubmit={(event) => {
            event.preventDefault();
            submit(input);
          }}
        >
          <input
            className="input"
            style={{ minHeight: 46, fontSize: 15 }}
            aria-label="Ask the analyst"
            placeholder="Ask about failures, NPT, tools, drilling rate, or source evidence…"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            disabled={busy || apiStatus !== "connected"}
          />
          <button
            type="submit"
            className="btn btn-primary"
            style={{ minHeight: 46, paddingInline: 18 }}
            disabled={busy || apiStatus !== "connected"}
          >
            Ask
          </button>
        </form>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(120px,100%),1fr))",
            borderBlockStart: "1px solid var(--color-divider)",
            borderInlineStart: "1px solid var(--color-divider)"
          }}
          aria-label="AI command dock"
        >
          {COMMANDS.map((command) => (
            <button
              type="button"
              key={command.label}
              className="mr-hover-accent"
              // The visible label is split across two elements, so the name is
              // stated explicitly rather than left to content concatenation.
              aria-label={`${command.label} — ${command.detail}`}
              onClick={() => submit(command.prompt)}
              disabled={busy || apiStatus !== "connected"}
              style={{
                display: "grid",
                gap: 2,
                background: "var(--color-bg)",
                border: "none",
                borderInlineEnd: "1px solid var(--color-divider)",
                borderBlockEnd: "1px solid var(--color-divider)",
                padding: "10px 12px",
                textAlign: "start",
                cursor: "pointer",
                fontFamily: "var(--font-body)",
                color: "inherit"
              }}
            >
              <strong
                style={{
                  fontFamily: "var(--font-heading)",
                  fontSize: 13.5,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  color: "var(--color-accent-700)"
                }}
              >
                {command.label}
              </strong>
              <span style={{ fontSize: 11, color: "var(--color-neutral-700)" }}>{command.detail}</span>
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }} aria-label="Starter prompts">
          {STARTERS.map((starter) => (
            <button
              type="button"
              key={starter}
              className="mr-hover-accent"
              onClick={() => submit(starter)}
              disabled={busy || apiStatus !== "connected"}
              style={{
                border: "1px solid var(--color-divider)",
                background: "transparent",
                color: "var(--color-neutral-800)",
                padding: "6px 11px",
                fontSize: 12,
                cursor: "pointer",
                fontFamily: "var(--font-body)"
              }}
            >
              {starter}
            </button>
          ))}
        </div>

        {error ? <ErrorState title="Nothing was asked" message={error} /> : null}

        <div style={{ display: "grid", alignContent: "start", gap: 14 }} aria-live="polite">
          {turns.length === 0 && !busy ? (
            <Frame style={{ padding: 16 }}>
              <p style={{ fontSize: 13.5, lineHeight: 1.55, margin: 0 }}>
                Nothing has been asked yet.{" "}
                {apiStatus === "connected"
                  ? "Use a command above or ask a question — answers come from this workspace's parsed evidence with citations attached."
                  : "The workspace API is unreachable, so questions cannot be answered right now."}
              </p>
            </Frame>
          ) : null}

          {turns.map((turn) => (
            <ChatTurn key={turn.id} turn={turn} onNavigate={navigate} readOnly={readOnly} />
          ))}

          {busy ? (
            <p
              data-skeleton=""
              className="text-muted"
              style={{ fontSize: 12.5, margin: 0 }}
              role="status"
            >
              Reasoning over workspace evidence…
            </p>
          ) : null}
        </div>
      </div>

      <aside style={{ display: "grid", gap: 16, minWidth: 0 }}>
        <div
          style={{
            display: "grid",
            borderBlockStart: "1px solid var(--color-divider)",
            borderInlineStart: "1px solid var(--color-divider)"
          }}
          aria-label="Workspace snapshot"
        >
          <SnapshotCell
            label="Validation gate"
            value={gateLabel}
            emphasis={openValidationTasks > 0}
            to="/app/validation"
          />
          <SnapshotCell
            label="Drilling rate"
            value={
              rate?.current != null
                ? `${Math.round(rate.current).toLocaleString()}${
                    rate.benchmark != null ? ` / ${Math.round(rate.benchmark).toLocaleString()}` : ""
                  }`
                : "Not recorded"
            }
            to="/app/benchmarking"
          />
          <SnapshotCell label="Latest report" value={latestReport ?? "None yet"} to="/app/reports" />
          <SnapshotCell
            label="Audit chain"
            value={auditIntegrity ? `${auditIntegrity.status} · ${auditIntegrity.total_events}` : "Unavailable"}
            to="/app/audit"
          />
        </div>

        <div style={{ border: "1px solid var(--color-divider)", padding: "12px 14px" }}>
          <strong
            style={{
              display: "block",
              fontFamily: "var(--font-heading)",
              fontSize: 13,
              letterSpacing: "0.04em",
              textTransform: "uppercase"
            }}
          >
            Local AI
          </strong>
          <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.55, margin: "6px 0 0" }}>
            {localAi
              ? `${localAi.runtime} · ${localAi.model ?? "no model reported"} — ${
                  localAi.reachable ? "reachable" : "not reachable"
                }, hosted fallback ${localAi.hosted_fallback_enabled ? "enabled" : "disabled"}. ${localAi.detail}`
              : "Local-AI status could not be read. Answers still come from the workspace's deterministic analysis path."}
          </p>
        </div>
      </aside>
    </section>
  );
}

function SnapshotCell({
  label,
  value,
  to,
  emphasis = false
}: {
  label: string;
  value: string;
  to: string;
  emphasis?: boolean;
}) {
  return (
    <Link
      to={to}
      className="mr-hover-accent"
      aria-label={`${label}: ${value}`}
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        gap: 10,
        background: "var(--color-bg)",
        borderInlineEnd: "1px solid var(--color-divider)",
        borderBlockEnd: "1px solid var(--color-divider)",
        padding: "11px 13px",
        fontFamily: "var(--font-body)",
        color: "inherit",
        textDecoration: "none",
        textAlign: "start"
      }}
    >
      <span
        style={{
          fontSize: 10.5,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--color-neutral-600)"
        }}
      >
        {label}
      </span>
      <strong
        style={{
          fontFamily: "var(--font-heading)",
          fontSize: 17,
          color: emphasis ? "var(--color-accent-800)" : "inherit"
        }}
      >
        {value}
      </strong>
    </Link>
  );
}

function ChatTurn({
  turn,
  onNavigate,
  readOnly
}: {
  turn: Turn;
  onNavigate: (path: string) => void;
  readOnly: boolean;
}) {
  const isUser = turn.role === "user";
  const answer = turn.answer;

  return (
    <article
      style={{
        display: "grid",
        gridTemplateColumns: "30px minmax(0,1fr)",
        gap: 10,
        maxWidth: isUser ? "86%" : "100%",
        marginInlineStart: isUser ? "auto" : 0
      }}
    >
      <span
        aria-hidden="true"
        style={{
          display: "grid",
          placeItems: "center",
          width: 30,
          height: 30,
          border: "1px solid var(--color-divider)",
          fontFamily: "var(--font-heading)",
          fontSize: 10.5,
          color: isUser ? "var(--color-bg)" : "var(--color-accent-800)",
          background: isUser ? "var(--color-accent-900)" : "transparent"
        }}
      >
        {isUser ? "YOU" : "MR"}
      </span>

      <div
        style={{
          border: "1px solid var(--color-divider)",
          padding: "11px 13px",
          background: isUser ? "var(--color-surface)" : "transparent"
        }}
      >
        <p style={{ fontSize: 13.5, lineHeight: 1.55, margin: 0, whiteSpace: "pre-wrap" }}>{turn.text}</p>

        {answer ? (
          <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
            {answer.workflow_steps.length > 0 ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit,minmax(min(100px,100%),1fr))",
                  borderBlockStart: "1px solid var(--color-divider)",
                  borderInlineStart: "1px solid var(--color-divider)"
                }}
                aria-label="Workflow runway"
              >
                {answer.workflow_steps.map((step) => (
                  <div
                    key={step.step}
                    style={{
                      background: STEP_TONE[step.status] ?? "var(--color-bg)",
                      borderInlineEnd: "1px solid var(--color-divider)",
                      borderBlockEnd: "1px solid var(--color-divider)",
                      padding: "8px 10px"
                    }}
                  >
                    <span
                      style={{
                        display: "block",
                        fontSize: 9,
                        letterSpacing: "0.08em",
                        textTransform: "uppercase",
                        color: "var(--color-accent-700)"
                      }}
                    >
                      {step.status}
                    </span>
                    <strong
                      style={{
                        fontFamily: "var(--font-heading)",
                        fontSize: 13.5,
                        textTransform: "uppercase",
                        letterSpacing: "0.03em"
                      }}
                    >
                      {step.step}
                    </strong>
                    <span
                      style={{
                        display: "block",
                        fontSize: 10.5,
                        color: "var(--color-neutral-700)",
                        marginTop: 2
                      }}
                    >
                      {step.detail}
                    </span>
                  </div>
                ))}
              </div>
            ) : null}

            {answer.insight_cards.length > 0 ? (
              <Cells
                label="Answer measures"
                min={120}
                items={answer.insight_cards.map((card) => ({
                  label: card.label,
                  value: card.value,
                  detail: card.detail
                }))}
              />
            ) : null}

            {answer.risk_register.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }}>
                {answer.risk_register.map((risk) => (
                  <div
                    key={risk.title}
                    style={{ border: "1px solid var(--color-divider)", padding: "8px 10px" }}
                  >
                    <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                      <strong style={{ fontFamily: "var(--font-heading)", fontSize: 13 }}>
                        {risk.title}
                      </strong>
                      <Tag tone={risk.severity === "critical" ? "critical" : "outline"}>
                        {risk.severity}
                      </Tag>
                    </div>
                    <p
                      style={{
                        fontSize: 11.5,
                        lineHeight: 1.5,
                        margin: "4px 0 0",
                        color: "var(--color-neutral-700)"
                      }}
                    >
                      {risk.detail} Mitigation: {risk.mitigation}
                    </p>
                  </div>
                ))}
              </div>
            ) : null}

            {answer.citations.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }} aria-label="Source citations">
                {answer.citations.map((citation) => (
                  <span
                    key={citation.id}
                    style={{
                      border: "1px solid var(--color-divider)",
                      padding: "7px 10px",
                      fontSize: 11.5,
                      lineHeight: 1.45,
                      color: "var(--color-neutral-700)"
                    }}
                  >
                    {formatSourceCitation(citation.locator_type, citation.locator)} ·{" "}
                    {Math.round(citation.confidence * 100)}% confidence
                    {citation.snippet ? ` — “${citation.snippet}”` : ""}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-muted" style={{ fontSize: 11.5 }}>
                No citations were returned with this answer.
              </span>
            )}

            {answer.confidence_notes.length > 0 ? (
              <ul
                className="text-muted"
                style={{ fontSize: 11.5, lineHeight: 1.5, margin: 0, paddingInlineStart: 18 }}
              >
                {answer.confidence_notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            ) : null}

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => onNavigate("/app/validation")}
              >
                Open validation
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => onNavigate("/app/studio")}
              >
                Open the draft
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => onNavigate("/app/exports")}
                disabled={readOnly}
              >
                Go to exports →
              </button>
            </div>

            {answer.export_actions.length > 0 ? (
              <span className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5 }}>
                Export actions offered by this answer: {answer.export_actions.join(", ")}. Exports are
                issued from the Exports view so the validation gate and audit entry apply.
              </span>
            ) : null}
          </div>
        ) : null}
      </div>
    </article>
  );
}
