import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  askChat,
  getMondayReports,
  getWorkspaceBenchmarking,
  type ApiChatResponse
} from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import { Cells, ErrorState, Frame, PageHeader, Tag } from "../components/primitives";
import { gateIsClear, gateLabel, newestReport, useWorkspace } from "../lib/workspace";

/**
 * Ask — the chat-first home.
 *
 * Every enriched block below is a real field of `ApiChatResponse`: `workflow_steps`
 * is the runway, `insight_cards` the cell grid, `risk_register` the risk list,
 * `citations` the source list, `tool_actions` the follow-on buttons, and
 * `followups` the suggestion chips. Nothing here is synthesised client-side, so an
 * answer can never display a citation or a confidence the backend did not return.
 *
 * The transcript is scoped to one workspace: switching workspaces clears it, and a
 * late answer for the previous workspace is dropped rather than appended under the
 * new one's heading.
 */

/** Where a returned tool action leads. `kind` is the API's own enum. */
const TOOL_ACTION_ROUTE: Record<string, string> = {
  plan: "/app/studio",
  draft: "/app/studio",
  schematic: "/app/well",
  audit: "/app/audit",
  export: "/app/exports",
  source: "/app/validation"
};

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
  const { activeWorkspace, apiStatus, session, gate, localAi, auditIntegrity, can } = useWorkspace();

  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [latestReport, setLatestReport] = useState<string | null>(null);
  const [rate, setRate] = useState<{ current: number | null; benchmark: number | null } | null>(null);
  const seq = useRef(0);

  const workspaceId = activeWorkspace?.id ?? null;
  // Read inside async resolutions to detect a workspace switch mid-request.
  const workspaceIdRef = useRef(workspaceId);
  workspaceIdRef.current = workspaceId;

  // Snapshot reads. Each is independently tolerant: a cell that cannot be read
  // says so rather than showing a zero that looks like a measurement.
  useEffect(() => {
    if (!workspaceId) return;
    let cancelled = false;
    void getMondayReports(workspaceId)
      .then((reports) => {
        if (cancelled) return;
        const newest = newestReport(reports);
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

  // The transcript belongs to one workspace. Answers cite that workspace's
  // evidence, so they must not survive a switch.
  useEffect(() => {
    setTurns([]);
    setError(null);
    setBusy(false);
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
      const askedFor = workspaceId; // captured: a late answer must not cross workspaces
      setError(null);
      setInput("");
      setBusy(true);
      setTurns((current) => [...current, { id: `u-${id}`, role: "user", text: trimmed }]);

      void askChat(askedFor, trimmed)
        .then((answer) => {
          if (askedFor !== workspaceIdRef.current) return;
          setTurns((current) => [
            ...current,
            { id: `a-${id}`, role: "assistant", text: answer.answer, answer }
          ]);
        })
        .catch((caught: unknown) => {
          if (askedFor !== workspaceIdRef.current) return;
          const message = caught instanceof Error ? caught.message : "";
          // A 403 is a permission refusal, not an unreachable API — the chat route
          // is gated on generate_reports. Saying "did not answer" would be wrong.
          const text = /403/.test(message)
            ? "This session is not permitted to ask: the chat route requires the generate_reports permission. Nothing was drafted, extracted, or recorded."
            : "The workspace API did not answer, so this question was not processed. Nothing was drafted, extracted, or recorded." +
              (message ? ` (${message})` : "");
          setTurns((current) => [...current, { id: `a-${id}`, role: "assistant", text }]);
        })
        .finally(() => {
          if (askedFor === workspaceIdRef.current) setBusy(false);
        });
    },
    [busy, workspaceId]
  );


  // The chat route is gated on generate_reports by the backend.
  const askDisabled = busy || apiStatus !== "connected" || !can("generate_reports");

  // The gate label is the backend's own report; Ask never re-derives it.
  const gateText = gateLabel(gate);

  // Short, factual announcement derived from the newest assistant turn.
  const announcement = useMemo(() => {
    if (busy) return "Working on the answer.";
    const last = turns[turns.length - 1];
    if (!last || last.role !== "assistant") return "";
    if (!last.answer) return "The question was not processed: the workspace API did not answer.";
    const citations = last.answer.citations.length;
    return `Answer received with ${citations} citation${citations === 1 ? "" : "s"}.`;
  }, [busy, turns]);

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
            disabled={askDisabled}
          />
          <button
            type="submit"
            className="btn btn-primary"
            style={{ minHeight: 46, paddingInline: 18 }}
            disabled={askDisabled}
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
          role="group"
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
              disabled={askDisabled}
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

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }} role="group" aria-label="Starter prompts">
          {STARTERS.map((starter) => (
            <button
              type="button"
              key={starter}
              className="mr-hover-accent"
              onClick={() => submit(starter)}
              disabled={askDisabled}
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

        {apiStatus === "connected" && !can("generate_reports") ? (
          <p
            role="status"
            style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
          >
            This session lacks <strong>generate_reports</strong>, which the chat route requires, so
            asking is disabled here.
          </p>
        ) : null}

        {error ? <ErrorState title="Nothing was asked" message={error} /> : null}

        {/* One concise announcement per answer instead of making the whole
            transcript a live region (which re-read the user's own message and
            every enriched block, and nested a second live region inside itself). */}
        <span className="mr-visually-hidden" role="status" aria-live="polite">
          {announcement}
        </span>

        {/* A plain labelled region, NOT role="log": log carries an implicit
            aria-live=polite, so combining it with the status line above announced
            every answer twice — once as a summary and once as the whole subtree. */}
        <div style={{ display: "grid", alignContent: "start", gap: 14 }} role="group" aria-label="Conversation">
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
            <ChatTurn
              key={turn.id}
              turn={turn}
              onNavigate={navigate}
              onSubmit={submit}
              disabled={askDisabled}
            />
          ))}
        </div>

        {/* Outside the log container: its own status, not a logged entry. */}
        {busy ? (
          <p data-skeleton="" className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
            Reasoning over workspace evidence…
          </p>
        ) : null}
      </div>

      {/* Named: a page with two complementary landmarks needs them distinguishable. */}
      <aside aria-label="Workspace snapshot and local AI status" style={{ display: "grid", gap: 16, minWidth: 0 }}>
        <div
          style={{
            display: "grid",
            borderBlockStart: "1px solid var(--color-divider)",
            borderInlineStart: "1px solid var(--color-divider)"
          }}
          role="group"
          aria-label="Workspace snapshot"
        >
          <SnapshotCell
            label="Validation gate"
            value={gateText}
            detail={gate.state === "ready" ? undefined : "not a queue-empty claim"}
            emphasis={!gateIsClear(gate)}
            to="/app/validation"
          />
          <SnapshotCell
            label="Drilling rate"
            value={
              rate?.current != null
                ? `${Math.round(rate.current).toLocaleString()} ft/day`
                : "Not recorded"
            }
            detail={
              rate?.current != null && rate.benchmark != null
                ? `vs ${Math.round(rate.benchmark).toLocaleString()}`
                : undefined
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

        {/* The handoff's rail also carries a well-schematic thumbnail. Its
            casing/plan/profile SVG generators port with the Stage 2 Well view, so
            rather than draw an unsourced picture the card states what is missing
            and links to the destination. */}
        <div style={{ border: "1px solid var(--color-divider)", padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 8 }}>
            <strong
              style={{
                fontFamily: "var(--font-heading)",
                fontSize: 13,
                letterSpacing: "0.04em",
                textTransform: "uppercase"
              }}
            >
              Well schematics
            </strong>
            <Link className="btn btn-ghost" to="/app/well" style={{ minHeight: 0, padding: "0 4px", fontSize: 12 }}>
              Open →
            </Link>
          </div>
          <p className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5, margin: "6px 0 0" }}>
            Casing, trajectory plan view, and vertical profile are drawn on the Well view, which is not
            part of this increment. No thumbnail is shown here rather than an illustration that is not
            this workspace's evidence.
          </p>
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
  detail,
  to,
  emphasis = false
}: {
  label: string;
  value: string;
  detail?: string;
  to: string;
  emphasis?: boolean;
}) {
  return (
    <Link
      to={to}
      className="mr-hover-accent"
      aria-label={`${label}: ${value}${detail ? ` ${detail}` : ""}`}
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
          color: "var(--color-neutral-700)"
        }}
      >
        {label}
      </span>
      <span style={{ textAlign: "end" }}>
        <strong
          style={{
            display: "block",
            fontFamily: "var(--font-heading)",
            fontSize: 17,
            color: emphasis ? "var(--color-accent-800)" : "inherit"
          }}
        >
          {value}
        </strong>
        {detail ? (
          <span style={{ display: "block", fontSize: 11, color: "var(--color-neutral-700)" }}>{detail}</span>
        ) : null}
      </span>
    </Link>
  );
}

function ChatTurn({
  turn,
  onNavigate,
  onSubmit,
  disabled
}: {
  turn: Turn;
  onNavigate: (path: string) => void;
  onSubmit: (prompt: string) => void;
  disabled: boolean;
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
                role="group"
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
              <div style={{ display: "grid", gap: 6 }} role="group" aria-label="Source citations">
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

            {/* The answer's own tool_actions decide the follow-on buttons — the
                backend's command-aware routing, not a fixed client list. */}
            {answer.tool_actions.length > 0 ? (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                {answer.tool_actions.map((action) => {
                  const route = TOOL_ACTION_ROUTE[action.kind];
                  return (
                    <button
                      type="button"
                      key={`${action.kind}-${action.label}`}
                      className="btn btn-secondary"
                      title={action.detail}
                      aria-label={`${action.label} — ${action.detail}`}
                      disabled={disabled && !route}
                      onClick={() => (route ? onNavigate(route) : onSubmit(action.prompt))}
                    >
                      {action.label}
                    </button>
                  );
                })}
              </div>
            ) : (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <button type="button" className="btn btn-secondary" onClick={() => onNavigate("/app/validation")}>
                  Open validation
                </button>
                <button type="button" className="btn btn-secondary" onClick={() => onNavigate("/app/studio")}>
                  Open the draft
                </button>
              </div>
            )}

            {answer.followups.length > 0 ? (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }} role="group" aria-label="Suggested follow-up questions">
                {answer.followups.map((followup) => (
                  <button
                    type="button"
                    key={followup}
                    className="mr-hover-accent"
                    disabled={disabled}
                    onClick={() => onSubmit(followup)}
                    style={{
                      border: "1px solid var(--color-divider)",
                      background: "transparent",
                      color: "var(--color-neutral-800)",
                      padding: "6px 11px",
                      fontSize: 12,
                      cursor: "pointer",
                      fontFamily: "var(--font-body)",
                      textAlign: "start"
                    }}
                  >
                    {followup}
                  </button>
                ))}
              </div>
            ) : null}

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
