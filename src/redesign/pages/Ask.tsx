import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  askChat,
  createUploadFileSignedUrl,
  getMondayReports,
  getWorkspaceBenchmarking,
  type ApiChatResponse,
  type ApiCitation
} from "../../lib/api";
import { formatSourceCitation } from "../../lib/citationFormat";
import { Cells, ErrorState, PageHeader, Tag } from "../components/primitives";
import { integrityStateLabel } from "./Audit";
import {
  apiUnreadReason,
  errorText,
  exportGateMessage,
  gateIsClear,
  gateIsClosed,
  gateLabel,
  newestReport,
  useWorkspace,
  type GateState,
  type Loadable
} from "../lib/workspace";
import { useLicense } from "../lib/license";

/**
 * Ask — the chat-first home.
 *
 * Answer-first and evidence-grounded. Each answer renders its prose first, then a
 * collapsed "Sources" disclosure (the API's own citations, opened through the
 * expiring signed-URL route), then a collapsed "Details" disclosure that folds in
 * every OTHER field of `ApiChatResponse` — `workflow_steps`, `insight_cards`,
 * `risk_register`, `confidence_notes`, `tool_actions` and `export_actions`. Nothing
 * here is synthesised client-side, so an answer can never display a citation or a
 * confidence the backend did not return, and it says so when there are none.
 *
 * The transcript is scoped to one workspace: switching workspaces clears it, and a
 * late answer for the previous workspace is dropped rather than appended under the
 * new one's heading.
 */

/**
 * Where a returned tool action leads. `kind` is the API's own enum.
 *
 * Only kinds whose destination EXISTS in this increment are routed. `schematic` and
 * `audit` would land on a labelled not-implemented page, which answers nothing, so
 * they fall through to asking the action's own prompt instead - the same treatment an
 * unknown kind gets.
 */
const TOOL_ACTION_ROUTE: Record<string, string> = {
  plan: "/app/studio",
  draft: "/app/studio",
  export: "/app/exports",
  source: "/app/validation"
};

/**
 * The guided empty state: four categories, at most two example prompts each. Picking
 * one submits it as the first question. This replaces the always-on command dock and
 * starter chips — once a conversation exists the guide is gone.
 */
const GUIDED_CATEGORIES: { heading: string; prompts: string[] }[] = [
  {
    heading: "Reports",
    prompts: ["Draft this week's Monday report", "Summarize this week's operations"]
  },
  {
    heading: "Failures / NPT",
    prompts: ["Which failures need attention first?", "Summarize NPT by service company"]
  },
  {
    heading: "Benchmarking",
    prompts: ["Why is the drilling rate below benchmark?", "Are there active benchmark anomalies?"]
  },
  {
    heading: "Evidence / Sources",
    prompts: ["What files were uploaded and parsed?", "Which sources mention stuck pipe?"]
  }
];

interface Turn {
  id: string;
  role: "user" | "assistant";
  text: string;
  answer?: ApiChatResponse;
  /** Set on an assistant turn that carries a refusal instead of an answer, so the
   *  live region can announce the SAME classification the transcript shows. */
  failed?: boolean;
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
  const { activeWorkspace, apiStatus, session, gate, auditIntegrity, can, localAi } = useWorkspace();

  // A small, truthful indicator of which analysis writes the answer text. Claims
  // "Local model" ONLY when the resolver selected it AND the runtime + model are actually
  // up (otherwise the local provider falls back to built-in analysis for every answer, so
  // built-in is what's really answering). No marketing.
  const aiProviderServing =
    localAi.state === "ready" &&
    localAi.data.active_provider === "local-model" &&
    !!localAi.data.reachable &&
    !!localAi.data.model_available;
  const aiProviderLabel = aiProviderServing ? "Local model" : "Built-in analysis";
  // A license-blocked answer should surface the app-wide read-only banner promptly.
  const { refresh: refreshLicense } = useLicense();

  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [error, setError] = useState<string | null>(null);
  // Loadable, not `| null`: null collapsed "not read yet", "refused", "failed" and
  // "read, and there is none" into one cell value, so the rail asserted "None yet"
  // for reads that never happened.
  const [latestReport, setLatestReport] = useState<Loadable<string | null>>({ state: "loading" });
  const [rate, setRate] = useState<Loadable<{ current: number | null; benchmark: number | null }>>({
    state: "loading"
  });
  const seq = useRef(0);
  // Keeps the newest turn (and the docked composer above it) in view as the
  // transcript grows.
  const endRef = useRef<HTMLDivElement | null>(null);
  // Kept mounted across the empty↔conversation switch so a send never blurs the caret.
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const workspaceId = activeWorkspace?.id ?? null;
  // Read inside async resolutions to detect a workspace switch mid-request.
  const workspaceIdRef = useRef(workspaceId);
  workspaceIdRef.current = workspaceId;

  // Snapshot reads. Each is independently tolerant: a cell that cannot be read
  // says so rather than showing a zero that looks like a measurement. A 403 is kept
  // apart from a failure (these two routes need view_reports / view_benchmarks), and
  // "no workspace resolved" is a third distinct case — not an empty result.
  useEffect(() => {
    if (!workspaceId) {
      // Two different causes. While the probe is in flight (or the API is not usable)
      // the read has not been attempted yet, which is `loading` - printing "Not read"
      // there asserts a finished attempt. Only a connected session with no workspace
      // is a real dead end.
      // Only `checking` is a read still in flight. `refused`, `misconfigured` and
      // `offline` are SETTLED outcomes, and leaving them on "Checking…" told the
      // operator a read was in progress that will never complete.
      const pending: Loadable<never> =
        apiStatus === "checking"
          ? { state: "loading" }
          : {
              state: "error",
              message: `${apiUnreadReason(apiStatus) ?? "No workspace is resolved"}, so there was nothing to read.`
            };
      setLatestReport(pending);
      setRate(pending);
      return;
    }
    let cancelled = false;
    const classify = (caught: unknown): Loadable<never> => {
      const message = caught instanceof Error ? caught.message : "";
      return /\b403\b/.test(message)
        ? { state: "unauthorized" }
        : { state: "error", message: errorText(caught) };
    };
    setLatestReport({ state: "loading" });
    setRate({ state: "loading" });
    void getMondayReports(workspaceId)
      .then((reports) => {
        if (cancelled) return;
        const newest = newestReport(reports);
        setLatestReport({ state: "ready", data: newest ? `${newest.period_end} · ${newest.status}` : null });
      })
      .catch((caught: unknown) => {
        if (!cancelled) setLatestReport(classify(caught));
      });
    void getWorkspaceBenchmarking(workspaceId)
      .then((status) => {
        if (cancelled) return;
        setRate({
          state: "ready",
          data: {
            current: status.current_ft_per_day ?? null,
            benchmark: status.gordon_average_benchmark ?? null
          }
        });
      })
      .catch((caught: unknown) => {
        if (!cancelled) setRate(classify(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId, apiStatus]);

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
      // Keep the caret in the composer through the empty→conversation switch and after
      // a guided-prompt click (whose button unmounts as the guide disappears).
      textareaRef.current?.focus();
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
          // Classify the way the provider's probe does. "Did not answer" is reserved
          // for a request that produced no status at all: a 403 is a permission
          // refusal, a 423 is the client-data readiness gate, and a 503 is a backend
          // that is up but not configured for client data. The tail goes through
          // errorText so a raw `API <status>: <detail>` never reaches the transcript.
          const status = /^API (\d{3})\b/.exec(message)?.[1];
          // Re-read the license so the app-wide banner reflects a read-only refusal.
          if (status === "423" && /licen[sc]e/i.test(message)) refreshLicense();
          // Scoped to what the client can actually know. The earlier blanket "nothing
          // was recorded" was false for a refusal: a 403 appends `permission_denied`
          // and a 423 appends `client_data.operation_blocked` to the audit chain.
          const nothingDrafted = " No report, draft or extraction was produced.";
          // "is recorded" would be an absolute the client cannot observe: both refusal
          // audits are best-effort on the backend and their success is never reported.
          const refusalRecorded = nothingDrafted + " Refusals like this are recorded in the report integrity record.";
          const text =
            status === "403"
              ? "This session is not permitted to ask questions here." +
                refusalRecorded
              : status === "423"
                ? // 423 is overloaded: the offline LICENSE read-only refusal (the
                  // runtime wrapper's middleware; its body names the license) vs. the
                  // client-data readiness gate (the main API, and only in client mode).
                  // A license refusal is blocked at/before the audit write, so it has
                  // NO audit record — do not claim one; point to the License page.
                  /licen[sc]e/i.test(message)
                  ? "Monday Report is read-only — its license is not active, so this question was not processed. Open the License page to activate; existing data, answers and backups stay available." +
                    nothingDrafted
                  : "Monday Report is not ready to record changes yet, so this question was not processed." +
                    refusalRecorded
                : status === "503"
                  ? /snapshot write conflict|please retry/i.test(message)
                    ? "Monday Report hit a temporary conflict and did not process this question. Ask again." +
                      nothingDrafted
                    : "The workspace API is not configured to serve client data yet, so this question was not processed." +
                      nothingDrafted
                  : status
                    ? `The workspace API refused this question: ${errorText(caught)}.` + nothingDrafted
                    : "The workspace API did not answer, so this question was not processed." +
                      nothingDrafted +
                      " Whether the request reached Monday Report is unknown.";
          setTurns((current) => [...current, { id: `a-${id}`, role: "assistant", text, failed: true }]);
        })
        .finally(() => {
          if (askedFor === workspaceIdRef.current) setBusy(false);
        });
    },
    [busy, workspaceId, refreshLicense]
  );

  // The chat route is gated on generate_reports by the backend.
  // Two different reasons this composer goes inert, and they need different mechanisms.
  // `askUnavailable` is STANDING - nothing is focused at the moment it becomes true, so
  // the native `disabled` attribute is correct and gives the right semantics. `busy` is
  // IN-FLIGHT and arrives while the caret is in the field: `disabled` would blur it to
  // <body> on every question, so that state is carried by readOnly/aria-disabled and an
  // inert submit handler instead.
  const askUnavailable = apiStatus !== "connected" || !can("generate_reports");
  const askDisabled = busy || askUnavailable;

  // The gate label is the backend's own report; Ask never re-derives it.
  const gateText = gateLabel(gate);

  const hasConversation = turns.length > 0;

  // Keep the newest turn in view (the composer docks at the bottom, so the operator
  // should not have to scroll to see the answer that just arrived).
  useEffect(() => {
    if (hasConversation) endRef.current?.scrollIntoView({ block: "end" });
  }, [turns, busy, hasConversation]);

  // Short, factual announcement derived from the newest assistant turn.
  const announcement = useMemo(() => {
    if (busy) return "Working on the answer.";
    const last = turns[turns.length - 1];
    if (!last || last.role !== "assistant") return "";
    // Announce the SAME thing the transcript shows. Keying on `!last.answer` made the
    // live region say "the workspace API did not answer" for a 403, a 423 and a 503 —
    // the three cases the visible text classifies correctly.
    if (last.failed) return `The question was not processed. ${last.text}`;
    if (!last.answer) return "The question was not processed.";
    const citations = last.answer.citations.length;
    return `Answer received with ${citations} citation${citations === 1 ? "" : "s"}.`;
  }, [busy, turns]);

  const scopeItems: ScopeItem[] = [
    {
      label: "Validation gate",
      value: gateText,
      detail: gate.state === "ready" ? undefined : "not a tasks-cleared claim",
      emphasis: !gateIsClear(gate),
      to: "/app/validation"
    },
    {
      label: "Drilling rate",
      value:
        rate.state !== "ready"
          ? unreadCellValue(rate)
          : rate.data.current != null
            ? `${Math.round(rate.data.current).toLocaleString()} ft/day`
            : "Not recorded",
      detail:
        rate.state === "ready" && rate.data.current != null && rate.data.benchmark != null
          ? `vs ${Math.round(rate.data.benchmark).toLocaleString()}`
          : rate.state === "unauthorized"
            ? "requires benchmark access"
            : undefined,
      to: "/app/benchmarking"
    },
    {
      label: "Latest report",
      value: latestReport.state !== "ready" ? unreadCellValue(latestReport) : (latestReport.data ?? "None yet"),
      detail: latestReport.state === "unauthorized" ? "requires report access" : undefined,
      to: "/app/reports"
    },
    {
      // Renamed from "Audit chain" to the customer term used across the app.
      label: "Report integrity",
      value:
        auditIntegrity.state === "ready"
          ? `${integrityStateLabel(auditIntegrity.data.integrity_state ?? null)} · ${auditIntegrity.data.total_events}`
          : unreadCellValue(auditIntegrity),
      detail: auditIntegrity.state === "unauthorized" ? "requires report-integrity access" : undefined,
      to: "/app/audit"
    }
  ];

  const scopeHint = askUnavailable
    ? "Asking is unavailable until the workspace API is connected and this session can generate reports."
    : `Grounded in ${activeWorkspace?.name ?? "this workspace"}${
        activeWorkspace?.asset ? ` · ${activeWorkspace.asset}` : ""
      } — your uploaded evidence in this workspace only.`;

  function newQuestion() {
    setTurns([]);
    setError(null);
    setInput("");
  }

  const composer = (
    <div style={{ display: "grid", gap: 6 }}>
      <form
        style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: 10 }}
        onSubmit={(event) => {
          event.preventDefault();
          submit(input);
        }}
      >
        <textarea
          ref={textareaRef}
          className="input"
          rows={1}
          // Overrides the base textarea.input (90px / resize:vertical): a compact,
          // non-resizable line that the operator can still grow with Shift+Enter.
          style={{ minHeight: 46, fontSize: 15, resize: "none", lineHeight: 1.5 }}
          aria-label="Ask the analyst"
          placeholder="Ask about failures, NPT, drilling rate, reports or sources…  (Enter to send · Shift+Enter for a new line)"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          // Enter sends; Shift+Enter inserts a newline. submit() itself no-ops while
          // busy or empty, so a keystroke can never double-send.
          onKeyDown={(event) => {
            // isComposing: an IME's confirm-Enter must commit the candidate, not send.
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault();
              submit(input);
            }
          }}
          disabled={askUnavailable}
          readOnly={busy}
          aria-busy={busy || undefined}
          aria-disabled={busy || undefined}
        />
        <button
          type="submit"
          className="btn btn-primary"
          style={{ minHeight: 46, paddingInline: 18 }}
          disabled={askUnavailable}
          aria-disabled={busy || undefined}
        >
          {busy ? "Asking…" : "Ask"}
        </button>
      </form>

      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        {hasConversation ? (
          <>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ minHeight: 0, padding: "0 2px", fontSize: 12 }}
              onClick={newQuestion}
              disabled={busy}
              aria-disabled={busy || undefined}
            >
              New question
            </button>
            <span aria-hidden="true" style={{ color: "var(--color-neutral-600)" }}>
              ·
            </span>
          </>
        ) : null}
        <span className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.45 }}>
          {scopeHint}
        </span>
        <span aria-hidden="true" style={{ color: "var(--color-neutral-600)" }}>
          ·
        </span>
        <span
          className="text-muted"
          style={{ fontSize: 11.5, lineHeight: 1.45 }}
          title="Which analysis writes the answer text"
        >
          {aiProviderLabel}
        </span>
      </div>
    </div>
  );

  return (
    <section
      data-askgrid=""
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(0,1fr)",
        gap: 20,
        alignItems: "start",
        maxWidth: 860
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
          lede={
            hasConversation
              ? undefined
              : "Ask about this workspace's evidence, reports, failures and benchmarks. Every answer cites the source it came from, and says so when there are none."
          }
        />

        {hasConversation ? (
          <SlimScope items={scopeItems} />
        ) : (
          <FullScope items={scopeItems} unreadReason={apiUnreadReason(apiStatus)} />
        )}

        {apiStatus === "connected" && !can("generate_reports") ? (
          <p
            role="status"
            style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
          >
            This session does not have <strong>permission to ask questions</strong>, so asking is
            disabled here.
          </p>
        ) : null}

        {error ? <ErrorState title="Nothing was asked" message={error} /> : null}

        {/* One concise announcement per answer instead of making the whole
            transcript a live region (which re-read the user's own message and
            every enriched block, and nested a second live region inside itself). */}
        <span className="mr-visually-hidden" role="status" aria-live="polite">
          {announcement}
        </span>

        {hasConversation ? (
          // A plain labelled region, NOT role="log": log carries an implicit
          // aria-live=polite, so combining it with the status line above announced
          // every answer twice — once as a summary and once as the whole subtree.
          <div style={{ display: "grid", alignContent: "start", gap: 16 }} role="group" aria-label="Conversation">
            {turns.map((turn) => (
              <ChatTurn
                key={turn.id}
                turn={turn}
                onNavigate={navigate}
                onSubmit={submit}
                standingDisabled={askUnavailable}
                busy={busy}
                gate={gate}
              />
            ))}

            {busy ? (
              // No data-skeleton on the text: the pulse animates opacity down to
              // 0.45, which would drop this real sentence to ~2:1 for half of every
              // cycle. The decorative dot pulses; the text stays legible.
              <p style={{ display: "flex", alignItems: "center", gap: 8, margin: 0 }}>
                <span data-skeleton="" aria-hidden="true" className="mr-pulse-dot" />
                <span className="text-muted" style={{ fontSize: 12.5 }}>
                  Reasoning over workspace evidence…
                </span>
              </p>
            ) : null}

            {/* scroll target for the newest turn; the bottom margin clears the sticky
                composer's height so the newest answer is not hidden behind it. */}
            <div ref={endRef} aria-hidden="true" style={{ scrollMarginBottom: 96 }} />
          </div>
        ) : null}

        {/* The composer holds ONE fixed position in the tree (with a stable key) so it
            is never unmounted when the layout switches between the empty and
            conversation states — otherwise a send would blur the caret to <body>. It
            only changes its wrapper: docked (sticky bottom) once a conversation exists,
            inline in the empty state. */}
        <div
          key="composer"
          data-composer-dock={hasConversation ? "" : undefined}
          style={
            hasConversation
              ? {
                  position: "sticky",
                  bottom: 0,
                  background: "var(--color-bg)",
                  borderBlockStart: "1px solid var(--color-divider)",
                  padding: "12px 0 6px",
                  marginTop: 4,
                  opacity: askUnavailable ? 0.85 : 1
                }
              : undefined
          }
        >
          {composer}
        </div>

        {hasConversation ? (
          <div style={{ height: 24 }} aria-hidden="true" />
        ) : (
          <Guided disabled={askDisabled} onPick={submit} />
        )}
      </div>
    </section>
  );
}

interface ScopeItem {
  label: string;
  value: string;
  detail?: string;
  to: string;
  emphasis?: boolean;
}

/** The full four-cell scope shown in the empty state, above the composer. */
function FullScope({ items, unreadReason }: { items: ScopeItem[]; unreadReason: string | null }) {
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(min(150px,100%),1fr))",
          borderBlockStart: "1px solid var(--color-divider)",
          borderInlineStart: "1px solid var(--color-divider)"
        }}
        role="group"
        aria-label="Workspace snapshot"
      >
        {items.map((item) => (
          <SnapshotCell key={item.label} {...item} />
        ))}
      </div>
      {unreadReason ? (
        <span className="text-muted" style={{ fontSize: 11.5 }}>
          {unreadReason}, so these read “not read”, not “none”.
        </span>
      ) : null}
    </div>
  );
}

/** The slim one-line scope shown once a conversation is underway. */
function SlimScope({ items }: { items: ScopeItem[] }) {
  return (
    <div
      role="group"
      aria-label="Workspace snapshot"
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: "4px 16px",
        fontSize: 12,
        alignItems: "baseline",
        border: "1px solid var(--color-divider)",
        padding: "7px 12px"
      }}
    >
      {items.map((item) => (
        <Link
          key={item.label}
          to={item.to}
          className="mr-hover-text"
          aria-label={`${item.label}: ${item.value}${item.detail ? ` ${item.detail}` : ""}`}
          style={{
            display: "inline-flex",
            gap: 6,
            alignItems: "baseline",
            color: "inherit",
            textDecoration: "none",
            padding: "2px 4px"
          }}
        >
          <span style={{ color: "var(--color-neutral-700)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: 10.5 }}>
            {item.label}
          </span>
          <strong
            style={{
              fontFamily: "var(--font-heading)",
              fontSize: 13,
              color: item.emphasis ? "var(--color-accent-800)" : "inherit"
            }}
          >
            {item.value}
          </strong>
          {item.detail ? (
            <span style={{ color: "var(--color-neutral-700)", fontSize: 11 }}>{item.detail}</span>
          ) : null}
        </Link>
      ))}
    </div>
  );
}

function SnapshotCell({ label, value, detail, to, emphasis = false }: ScopeItem) {
  return (
    <Link
      to={to}
      className="mr-hover-accent mr-cell-bg"
      aria-label={`${label}: ${value}${detail ? ` ${detail}` : ""}`}
      // No inline `background`: an inline value always beats the stylesheet, which
      // makes the .mr-hover-accent tint inert. `.mr-cell-bg` carries the resting fill.
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        gap: 10,
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

/** The guided 2×2 example-prompt grid — only rendered in the empty state. */
function Guided({ disabled, onPick }: { disabled: boolean; onPick: (prompt: string) => void }) {
  return (
    <div style={{ display: "grid", gap: 10 }}>
      <span style={{ fontSize: 13, color: "var(--color-neutral-800)" }}>
        Choose a question below or type your own.
      </span>
      <div
        style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 12 }}
        role="group"
        aria-label="Example questions"
      >
        {GUIDED_CATEGORIES.map((category) => (
          <div
            key={category.heading}
            style={{
              border: "1px solid var(--color-divider)",
              padding: "11px 12px",
              display: "grid",
              gap: 7,
              alignContent: "start"
            }}
          >
            <strong
              style={{
                fontFamily: "var(--font-heading)",
                fontSize: 12.5,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--color-accent-800)"
              }}
            >
              {category.heading}
            </strong>
            {category.prompts.map((prompt) => (
              <button
                type="button"
                key={prompt}
                className="mr-hover-accent"
                onClick={() => onPick(prompt)}
                disabled={disabled}
                // neutral-600 (3.82:1), not --color-divider: this border is the only
                // thing that identifies the chip as a control. No inline background.
                style={{
                  border: "1px solid var(--color-neutral-600)",
                  background: "transparent",
                  color: "var(--color-neutral-800)",
                  padding: "6px 10px",
                  fontSize: 12.5,
                  textAlign: "start",
                  cursor: disabled ? "not-allowed" : "pointer",
                  fontFamily: "var(--font-body)"
                }}
              >
                {prompt}
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

/** What a snapshot cell shows when its read did not produce a value. Never a figure,
 *  and never a claim about the workspace. */
function unreadCellValue(state: Loadable<unknown>): string {
  return state.state === "loading"
    ? "Checking…"
    : state.state === "unauthorized"
      ? "Not visible"
      : "Not read";
}

/**
 * `export_actions` is the backend's own token list. Only `monday_report_<fmt>` for
 * the five committed formats names something the Exports view can issue; other
 * tokens (`benchmark_evidence_json`, `moc_evidence_pdf`) name artifacts no export
 * route produces, so they are disclosed as text rather than turned into a control
 * that would lead nowhere.
 */
const MONDAY_REPORT_EXPORT = /^monday_report_(pdf|xlsx|html|csv|json)$/;

/** Per-citation progress for the "open the source" action. */
type SourceActionStatus =
  | { state: "working"; message: string }
  | { state: "done"; message: string; url: string }
  | { state: "error"; message: string };

function ChatTurn({
  turn,
  onNavigate,
  onSubmit,
  standingDisabled,
  busy,
  gate
}: {
  turn: Turn;
  onNavigate: (path: string) => void;
  onSubmit: (prompt: string) => void;
  /** A STANDING condition (no permission / API not connected): native `disabled` is
   *  correct, because nothing is focused at the moment it becomes true. */
  standingDisabled: boolean;
  /** IN-FLIGHT: it becomes true because the operator just pressed one of these, so it
   *  must never take the native attribute - that would blur them to <body>. */
  busy: boolean;
  gate: GateState;
}) {
  const isUser = turn.role === "user";
  const answer = turn.answer;

  // The citation SOURCE action, ported from the committed v1 behaviour: each cited
  // source can be opened through the API's expiring signed-URL route. Statuses are
  // per-citation and local to this turn; the URL is never a storage path.
  const [sourceStatuses, setSourceStatuses] = useState<Record<string, SourceActionStatus>>({});

  async function openSourceCitation(citation: ApiCitation): Promise<void> {
    if (!citation.file_id) {
      setSourceStatuses((current) => ({
        ...current,
        [citation.id]: { state: "error", message: "Source file is not attached to this citation." }
      }));
      return;
    }
    setSourceStatuses((current) => ({
      ...current,
      [citation.id]: { state: "working", message: "Preparing source…" }
    }));
    try {
      const signed = await createUploadFileSignedUrl(citation.file_id);
      window.open(signed.url, "_blank", "noopener,noreferrer");
      setSourceStatuses((current) => ({
        ...current,
        [citation.id]: { state: "done", message: "Source ready", url: signed.url }
      }));
    } catch (caught) {
      setSourceStatuses((current) => ({
        ...current,
        [citation.id]: { state: "error", message: `The source was not opened. ${errorText(caught)}` }
      }));
    }
  }

  if (isUser) {
    return (
      <article aria-label="Your question" style={{ display: "grid", justifyItems: "end", gap: 2 }}>
        <span
          style={{
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            color: "var(--color-neutral-700)"
          }}
        >
          You asked
        </span>
        <div
          style={{
            maxWidth: "min(70%,46ch)",
            textAlign: "end",
            fontSize: 15.5,
            fontWeight: 600,
            lineHeight: 1.4,
            whiteSpace: "pre-wrap"
          }}
        >
          {turn.text}
        </div>
      </article>
    );
  }

  const exportTokens = answer?.export_actions ?? [];
  const issuableExports = exportTokens.flatMap((token) => {
    const match = MONDAY_REPORT_EXPORT.exec(token);
    return match ? [{ token, format: match[1] }] : [];
  });
  const otherExports = exportTokens.filter((token) => !MONDAY_REPORT_EXPORT.test(token));
  // Only a gate the backend reported CLOSED blocks the control. Unread is not closed.
  const exportGated = gateIsClosed(gate);
  const sourceCount = answer?.citations.length ?? 0;

  return (
    <article aria-label="Monday Report answer" style={{ display: "grid", gap: 5 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          aria-hidden="true"
          style={{
            display: "grid",
            placeItems: "center",
            width: 24,
            height: 24,
            border: "1px solid var(--color-divider)",
            fontFamily: "var(--font-heading)",
            fontSize: 10,
            color: "var(--color-accent-800)"
          }}
        >
          MR
        </span>
        <span
          style={{
            fontFamily: "var(--font-heading)",
            fontSize: 12.5,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            color: "var(--color-neutral-700)"
          }}
        >
          Monday Report
        </span>
      </div>

      <div style={{ border: "1px solid var(--color-divider)", padding: "10px 12px", display: "grid", gap: 9 }}>
        {/* Answer prose first, at the house reading measure. */}
        <div style={{ fontSize: 14.5, lineHeight: 1.6, maxWidth: "62ch", whiteSpace: "pre-wrap" }}>
          {turn.text}
        </div>

        {answer ? (
          <>
            {/* Sources — collapsed by default so the answer reads first. */}
            <details style={{ border: 0 }}>
              <summary
                style={{ cursor: "pointer", listStyle: "none", fontSize: 12, color: "var(--color-neutral-700)" }}
              >
                {`▸ Sources (${sourceCount})`}
              </summary>
              {answer.citations.length > 0 ? (
                <div style={{ display: "grid", gap: 6, marginTop: 6 }} role="group" aria-label="Source citations">
                  {answer.citations.map((citation) => {
                    const sourceStatus = sourceStatuses[citation.id];
                    return (
                      <div key={citation.id} className="citation-item">
                        <div className="citation-line">
                          <strong style={{ fontWeight: 600 }}>
                            {formatSourceCitation(citation.locator_type, citation.locator)}
                          </strong>
                          <span className="text-muted">
                            {Math.round(citation.confidence * 100)}% confidence
                          </span>
                          {/* Native `disabled` only for the STANDING condition (no file
                              attached); the in-flight state stays focusable and is made
                              inert by the handler, matching this entry's control rules. */}
                          <button
                            type="button"
                            className="source-link-button"
                            disabled={!citation.file_id}
                            aria-disabled={sourceStatus?.state === "working" || undefined}
                            aria-label={`Open source for ${formatSourceCitation(citation.locator_type, citation.locator)}`}
                            onClick={() => {
                              if (sourceStatus?.state === "working") return;
                              void openSourceCitation(citation);
                            }}
                          >
                            {sourceStatus?.state === "working" ? "Preparing…" : "Source"}
                          </button>
                        </div>
                        {citation.snippet ? (
                          <span style={{ display: "block" }}>“{citation.snippet}”</span>
                        ) : null}
                        {sourceStatus ? (
                          <span role="status" className={`source-status source-status-${sourceStatus.state}`}>
                            {sourceStatus.state === "done" ? (
                              <a href={sourceStatus.url} rel="noreferrer" target="_blank">
                                {sourceStatus.message} — opens the expiring signed URL
                              </a>
                            ) : (
                              sourceStatus.message
                            )}
                          </span>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <span className="text-muted" style={{ display: "block", marginTop: 6, fontSize: 12 }}>
                  No citations were returned with this answer — nothing here is invented.
                </span>
              )}
            </details>

            {/* Details — the rest of the backend's structured answer, folded away so it
                supports the prose without competing with it. Nothing is dropped. */}
            <details style={{ border: 0 }}>
              <summary
                style={{ cursor: "pointer", listStyle: "none", fontSize: 11.5, color: "var(--color-neutral-700)" }}
              >
                ▸ Details
              </summary>
              <div style={{ display: "grid", gap: 10, padding: "8px 0 2px" }}>
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
                          style={{ display: "block", fontSize: 10.5, color: "var(--color-neutral-700)", marginTop: 2 }}
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
                      <div key={risk.title} style={{ border: "1px solid var(--color-divider)", padding: "8px 10px" }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                          <strong style={{ fontFamily: "var(--font-heading)", fontSize: 13 }}>{risk.title}</strong>
                          <Tag tone={risk.severity === "critical" ? "critical" : "outline"}>{risk.severity}</Tag>
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

                {/* The follow-on buttons come from the response's own `tool_actions`
                    rather than a hard-coded client list. `chat_tool_actions()` takes no
                    arguments and returns the same kinds for every prompt — only the
                    narrative, workflow steps and insight cards vary with what was asked. */}
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
                          disabled={standingDisabled && !route}
                          aria-disabled={(busy && !route) || undefined}
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

                {answer.export_actions.length > 0 ? (
                  <div style={{ display: "grid", gap: 6 }}>
                    {issuableExports.length > 0 ? (
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                        {issuableExports.map(({ token, format }) =>
                          // The gate, in the answer. A closed gate disables the control
                          // and states the committed refusal copy; an unread gate leaves
                          // it available, because the backend is the authority and
                          // refuses on its own. Issuance itself happens on the Exports
                          // view — that is where the report is named and the audit entry
                          // is written.
                          exportGated ? (
                            <button
                              key={token}
                              type="button"
                              className="btn btn-secondary"
                              disabled
                              title={exportGateMessage(gate.state === "ready" ? gate.openTasks : 0)}
                            >
                              Export {format.toUpperCase()}
                            </button>
                          ) : (
                            <Link
                              key={token}
                              className="btn btn-secondary"
                              to="/app/exports"
                              // Prefixed with the exact visible string (WCAG 2.5.3 Label
                              // in Name), not paraphrased around it.
                              aria-label={`Export ${format.toUpperCase()} — opens the Exports view to issue it`}
                            >
                              Export {format.toUpperCase()}
                            </Link>
                          )
                        )}
                      </div>
                    ) : null}
                    <span className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5 }}>
                      {/* Only claim an issuance path when a control for it is actually
                          rendered. A benchmarking answer names only non-report artifacts,
                          so the "Issued from the Exports view" sentence described a route
                          that does not exist for anything on offer. */}
                      {issuableExports.length > 0
                        ? exportGated
                          ? exportGateMessage(gate.state === "ready" ? gate.openTasks : 0)
                          : "Issued from the Exports view, where the validation gate is enforced, the file's digital fingerprint is recorded, and the issuance is added to the report integrity record."
                        : ""}
                      {otherExports.length > 0
                        ? `${issuableExports.length > 0 ? " This answer also names" : "This answer names"} ${otherExports.join(", ")}, which ${otherExports.length === 1 ? "is not a Monday-report export and is" : "are not Monday-report exports and are"} not issued from the Exports view.`
                        : ""}
                    </span>
                  </div>
                ) : null}

                <span className="text-muted" style={{ fontSize: 11, lineHeight: 1.5 }}>
                  Answers are drawn only from this workspace's uploaded evidence — never generated freely.
                </span>
              </div>
            </details>

            {/* Follow-up questions stay visible: they are the primary next step. */}
            {answer.followups.length > 0 ? (
              <div
                style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 2 }}
                role="group"
                aria-label="Suggested follow-up questions"
              >
                {answer.followups.map((followup) => (
                  <button
                    type="button"
                    key={followup}
                    className="mr-hover-accent"
                    disabled={standingDisabled}
                    aria-disabled={busy || undefined}
                    onClick={() => onSubmit(followup)}
                    style={{
                      border: "1px solid var(--color-neutral-600)",
                      background: "transparent",
                      color: "var(--color-neutral-800)",
                      padding: "6px 11px",
                      fontSize: 12,
                      cursor: standingDisabled || busy ? "not-allowed" : "pointer",
                      fontFamily: "var(--font-body)",
                      textAlign: "start"
                    }}
                  >
                    {followup}
                  </button>
                ))}
              </div>
            ) : null}
          </>
        ) : null}
      </div>
    </article>
  );
}
