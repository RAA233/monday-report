import { useState } from "react";
import type { JSX } from "react";
import {
  Bot,
  Cpu,
  Database,
  Download,
  FileSearch,
  LockKeyhole,
  Send,
  Sparkles,
  UserRound,
  Workflow
} from "lucide-react";
import type { FailureEvent, FilterState } from "../data/domain";
import {
  askChat,
  createReportExportSignedUrl,
  createMondayReport,
  createUploadFileSignedUrl,
  exportMondayReport,
  type ApiChatResponse,
  type ApiCitation,
  type ApiMondayReport,
  type ApiReportExport
} from "../lib/api";
import { answerQuestion, formatHours, formatPercent } from "../lib/analytics";
import { formatSourceCitation } from "../lib/citationFormat";
import { Badge } from "./Badge";

interface ChatAnalystProps {
  events: FailureEvent[];
  filters: FilterState;
  workspaceId?: string;
}

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  answer?: ReturnType<typeof answerQuestion>;
  apiAnswer?: ApiChatResponse;
}

interface ExportActionStatus {
  state: "working" | "done" | "error";
  message: string;
  url?: string;
}

interface SourceActionStatus {
  state: "working" | "done" | "error";
  message: string;
  url?: string;
}

const starterPrompts = [
  "Generate this week's Monday Report executive summary.",
  "Which failures need validation before Monday Report?",
  "Show MWD and RSS tool risk with citations.",
  "Compare NPT by service company and well."
];

export function ChatAnalyst({ events, filters, workspaceId }: ChatAnalystProps): JSX.Element {
  const [question, setQuestion] = useState("");
  const [isAsking, setIsAsking] = useState(false);
  const [chatMode, setChatMode] = useState<"api" | "fallback">(workspaceId ? "api" : "fallback");
  const [reportId, setReportId] = useState<string | null>(null);
  const [exportStatuses, setExportStatuses] = useState<Record<string, ExportActionStatus>>({});
  const [sourceStatuses, setSourceStatuses] = useState<Record<string, SourceActionStatus>>({});
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "assistant-ready",
      role: "assistant",
      text:
        "Local AI is ready. Ask across uploaded rig reports, BHA, MWD/LWD, mud motor, RSS, bit records, NPT logs, and service-company files. Source citations stay attached."
    }
  ]);

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
      [citation.id]: { state: "working", message: "Preparing source..." }
    }));

    try {
      const signed = await createUploadFileSignedUrl(citation.file_id);
      window.open(signed.url, "_blank", "noopener,noreferrer");
      setSourceStatuses((current) => ({
        ...current,
        [citation.id]: { state: "done", message: "Source ready", url: signed.url }
      }));
    } catch (error) {
      setSourceStatuses((current) => ({
        ...current,
        [citation.id]: {
          state: "error",
          message: error instanceof Error ? error.message : "Source download failed."
        }
      }));
    }
  }

  async function runExportAction(action: string): Promise<void> {
    const format = exportFormatFromAction(action);
    if (!format) {
      return;
    }

    if (!workspaceId) {
      setExportStatuses((current) => ({
        ...current,
        [action]: { state: "error", message: "Workspace API context unavailable." }
      }));
      return;
    }

    setExportStatuses((current) => ({
      ...current,
      [action]: { state: "working", message: `Creating ${format.toUpperCase()} export...` }
    }));

    try {
      let activeReportId = reportId;
      if (!activeReportId) {
        const period = currentMondayPeriod();
        const report = await createMondayReport({
          workspaceId,
          periodStart: period.start,
          periodEnd: period.end
        });
        const openValidationTasks = reportOpenValidationCount(report);
        if (openValidationTasks > 0) {
          setExportStatuses((current) => ({
            ...current,
            [action]: {
              state: "error",
              message: `Resolve ${openValidationTasks} validation task(s) before exporting an official Monday Report.`
            }
          }));
          return;
        }
        activeReportId = report.id;
        setReportId(report.id);
      }

      const exported = await exportMondayReport(activeReportId, format);
      const signed = await createReportExportSignedUrl(exported.id);
      setExportStatuses((current) => ({
        ...current,
        [action]: {
          state: "done",
          message: `${format.toUpperCase()} ready, ${formatBytes(exported.byte_size)}, SHA ${exported.sha256.slice(0, 12)}`,
          url: signed.url
        }
      }));
    } catch (error) {
      setExportStatuses((current) => ({
        ...current,
        [action]: {
          state: "error",
          message: error instanceof Error ? error.message : "Export failed."
        }
      }));
    }
  }

  async function submitQuestion(text: string): Promise<void> {
    const trimmed = text.trim();
    if (!trimmed) {
      return;
    }

    setIsAsking(true);
    setMessages((current) => [
      ...current,
      { id: `user-${Date.now()}`, role: "user", text: trimmed }
    ]);
    setQuestion("");

    try {
      if (!workspaceId) {
        throw new Error("Workspace API context unavailable");
      }
      const apiAnswer = await askChat(workspaceId, trimmed);
      setChatMode("api");
      setMessages((current) => [
        ...current,
        {
          id: `assistant-${Date.now()}`,
          role: "assistant",
          text: apiAnswer.answer,
          apiAnswer
        }
      ]);
    } catch {
      const answer = answerQuestion(trimmed, events, filters);
      setChatMode("fallback");
      setMessages((current) => [
        ...current,
        { id: `assistant-${Date.now()}`, role: "assistant", text: answer.message, answer }
      ]);
    } finally {
      setIsAsking(false);
    }
  }

  return (
    <main className="chat-layout">
      <section className="chat-main" aria-label="AI analyst chat">
        <div className="chat-header">
          <div>
            <p className="eyebrow">Local AI analyst</p>
            <h1>Ask Monday Report first</h1>
            <p>
              Start with a question, then move to upload, validation, dashboards, and exports when
              the answer needs support.
            </p>
          </div>
          <Badge tone={chatMode === "api" ? "good" : "warning"}>
            {chatMode === "api" ? "API connected" : "local fallback"}
          </Badge>
        </div>

        <div className="messages" aria-live="polite">
          {messages.map((message) => (
            <article className={`message message-${message.role}`} key={message.id}>
              <div className="message-avatar" aria-hidden="true">
                {message.role === "assistant" ? <Bot size={18} /> : <UserRound size={18} />}
              </div>
              <div className="message-body">
                {message.answer ? (
                  <AnswerBlock answer={message.answer} onChoice={(choice) => void submitQuestion(choice)} />
                ) : message.apiAnswer ? (
                  <ApiAnswerBlock
                    answer={message.apiAnswer}
                    exportStatuses={exportStatuses}
                    sourceStatuses={sourceStatuses}
                    onExportAction={(action) => void runExportAction(action)}
                    onFollowup={(choice) => void submitQuestion(choice)}
                    onOpenSource={(citation) => void openSourceCitation(citation)}
                  />
                ) : (
                  <p>{message.text}</p>
                )}
              </div>
            </article>
          ))}
        </div>

        <form
          className="composer"
          onSubmit={(event) => {
            event.preventDefault();
            void submitQuestion(question);
          }}
        >
          <input
            value={question}
            onChange={(event) => setQuestion(event.currentTarget.value)}
            placeholder="Ask about failures, NPT, tools, companies, risk, or source evidence"
            disabled={isAsking}
          />
          <button className="primary-action icon-action" type="submit" aria-label="Send question" disabled={isAsking}>
            <Send size={18} aria-hidden="true" />
          </button>
        </form>
      </section>

      <aside className="prompt-panel" aria-label="Suggested prompts">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Prompts</p>
            <h2>Chat-first workflow</h2>
          </div>
          <Sparkles size={19} aria-hidden="true" />
        </div>
        <div className="prompt-list">
          {starterPrompts.map((prompt) => (
            <button type="button" key={prompt} onClick={() => void submitQuestion(prompt)}>
              {prompt}
            </button>
          ))}
        </div>
        <div className="local-ai-stack" aria-label="Local AI routing">
          <LocalAiCard
            icon={Cpu}
            title="Local model first"
            body="Ollama or LM Studio before hosted fallback."
          />
          <LocalAiCard
            icon={Database}
            title="RAG plus tables"
            body="Vector chunks and structured failure data answer together."
          />
          <LocalAiCard
            icon={Workflow}
            title="Validation loop"
            body="Low-confidence failures route to human review."
          />
        </div>
        <div className="citation-policy">
          <LockKeyhole size={19} aria-hidden="true" />
          <p>Private report data stays tenant-scoped with citations, confidence, and audit trails.</p>
        </div>
      </aside>
    </main>
  );
}

interface ApiAnswerBlockProps {
  answer: ApiChatResponse;
  exportStatuses: Record<string, ExportActionStatus>;
  sourceStatuses: Record<string, SourceActionStatus>;
  onExportAction: (action: string) => void;
  onFollowup: (choice: string) => void;
  onOpenSource: (citation: ApiCitation) => void;
}

function ApiAnswerBlock({
  answer,
  exportStatuses,
  sourceStatuses,
  onExportAction,
  onFollowup,
  onOpenSource
}: ApiAnswerBlockProps): JSX.Element {
  return (
    <div className="answer-block">
      <div className="answer-title">
        <Badge tone="good">api</Badge>
        <strong>Source-backed response</strong>
      </div>
      <p>{answer.answer}</p>
      {answer.confidence_notes.length > 0 && (
        <div className="confidence-notes">
          {answer.confidence_notes.map((note) => (
            <span key={note}>{note}</span>
          ))}
        </div>
      )}
      {answer.followups.length > 0 && (
        <div className="choice-row">
          {answer.followups.map((choice) => (
            <button type="button" key={choice} onClick={() => onFollowup(choice)}>
              {choice}
            </button>
          ))}
        </div>
      )}
      {answer.citations.length > 0 && (
        <div className="citation-list">
          {answer.citations.slice(0, 6).map((citation) => {
            const sourceStatus = sourceStatuses[citation.id];
            return (
            <div className="citation-item" key={citation.id}>
              <div className="citation-line">
                <strong>{formatSourceCitation(citation.locator_type, citation.locator)}</strong>
                <button
                  className="source-link-button"
                  type="button"
                  onClick={() => onOpenSource(citation)}
                  disabled={!citation.file_id || sourceStatus?.state === "working"}
                  aria-label={`Open source for ${formatSourceCitation(citation.locator_type, citation.locator)}`}
                >
                  {sourceStatus?.state === "working" ? "Preparing" : "Source"}
                </button>
              </div>
              {citation.snippet}
              {sourceStatus && (
                <span className={`source-status source-status-${sourceStatus.state}`}>
                  {sourceStatus.url ? (
                    <a href={sourceStatus.url} rel="noreferrer" target="_blank">
                      {sourceStatus.message}
                    </a>
                  ) : (
                    sourceStatus.message
                  )}
                </span>
              )}
            </div>
            );
          })}
        </div>
      )}
      {answer.export_actions.length > 0 && (
        <div className="export-actions">
          {answer.export_actions.map((action) => (
            <button
              className="secondary-action export-action"
              type="button"
              key={action}
              onClick={() => onExportAction(action)}
              disabled={exportStatuses[action]?.state === "working"}
            >
              <Download size={16} aria-hidden="true" />
              {exportActionLabel(action)}
            </button>
          ))}
          {Object.entries(exportStatuses).map(([action, status]) => (
            <span className={`export-status export-status-${status.state}`} key={action}>
              {status.url ? (
                <a href={status.url} rel="noreferrer" target="_blank">
                  {status.message}
                </a>
              ) : (
                status.message
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

interface LocalAiCardProps {
  icon: typeof FileSearch;
  title: string;
  body: string;
}

function LocalAiCard({ icon: Icon, title, body }: LocalAiCardProps): JSX.Element {
  return (
    <div className="local-ai-card">
      <Icon size={18} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <span>{body}</span>
      </div>
    </div>
  );
}

interface AnswerBlockProps {
  answer: ReturnType<typeof answerQuestion>;
  onChoice: (choice: string) => void;
}

function AnswerBlock({ answer, onChoice }: AnswerBlockProps): JSX.Element {
  return (
    <div className="answer-block">
      <div className="answer-title">
        <Badge tone={answerTone(answer.kind)}>{answer.kind}</Badge>
        <strong>{answer.title}</strong>
      </div>
      <p>{answer.message}</p>
      {answer.choices && (
        <div className="choice-row">
          {answer.choices.map((choice) => (
            <button type="button" key={choice} onClick={() => onChoice(choice)}>
              {choice}
            </button>
          ))}
        </div>
      )}
      {answer.rows.length > 0 && (
        <div className="answer-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Event</th>
                <th>Company</th>
                <th>Tool</th>
                <th>NPT</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {answer.rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.eventType}</td>
                  <td>{row.company}</td>
                  <td>{row.toolSerial}</td>
                  <td>{formatHours(row.nptHours)}</td>
                  <td>{formatPercent(row.confidence)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {answer.citations.length > 0 && (
        <div className="citation-list">
          {answer.citations.slice(0, 6).map((citation) => (
            <span key={citation}>{citation}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function answerTone(kind: ReturnType<typeof answerQuestion>["kind"]): "good" | "warning" | "danger" | "info" {
  if (kind === "unsupported") {
    return "danger";
  }
  if (kind === "clarification") {
    return "warning";
  }
  if (kind === "export") {
    return "good";
  }
  return "info";
}

function exportFormatFromAction(action: string): ApiReportExport["format"] | null {
  const format = action.replace("monday_report_", "");
  if (format === "json" || format === "csv" || format === "html" || format === "pdf" || format === "xlsx") {
    return format;
  }
  return null;
}

function reportOpenValidationCount(report: ApiMondayReport): number {
  const validation = report.report_json.validation;
  if (!validation || typeof validation !== "object" || Array.isArray(validation)) {
    return 0;
  }
  const openTasks = (validation as Record<string, unknown>).open_tasks;
  return typeof openTasks === "number" ? openTasks : 0;
}

function exportActionLabel(action: string): string {
  const format = exportFormatFromAction(action);
  return format ? format.toUpperCase() : action.replace(/_/g, " ");
}

function currentMondayPeriod(): { start: string; end: string } {
  const today = new Date();
  const day = today.getDay();
  const mondayOffset = day === 0 ? -6 : 1 - day;
  const start = new Date(today);
  start.setDate(today.getDate() + mondayOffset);
  const end = new Date(start);
  end.setDate(start.getDate() + 6);
  return { start: toDateInputValue(start), end: toDateInputValue(end) };
}

function toDateInputValue(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  return `${(bytes / 1024).toFixed(1)} KB`;
}
