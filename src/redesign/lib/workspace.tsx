import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import {
  getAuditIntegrity,
  getFailures,
  getLocalAiStatus,
  getSession,
  getValidationTasks,
  getWorkspaceBenchmarking,
  getWorkspaces,
  type ApiAuditIntegrityStatus,
  type ApiLocalAiStatus,
  type ApiSession,
  type ApiValidationTask,
  type ApiWorkspace
} from "../../lib/api";

/**
 * Workspace context for the redesigned application.
 *
 * Everything here reads the COMMITTED client in `src/lib/api.ts`. No endpoint is
 * invented and no shape is redefined; this only holds the cross-view state the
 * shell and pages share — session, workspaces, connectivity, and the open
 * validation count that gates exports.
 *
 * Connectivity is this entry's own model, in the same SPIRIT as the committed v1
 * behaviour in `src/App.tsx` (probe on mount, degrade honestly, offer a retry) but not
 * the same states: v1 carries a two-value online/offline flag and falls back to local
 * data, while this entry has no fallback dataset and distinguishes four outcomes —
 * `checking` → `connected` | `refused` | `misconfigured` | `offline`. When the API
 * cannot be used the app says which of those it is and disables actions rather than
 * pretending to have data.
 */
/**
 * `refused` and `misconfigured` are both distinct from `offline`, and from each
 * other. All three mean something other than "unreachable":
 *
 *   refused       — 401/403. The API answered; the credential or the role is the
 *                   problem, and a retry with the same key cannot succeed.
 *   misconfigured — 503. The service is up but has no client API key or no active
 *                   audit key, so it refuses BEFORE authentication runs at all.
 *                   Blaming the operator's credential for this sends them to rotate
 *                   a key that was never the cause.
 *   offline       — the request did not complete.
 */
export type ApiStatus = "checking" | "connected" | "refused" | "misconfigured" | "offline";

/**
 * Why a surface holds no data when the API is not connected — one sentence stem,
 * in one place, so a new surface cannot regress into asserting "unreachable" while
 * the probe is still in flight or after a refusal. `null` when connected: the
 * caller then has a real answer to describe.
 */
export function apiUnreadReason(apiStatus: ApiStatus): string | null {
  switch (apiStatus) {
    case "connected":
      return null;
    case "checking":
      return "The workspace API has not answered yet";
    case "refused":
      return "The workspace API refused this session's credential";
    case "misconfigured":
      return "The workspace API is not configured to serve client data yet";
    default:
      return "The workspace API is unreachable";
  }
}

/** Async state for one data surface, so every list can render the same four states. */
export type Loadable<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  /** The session may not read this surface (403). A retry cannot help. */
  | { state: "unauthorized" }
  | { state: "error"; message: string };

export interface WorkspaceContextValue {
  apiStatus: ApiStatus;
  retry: () => void;
  session: ApiSession | null;
  workspaces: ApiWorkspace[];
  activeWorkspace: ApiWorkspace | null;
  selectWorkspace: (id: string) => void;
  /**
   * Count of unresolved tasks in the tenant's validation QUEUE — what the
   * Validation view lists and the sidebar badge counts. This is NOT the export
   * gate: see `gate` below.
   *
   * `null` when the queue was not read (loading, unauthorized, or failed). Callers
   * must render the absence, never substitute 0: "0 open" is a positive claim that
   * the queue is empty, and an unread queue is not evidence of that.
   */
  openQueueTasks: number | null;
  /**
   * The export gate, computed with the BACKEND's exact predicate.
   *
   * `POST /monday-reports/{id}/exports/{fmt}` enforces
   * `_open_validation_tasks_for_workspace`, which counts a validation task only
   * when: status is `open` (NOT `conflict`), the target type is `failure` or
   * `anomaly_event`, and that target belongs to the report's workspace. A naive
   * count over `GET /validation-tasks` satisfies none of those three conditions —
   * it is tenant-wide, all target types, and counts `conflict` — so it would put a
   * figure in the committed gate copy that the backend does not enforce.
   *
   * Reconstructed here from three READ-ONLY endpoints that carry the needed scope:
   * `/validation-tasks`, `/failures` (failure -> workspace) and
   * `/workspaces/{id}/benchmarking` (anomaly -> workspace). The `/validation-tasks`
   * payload is the snapshot this provider already holds (`validationTasks`), never a
   * second read — a refused GET appends a `permission_denied` audit event, so asking
   * twice would double them for one user intent.
   *
   * Deliberately NOT read from `GET /workspaces/{id}/report-draft`. That endpoint
   * publishes the backend's own number, but it calls
   * `store.audit("report_draft.generate")` — reading it on page load would append an
   * audit event claiming a draft was generated when the user merely opened a page,
   * inflating a hash-chained trust surface, and would put a write in the path of
   * every navigation.
   *
   * `unauthorized` is distinct from `error`: a session that may not read the queue
   * has produced no evidence about the gate, and must not strand a user who IS
   * permitted to export — the backend remains the authority in that case.
   */
  gate: GateState;
  reloadGate: () => void;
  validationTasks: Loadable<ApiValidationTask[]>;
  reloadValidationTasks: () => void;
  /**
   * Both are permission-gated status reads, so "not read" has three causes that must
   * not collapse into one word: still loading, refused for want of the permission
   * (`view_audit_history` / `view_runtime_status`), or a read that failed. Only the
   * last is an outage.
   */
  auditIntegrity: Loadable<ApiAuditIntegrityStatus>;
  localAi: Loadable<ApiLocalAiStatus>;
  /** True when nothing can mutate at all (API unreachable / still probing). */
  readOnly: boolean;
  /**
   * Server-derived capability check against the session's permission map
   * (`permission_map` over the identity's roles — the same model the backend
   * enforces per route). Default-deny: unknown permission, missing map, or a
   * role without the grant all return false.
   */
  can: (permission: string) => boolean;
  roles: string[];
  toast: { kind: string; text: string } | null;
  showToast: (kind: string, text: string) => void;
  dismissToast: () => void;
  /** Hold the toast open (hover/focus) so it is not dismissed mid-read. */
  pauseToast: () => void;
  resumeToast: () => void;
}

/**
 * The export gate: the backend's own PREDICATE, applied by this client to read-only
 * data the backend returned. It is not a figure the backend published - see the
 * `gate` field's own note - except on the Studio's draft path, where
 * `ApiReportDraft.open_validation_tasks` IS the backend's own count.
 *
 *   loading      — the read is in flight; assert nothing
 *   ready        — `openTasks` is the count that predicate yields for this workspace
 *   unauthorized — this session may not read the gate (403). Not evidence about
 *                  the gate; the backend still enforces it on export.
 *   error        — the read failed. Also not evidence.
 *   unavailable  — no workspace selected / API offline
 */
export type GateState =
  | { state: "loading" }
  | { state: "ready"; openTasks: number; clear: boolean }
  | { state: "unauthorized" }
  | { state: "error"; message: string }
  | { state: "unavailable" };

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

/**
 * Validation-task statuses that still need a reviewer decision.
 *
 * `ApiValidationTask.status` is the committed union open|validated|rejected|conflict.
 * Used for the QUEUE count (what a reviewer still has to look at) — a `conflict`
 * needs human attention even though the backend's export gate counts only `open`.
 */
const UNRESOLVED_TASK_STATUSES: ReadonlyArray<ApiValidationTask["status"]> = ["open", "conflict"];

export function isOpenValidationTask(task: ApiValidationTask): boolean {
  return UNRESOLVED_TASK_STATUSES.includes(task.status);
}

/**
 * The committed gate copy. `count` must come from `GateState.openTasks` - the
 * backend's predicate applied to backend data, or the draft's own published count -
 * never from an ad-hoc count of `/validation-tasks`, which is tenant-wide, includes
 * every target type, and counts `conflict`.
 */
export function exportGateMessage(count: number): string {
  return `Resolve ${count} validation task(s) before exporting an official Monday Report.`;
}

/** True only when the backend reported the gate AND reported it clear. */
export function gateIsClear(gate: GateState): boolean {
  return gate.state === "ready" && gate.clear;
}

/** True only when the backend reported the gate AND reported it closed. */
export function gateIsClosed(gate: GateState): boolean {
  return gate.state === "ready" && !gate.clear;
}

/** Short label for a gate chip/cell. Never says "clear" unless the backend did. */
export function gateLabel(gate: GateState): string {
  switch (gate.state) {
    case "ready":
      return gate.clear ? "Clear" : `${gate.openTasks} open`;
    case "loading":
      return "Checking…";
    case "unauthorized":
      return "Not visible";
    case "error":
      return "Unknown";
    default:
      return "Unavailable";
  }
}

/**
 * Newest report by an explicit ordering key.
 *
 * `GET /monday-reports` applies no sort, so array position is backend-dependent
 * (dict insertion order on the local JSON store, physical row order on Postgres).
 * Order by created_at, then period_end, and use position only to break an exact
 * tie — so "the current report" means the same thing on both backends.
 */
export function newestReport<T extends { id: string; created_at: string; period_end: string }>(
  reports: readonly T[]
): T | null {
  if (reports.length === 0) return null;
  return reports.reduce((best, candidate) => (compareReports(candidate, best) > 0 ? candidate : best));
}

function compareReports(
  a: { id: string; created_at: string; period_end: string },
  b: { id: string; created_at: string; period_end: string }
): number {
  const byCreated = compareTimestamp(a.created_at, b.created_at);
  if (byCreated !== 0) return byCreated;
  const byPeriod = compareTimestamp(a.period_end, b.period_end);
  if (byPeriod !== 0) return byPeriod;
  // Final tie-break on the id, which is stable across backends. Array position is
  // NOT usable here: it is dict-insertion order on the local JSON store and
  // physical row order on Postgres.
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function compareTimestamp(a: string, b: string): number {
  // Never compare ISO instants as strings: pydantic omits a zero microsecond field,
  // and "…56Z" > "…56.000001Z" byte-wise ('Z' > '.'), which sorts the EARLIER
  // instant last. Parse first; fall back to the raw strings only if unparseable.
  const left = Date.parse(a);
  const right = Date.parse(b);
  if (!Number.isNaN(left) && !Number.isNaN(right)) {
    return left === right ? 0 : left < right ? -1 : 1;
  }
  return a === b ? 0 : a < b ? -1 : 1;
}

/** The HTTP status embedded in a thrown request error, or null when the request
 *  never produced a response (network failure, abort, timeout, CORS). Reads the
 *  ORIGINAL typed message the api client throws (`API <status>: …`), never the
 *  sanitized `errorText()` output — sanitization is presentation-only and must not
 *  drive classification, or a refused request reads as an incomplete one. */
export function requestStatus(error: unknown): number | null {
  if (error instanceof Error && error.message) {
    const match = /^API (\d{3})\b/.exec(error.message);
    if (match) return Number(match[1]);
  }
  return null;
}

/** True only when the status PROVES the server rejected the request before applying
 *  it — a 4xx client error (validation, auth, permission, state/conflict, rate limit).
 *  For those, and only those, is the mutation's effect KNOWN to be "nothing applied",
 *  so the caller may safely re-decide.
 *
 *  A 5xx or gateway status (500/502/503/504) is deliberately NOT a refusal: a 500 can
 *  be raised AFTER a partial write or a commit, and a 502/503/504 can be minted by a
 *  proxy that never received the backend's answer — so whether the mutation landed is
 *  genuinely unknown. Those, like a null status (network failure/abort/timeout/CORS),
 *  fall through to the fail-closed branch: reconcile before retrying, never tell the
 *  operator "nothing was applied". */
export function isBackendRefusal(error: unknown): boolean {
  const status = requestStatus(error);
  return status !== null && status >= 400 && status < 500;
}

/** The one place that turns a failed AUDITED MUTATION into operator-facing words.
 *
 *  Every mutating call site in the redesign routes its catch through this instead of
 *  writing its own string, because the distinction is not a wording preference — it is
 *  a safety claim. A 4xx PROVES the backend rejected the request before applying it, so
 *  naming the mutation "refused"/"not recorded"/"not built" is honest and repeating the
 *  action is safe. Everything else — a 5xx (which can be raised after a commit), a
 *  gateway 502/504 minted by a proxy that never received the backend's answer, a
 *  timeout, an aborted or dropped connection — leaves the outcome UNKNOWN. Claiming
 *  "nothing happened" there is the one statement that must never be made: the api
 *  client mints a FRESH Idempotency-Key per call, so an operator who believes the
 *  mutation did not land repeats it and creates a second audited effect for one intent.
 *
 *  @param noun     what the operator tried to do, e.g. "export", "decision".
 *  @param refused  the headline for a PROVEN refusal, e.g. "Not recorded".
 *  @param next     optional next action, appended to BOTH branches — a useful action
 *                  does not require a false certainty claim to be worth offering.
 */
export function describeMutationFailure(
  error: unknown,
  { noun, refused, next }: { noun: string; refused: string; next?: string }
): { headline: string; body: string; proven: boolean } {
  const detail = errorText(error);
  const tail = next ? ` ${next}` : "";
  if (isBackendRefusal(error)) {
    return {
      headline: refused,
      body: `${detail}${tail}`,
      proven: true
    };
  }
  return {
    headline: "Outcome unknown",
    body:
      `The backend's answer was lost, so this ${noun} may or may not have been applied — ` +
      `do not repeat it until you have re-read the current state, because a repeat that ` +
      `lands twice is recorded twice. ${detail}${tail}`,
    proven: false
  };
}

/** Short, sanitized form of a thrown request error. Exported so every user-facing
 *  string goes through one sanitizer instead of interpolating `API 409: …` raw.
 *  Classification must use `requestStatus`/`isBackendRefusal` on the raw error, not
 *  this string, whose `^API ` rewrite deliberately erases the typed status. */
export function errorText(error: unknown): string {
  // Surfaced to users, so keep it short and never leak a raw stack or a URL.
  if (error instanceof Error && error.message) {
    return error.message.replace(/^API\s/, "Request failed: ");
  }
  return "The request did not complete.";
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [session, setSession] = useState<ApiSession | null>(null);
  const [workspaces, setWorkspaces] = useState<ApiWorkspace[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [validationTasks, setValidationTasks] = useState<Loadable<ApiValidationTask[]>>({
    state: "loading"
  });
  const [gate, setGate] = useState<GateState>({ state: "unavailable" });
  const [gateTick, setGateTick] = useState(0);
  const [auditIntegrity, setAuditIntegrity] = useState<Loadable<ApiAuditIntegrityStatus>>({
    state: "loading"
  });
  const [localAi, setLocalAi] = useState<Loadable<ApiLocalAiStatus>>({ state: "loading" });
  const [toast, setToast] = useState<{ kind: string; text: string } | null>(null);
  const [probe, setProbe] = useState(0);
  const toastTimer = useRef<number | undefined>(undefined);

  const toastPaused = useRef(false);

  const armToastTimer = useCallback(() => {
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => {
      if (toastPaused.current) return; // held open by hover/focus; resume re-arms
      setToast(null);
    }, 5200);
  }, []);

  const showToast = useCallback(
    (kind: string, text: string) => {
      // Reset the hold: a pause left set by a previous toast (e.g. dismissed from
      // the keyboard, so no mouseleave ever fired) would make this one permanent.
      toastPaused.current = false;
      setToast({ kind, text });
      armToastTimer();
    },
    [armToastTimer]
  );

  const dismissToast = useCallback(() => {
    toastPaused.current = false;
    window.clearTimeout(toastTimer.current);
    setToast(null);
  }, []);

  const pauseToast = useCallback(() => {
    toastPaused.current = true;
    window.clearTimeout(toastTimer.current);
  }, []);

  const resumeToast = useCallback(() => {
    toastPaused.current = false;
    armToastTimer();
  }, [armToastTimer]);

  // The auto-dismiss timer must not outlive the provider.
  useEffect(() => () => window.clearTimeout(toastTimer.current), []);

  // A monotonic token: only the newest queue read may publish its result, so a
  // slow earlier read cannot overwrite a newer one.
  const queueToken = useRef(0);
  // Bumped only when a queue read reaches a TERMINAL state. The gate effect keys on
  // this scalar instead of the Loadable object, whose identity changes on the
  // intermediate "loading" transition too and re-ran the gate's three fetches twice.
  const [queueVersion, setQueueVersion] = useState(0);

  const loadValidationTasks = useCallback(async () => {
    const token = ++queueToken.current;
    setValidationTasks({ state: "loading" });
    try {
      const tasks = await getValidationTasks();
      if (token !== queueToken.current) return;
      setValidationTasks({ state: "ready", data: tasks });
      setQueueVersion((n) => n + 1);
    } catch (error) {
      if (token !== queueToken.current) return;
      // A 403 is not a load failure: retrying cannot help, and offering Retry
      // implies it could. GET /validation-tasks requires view_validation_queue.
      const message = error instanceof Error ? error.message : "";
      if (/\b403\b/.test(message)) {
        setValidationTasks({ state: "unauthorized" });
        setQueueVersion((n) => n + 1);
        return;
      }
      setValidationTasks({ state: "error", message: errorText(error) });
      setQueueVersion((n) => n + 1);
    }
  }, []);

  // Re-reading the gate re-reads everything it is computed from. The queue snapshot
  // is one of its inputs, so bumping only the tick would recompute the same verdict
  // from the same stale task list.
  const reloadGate = useCallback(() => {
    void loadValidationTasks();
    setGateTick((n) => n + 1);
  }, [loadValidationTasks]);

  useEffect(() => {
    let cancelled = false;
    setApiStatus("checking");

    void (async () => {
      let probedSession: ApiSession;
      try {
        // The session probe decides connectivity: it is the cheapest authenticated
        // read and it is what tells us the tenant we are scoped to.
        const [nextSession, nextWorkspaces] = await Promise.all([getSession(), getWorkspaces()]);
        if (cancelled) return;
        probedSession = nextSession;
        setSession(nextSession);
        setWorkspaces(nextWorkspaces);
        setActiveId((current) => current ?? nextWorkspaces[0]?.id ?? null);
        setApiStatus("connected");
      } catch (error) {
        if (cancelled) return;
        // Classify the refusal instead of calling every failure unreachability.
        // `src/lib/api.ts` throws `API <status>: <detail>`, so the status is here:
        // 401/403 = credential or role, 503 = a backend that is up but has no client
        // API key or no active audit key. All three answered; none is "unreachable",
        // the retry offered for `offline` cannot fix any of them, and a 503 must not
        // be attributed to the operator's credential.
        const message = error instanceof Error ? error.message : "";
        const refusal = /^API (401|403|503)\b/.exec(message);
        // The two status surfaces must leave `loading` on this path too, or a chip
        // would sit on "Checking…" forever after a failed probe.
        // `unauthorized` means "this session may not read THIS surface", and the
        // consumers name the specific permission when they render it. A 401 (no valid
        // credential at all) and a 503 (unconfigured backend) are not that, so they
        // stay `error` with their own sentence; only a 403 earns `unauthorized`.
        const unreadStatus: Loadable<never> = refusal
          ? refusal[1] === "403"
            ? { state: "unauthorized" }
            : {
                state: "error",
                message:
                  refusal[1] === "503"
                    ? "The workspace API is not configured to serve client data yet."
                    : "The workspace API refused this session's credential."
              }
          : { state: "error", message: "The workspace API is unreachable." };
        setAuditIntegrity(unreadStatus);
        setLocalAi(unreadStatus);
        if (refusal) {
          const misconfigured = refusal[1] === "503";
          setApiStatus(misconfigured ? "misconfigured" : "refused");
          // Not `unauthorized`: the Validation view renders that as "this session lacks
          // view_validation_queue", and a probe refusal on /auth/session or /workspaces
          // tests neither that route nor that permission. Report what was observed.
          setValidationTasks({
            state: "error",
            message: `${apiUnreadReason(misconfigured ? "misconfigured" : "refused")}, so the validation queue was not read.`
          });
          return;
        }
        setApiStatus("offline");
        setValidationTasks({
          state: "error",
          message: "The workspace API is unreachable, so validation state cannot be read."
        });
        return;
      }

      // Secondary reads are individually tolerant: one failing surface must not
      // take down the shell. Success paths also honour `cancelled` so a stale
      // probe cannot overwrite a newer one's result.
      //
      // Both are permission-gated (`view_audit_history`, `view_runtime_status`), and
      // ENGINEER holds neither. Asking anyway produced a refused GET — one more
      // `permission_denied` entry in the hash-chained log per mount — and the chip
      // then reported the refusal as "unavailable", i.e. an outage. Skip the request
      // when the session we just probed says it may not read it, and record which of
      // the two it was.
      void loadValidationTasks();
      const permits = (permission: string) => probedSession.permissions?.[permission] === true;
      if (!permits("view_audit_history")) {
        if (!cancelled) setAuditIntegrity({ state: "unauthorized" });
      } else {
        try {
          const integrity = await getAuditIntegrity();
          if (!cancelled) setAuditIntegrity({ state: "ready", data: integrity });
        } catch (integrityError) {
          if (!cancelled) setAuditIntegrity({ state: "error", message: errorText(integrityError) });
        }
      }
      if (!permits("view_runtime_status")) {
        if (!cancelled) setLocalAi({ state: "unauthorized" });
      } else {
        try {
          const ai = await getLocalAiStatus();
          if (!cancelled) setLocalAi({ state: "ready", data: ai });
        } catch (aiError) {
          if (!cancelled) setLocalAi({ state: "error", message: errorText(aiError) });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [probe, loadValidationTasks]);

  const retry = useCallback(() => setProbe((n) => n + 1), []);

  const roles = useMemo(() => {
    const raw = session?.authenticated_identity?.roles ?? session?.user.roles ?? [];
    return raw.map(String);
  }, [session]);

  // Offline / probing = nothing can mutate. Per-action capability is `can()`.
  const readOnly = apiStatus !== "connected";

  const can = useCallback(
    (permission: string): boolean => {
      if (apiStatus !== "connected") return false;
      // The session's permission map is the backend's own `permission_map` over
      // the identity's roles — the model each route enforces. Default-deny when
      // the map or the key is absent, exactly like the server.
      return session?.permissions?.[permission] === true;
    },
    [apiStatus, session]
  );

  const openQueueTasks = useMemo(() => {
    if (validationTasks.state !== "ready") return null;
    return validationTasks.data.filter(isOpenValidationTask).length;
  }, [validationTasks]);

  const activeWorkspace = useMemo(
    () => workspaces.find((workspace) => workspace.id === activeId) ?? workspaces[0] ?? null,
    [workspaces, activeId]
  );

  // Reconstruct the gate with the backend's own predicate, from READ-ONLY reads.
  // Tokened so a slow read for a previous workspace cannot publish over a newer one.
  const gateToken = useRef(0);
  const activeWorkspaceId = activeWorkspace?.id ?? null;
  // The queue snapshot this provider already holds, read through a ref: the gate's
  // task list must NOT be fetched a second time. Every refused GET
  // /validation-tasks appends a `permission_denied` event to the hash-chained audit
  // log, so a session without view_validation_queue was writing two of them per
  // mount for one user intent.
  const queueRef = useRef(validationTasks);
  queueRef.current = validationTasks;
  useEffect(() => {
    const token = ++gateToken.current;
    if (apiStatus !== "connected" || !activeWorkspaceId) {
      setGate({ state: "unavailable" });
      return;
    }
    const queue = queueRef.current;
    // Not read yet — stay in `loading`. The terminal transition bumps
    // `queueVersion`, which re-runs this effect with a real snapshot.
    if (queue.state === "loading") {
      setGate({ state: "loading" });
      return;
    }
    // The queue's own outcome IS the gate's outcome for these two: a session that
    // may not read the queue has produced no evidence about the gate, and a failed
    // read is not evidence either. Neither needs another request to establish.
    if (queue.state === "unauthorized") {
      setGate({ state: "unauthorized" });
      return;
    }
    if (queue.state === "error") {
      setGate({ state: "error", message: queue.message });
      return;
    }
    const tasks = queue.data;
    setGate({ state: "loading" });
    void (async () => {
      try {
        const failures = await getFailures();
        // Anomaly-targeted tasks also hold the gate, and only this workspace-scoped
        // read maps an anomaly to its workspace. Without it there is no defensible
        // count: counting every tenant anomaly task would inflate the number printed
        // in the committed gate copy, and dropping them would understate the gate.
        // So the gate is reported as UNREADABLE rather than guessed.
        let anomalyIds: Set<string>;
        try {
          const benchmarking = await getWorkspaceBenchmarking(activeWorkspaceId);
          anomalyIds = new Set(
            [...benchmarking.active_anomalies, ...benchmarking.historical_anomalies].map(
              (anomaly) => anomaly.id
            )
          );
        } catch (benchmarkingError) {
          if (token !== gateToken.current) return;
          const message = benchmarkingError instanceof Error ? benchmarkingError.message : "";
          setGate(
            /\b403\b/.test(message)
              ? { state: "unauthorized" }
              : {
                  state: "error",
                  message:
                    "Anomaly scope could not be read, so the gate count cannot be attributed to this workspace."
                }
          );
          return;
        }
        if (token !== gateToken.current) return;

        const workspaceFailureIds = new Set(
          failures
            .filter((failure) => failure.workspace_id === activeWorkspaceId)
            .map((failure) => failure.id)
        );
        const holding = tasks.filter((task) => {
          if (task.status !== "open") return false; // the backend counts `open` only
          if (task.target_type === "failure") return workspaceFailureIds.has(task.target_id);
          if (task.target_type === "anomaly_event") return anomalyIds.has(task.target_id);
          return false; // every other target type is outside the gate
        });
        setGate({ state: "ready", openTasks: holding.length, clear: holding.length === 0 });
      } catch (error) {
        if (token !== gateToken.current) return;
        const message = error instanceof Error ? error.message : "";
        // A 403 is evidence about this session's permissions, not about the gate.
        if (/\b403\b/.test(message)) {
          setGate({ state: "unauthorized" });
          return;
        }
        setGate({ state: "error", message: errorText(error) });
      }
    })();
  }, [apiStatus, activeWorkspaceId, gateTick, queueVersion]);

  const value = useMemo<WorkspaceContextValue>(
    () => ({
      apiStatus,
      retry,
      session,
      workspaces,
      activeWorkspace,
      selectWorkspace: setActiveId,
      openQueueTasks,
      gate,
      reloadGate,
      validationTasks,
      reloadValidationTasks: () => void loadValidationTasks(),
      auditIntegrity,
      localAi,
      readOnly,
      can,
      roles,
      toast,
      showToast,
      dismissToast,
      pauseToast,
      resumeToast
    }),
    [
      apiStatus,
      retry,
      session,
      workspaces,
      activeWorkspace,
      openQueueTasks,
      gate,
      reloadGate,
      validationTasks,
      loadValidationTasks,
      auditIntegrity,
      localAi,
      readOnly,
      can,
      roles,
      toast,
      showToast,
      dismissToast,
      pauseToast,
      resumeToast
    ]
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) {
    throw new Error("useWorkspace must be used inside WorkspaceProvider");
  }
  return value;
}

/** Load one surface on mount, exposing the same four states every list renders. */
export function useLoadable<T>(load: () => Promise<T>, deps: unknown[]): {
  value: Loadable<T>;
  reload: () => void;
} {
  const [value, setValue] = useState<Loadable<T>>({ state: "loading" });
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    let cancelled = false;
    setValue({ state: "loading" });
    void loadRef.current()
      .then((data) => {
        if (!cancelled) setValue({ state: "ready", data });
      })
      .catch((error: unknown) => {
        if (!cancelled) setValue({ state: "error", message: errorText(error) });
      });
    return () => {
      cancelled = true;
    };
    // `load` is intentionally not a dependency: it is read through a ref so an
    // inline closure does not retrigger the fetch on every render. Callers pass
    // the values that should retrigger it in `deps`.
  }, [...deps, tick]);

  return { value, reload: () => setTick((n) => n + 1) };
}
