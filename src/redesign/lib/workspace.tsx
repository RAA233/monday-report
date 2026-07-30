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
 * Connectivity mirrors the committed v1 behaviour in `src/App.tsx`: a probe on
 * mount, `checking` → `connected` | `offline`, and an explicit retry. When the
 * API is unreachable the app says so and disables actions rather than pretending
 * to have data.
 */
export type ApiStatus = "checking" | "connected" | "offline";

/** Async state for one data surface, so every list can render the same four states. */
export type Loadable<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
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
   */
  openQueueTasks: number;
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
   * `/workspaces/{id}/benchmarking` (anomaly -> workspace).
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
  auditIntegrity: ApiAuditIntegrityStatus | null;
  localAi: ApiLocalAiStatus | null;
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
 * The export gate, as reported by the backend.
 *
 *   loading      — the read is in flight; assert nothing
 *   ready        — `openTasks` is the backend's own count for this workspace
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
 * The committed gate copy. `count` must be the BACKEND's own gate count
 * (`GateState.openTasks`), never a client re-derivation.
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
export function newestReport<T extends { created_at: string; period_end: string }>(
  reports: readonly T[]
): T | null {
  if (reports.length === 0) return null;
  return reports.reduce((best, candidate) => {
    if (candidate.created_at !== best.created_at) {
      return candidate.created_at > best.created_at ? candidate : best;
    }
    if (candidate.period_end !== best.period_end) {
      return candidate.period_end > best.period_end ? candidate : best;
    }
    return candidate;
  });
}

function errorText(error: unknown): string {
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
  const [auditIntegrity, setAuditIntegrity] = useState<ApiAuditIntegrityStatus | null>(null);
  const [localAi, setLocalAi] = useState<ApiLocalAiStatus | null>(null);
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

  const loadValidationTasks = useCallback(async () => {
    const token = ++queueToken.current;
    setValidationTasks({ state: "loading" });
    try {
      const tasks = await getValidationTasks();
      if (token !== queueToken.current) return;
      setValidationTasks({ state: "ready", data: tasks });
    } catch (error) {
      if (token !== queueToken.current) return;
      setValidationTasks({ state: "error", message: errorText(error) });
    }
  }, []);

  const reloadGate = useCallback(() => setGateTick((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setApiStatus("checking");

    void (async () => {
      try {
        // The session probe decides connectivity: it is the cheapest authenticated
        // read and it is what tells us the tenant we are scoped to.
        const [nextSession, nextWorkspaces] = await Promise.all([getSession(), getWorkspaces()]);
        if (cancelled) return;
        setSession(nextSession);
        setWorkspaces(nextWorkspaces);
        setActiveId((current) => current ?? nextWorkspaces[0]?.id ?? null);
        setApiStatus("connected");
      } catch {
        if (cancelled) return;
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
      void loadValidationTasks();
      try {
        const integrity = await getAuditIntegrity();
        if (!cancelled) setAuditIntegrity(integrity);
      } catch {
        if (!cancelled) setAuditIntegrity(null);
      }
      try {
        const ai = await getLocalAiStatus();
        if (!cancelled) setLocalAi(ai);
      } catch {
        if (!cancelled) setLocalAi(null);
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
    if (validationTasks.state !== "ready") return 0;
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
  useEffect(() => {
    const token = ++gateToken.current;
    if (apiStatus !== "connected" || !activeWorkspaceId) {
      setGate({ state: "unavailable" });
      return;
    }
    setGate({ state: "loading" });
    void (async () => {
      try {
        const [tasks, failures] = await Promise.all([getValidationTasks(), getFailures()]);
        // Anomaly-targeted tasks also hold the gate. This read is workspace-scoped
        // and read-only; if it is unavailable, anomaly-targeted tasks are COUNTED
        // (fail closed) rather than silently dropped from the gate.
        let anomalyIds: Set<string> | null = null;
        try {
          const benchmarking = await getWorkspaceBenchmarking(activeWorkspaceId);
          anomalyIds = new Set(
            [...benchmarking.active_anomalies, ...benchmarking.historical_anomalies].map(
              (anomaly) => anomaly.id
            )
          );
        } catch {
          anomalyIds = null;
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
          if (task.target_type === "anomaly_event") {
            return anomalyIds === null ? true : anomalyIds.has(task.target_id);
          }
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
  }, [apiStatus, activeWorkspaceId, gateTick, validationTasks]);

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
