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
  getLocalAiStatus,
  getSession,
  getValidationTasks,
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
  /** Validation tasks in an open state — the export gate's authoritative count. */
  openValidationTasks: number;
  /**
   * True only when the validation queue actually loaded. While this is false the
   * gate state is UNKNOWN — a zero count from a failed or in-flight read must
   * never be presented as "gate clear".
   */
  validationGateKnown: boolean;
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

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

/**
 * Validation-task statuses that still hold the export gate closed.
 *
 * `ApiValidationTask.status` is the committed union open|validated|rejected|conflict.
 * A conflict is unresolved by definition, so both it and `open` keep the gate shut.
 */
const OPEN_TASK_STATUSES: ReadonlyArray<ApiValidationTask["status"]> = ["open", "conflict"];

export function isOpenValidationTask(task: ApiValidationTask): boolean {
  return OPEN_TASK_STATUSES.includes(task.status);
}

/** The committed gate copy. `count` must be the real calculated open-task count. */
export function exportGateMessage(count: number): string {
  return `Resolve ${count} validation task(s) before exporting an official Monday Report.`;
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
      setToast({ kind, text });
      armToastTimer();
    },
    [armToastTimer]
  );

  const dismissToast = useCallback(() => {
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

  const loadValidationTasks = useCallback(async () => {
    setValidationTasks({ state: "loading" });
    try {
      const tasks = await getValidationTasks();
      setValidationTasks({ state: "ready", data: tasks });
    } catch (error) {
      setValidationTasks({ state: "error", message: errorText(error) });
    }
  }, []);

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

  const openValidationTasks = useMemo(() => {
    if (validationTasks.state !== "ready") return 0;
    return validationTasks.data.filter(isOpenValidationTask).length;
  }, [validationTasks]);

  const validationGateKnown = validationTasks.state === "ready";

  const activeWorkspace = useMemo(
    () => workspaces.find((workspace) => workspace.id === activeId) ?? workspaces[0] ?? null,
    [workspaces, activeId]
  );

  const value = useMemo<WorkspaceContextValue>(
    () => ({
      apiStatus,
      retry,
      session,
      workspaces,
      activeWorkspace,
      selectWorkspace: setActiveId,
      openValidationTasks,
      validationGateKnown,
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
      openValidationTasks,
      validationGateKnown,
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
