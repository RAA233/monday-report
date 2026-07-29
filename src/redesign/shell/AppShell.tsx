import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { useWorkspace } from "../lib/workspace";

/**
 * The authenticated application frame: rail + topbar + the offline banner + a
 * single <main> landmark that every route renders into.
 *
 * The banner is the honest-degradation contract carried over from v1: when the
 * workspace API is unreachable the app says so in words and marks itself
 * read-only, rather than showing empty lists that look like real "no data".
 */
export function AppShell() {
  const { apiStatus, retry, toast, dismissToast } = useWorkspace();
  const offline = apiStatus === "offline";

  return (
    <div
      data-shell=""
      style={{
        display: "grid",
        gridTemplateColumns: "236px minmax(0,1fr)",
        minHeight: "100vh",
        alignItems: "start"
      }}
    >
      <Sidebar />

      <div style={{ minWidth: 0, display: "flex", flexDirection: "column", minHeight: "100vh" }}>
        <Topbar />

        {offline ? (
          <div
            role="alert"
            style={{
              display: "flex",
              gap: 10,
              alignItems: "baseline",
              flexWrap: "wrap",
              padding: "9px clamp(14px,3vw,28px)",
              borderBlockEnd: "1px solid var(--color-divider)",
              background: "var(--color-surface)",
              fontSize: 13
            }}
          >
            <strong
              style={{
                fontFamily: "var(--font-heading)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                fontSize: 12.5
              }}
            >
              Local fallback
            </strong>
            The workspace API is unreachable. Views show local, read-only context; uploads, drafts, and
            exports need the backend.
            <button
              type="button"
              className="btn btn-ghost"
              style={{ minHeight: 0, padding: "0 4px", fontSize: 13 }}
              onClick={retry}
            >
              Retry connection
            </button>
          </div>
        ) : null}

        <main
          style={{
            flex: 1,
            padding: "clamp(16px,3vw,28px)",
            display: "grid",
            // Explicit minmax(0,…) so a wide table scrolls in its own container
            // rather than widening this track and the page with it.
            gridTemplateColumns: "minmax(0, 1fr)",
            gap: 24,
            alignContent: "start"
          }}
        >
          <Outlet />
        </main>
      </div>

      {toast ? (
        <div
          role="status"
          aria-live="polite"
          className="elev-lg"
          style={{
            position: "fixed",
            insetBlockEnd: 18,
            insetInlineEnd: 18,
            zIndex: 60,
            maxWidth: "min(420px, calc(100vw - 36px))",
            background: "var(--color-bg)",
            border: "1px solid var(--color-divider)",
            padding: "12px 14px",
            display: "grid",
            gap: 4
          }}
        >
          <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
            <strong
              style={{
                fontFamily: "var(--font-heading)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                fontSize: 12.5
              }}
            >
              {toast.kind}
            </strong>
            <button
              type="button"
              className="btn btn-ghost"
              aria-label="Dismiss notification"
              style={{ minHeight: 0, padding: "0 4px", fontSize: 12, marginInlineStart: "auto" }}
              onClick={dismissToast}
            >
              Dismiss
            </button>
          </div>
          <span style={{ fontSize: 12.5, lineHeight: 1.5 }}>{toast.text}</span>
        </div>
      ) : null}
    </div>
  );
}
