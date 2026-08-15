import { useRef } from "react";
import { Link, Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { useWorkspace } from "../lib/workspace";
import { SHOW_INTERNAL } from "../lib/build";
import { LicenseBanner, LicenseProvider } from "../lib/license";

/**
 * The authenticated application frame: rail + topbar + the offline banner + a
 * single <main> landmark that every route renders into.
 *
 * The banner is the honest-degradation contract: when the workspace API is
 * unreachable the app says so in words and marks itself read-only. It does NOT
 * claim a local fallback dataset — this entry has none, and every view states that
 * an empty list means "not read" rather than "none exist".
 */
export function AppShell() {
  const { apiStatus, retry, toast, dismissToast, pauseToast, resumeToast } = useWorkspace();
  // Three degraded states, one banner, three different sentences. Adding
  // `misconfigured` without adding it here left a 503 backend rendering a silently
  // read-only app with no banner at all.
  const refused = apiStatus === "refused";
  const misconfigured = apiStatus === "misconfigured";
  const unreachable = apiStatus === "offline" || refused || misconfigured;
  // `retry()` sets apiStatus to "checking" as its FIRST act, which used to make this
  // banner - and the "Retry connection" button inside it that the operator had just
  // pressed - vanish, dropping focus to <body>. Once the banner has been shown, it
  // stays mounted through the re-probe and the button reports itself as retrying,
  // so the same element is still under the keyboard user's cursor when the probe
  // fails. It leaves only when the API is actually reachable again.
  const shownOnce = useRef(false);
  if (unreachable) shownOnce.current = true;
  const retrying = apiStatus === "checking" && shownOnce.current;
  if (apiStatus === "connected") shownOnce.current = false;
  const degraded = unreachable || retrying;

  return (
    <LicenseProvider>
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

        <LicenseBanner />

        {degraded ? (
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
              {retrying
                ? "Reconnecting to the API"
                : refused
                  ? "API refused this session"
                  : misconfigured
                    ? "API not configured for client data"
                    : "API unreachable"}
            </strong>
            {retrying
              ? "The last probe did not reach the workspace API and it is being re-checked, so nothing can be read or recorded until it answers. Empty lists below mean \"not read\", not \"none exist\"."
              : refused
              ? "The workspace API answered and refused this session's credential, so no workspace data can be read and nothing can be recorded. The service is running — the API key or the role has to change. Empty lists below mean \"not read\", not \"none exist\"."
              : misconfigured
                ? "The workspace API answered, but it is not configured to serve client data yet — it reports a missing client API key or audit key. Nothing can be read or recorded until that is configured on the backend. Empty lists below mean \"not read\", not \"none exist\"."
                : "The workspace API is unreachable, so no workspace data can be read and nothing can be recorded. Empty lists below mean \"not read\", not \"none exist\"."}
            {refused || misconfigured ? (
              // No retry: neither a credential refusal nor an unconfigured backend can be
              // fixed by repeating the same request. The sign-in surface reports what the
              // server actually said — but it is an internal-build surface, so the
              // customer build shows the explanation without a link into it.
              SHOW_INTERNAL ? (
                <Link className="btn btn-ghost" to="/app/signin" style={{ minHeight: 0, padding: "0 4px", fontSize: 13 }}>
                  Check the session
                </Link>
              ) : null
            ) : (
              <button
                type="button"
                className="btn btn-ghost"
                style={{ minHeight: 0, padding: "0 4px", fontSize: 13 }}
                onClick={() => {
                  if (retrying) return;
                  retry();
                }}
                aria-disabled={retrying || undefined}
              >
                {retrying ? "Reconnecting…" : "Retry connection"}
              </button>
            )}
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

      {/* Permanently-mounted live region: a region created together with its
          content is often not announced, so only the CONTENT is conditional.
          Hover or focus holds the toast open instead of racing its timer. */}
      <div
        role="status"
        aria-live="polite"
        className={toast ? "elev-lg" : undefined}
        onMouseEnter={pauseToast}
        onMouseLeave={resumeToast}
        onFocus={pauseToast}
        onBlur={resumeToast}
        style={{
          position: "fixed",
          insetBlockEnd: 18,
          insetInlineEnd: 18,
          zIndex: 60,
          maxWidth: "min(420px, calc(100vw - 36px))",
          // The empty container still has a box; without this it would sit over the
          // page corner and swallow clicks on whatever is underneath.
          pointerEvents: toast ? "auto" : "none",
          ...(toast
            ? {
                background: "var(--color-bg)",
                border: "1px solid var(--color-divider)",
                padding: "12px 14px",
                display: "grid",
                gap: 4
              }
            : {})
        }}
      >
        {toast ? (
          <>
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
          </>
        ) : null}
      </div>
    </div>
    </LicenseProvider>
  );
}
