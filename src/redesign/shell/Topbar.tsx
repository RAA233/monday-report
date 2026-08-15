import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ChevronDown, ShieldCheck } from "lucide-react";
import { apiUnreadReason, useWorkspace } from "../lib/workspace";
import { integrityStateLabel } from "../pages/Audit";
import { routeLabel } from "./navigation";
import { SHOW_INTERNAL } from "../lib/build";

/**
 * Topbar: workspace selector, the current route, and the trust chips.
 *
 * The API chip is a live `role="status"` so a connectivity change is announced;
 * the audit chip reports the real chain state from `GET /audit-logs/integrity` and
 * links into the audit view. Both describe what the backend actually returned —
 * neither invents a "sealed" claim when the read failed, and neither calls a
 * permission refusal an outage.
 */
export function Topbar() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const {
    apiStatus,
    retry,
    session,
    workspaces,
    activeWorkspace,
    selectWorkspace,
    auditIntegrity
  } = useWorkspace();

  const [profileOpen, setProfileOpen] = useState(false);
  const profileRef = useRef<HTMLDivElement | null>(null);
  const profileTriggerRef = useRef<HTMLButtonElement | null>(null);
  const profilePanelRef = useRef<HTMLDivElement | null>(null);

  /**
   * Disclosure behaviour: close on outside click, close on Escape and return focus to
   * the trigger, and while it is open keep Tab inside the panel.
   *
   * The trap matters because the panel is the last thing in the topbar: without it Tab
   * left the open panel and walked into the page behind it, so a keyboard user could be
   * operating the page while an overlay they could not see was still open.
   */
  useEffect(() => {
    if (!profileOpen) return;
    const focusable = () =>
      [...(profilePanelRef.current?.querySelectorAll<HTMLElement>("button, a[href]") ?? [])].filter(
        (node) => !node.hasAttribute("disabled")
      );
    // Move focus in, so the panel's content is where the keyboard already is.
    focusable()[0]?.focus();
    const close = (restoreFocus: boolean) => {
      setProfileOpen(false);
      if (restoreFocus) profileTriggerRef.current?.focus();
    };
    const onPointerDown = (event: PointerEvent) => {
      if (!profileRef.current?.contains(event.target as Node)) close(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close(true);
        return;
      }
      if (event.key !== "Tab") return;
      const nodes = focusable();
      if (nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !profilePanelRef.current?.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [profileOpen]);

  const offline = apiStatus === "offline";
  // Same shape as the shell banner: retry() flips apiStatus to "checking" first, which
  // used to delete this button mid-press and drop focus to <body>. Once shown, it stays
  // until the API is reachable again.
  const offlineShownOnce = useRef(false);
  if (offline) offlineShownOnce.current = true;
  const retrying = apiStatus === "checking" && offlineShownOnce.current;
  if (apiStatus === "connected") offlineShownOnce.current = false;
  // NOT "Local fallback": that is v1's label, and v1 really does degrade to local
  // data. This entry has no fallback dataset, so the chip must not imply one — the
  // shell banner beside it says the same thing.
  // Four distinct facts, four labels. "Unreachable" is reserved for a request that
  // did not complete: the API answering with a refusal or an unconfigured-service
  // 503 is not an outage, and saying so sends the operator to the wrong place.
  const apiLabel =
    apiStatus === "connected"
      ? "API connected"
      : apiStatus === "checking"
        ? "Checking API"
        : apiStatus === "refused"
          ? "API refused session"
          : apiStatus === "misconfigured"
            ? "API not configured"
            : "API unreachable";
  const apiDotFill =
    apiStatus === "connected"
      ? "var(--color-accent)"
      : apiStatus === "checking"
        ? "var(--color-neutral-400)"
        : "var(--color-bg)";

  const identity = session?.authenticated_identity ?? null;
  const displayName = identity?.display_name ?? session?.user.full_name ?? "Signed-out session";
  const email = identity?.email ?? session?.user.email ?? "No session identity";
  const roles = identity?.roles ?? session?.user.roles ?? [];
  // `?? "system"` substituted a value the backend never sent and then stated a fact
  // about it. An unread session is not a session with no identity - the rest of the
  // shell is careful about exactly this distinction, and this line was not.
  const actorSource = identity?.actor_source ?? (session ? "unreported" : null);
  const actorNote =
    actorSource === null
      ? `not read — ${apiUnreadReason(apiStatus) ?? "the session has not resolved"}, so this session's identity is unknown.`
      : actorSource === "authenticated"
        ? "actions are attributed to a verified authenticated identity."
        : actorSource === "demo_bootstrap"
          ? "a shared-key demo bootstrap, so actions are not verified-reviewer attributed."
          : "the session reported no authenticated identity.";

  const initials = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("") || "MR";

  // The chip states the integrity view the backend returned, never more — and names
  // WHY it has none: a session without view_audit_history was refused, which is not
  // the same as the read failing.
  const auditChipLabel =
    auditIntegrity.state === "ready"
      ? `${integrityStateLabel(auditIntegrity.data.integrity_state ?? null)} · ${auditIntegrity.data.total_events} events`
      : auditIntegrity.state === "loading"
        ? "checking"
        : auditIntegrity.state === "unauthorized"
          ? "not visible to this session"
          : "unavailable";

  const chipBase = {
    display: "inline-flex" as const,
    alignItems: "center" as const,
    gap: 7,
    fontSize: 12.5,
    // neutral-600 (3.82:1), not --color-divider (1.38:1): two of these chips are
    // buttons, and this hairline is the only boundary that identifies them.
    border: "1px solid var(--color-neutral-600)",
    padding: "5px 10px"
  };

  return (
    <header
      data-topbar=""
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        minHeight: 52,
        // Containing block for the profile disclosure. Anchored to the CHIP, the panel
        // rendered off the inline-start edge once the topbar wrapped and the chip
        // started the line; anchored to the header it is always inside the viewport.
        position: "relative",
        padding: "8px clamp(14px,3vw,28px)",
        borderBlockEnd: "1px solid var(--color-divider)"
      }}
    >
      <label
        style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--color-neutral-700)" }}
      >
        <span style={{ fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase" }}>Workspace</span>
        <select
          className="input"
          aria-label="Workspace"
          value={activeWorkspace?.id ?? ""}
          onChange={(event) => selectWorkspace(event.target.value)}
          disabled={workspaces.length === 0}
          style={{
            minHeight: 32,
            width: "auto",
            maxWidth: "min(300px, 38vw)",
            padding: "2px 8px",
            fontSize: 13
          }}
        >
          {workspaces.length === 0 ? (
            // "None available" is a claim about a read that happened. Before the probe
            // resolves, or after it fails, the list is simply unread.
            <option value="">
              {apiStatus === "connected" ? "No workspace available" : "Workspaces not read"}
            </option>
          ) : (
            workspaces.map((workspace) => (
              <option key={workspace.id} value={workspace.id}>
                {[workspace.name, workspace.asset].filter(Boolean).join(" — ")}
              </option>
            ))
          )}
        </select>
      </label>

      <span
        style={{
          fontFamily: "var(--font-heading)",
          fontSize: 12,
          color: "var(--color-neutral-700)",
          letterSpacing: "0.04em"
        }}
      >
        {routeLabel(pathname)}
      </span>

      <span style={{ marginInlineStart: "auto" }} />

      <span data-chip="" role="status" aria-label={`Workspace API: ${apiLabel}`} style={chipBase}>
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
          <circle cx="5" cy="5" r="4" fill={apiDotFill} stroke="var(--color-text)" strokeOpacity="0.35" strokeWidth="1" />
        </svg>
        {apiLabel}
        {offline || retrying ? (
          <button
            type="button"
            className="btn btn-ghost"
            style={{ minHeight: 0, padding: "0 4px", fontSize: 12 }}
            onClick={() => {
              if (retrying) return;
              retry();
            }}
            aria-disabled={retrying || undefined}
          >
            {retrying ? "Retrying…" : "Retry"}
          </button>
        ) : null}
      </span>

      <button
        data-chip=""
        type="button"
        className="mr-hover-text"
        onClick={() => navigate("/app/audit")}
        // The accessible name must CONTAIN the visible label (WCAG 2.5.3), so it is
        // built by suffixing the exact visible string rather than paraphrasing it.
        aria-label={`Report integrity · ${auditChipLabel} — open the report integrity record`}
        // No inline `background`: an inline value beats the stylesheet, which made
        // `.mr-hover-text:hover` inert. The class owns the resting fill and the tint.
        style={{ ...chipBase, color: "inherit", cursor: "pointer", fontFamily: "var(--font-body)" }}
      >
        <ShieldCheck size={13} strokeWidth={1.5} aria-hidden="true" />
        Report integrity · {auditChipLabel}
      </button>

      <div ref={profileRef}>
        <button
          data-chip=""
          type="button"
          className="mr-hover-text"
          ref={profileTriggerRef}
          onClick={() => setProfileOpen((open) => !open)}
          // A plain disclosure, not role="menu": two actions plus identity text
          // are not menu content, and Tab is the right navigation model here.
          aria-expanded={profileOpen}
          aria-controls="mr-profile-disclosure"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            // neutral-600, and no inline background: see chipBase above.
            border: "1px solid var(--color-neutral-600)",
            color: "inherit",
            padding: "4px 10px 4px 4px",
            cursor: "pointer",
            fontFamily: "var(--font-body)",
            fontSize: 12.5
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: "grid",
              placeItems: "center",
              width: 26,
              height: 26,
              background: "var(--color-accent-900)",
              color: "var(--color-bg)",
              fontFamily: "var(--font-heading)",
              fontSize: 11
            }}
          >
            {initials}
          </span>
          {displayName}
          <ChevronDown size={12} strokeWidth={1.5} aria-hidden="true" />
        </button>

        {profileOpen ? (
          <div
            id="mr-profile-disclosure"
            className="elev-md"
            ref={profilePanelRef}
            style={{
              position: "absolute",
              // Logical properties throughout, and clamped to the header's content box,
              // so the panel stays inside the viewport at every width and flips with
              // dir="rtl" without a second rule.
              insetInlineEnd: "clamp(14px,3vw,28px)",
              insetBlockStart: "calc(100% - 6px)",
              inlineSize: "min(264px, calc(100vw - 2 * clamp(14px,3vw,28px)))",
              maxInlineSize: "calc(100vw - 2 * clamp(14px,3vw,28px))",
              background: "var(--color-bg)",
              border: "1px solid var(--color-divider)",
              padding: 14,
              zIndex: 40
            }}
          >
            <strong style={{ display: "block", fontFamily: "var(--font-heading)", fontSize: 15 }}>
              {displayName}
            </strong>
            <span className="text-muted" style={{ display: "block", fontSize: 12, marginTop: 2 }}>
              {email}
            </span>
            {roles.length > 0 ? (
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 10 }}>
                {roles.map((role) => (
                  <span className="tag tag-neutral" key={role}>
                    {role}
                  </span>
                ))}
              </div>
            ) : null}
            <p className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5, margin: "10px 0 0" }}>
              Actor source: <strong>{actorSource}</strong> — {actorNote}
            </p>
            <hr className="hr" style={{ margin: "12px 0" }} />
            <div style={{ display: "grid", gap: 6 }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setProfileOpen(false);
                  navigate("/app/settings");
                }}
              >
                Settings &amp; session
              </button>
              {/* The sign-in surface is an internal-build affordance: there is
                  no login endpoint and the credential is build-time, so a
                  customer has nothing to sign into or out of. The customer build
                  hides it (see src/redesign/lib/build.ts). */}
              {SHOW_INTERNAL ? (
                <>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => {
                      setProfileOpen(false);
                      navigate("/app/signin");
                    }}
                  >
                    Sign out
                  </button>
                  {/* No logout endpoint exists and the credential is build-time, so
                      "sign out" cannot revoke anything — say so instead of implying it. */}
                  <span className="text-muted" style={{ fontSize: 10.5, lineHeight: 1.45 }}>
                    Returns to the sign-in surface. The build-time credential stays active — there is no
                    session token to revoke.
                  </span>
                </>
              ) : null}
            </div>
          </div>
        ) : null}
      </div>
    </header>
  );
}
