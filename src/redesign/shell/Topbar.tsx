import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ChevronDown, ShieldCheck } from "lucide-react";
import { useWorkspace } from "../lib/workspace";
import { routeLabel } from "./navigation";

/**
 * Topbar: workspace selector, the current route, and the trust chips.
 *
 * The API chip is a live `role="status"` so a connectivity change is announced;
 * the audit chip reports the real chain state from `GET /audit/integrity` and
 * links into the audit view. Both describe what the backend actually returned —
 * neither invents a "sealed" claim when the read failed.
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

  // Close on outside click and on Escape, and return focus to the trigger.
  useEffect(() => {
    if (!profileOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!profileRef.current?.contains(event.target as Node)) setProfileOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setProfileOpen(false);
        profileRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
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
  const apiLabel =
    apiStatus === "connected" ? "API connected" : apiStatus === "checking" ? "Checking API" : "Local fallback";
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
  const actorSource = identity?.actor_source ?? "system";
  const actorNote =
    actorSource === "authenticated"
      ? "actions are attributed to a verified authenticated identity."
      : actorSource === "demo_bootstrap"
        ? "a shared-key demo bootstrap, so actions are not verified-reviewer attributed."
        : "no authenticated identity is attached to this session.";

  const initials = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("") || "MR";

  // The chip states the integrity view the backend returned, never more.
  const auditChipLabel = auditIntegrity
    ? `${auditIntegrity.status} · ${auditIntegrity.total_events} events`
    : "unavailable";

  const chipBase = {
    display: "inline-flex" as const,
    alignItems: "center" as const,
    gap: 7,
    fontSize: 12.5,
    border: "1px solid var(--color-divider)",
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
            <option value="">No workspace available</option>
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
          color: "var(--color-neutral-600)",
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
        {offline ? (
          <button
            type="button"
            className="btn btn-ghost"
            style={{ minHeight: 0, padding: "0 4px", fontSize: 12 }}
            onClick={retry}
          >
            Retry
          </button>
        ) : null}
      </span>

      <button
        data-chip=""
        type="button"
        className="mr-hover-text"
        onClick={() => navigate("/app/audit")}
        aria-label={`Audit chain ${auditChipLabel}`}
        style={{ ...chipBase, background: "transparent", color: "inherit", cursor: "pointer", fontFamily: "var(--font-body)" }}
      >
        <ShieldCheck size={13} strokeWidth={1.5} aria-hidden="true" />
        Audit · {auditChipLabel}
      </button>

      <div style={{ position: "relative" }} ref={profileRef}>
        <button
          data-chip=""
          type="button"
          className="mr-hover-text"
          onClick={() => setProfileOpen((open) => !open)}
          aria-expanded={profileOpen}
          aria-haspopup="true"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            border: "1px solid var(--color-divider)",
            background: "transparent",
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
            role="menu"
            className="elev-md"
            style={{
              position: "absolute",
              insetInlineEnd: 0,
              top: "calc(100% + 6px)",
              width: 264,
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
                role="menuitem"
                className="btn btn-secondary"
                onClick={() => {
                  setProfileOpen(false);
                  navigate("/app/settings");
                }}
              >
                Settings &amp; session
              </button>
              {/* Returns to the sign-in surface. There is no logout endpoint and the
                  browser holds no session token, so the surface itself discloses how
                  this client authenticates rather than implying a revoked credential. */}
              <button
                type="button"
                role="menuitem"
                className="btn btn-ghost"
                onClick={() => {
                  setProfileOpen(false);
                  navigate("/app/signin");
                }}
              >
                Sign out
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </header>
  );
}
