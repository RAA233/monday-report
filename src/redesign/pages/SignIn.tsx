import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BrandMark, SegControl, Tag } from "../components/primitives";
import { getSession } from "../../lib/api";
import { errorText, useWorkspace } from "../lib/workspace";

/**
 * Sign-in surface.
 *
 * A note on what this can honestly do. This client sends a credential that is
 * configured at build time (`VITE_MONDAY_REPORT_API_KEY`, sent as the
 * `X-Monday-Report-Key` header by `src/lib/api.ts`). There is no login endpoint,
 * the browser holds no session token, and no code path exists for typing a
 * credential in here and having it take effect. A token field would therefore be
 * theatre.
 *
 * So this surface does the real equivalent: it calls `GET /auth/session` and reports
 * the identity the server derived from the configured credential — tenant,
 * display name, roles, authentication source, and actor source. That is a genuine
 * authorization check whose failure mode is genuine too, and it states plainly how
 * the credential got here.
 */
type Mode = "configured" | "demo";

export function SignIn() {
  const navigate = useNavigate();
  const { retry } = useWorkspace();
  const [mode, setMode] = useState<Mode>("configured");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resolved, setResolved] = useState<{
    tenant: string;
    name: string;
    email: string;
    roles: string[];
    authSource: string;
    actorSource: string;
  } | null>(null);

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      const session = await getSession();
      const identity = session.authenticated_identity ?? null;
      setResolved({
        tenant: session.tenant.name,
        name: identity?.display_name ?? session.user.full_name,
        email: identity?.email ?? session.user.email,
        roles: identity?.roles ?? session.user.roles,
        authSource: identity?.authentication_source ?? "unreported",
        actorSource: identity?.actor_source ?? "unreported"
      });
      retry();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "";
      // Classify on the status the client actually threw. "Did not answer" is reserved
      // for a request that produced no status: a 503 means the backend answered and is
      // missing its client API key or audit key, so telling the operator to confirm the
      // backend is running points at the wrong thing entirely.
      const status = /^API (\d{3})\b/.exec(message)?.[1];
      setError(
        status === "401" || status === "403"
          ? "The configured credential was refused. Check the API key this build was compiled with."
          : status === "503"
            ? "The workspace API answered, but it is not configured to serve client data yet — it reports a missing client API key or audit key. That is a backend configuration change, not a credential problem."
            : status
              ? `The workspace API refused the session check: ${errorText(caught)}`
              : "The workspace API did not answer. Confirm the backend is running and reachable from this origin."
      );
      setResolved(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: "clamp(16px,4vw,48px)"
      }}
    >
      <div style={{ width: "min(440px, 100%)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 28 }}>
          <BrandMark size={38} fontSize={15} />
          <span
            style={{
              fontFamily: "var(--font-heading)",
              fontWeight: "var(--font-heading-weight)" as never,
              fontSize: 20,
              letterSpacing: "0.02em",
              textTransform: "uppercase"
            }}
          >
            Monday Report
          </span>
        </div>

        <div className="blueprint" style={{ padding: "clamp(20px,4vw,32px)" }}>
          <i className="corner tl" />
          <i className="corner tr" />
          <i className="corner bl" />
          <i className="corner br" />

          <h1
            tabIndex={-1}
            data-page-heading=""
            style={{ fontSize: 26, letterSpacing: "0.02em", textTransform: "uppercase", margin: 0 }}
          >
            Sign in to the workspace
          </h1>
          <p className="text-muted" style={{ fontSize: 13, lineHeight: 1.55, margin: "8px 0 0" }}>
            Sessions are tenant-scoped. Your credential resolves server-side to one tenant, one
            identity, and its roles — nothing else is visible.
          </p>

          <div style={{ marginTop: 18 }}>
            <SegControl<Mode>
              name="mr-authmode"
              label="Authentication source"
              value={mode}
              onChange={setMode}
              options={[
                { id: "configured", label: "Workspace API token" },
                { id: "demo", label: "Demo bootstrap" }
              ]}
            />
          </div>

          {mode === "configured" ? (
            <p
              style={{
                fontSize: 13,
                lineHeight: 1.55,
                margin: "16px 0 0",
                border: "1px solid var(--color-divider)",
                padding: "10px 12px"
              }}
            >
              This build sends its credential as the <code>X-Monday-Report-Key</code> request header,
              configured when the frontend was compiled. There is nothing to type here and no session
              token is stored in the browser — the server derives identity and roles from that
              credential on every request.
            </p>
          ) : (
            <p
              style={{
                fontSize: 13,
                lineHeight: 1.55,
                margin: "16px 0 0",
                border: "1px solid var(--color-divider)",
                padding: "10px 12px"
              }}
            >
              When the backend runs on its local shared key, the same request resolves to the demo
              operator and actions are recorded with the{" "}
              <span className="tag tag-neutral">demo_bootstrap</span> actor source — not a verified
              per-user identity. Which of these two applies is decided by the server, not chosen here.
            </p>
          )}

          {error ? (
            <p
              role="alert"
              style={{
                display: "flex",
                gap: 8,
                alignItems: "baseline",
                flexWrap: "wrap",
                fontSize: 13,
                margin: "14px 0 0",
                border: "1px solid var(--color-accent-800)",
                padding: "10px 12px"
              }}
            >
              <strong
                style={{
                  fontFamily: "var(--font-heading)",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em"
                }}
              >
                Check failed
              </strong>
              <span>{error}</span>
            </p>
          ) : null}

          {resolved ? (
            <div
              role="status"
              style={{
                margin: "14px 0 0",
                border: "1px solid var(--color-divider)",
                padding: "10px 12px",
                display: "grid",
                gap: 4,
                fontSize: 13
              }}
            >
              <strong
                style={{
                  fontFamily: "var(--font-heading)",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  fontSize: 12.5
                }}
              >
                {/* A 200 means an identity resolved, which is NOT the same as the
                    presented credential having authenticated: in demo mode an
                    unrecognised or disabled credential falls back to the demo
                    bootstrap identity. Only claim acceptance when the server says
                    the actor was actually authenticated. */}
                {resolved.actorSource === "authenticated" ? "Credential accepted" : "Identity resolved"}
              </strong>
              <span>
                {resolved.name} · {resolved.email}
              </span>
              <span className="text-muted" style={{ fontSize: 12 }}>
                Tenant {resolved.tenant} · authentication source {resolved.authSource} · actor source{" "}
                {resolved.actorSource}
              </span>
              {resolved.roles.length > 0 ? (
                <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
                  {resolved.roles.map((role) => (
                    <Tag tone="neutral" key={role}>
                      {role}
                    </Tag>
                  ))}
                </div>
              ) : (
                <span className="text-muted" style={{ fontSize: 12 }}>
                  The server reported no roles for this credential.
                </span>
              )}
              {resolved.actorSource !== "authenticated" ? (
                <span style={{ fontSize: 12, lineHeight: 1.45, color: "var(--color-accent-800)" }}>
                  This identity came from the local fallback, not from the credential presented — the
                  request would have resolved the same way without it.
                </span>
              ) : null}
            </div>
          ) : null}

          <button
            type="button"
            className="btn btn-primary btn-block"
            style={{ minHeight: 40, marginTop: 20 }}
            onClick={() => {
              if (resolved) {
                navigate("/app");
                return;
              }
              void verify();
            }}
            disabled={busy}
          >
            {busy ? "Checking credential…" : resolved ? "Continue to the workspace" : "Check credential"}
          </button>

          <Link
            className="btn btn-ghost btn-block"
            to="/app"
            style={{ marginTop: 8, textDecoration: "none" }}
          >
            Open the workspace without checking
          </Link>

          {/* Both halves of the prototype's closing line were wrong for this
              build. Disabled accounts are refused only in client mode (demo mode
              falls back to the bootstrap identity), and GET /auth/session is a
              read that appends no audit event — only rejections are recorded. */}
          <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.5, margin: "14px 0 0" }}>
            In client mode a disabled account or a revoked credential is refused with 401 and the
            refusal is written to the tenant's hash-chained audit log. A successful check is a read and
            is not itself audited.
          </p>
        </div>

        <p className="text-muted" style={{ fontSize: 12, margin: "16px 0 0", textAlign: "center" }}>
          <Link to="/">← Back to the product page</Link>
        </p>
      </div>
    </main>
  );
}
