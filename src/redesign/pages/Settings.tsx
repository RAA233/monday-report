import {
  Cells,
  Frame,
  PageHeader,
  Skeleton,
  Tag,
  type CellSpec
} from "../components/primitives";
import { apiUnreadReason, useWorkspace } from "../lib/workspace";
import { SHOW_INTERNAL } from "../lib/build";

/**
 * Settings — a READ-ONLY disclosure surface.
 *
 * It renders what the backend says about this session (identity, roles, the
 * server-derived permission map) and about the runtime (local AI status and the
 * active repository/queue backends, both behind view_runtime_status). It
 * deliberately contains NO mutation control of any kind — no button, no input,
 * no form: the backend exposes administration routes, but no interface in this
 * increment calls them, and pretending otherwise here would claim a capability
 * this page does not have. Changing a credential, role or runtime setting is an
 * operator action outside this interface.
 */

/**
 * Humanize the raw actor_source attribution enum for customer display. The raw
 * enum value (authenticated / demo_bootstrap / system) is never shown; a demo or
 * shared session is honestly labelled as not attributed to a confirmed reviewer.
 */
function actorSourceLabel(actorSource: string): string {
  switch (actorSource) {
    case "authenticated":
      return "Verified identity";
    case "demo_bootstrap":
      return "Shared demo session";
    default:
      return "Not reported";
  }
}

export function Settings() {
  const { apiStatus, session, roles, localAi, runtimeBackends } = useWorkspace();

  const identity = session?.authenticated_identity ?? null;
  const permissions = session?.permissions ?? null;
  const permissionEntries = permissions
    ? Object.entries(permissions).sort(([a], [b]) => (a < b ? -1 : 1))
    : null;
  const grantedCount = permissionEntries?.filter(([, granted]) => granted).length ?? 0;

  const runtimeCells: CellSpec[] =
    runtimeBackends.state === "ready"
      ? [
          {
            label: "Repository",
            value: runtimeBackends.data.active_repository_backend,
            detail: `Requested: ${runtimeBackends.data.requested_repository_backend}`,
            ok: runtimeBackends.data.repository_ready
          },
          {
            label: "Queue",
            value: runtimeBackends.data.active_queue_backend,
            detail: `Requested: ${runtimeBackends.data.requested_queue_backend}`,
            ok: runtimeBackends.data.queue_ready
          },
          {
            label: "Database URL",
            value: runtimeBackends.data.database_url_configured ? "Configured" : "Not set",
            ok: runtimeBackends.data.database_url_configured
          },
          {
            label: "Redis URL",
            value: runtimeBackends.data.redis_url_configured ? "Configured" : "Not set",
            ok: runtimeBackends.data.redis_url_configured
          },
          {
            label: "Client data",
            value: runtimeBackends.data.client_data_ready ? "Ready" : "Not ready",
            detail:
              runtimeBackends.data.blocking_checks.length > 0
                ? `${runtimeBackends.data.blocking_checks.length} blocking check(s)`
                : "No blocking checks",
            ok: runtimeBackends.data.client_data_ready
          }
        ]
      : [];

  return (
    <>
      <PageHeader
        kicker="Trust"
        title="Settings"
        lede="What Monday Report reports about this session and this runtime — read-only. This page changes nothing: it has no save, no toggle and no form. Administration routes exist, but no interface in this increment calls them."
        actions={<Tag tone="outline">Read-only</Tag>}
      />

      <Frame as="section" aria-label="Session identity" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Session
        </h2>
        {session ? (
          <Cells
            label="Session identity"
            min={150}
            items={[
              { label: "Signed in as", value: session.user.full_name, detail: session.user.email },
              { label: "Organization", value: session.tenant.name, detail: session.tenant.slug },
              {
                label: "Roles",
                value: roles.length > 0 ? roles.join(", ") : "None",
                detail: "Server-derived; permissions below follow from these"
              },
              {
                label: "Authentication",
                value: identity ? identity.authentication_source.replace(/_/g, " ") : "Not reported",
                detail: identity
                  ? identity.actor_source === "demo_bootstrap"
                    ? "Shared demo session — its actions are not attributed to a confirmed individual reviewer"
                    : `Session: ${actorSourceLabel(identity.actor_source)}`
                  : "The session payload carries no authenticated identity"
              },
              ...(SHOW_INTERNAL
                ? [
                    {
                      label: "Local LLM policy",
                      value: session.tenant.local_llm_policy.mode.replace(/_/g, " "),
                      detail: session.tenant.local_llm_policy.hosted_fallback_enabled
                        ? "Hosted fallback enabled"
                        : "Hosted fallback disabled"
                    }
                  ]
                : [])
            ]}
          />
        ) : apiStatus === "checking" ? (
          <Skeleton rows={2} label="Resolving the session" />
        ) : (
          <p role="status" style={{ fontSize: 13, margin: 0 }}>
            {apiUnreadReason(apiStatus) ?? "The session is not resolved"}, so no session details can
            be shown.
          </p>
        )}
      </Frame>

      {/* The raw RBAC permission map is an engineering/internal disclosure (snake_case
          permission ids); the customer build hides it, the internal build keeps it. */}
      {SHOW_INTERNAL ? (
      <Frame as="section" aria-label="Permission map" style={{ padding: 18, display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            Permission map
          </h2>
          {permissionEntries ? (
            <Tag tone="outline">
              {grantedCount} of {permissionEntries.length} granted
            </Tag>
          ) : null}
        </div>
        <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "80ch" }}>
          Monday Report's own permission map for this session's roles — the same model every route
          enforces. Default-deny: what is not granted here is refused server-side, whatever any
          interface renders.
        </p>
        {permissionEntries ? (
          <ul data-permission-map="" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(min(250px,100%),1fr))", gap: 6 }}>
            {permissionEntries.map(([permission, granted]) => (
              <li
                key={permission}
                data-permission={permission}
                data-granted={granted ? "true" : "false"}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: 8,
                  border: "1px solid var(--color-divider)",
                  padding: "6px 10px",
                  fontSize: 12.5
                }}
              >
                <code style={{ fontSize: 12 }}>{permission}</code>
                <Tag tone={granted ? "accent" : "neutral"}>{granted ? "granted" : "denied"}</Tag>
              </li>
            ))}
          </ul>
        ) : apiStatus === "checking" ? (
          <Skeleton rows={2} label="Resolving the permission map" />
        ) : (
          <p role="status" style={{ fontSize: 13, margin: 0 }}>
            {apiUnreadReason(apiStatus) ?? "The session is not resolved"}, so the permission map was
            not read. This is not a statement that anything is granted or denied.
          </p>
        )}
      </Frame>
      ) : null}

      <Frame as="section" aria-label="AI and model" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          AI &amp; model
        </h2>
        <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "80ch" }}>
          How Monday Report answers questions and drafts reports on this computer.
        </p>
        <Cells
          label="AI and model"
          min={160}
          items={[
            {
              label: "Built-in analysis",
              value: "Active",
              detail: "On this computer · no language model",
              ok: true
            },
            { label: "Local model", value: "Not configured", detail: "Planned for a future version" },
            { label: "Online API", value: "Not configured", detail: "This version makes no external AI calls" }
          ]}
        />
        <p style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0, maxWidth: "80ch" }}>
          Answers come from Monday Report's built-in analysis: deterministic reasoning over this
          workspace's uploaded evidence. It runs entirely on this computer, uses no language model, and
          cites the evidence each answer draws on — it does not invent citations, and shows when an answer
          has none. Running a local model or connecting an online provider are planned for a future
          version and are off here.
        </p>
        {localAi.state === "ready" && localAi.data.reachable ? (
          <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.5, margin: 0, maxWidth: "80ch" }}>
            A local model runtime was detected on this computer, but this version uses built-in analysis and
            does not send your questions to it.
          </p>
        ) : null}
      </Frame>

      {SHOW_INTERNAL ? (
      <Frame as="section" aria-label="Runtime status" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Runtime status
        </h2>

        <div style={{ display: "grid", gap: 6 }}>
          <h3 style={{ fontSize: 13.5, letterSpacing: "0.04em", textTransform: "uppercase", margin: 0 }}>
            Local AI
          </h3>
          {localAi.state === "ready" ? (
            <Cells
              label="Local AI status"
              min={130}
              items={[
                {
                  label: "Runtime",
                  value:
                    localAi.data.runtime === "lm_studio"
                      ? "LM Studio"
                      : localAi.data.runtime === "ollama"
                        ? "Ollama"
                        : "Unconfigured",
                  ok: localAi.data.configured
                },
                {
                  label: "Reachable",
                  value: localAi.data.reachable ? "Yes" : "No",
                  ok: localAi.data.reachable
                },
                {
                  label: "Model",
                  value: localAi.data.model ?? "Not pinned",
                  ok: localAi.data.model_available
                },
                {
                  label: "Hosted fallback",
                  value: localAi.data.hosted_fallback_enabled ? "Enabled" : "Disabled"
                }
              ]}
            />
          ) : localAi.state === "loading" ? (
            <Skeleton rows={1} label="Reading the local AI status" />
          ) : localAi.state === "unauthorized" ? (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              This session lacks the <strong>view_runtime_status</strong> permission, so the local AI
              status was not read. This is not a statement that the runtime is up or down.
            </p>
          ) : (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              {localAi.message} The status was not read — this is not a statement that the runtime is
              up or down.
            </p>
          )}
          {localAi.state === "ready" ? (
            <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
              Backend detail: {localAi.data.detail}
            </p>
          ) : null}
        </div>

        <div style={{ display: "grid", gap: 6 }}>
          <h3 style={{ fontSize: 13.5, letterSpacing: "0.04em", textTransform: "uppercase", margin: 0 }}>
            Repository and queue backends
          </h3>
          {runtimeBackends.state === "ready" ? (
            <Cells label="Runtime backends" min={130} items={runtimeCells} />
          ) : runtimeBackends.state === "loading" ? (
            <Skeleton rows={1} label="Reading the runtime backends" />
          ) : runtimeBackends.state === "unauthorized" ? (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              This session lacks the <strong>view_runtime_status</strong> permission, so the runtime
              configuration was not read.
            </p>
          ) : (
            <p role="status" style={{ fontSize: 13, margin: 0 }}>
              {runtimeBackends.message} The configuration was not read.
            </p>
          )}
        </div>
      </Frame>
      ) : null}
    </>
  );
}
