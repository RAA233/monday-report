import { Link, useLocation } from "react-router-dom";
import { BrandMark, Tag } from "../components/primitives";
import { NAV_GROUPS, isCurrent } from "./navigation";
import { useWorkspace } from "../lib/workspace";

/**
 * Primary rail: brand, the three nav groups, and the tenant card.
 *
 * At ≤900px the CSS in redesign.css turns this into a horizontally scrolling bar
 * with 44px hit targets; the group labels and tenant card hide there because
 * identity stays visible in the topbar.
 */
export function Sidebar() {
  const { pathname } = useLocation();
  // The badge counts the tenant validation QUEUE, which is what the Validation view
  // lists. The export gate is a different, workspace-scoped number (see `gate`).
  const { openQueueTasks, activeWorkspace, apiStatus, session } = useWorkspace();
  const tenantName = session?.tenant.name ?? null;

  return (
    <aside
      data-sidebar=""
      aria-label="Primary"
      style={{
        position: "sticky",
        top: 0,
        display: "flex",
        flexDirection: "column",
        gap: 20,
        height: "100vh",
        overflowY: "auto",
        padding: "18px 14px",
        borderInlineEnd: "1px solid var(--color-divider)",
        boxSizing: "border-box"
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, paddingInline: 6 }}>
        <BrandMark />
        <span
          style={{
            fontFamily: "var(--font-heading)",
            fontWeight: "var(--font-heading-weight)" as never,
            fontSize: 17,
            letterSpacing: "0.03em",
            textTransform: "uppercase",
            lineHeight: 1.1
          }}
        >
          Monday
          <br />
          Report
        </span>
      </div>

      <nav data-navgroups="" style={{ display: "grid", gap: 16 }} aria-label="Application">
        {NAV_GROUPS.map((group) => (
          <div data-navgroup="" key={group.label} style={{ display: "grid", gap: 2 }}>
            <span
              data-navlabel=""
              style={{
                fontSize: 10,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "var(--color-neutral-700)",
                padding: "0 8px 6px"
              }}
            >
              {group.label}
            </span>
            {group.items.map((item) => {
              const current = isCurrent(item, pathname);
              const Icon = item.icon;
              const badge =
                item.showsValidationCount && openQueueTasks > 0
                  ? String(openQueueTasks)
                  : null;
              return (
                <Link
                  data-navbtn=""
                  key={item.path}
                  to={item.path}
                  aria-current={current ? "page" : undefined}
                  // The count is a bare visual number, so it is folded into the
                  // accessible name rather than left to be read as loose text.
                  aria-label={badge ? `${item.label}, ${badge} open` : undefined}
                  className="mr-hover-text"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 9,
                    minHeight: 34,
                    padding: "4px 8px",
                    border: "none",
                    borderInlineStart: `2px solid ${current ? "var(--color-accent)" : "transparent"}`,
                    background: current
                      ? "color-mix(in srgb, var(--color-accent) 10%, transparent)"
                      : "transparent",
                    color: current ? "var(--color-accent-800)" : "var(--color-text)",
                    fontFamily: "var(--font-body)",
                    fontSize: 13.5,
                    textAlign: "start",
                    textDecoration: "none",
                    borderRadius: 0
                  }}
                >
                  <span style={{ display: "inline-flex", flex: "none" }} aria-hidden="true">
                    <Icon size={15} strokeWidth={1.5} />
                  </span>
                  {item.label}
                  {badge ? (
                    <span
                      style={{
                        marginInlineStart: "auto",
                        fontFamily: "var(--font-heading)",
                        fontSize: 12,
                        color: "var(--color-accent-700)"
                      }}
                    >
                      {badge}
                    </span>
                  ) : null}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div
        data-tenantcard=""
        className="blueprint"
        style={{ marginTop: "auto", padding: 12 }}
        role="group"
        aria-label="Tenant status"
      >
        <i className="corner tl" />
        <i className="corner tr" />
        <i className="corner bl" />
        <i className="corner br" />
        <span
          style={{
            display: "block",
            fontSize: 10,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "var(--color-neutral-700)"
          }}
        >
          Tenant
        </span>
        <strong
          style={{
            display: "block",
            fontFamily: "var(--font-heading)",
            fontWeight: "var(--font-heading-weight)" as never,
            fontSize: 16,
            marginTop: 3
          }}
        >
          {tenantName ?? (apiStatus === "connected" ? "No tenant" : "Tenant unavailable")}
        </strong>
        <span className="text-muted" style={{ display: "block", fontSize: 12, marginTop: 2 }}>
          {activeWorkspace
            ? [activeWorkspace.name, activeWorkspace.asset].filter(Boolean).join(" · ")
            : "Connect the workspace API to read tenant scope"}
        </span>
        {/* Tenant-scoping properties describe a resolved tenant. With none
            resolved there is nothing for them to be true of, so they are not shown. */}
        {tenantName ? (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            <Tag tone="accent">Isolated</Tag>
            <Tag tone="neutral">RLS-ready</Tag>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
