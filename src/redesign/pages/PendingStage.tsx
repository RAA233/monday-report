import { Link, useLocation } from "react-router-dom";
import { PageHeader, Frame, Tag } from "../components/primitives";
import { navItemForPath } from "../shell/navigation";

/**
 * Reserved destination that the redesign has NOT implemented yet.
 *
 * The route exists so the navigation reflects the real product shape, but this
 * page must never read as a finished workflow. It names the view, states plainly
 * that the redesigned surface is not built, and points at the destinations that
 * are. The equivalent workflow still exists in the v1 interface, so it says so
 * instead of implying the capability is missing from the product.
 */
export function PendingStage() {
  const { pathname } = useLocation();
  const item = navItemForPath(pathname);
  const name = item?.label ?? "This view";

  return (
    <>
      <PageHeader
        kicker="Not implemented in this increment"
        title={name}
        lede={`The redesigned ${name.toLowerCase()} surface has not been built yet. Nothing on this page reflects workspace data, and no part of this workflow is available here.`}
      />

      <Frame style={{ display: "grid", gap: 12, padding: 20, maxWidth: "72ch" }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <Tag tone="outline">Redesign pending</Tag>
          <Tag tone="neutral">No data shown</Tag>
        </div>
        <p style={{ fontSize: 13.5, lineHeight: 1.6, margin: 0 }}>
          This route is reserved so the navigation matches the product's real information
          architecture. It is a placeholder, not a preview — treat any decision that needs{" "}
          {name.toLowerCase()} as unsupported by this interface today.
        </p>
        <p className="text-muted" style={{ fontSize: 13, lineHeight: 1.6, margin: 0 }}>
          The underlying capability is unchanged in the backend and still reachable through the
          existing interface. The redesigned surface arrives in a later increment.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Link className="btn btn-primary" to="/app">
            Back to Ask
          </Link>
          <Link className="btn btn-secondary" to="/app/reports">
            Monday reports
          </Link>
          <Link className="btn btn-ghost" to="/app/validation">
            Validation
          </Link>
        </div>
      </Frame>
    </>
  );
}
