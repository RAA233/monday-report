import { Link, useLocation } from "react-router-dom";
import { EmptyState, PageHeader } from "../components/primitives";

/**
 * In-shell not-found for unknown `/app/*` paths.
 *
 * Rendered inside the shell so the operator keeps their navigation and identity
 * context instead of being dropped onto a bare error page.
 */
export function NotFound() {
  const { pathname } = useLocation();

  return (
    <>
      <PageHeader kicker="Route not found" title="No such view" />
      <EmptyState
        title="This route does not exist"
        body={`Nothing is mapped to ${pathname}. Use the navigation to reach a view, or start from Ask.`}
        action={
          <Link className="btn btn-primary" to="/app">
            Go to Ask
          </Link>
        }
      />
    </>
  );
}
