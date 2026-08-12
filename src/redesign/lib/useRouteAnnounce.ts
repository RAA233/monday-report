import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";

/**
 * Announce SPA route changes.
 *
 * A client-side navigation replaces the page content without any of the signals a
 * real document load gives: the title never changes and focus stays wherever the
 * activated link was. This sets the document title from the route and moves focus
 * to the new view's heading, which is the conventional SPA remedy.
 *
 * Two things this must get right, both of which an earlier version got wrong:
 *
 * 1. It must not steal focus on the FIRST paint. A real document load already
 *    announced itself. A `useRef(true)` flag does not survive StrictMode, which
 *    intentionally runs setup → cleanup → setup with refs preserved: the second
 *    setup saw `false` and focused. The guard is therefore the PATH itself — focus
 *    moves only when the pathname actually differs from the one last announced,
 *    which is false for any number of repeated setups on the same route.
 *
 * 2. It must find the heading on every route. Focus targets `[data-page-heading]`
 *    (set by PageHeader and by the standalone headings on the surfaces outside the
 *    shell), not a bare `h1`, so the sign-in and landing routes participate too.
 */
const TITLES: Array<[RegExp, string]> = [
  [/^\/$/, "Rig evidence in, audited reports out"],
  [/^\/app\/signin\/?$/, "Sign in"],
  [/^\/app\/?$/, "Ask"],
  [/^\/app\/reports\/[^/]+\/draft\/?$/, "Report Studio"],
  [/^\/app\/reports\/?$/, "Monday reports"],
  [/^\/app\/studio\/?$/, "Report Studio"],
  [/^\/app\/validation\/?$/, "Validation queue"],
  [/^\/app\/exports\/?$/, "Exports"],
  [/^\/app\/well\/?$/, "Well schematics"],
  [/^\/app\/upload\/?$/, "Upload"],
  [/^\/app\/benchmarking\/?$/, "Benchmarking"],
  [/^\/app\/failures\/?$/, "Failures"],
  [/^\/app\/audit\/?$/, "Audit chain"],
  [/^\/app\/settings\/?$/, "Settings"],
  [/^\/app\/tracker\/?$/, "Project tracker"],
  [/^\/app\/roadmap\/?$/, "Product roadmap"]
];

function titleFor(pathname: string): string {
  const match = TITLES.find(([pattern]) => pattern.test(pathname));
  return match ? `${match[1]} — Monday Report` : "Not found — Monday Report";
}

export function useRouteAnnounce(): void {
  const { pathname } = useLocation();
  // Seeded with the entry path, so the first route never counts as a change.
  const announced = useRef<string | null>(null);

  useEffect(() => {
    document.title = titleFor(pathname);
    if (announced.current === null) {
      announced.current = pathname;
      return;
    }
    if (announced.current === pathname) return;
    announced.current = pathname;

    // Do not yank focus out of a control the user is actively using (a redirect can
    // fire while a field has focus).
    const active = document.activeElement;
    if (
      active instanceof HTMLElement &&
      (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.isContentEditable)
    ) {
      return;
    }

    const heading =
      document.querySelector<HTMLElement>("[data-page-heading]") ??
      document.querySelector<HTMLElement>("h1");
    heading?.focus();
  }, [pathname]);
}
