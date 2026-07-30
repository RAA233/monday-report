import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";

/**
 * Announce SPA route changes.
 *
 * A client-side navigation replaces the page content without any of the signals a
 * real document load gives: the title never changes and focus stays wherever the
 * activated link was. Screen-reader and keyboard users get no indication that the
 * view changed. This sets the document title from the route and moves focus to the
 * new view's <h1> (which carries tabIndex={-1} via PageHeader), which is the
 * conventional SPA remedy.
 *
 * The first render is skipped: a real document load already announced itself, and
 * stealing focus on arrival would be its own defect.
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
  [/^\/app\/settings\/?$/, "Settings"]
];

function titleFor(pathname: string): string {
  const match = TITLES.find(([pattern]) => pattern.test(pathname));
  return match ? `${match[1]} — Monday Report` : "Not found — Monday Report";
}

export function useRouteAnnounce(): void {
  const { pathname } = useLocation();
  const first = useRef(true);

  useEffect(() => {
    document.title = titleFor(pathname);
    if (first.current) {
      first.current = false;
      return;
    }
    const heading = document.querySelector<HTMLElement>("h1");
    heading?.focus();
  }, [pathname]);
}
