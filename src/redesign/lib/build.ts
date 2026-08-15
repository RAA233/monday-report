/**
 * Customer vs. internal build surface.
 *
 * The shipped offline product is the CUSTOMER build. Internal/program surfaces
 * — the ported project-tracker and product-roadmap records — and the sign-in
 * surface are hidden from navigation and are not reachable by URL in that build.
 * They stay in the codebase and render in an INTERNAL build, so their guards and
 * the canonical UI suite keep exercising them; nothing is deleted.
 *
 * Fail-safe direction: the flag DEFAULTS to the customer build. A build that
 * forgets to set it hides the internal surfaces rather than leaking them. A
 * developer opts into the internal surfaces with `VITE_MONDAY_REPORT_INTERNAL=1`
 * at build/serve time (mirrors how `src/lib/api.ts` reads its `VITE_` config).
 */
export const SHOW_INTERNAL: boolean =
  (import.meta.env.VITE_MONDAY_REPORT_INTERNAL as string | undefined) === "1";

/** Convenience inverse: true in the shipped customer build. */
export const IS_CUSTOMER_BUILD: boolean = !SHOW_INTERNAL;
