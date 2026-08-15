import {
  Activity,
  BarChart3,
  Calendar,
  ClipboardCheck,
  Download,
  FileText,
  ListChecks,
  MessageSquare,
  Route,
  SearchCheck,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud,
  type LucideIcon
} from "lucide-react";
import { SHOW_INTERNAL } from "../lib/build";

/**
 * The application navigation.
 *
 * The first three groups — Operate / Review / Trust — are the handoff's
 * information architecture, unchanged. The fourth group, Program, carries the
 * two surfaces ported from the v1 interface on the owner's instruction: the
 * committed project-tracker and product-roadmap records. Every destination
 * listed here is implemented; none renders a placeholder.
 */
export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  /** Set for the item whose badge shows the open validation count. */
  showsValidationCount?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Operate",
    items: [
      { path: "/app", label: "Ask", icon: MessageSquare },
      { path: "/app/reports", label: "Monday reports", icon: Calendar },
      { path: "/app/studio", label: "Report Studio", icon: FileText },
      { path: "/app/well", label: "Well schematics", icon: Activity },
      { path: "/app/upload", label: "Upload", icon: UploadCloud }
    ]
  },
  {
    label: "Review",
    items: [
      { path: "/app/benchmarking", label: "Benchmarking", icon: BarChart3 },
      {
        path: "/app/validation",
        label: "Validation",
        icon: ClipboardCheck,
        showsValidationCount: true
      },
      { path: "/app/failures", label: "Failures", icon: SearchCheck }
    ]
  },
  {
    label: "Trust",
    items: [
      { path: "/app/audit", label: "Report integrity", icon: ShieldCheck },
      { path: "/app/exports", label: "Exports", icon: Download },
      { path: "/app/settings", label: "Settings", icon: SlidersHorizontal }
    ]
  },
  {
    label: "Program",
    items: [
      { path: "/app/tracker", label: "Tracker", icon: ListChecks },
      { path: "/app/roadmap", label: "Roadmap", icon: Route }
    ]
  }
];

/**
 * The nav groups visible in the current build. The shipped CUSTOMER build hides
 * the internal Program group (the ported tracker/roadmap records); an internal
 * build (`VITE_MONDAY_REPORT_INTERNAL=1`) shows every group. `NAV_GROUPS` stays
 * the full set, so the route-label / current-item resolution below still covers
 * the internal paths in either build.
 */
export function activeNavGroups(): NavGroup[] {
  return SHOW_INTERNAL ? NAV_GROUPS : NAV_GROUPS.filter((group) => group.label !== "Program");
}

const ALL_ITEMS = NAV_GROUPS.flatMap((group) => group.items);

/**
 * Short label for the topbar route indicator. Report Studio is entered through a
 * report, so `/app/reports/:id/draft` maps to the Studio rather than to Reports.
 */
export function routeLabel(pathname: string): string {
  if (pathname === "/app" || pathname === "/app/") return "/app";
  // Collapse the report id: the raw UUID is unreadable in a 12px chip, and the
  // Studio already discloses the full id beside its heading.
  if (/^\/app\/reports\/[^/]+\/draft\/?$/.test(pathname)) return "/app/reports/…/draft";
  const match = ALL_ITEMS.filter((item) => item.path !== "/app").find((item) =>
    pathname === item.path || pathname.startsWith(`${item.path}/`)
  );
  return match ? match.path : pathname;
}

/** True when a nav item should be marked `aria-current="page"`. */
export function isCurrent(item: NavItem, pathname: string): boolean {
  if (item.path === "/app") return pathname === "/app" || pathname === "/app/";
  if (item.path === "/app/studio") {
    return pathname.startsWith("/app/studio") || /^\/app\/reports\/[^/]+\/draft/.test(pathname);
  }
  if (item.path === "/app/reports") {
    return pathname === "/app/reports" || /^\/app\/reports\/?$/.test(pathname);
  }
  return pathname === item.path || pathname.startsWith(`${item.path}/`);
}

/** The nav item owning a path, so a view can name itself consistently. */
export function navItemForPath(pathname: string): NavItem | undefined {
  return ALL_ITEMS.find((item) => isCurrent(item, pathname));
}
