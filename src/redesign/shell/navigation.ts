import {
  Activity,
  BarChart3,
  Calendar,
  ClipboardCheck,
  Download,
  FileText,
  MessageSquare,
  SearchCheck,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud,
  type LucideIcon
} from "lucide-react";

/**
 * The application navigation, grouped Operate / Review / Trust exactly as the
 * handoff specifies.
 *
 * `stage` records which increment owns a destination. Stage 2 entries are listed
 * here on purpose: the handoff's information architecture is the whole three-group
 * rail, and hiding half of it would misrepresent the product's shape. Those routes
 * render an explicitly labelled implementation-pending surface instead of a
 * workflow that does not exist yet.
 */
export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  stage: 1 | 2;
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
      { path: "/app", label: "Ask", icon: MessageSquare, stage: 1 },
      { path: "/app/reports", label: "Monday reports", icon: Calendar, stage: 1 },
      { path: "/app/studio", label: "Report Studio", icon: FileText, stage: 1 },
      { path: "/app/well", label: "Well schematics", icon: Activity, stage: 2 },
      { path: "/app/upload", label: "Upload", icon: UploadCloud, stage: 2 }
    ]
  },
  {
    label: "Review",
    items: [
      { path: "/app/benchmarking", label: "Benchmarking", icon: BarChart3, stage: 2 },
      {
        path: "/app/validation",
        label: "Validation",
        icon: ClipboardCheck,
        stage: 1,
        showsValidationCount: true
      },
      { path: "/app/failures", label: "Failures", icon: SearchCheck, stage: 2 }
    ]
  },
  {
    label: "Trust",
    items: [
      { path: "/app/audit", label: "Audit chain", icon: ShieldCheck, stage: 2 },
      { path: "/app/exports", label: "Exports", icon: Download, stage: 1 },
      { path: "/app/settings", label: "Settings", icon: SlidersHorizontal, stage: 2 }
    ]
  }
];

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

/** Stage-2 destinations, so the pending page can name itself accurately. */
export function navItemForPath(pathname: string): NavItem | undefined {
  return ALL_ITEMS.find((item) => isCurrent(item, pathname));
}
