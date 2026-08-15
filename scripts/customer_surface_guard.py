from __future__ import annotations

"""Customer-surface guard.

Locks the invariant introduced by the customer frontend polish: the shipped
CUSTOMER build hides the internal/program surfaces (project tracker, product
roadmap) and the sign-in surface, and presents the audit view as "Report
integrity" — WITHOUT deleting any internal coverage. This is a static source
guard (no server, no browser), safe to run inside audit:all.

Two halves, both required:

  * HIDING — the customer build actually hides the internal surfaces:
      - the build flag defaults to the customer build (unset => hidden);
      - navigation exposes `activeNavGroups()` that drops the internal Program
        group unless SHOW_INTERNAL;
      - the sidebar renders `activeNavGroups()` rather than the raw table;
      - Tracker/Roadmap/SignIn early-return on `!SHOW_INTERNAL`;
      - the sign-out / sign-in affordances are gated on SHOW_INTERNAL;
      - the audit surface is labelled "Report integrity", not "Audit chain".

  * COVERAGE RETAINED — nothing was removed to achieve the hiding:
      - the internal page components and their committed data records still exist;
      - router.tsx still declares the tracker/roadmap routes verbatim
        (the same literals roadmap_guard pins), so the internal build and the
        canonical UI suite keep exercising them.
"""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(rel: str) -> str | None:
    path = ROOT / rel
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _contains(rel: str, needle: str) -> bool:
    text = _text(rel)
    return text is not None and needle in text


def _absent(rel: str, needle: str) -> bool:
    text = _text(rel)
    return text is not None and needle not in text


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))

    # ── build flag: defaults to the customer build (unset => hidden) ──────────
    build = "src/redesign/lib/build.ts"
    check(
        "build flag exists and defaults to the customer build",
        _contains(build, "export const SHOW_INTERNAL")
        and _contains(build, "VITE_MONDAY_REPORT_INTERNAL")
        and _contains(build, '=== "1"'),
        f"{build} gates SHOW_INTERNAL on VITE_MONDAY_REPORT_INTERNAL === \"1\"",
    )

    # ── navigation: customer build drops the internal Program group ───────────
    nav = "src/redesign/shell/navigation.ts"
    check(
        "navigation exposes activeNavGroups() that hides the Program group",
        _contains(nav, "export function activeNavGroups")
        and _contains(nav, "SHOW_INTERNAL")
        and _contains(nav, '!== "Program"'),
        f"{nav} filters the internal Program group unless SHOW_INTERNAL",
    )
    check(
        "audit nav item is relabelled to Report integrity",
        _contains(nav, 'label: "Report integrity"')
        and _absent(nav, 'label: "Audit chain"'),
        f"{nav} names the audit destination \"Report integrity\"",
    )

    # ── sidebar renders the active (build-scoped) groups ──────────────────────
    sidebar = "src/redesign/shell/Sidebar.tsx"
    check(
        "sidebar renders activeNavGroups(), not the raw table",
        _contains(sidebar, "activeNavGroups(")
        and _absent(sidebar, "NAV_GROUPS.map"),
        f"{sidebar} maps activeNavGroups()",
    )

    # ── the internal pages early-return in the customer build ─────────────────
    for rel in (
        "src/redesign/pages/Tracker.tsx",
        "src/redesign/pages/Roadmap.tsx",
        "src/redesign/pages/SignIn.tsx",
    ):
        check(
            f"{Path(rel).name} hides itself in the customer build",
            _contains(rel, "if (!SHOW_INTERNAL)")
            and _contains(rel, 'from "../lib/build"'),
            f"{rel} early-returns on !SHOW_INTERNAL",
        )

    # ── sign-out / sign-in affordances are gated ──────────────────────────────
    check(
        "sign-out affordance is gated on SHOW_INTERNAL",
        _contains("src/redesign/shell/Topbar.tsx", "SHOW_INTERNAL"),
        "Topbar.tsx gates the sign-out control",
    )
    check(
        "in-shell sign-in link is gated on SHOW_INTERNAL",
        _contains("src/redesign/shell/AppShell.tsx", "SHOW_INTERNAL"),
        "AppShell.tsx gates the sign-in link",
    )

    # ── audit surface reads as "Report integrity", not "Audit chain" ──────────
    audit = "src/redesign/pages/Audit.tsx"
    check(
        "audit page heading is Report integrity",
        _contains(audit, 'title="Report integrity"')
        and _absent(audit, 'title="Audit chain"'),
        f"{audit} heading is \"Report integrity\"",
    )

    # ── AI/Model settings: Built-in analysis only; runtime internals gated ─────
    settings = "src/redesign/pages/Settings.tsx"
    check(
        "settings shows Built-in analysis only and gates runtime internals",
        _contains(settings, 'aria-label="AI and model"')
        and _contains(settings, "Built-in analysis")
        and _contains(settings, "Not configured")
        and _contains(settings, "SHOW_INTERNAL"),
        f"{settings} shows Built-in analysis (Local/Online not configured) and gates runtime internals",
    )

    # ── COVERAGE RETAINED: nothing deleted to achieve the hiding ──────────────
    for rel in (
        "src/redesign/pages/Tracker.tsx",
        "src/redesign/pages/Roadmap.tsx",
        "src/redesign/pages/SignIn.tsx",
        "src/data/projectTracker.ts",
        "src/data/productRoadmap.ts",
    ):
        check(
            f"internal coverage retained: {rel} still present",
            _text(rel) is not None,
            f"{rel} exists (internal build + guards still exercise it)",
        )
    router = "src/redesign/router.tsx"
    check(
        "router still declares the internal routes verbatim (coverage intact)",
        _contains(router, "<Route path=\"tracker\" element={<Tracker />} />")
        and _contains(router, "<Route path=\"roadmap\" element={<Roadmap />} />"),
        f"{router} keeps the tracker/roadmap route literals",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}: {name} - {detail}")

    result = {
        "status": "fail" if failed else "pass",
        "guard": "customer-surface",
        "summary": {"passed": len(checks) - len(failed), "failed": len(failed)},
        "detail": "customer build hides tracker/roadmap/sign-in and relabels audit; internal coverage retained"
        if not failed
        else f"{len(failed)} failing check(s)",
    }
    print(json.dumps(result, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
