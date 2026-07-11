from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    checks = [
        check_contains(
            "Markdown clear tracker snapshot",
            ROOT / "docs" / "PROJECT_TRACKER.md",
            [
                "## Clear Tracker Snapshot",
                "Accepted now",
                "Safe operating mode",
                "Real-client blockers",
                "Next execution order",
                "not ready",
            ],
        ),
        check_contains(
            "Tracker data clear lanes",
            ROOT / "src" / "data" / "projectTracker.ts",
            [
                "export const clearTrackerLanes",
                "Accepted Now",
                "Safe Operating Mode",
                "Real-Client Blockers",
                "Next Execution Order",
            ],
        ),
        check_contains(
            "Tracker UI clear lanes",
            ROOT / "src" / "components" / "ProjectTracker.tsx",
            [
                "clearTrackerLanes",
                "Clear tracker",
                "clear-tracker-grid",
                "clear-tracker-card",
            ],
        ),
        check_contains(
            "Tracker clear lane styling",
            ROOT / "src" / "styles.css",
            [
                ".clear-tracker-grid",
                ".clear-tracker-card",
            ],
        ),
    ]

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")

    if failed:
        print(f"\nTracker clarity guard failed with {len(failed)} failing check(s).")
        return 1

    print("\nTracker clarity guard passed.")
    return 0


def check_contains(name: str, path: Path, expected: list[str]) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    missing = [item for item in expected if item not in text]
    return {
        "name": name,
        "ok": not missing,
        "detail": "all expected tracker clarity markers present" if not missing else f"missing: {', '.join(missing)}",
    }


if __name__ == "__main__":
    sys.exit(main())
