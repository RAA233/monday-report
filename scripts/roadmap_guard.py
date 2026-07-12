from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


CHECKS = [
    (
        ROOT / "src" / "data" / "productRoadmap.ts",
        [
            "capabilitySignals",
            "roadmapLanes",
            "releaseGates",
            "roadmapRisks",
            "gemma4:e2b",
            "Client Pilot",
            "Citation-backed AI drafts",
        ],
    ),
    (
        ROOT / "src" / "components" / "ProductRoadmap.tsx",
        [
            "Product roadmap",
            "Delivery lanes",
            "Release train",
            "Roadmap risk controls",
            "Capability map",
            "roadmap-lanes",
        ],
    ),
    (
        ROOT / "src" / "App.tsx",
        [
            '"roadmap"',
            'label: "Roadmap"',
            "<ProductRoadmap />",
        ],
    ),
    (
        ROOT / "src" / "data" / "projectTracker.ts",
        [
            "Roadmap cockpit",
            "gate-roadmap",
            "pnpm run audit:roadmap",
        ],
    ),
    (
        ROOT / "scripts" / "ui_quality_e2e.mjs",
        [
            'label: "Roadmap"',
            "09-roadmap.png",
            "/Product roadmap/i",
        ],
    ),
    (
        ROOT / "package.json",
        [
            '"audit:roadmap"',
            "scripts/roadmap_guard.py",
        ],
    ),
]


def main() -> int:
    missing: list[str] = []
    for path, markers in CHECKS:
        if not path.exists():
            missing.append(f"{path.relative_to(ROOT)} missing")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                missing.append(f"{path.relative_to(ROOT)} missing marker: {marker}")

    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    audit_all = package["scripts"].get("audit:all", "")
    if "python scripts/roadmap_guard.py" not in audit_all:
        missing.append("package.json audit:all missing roadmap_guard.py")

    result = {
        "status": "fail" if missing else "pass",
        "guard": "roadmap",
        "detail": "all expected roadmap markers present" if not missing else f"missing: {', '.join(missing)}",
        "checked_files": [str(path.relative_to(ROOT)) for path, _ in CHECKS],
    }
    print(json.dumps(result, indent=2))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
