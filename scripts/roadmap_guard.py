from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


CHECKS = [
    (
        ROOT / "src" / "data" / "productRoadmap.ts",
        [
            "capabilitySignals",
            "roadmapExecutionBoard",
            "roadmapLanes",
            "releaseGates",
            "roadmapRisks",
            "gemma4:e2b",
            "Client Pilot",
            "Client landing",
            "MR-SCHEMA-1",
            "Citation-backed AI drafts",
            "schematic extraction",
        ],
    ),
    (
        ROOT / "src" / "data" / "reportVariantSchemas.ts",
        [
            "reportVariantSchemaVersion",
            "MR-SCHEMA-1",
            '"directional"',
            "extractionMarkers",
            "draftingChecks",
            "outputSections",
        ],
    ),
    (
        ROOT / "src" / "components" / "ClientLanding.tsx",
        [
            "Client landing",
            "Rigs and Monday Reports",
            "Rig MR list",
            "Import coverage",
            "Export coverage",
            "ZIP archives",
            "XLSX",
        ],
    ),
    (
        ROOT / "src" / "components" / "ProductRoadmap.tsx",
        [
            "Product roadmap",
            "Roadmap execution board",
            "Next controlled moves",
            "Delivery lanes",
            "Release train",
            "Roadmap risk controls",
            "Capability map",
            "roadmap-lanes",
            "roadmap-execution-grid",
        ],
    ),
    (
        ROOT / "src" / "App.tsx",
        [
            '"client"',
            'label: "Client Home"',
            "<ClientLanding",
            '"roadmap"',
            'label: "Roadmap"',
            "<ProductRoadmap />",
        ],
    ),
    (
        ROOT / "src" / "data" / "projectTracker.ts",
        [
            "Roadmap cockpit",
            "gate-report-variants",
            "gate-roadmap",
            "pnpm run audit:roadmap",
        ],
    ),
    (
        ROOT / "scripts" / "ui_quality_e2e.mjs",
        [
            'label: "Client Home"',
            "00-client-home.png",
            "/Rigs and Monday Reports/i",
            'label: "Roadmap"',
            "09-roadmap.png",
            "/Product roadmap/i",
        ],
    ),
    (
        ROOT / "package.json",
        [
            '"audit:roadmap"',
            '"audit:report-variants"',
            "scripts/roadmap_guard.py",
            "scripts/report_variant_schema_guard.py",
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
