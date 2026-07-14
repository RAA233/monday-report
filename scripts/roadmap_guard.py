from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_UI_VIEWS = [
    ("Client Home", "00-client-home.png"),
    ("Local AI Chat", "01-chat-initial.png"),
    ("Report Studio", "03-report-studio.png"),
    ("Benchmarking", "04-benchmarking.png"),
    ("Upload", "05-upload.png"),
    ("Dashboard", "06-dashboard.png"),
    ("Explorer", "07-explorer.png"),
    ("Validation", "08-validation.png"),
    ("Tracker", "09-tracker.png"),
    ("Roadmap", "10-roadmap.png"),
    ("Architecture", "11-architecture.png"),
]


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
            "Advanced drilling reports without visual noise",
            "Document hero landing / black and white",
            "Rig MR list",
            "Import coverage",
            "Export package",
            "Casing / directional schematic",
            "ZIP",
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
            "/Advanced drilling reports without visual noise/i",
            'label: "Benchmarking"',
            "04-benchmarking.png",
            'label: "Roadmap"',
            "10-roadmap.png",
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

    ui_e2e_path = ROOT / "scripts" / "ui_quality_e2e.mjs"
    if ui_e2e_path.exists():
        missing.extend(validate_ui_e2e_views(ui_e2e_path.read_text(encoding="utf-8")))

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


def validate_ui_e2e_views(source: str) -> list[str]:
    issues: list[str] = []
    block_match = re.search(r"const\s+views\s*=\s*\[(.*?)\];", source, re.DOTALL)
    if not block_match:
        return ["scripts/ui_quality_e2e.mjs missing deterministic views array"]

    actual = re.findall(
        r'\{\s*label:\s*"([^"]+)".*?file:\s*"([^"]+)"\s*\}',
        block_match.group(1),
        re.DOTALL,
    )
    if actual != EXPECTED_UI_VIEWS:
        issues.append(
            "scripts/ui_quality_e2e.mjs view order/count mismatch: "
            f"expected {EXPECTED_UI_VIEWS!r}, found {actual!r}"
        )

    labels = [label for label, _ in actual]
    files = [file_name for _, file_name in actual]
    if len(labels) != len(set(labels)):
        issues.append("scripts/ui_quality_e2e.mjs contains duplicate view labels")
    if len(files) != len(set(files)):
        issues.append("scripts/ui_quality_e2e.mjs contains duplicate screenshot filenames")

    indices: list[int] = []
    for file_name in files:
        index_match = re.fullmatch(r"(\d{2})-[a-z0-9-]+\.png", file_name)
        if not index_match:
            issues.append(f"scripts/ui_quality_e2e.mjs has invalid screenshot filename: {file_name}")
            continue
        indices.append(int(index_match.group(1)))
    if len(indices) != len(set(indices)):
        issues.append("scripts/ui_quality_e2e.mjs contains duplicate screenshot indices")
    if indices != sorted(indices):
        issues.append("scripts/ui_quality_e2e.mjs screenshot indices are out of order")
    if "09-roadmap.png" in source:
        issues.append("scripts/ui_quality_e2e.mjs contains obsolete 09-roadmap.png")
    return issues


if __name__ == "__main__":
    raise SystemExit(main())
