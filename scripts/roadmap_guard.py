from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# The canonical UI suite's deterministic route table: (path, label), in order.
# Mirrors `const ROUTES = [...]` in scripts/ui_redesign_e2e.mjs, which drives the
# per-route heading assertions (`route-renders:<label>`), so a route that silently
# disappears from the suite fails HERE rather than shrinking coverage unnoticed.
EXPECTED_UI_ROUTES = [
    ("/", "landing"),
    ("/app/signin", "signin"),
    ("/app", "ask"),
    ("/app/reports", "reports"),
    ("/app/studio", "studio"),
    ("/app/validation", "validation"),
    ("/app/exports", "exports"),
    ("/app/well", "well"),
    ("/app/upload", "upload"),
    ("/app/benchmarking", "benchmarking"),
    ("/app/failures", "failures"),
    ("/app/audit", "audit"),
    ("/app/settings", "settings"),
    ("/app/tracker", "tracker"),
    ("/app/roadmap", "roadmap"),
]

# The responsive/zoom sweep: landing plus every in-shell view (no /app/signin,
# which renders outside the shell).
EXPECTED_RESPONSIVE_ROUTES = [
    "/",
    "/app",
    "/app/reports",
    "/app/validation",
    "/app/exports",
    "/app/studio",
    "/app/well",
    "/app/upload",
    "/app/benchmarking",
    "/app/failures",
    "/app/audit",
    "/app/settings",
    "/app/tracker",
    "/app/roadmap",
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
        ROOT / "src" / "redesign" / "pages" / "Landing.tsx",
        [
            "Rig evidence in.",
            "Audited reports out.",
            "Open the app",
            "MR-SCHEMA-1",
            "Source-cited drafting",
            "Audited exports",
            "Import the evidence",
            "Demo workspace, demo data. No client data is stored.",
        ],
    ),
    (
        ROOT / "src" / "redesign" / "pages" / "Roadmap.tsx",
        [
            "Product roadmap",
            "Committed record",
            "capabilitySignals",
            "roadmapExecutionBoard",
            "roadmapLanes",
            "releaseGates",
            "roadmapRisks",
            "src/data/productRoadmap.ts",
            "Capability signals",
        ],
    ),
    (
        ROOT / "src" / "redesign" / "router.tsx",
        [
            "element={<Landing />}",
            '<Route path="roadmap" element={<Roadmap />} />',
            '<Route path="tracker" element={<Tracker />} />',
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
        ROOT / "scripts" / "ui_redesign_e2e.mjs",
        [
            '{ path: "/app/benchmarking", heading: "Benchmarking", label: "benchmarking" }',
            '{ path: "/app/roadmap", heading: "Product roadmap", label: "roadmap" }',
            '{ path: "/app/tracker", heading: "Project tracker", label: "tracker" }',
            "roadmap-committed-record",
            "tracker-committed-record",
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

    ui_e2e_path = ROOT / "scripts" / "ui_redesign_e2e.mjs"
    if ui_e2e_path.exists():
        missing.extend(validate_ui_e2e_routes(ui_e2e_path.read_text(encoding="utf-8")))

    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    audit_all = package["scripts"].get("audit:all", "")
    if "python scripts/roadmap_guard.py" not in audit_all:
        missing.append("package.json audit:all missing roadmap_guard.py")
    if package["scripts"].get("test:ui") != "node scripts/ui_redesign_e2e.mjs":
        missing.append("package.json test:ui does not run the canonical UI suite")

    result = {
        "status": "fail" if missing else "pass",
        "guard": "roadmap",
        "detail": "all expected roadmap markers present" if not missing else f"missing: {', '.join(missing)}",
        "checked_files": [str(path.relative_to(ROOT)) for path, _ in CHECKS],
    }
    print(json.dumps(result, indent=2))
    return 1 if missing else 0


def validate_ui_e2e_routes(source: str) -> list[str]:
    """Deterministic check over the canonical suite's ROUTES/RESPONSIVE_ROUTES tables.

    Every entry must carry a heading assertion (a literal `heading` or a
    `headingPattern`), the (path, label) inventory must match EXPECTED_UI_ROUTES in
    order, and the responsive sweep must cover landing plus every in-shell view.
    """
    issues: list[str] = []
    block_match = re.search(r"const\s+ROUTES\s*=\s*\[(.*?)\n\];", source, re.DOTALL)
    if not block_match:
        return ["scripts/ui_redesign_e2e.mjs missing deterministic ROUTES table"]

    entries = re.findall(
        r'\{\s*path:\s*"([^"]+)",\s*'
        r'(?:heading:\s*"[^"]+"|headingPattern:\s*/[^\n]+?/[a-z]*),\s*'
        r'label:\s*"([^"]+)"\s*\}',
        block_match.group(1),
        re.DOTALL,
    )
    if entries != EXPECTED_UI_ROUTES:
        issues.append(
            "scripts/ui_redesign_e2e.mjs ROUTES order/count mismatch: "
            f"expected {EXPECTED_UI_ROUTES!r}, found {entries!r}"
        )

    paths = [path for path, _ in entries]
    labels = [label for _, label in entries]
    if len(paths) != len(set(paths)):
        issues.append("scripts/ui_redesign_e2e.mjs ROUTES contains duplicate paths")
    if len(labels) != len(set(labels)):
        issues.append("scripts/ui_redesign_e2e.mjs ROUTES contains duplicate labels")

    responsive_match = re.search(r"const\s+RESPONSIVE_ROUTES\s*=\s*\[(.*?)\n\];", source, re.DOTALL)
    if not responsive_match:
        issues.append("scripts/ui_redesign_e2e.mjs missing deterministic RESPONSIVE_ROUTES table")
    else:
        responsive = re.findall(r'"([^"]+)"', responsive_match.group(1))
        if responsive != EXPECTED_RESPONSIVE_ROUTES:
            issues.append(
                "scripts/ui_redesign_e2e.mjs RESPONSIVE_ROUTES order/count mismatch: "
                f"expected {EXPECTED_RESPONSIVE_ROUTES!r}, found {responsive!r}"
            )

    return issues


if __name__ == "__main__":
    raise SystemExit(main())
