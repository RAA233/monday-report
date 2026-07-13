from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "src" / "data" / "reportVariantSchemas.ts"
STUDIO_PATH = ROOT / "src" / "components" / "ReportStudio.tsx"
UI_E2E_PATH = ROOT / "scripts" / "ui_quality_e2e.mjs"
PACKAGE_PATH = ROOT / "package.json"
OUTPUT_PATH = ROOT / "output" / "qa" / "report_variant_schema_guard.json"

EXPECTED_IDS = ["ddr", "bha", "mud", "survey", "directional"]
REQUIRED_KEYS = ["requiredSections", "extractionMarkers", "draftingChecks", "outputSections"]


def main() -> int:
    checks: list[dict[str, object]] = []

    schema_text = read_text(SCHEMA_PATH)
    studio_text = read_text(STUDIO_PATH)
    ui_text = read_text(UI_E2E_PATH)
    package = json.loads(PACKAGE_PATH.read_text(encoding="utf-8"))

    checks.append(assert_check("Schema source exists", SCHEMA_PATH.exists(), str(SCHEMA_PATH.relative_to(ROOT))))
    checks.append(
        assert_check(
            "Schema version declared",
            'reportVariantSchemaVersion = "MR-SCHEMA-1"' in schema_text,
            "MR-SCHEMA-1",
        )
    )

    variants = parse_variants(schema_text)
    variant_ids = [variant["id"] for variant in variants]
    checks.append(
        assert_check(
            "Expected variant IDs",
            variant_ids == EXPECTED_IDS,
            {"expected": EXPECTED_IDS, "actual": variant_ids},
        )
    )

    for variant in variants:
        detail = {
            key: len(variant.get(key, []))
            for key in REQUIRED_KEYS
        }
        checks.append(
            assert_check(
                f"{variant['id']} schema has reviewed sections",
                all(detail[key] >= 6 for key in REQUIRED_KEYS)
                and bool(variant.get("schemaId"))
                and bool(variant.get("phase")),
                detail,
            )
        )

    checks.append(
        assert_check(
            "Report Studio imports shared schemas",
            "reportVariantSchemas" in studio_text
            and "Reviewed schema variants" in studio_text
            and "reportVariantSchemaVersion" in studio_text
            and "variant.extractionMarkers.length" in studio_text,
            "shared schema import and schema board markers present",
        )
    )
    checks.append(
        assert_check(
            "UI E2E covers Directional variant",
            "Directional steering report" in ui_text
            and "Reviewed schema variants" in ui_text
            and "DIR" in ui_text,
            "directional tab and schema board covered",
        )
    )
    scripts = package.get("scripts", {})
    checks.append(
        assert_check(
            "Package script is wired",
            scripts.get("audit:report-variants") == "python scripts/report_variant_schema_guard.py"
            and "python scripts/report_variant_schema_guard.py" in scripts.get("audit:all", ""),
            "audit:report-variants included in audit:all",
        )
    )

    failed = [check for check in checks if not check["ok"]]
    result = {
        "status": "fail" if failed else "pass",
        "schema_version": "MR-SCHEMA-1",
        "variant_ids": variant_ids,
        "checks": checks,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")

    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    print(f"\nReport variant schema guard: {OUTPUT_PATH}")
    return 1 if failed else 0


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def parse_variants(schema_text: str) -> list[dict[str, object]]:
    body_match = re.search(r"reportFormatVariants:\s*ReportFormatVariant\[\]\s*=\s*\[(.*)\];", schema_text, re.S)
    if not body_match:
        return []
    body = body_match.group(1)
    starts = list(re.finditer(r"\{\s*id:\s*\"([^\"]+)\"", body))
    variants: list[dict[str, object]] = []
    for index, match in enumerate(starts):
        variant_id = match.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(body)
        block = body[match.start():end]
        variant: dict[str, object] = {"id": variant_id}
        schema_id = re.search(r"schemaId:\s*\"([^\"]+)\"", block)
        phase = re.search(r"phase:\s*\"([^\"]+)\"", block)
        variant["schemaId"] = schema_id.group(1) if schema_id else ""
        variant["phase"] = phase.group(1) if phase else ""
        for key in REQUIRED_KEYS:
            array_match = re.search(rf"{key}:\s*\[(.*?)\]", block, re.S)
            variant[key] = re.findall(r"\"([^\"]+)\"", array_match.group(1)) if array_match else []
        variants.append(variant)
    return variants


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
