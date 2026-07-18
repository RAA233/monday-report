"""Portable FORGE evaluation specification guard.

Runs WITHOUT the local FORGE corpus. Validates the committed manifest and
reviewed expectations under evals/forge/, then proves the validator and the
check engine reject malformed specifications (duplicate IDs, absolute paths,
invalid hashes, orphan or missing coverage, unsupported check types, invalid
tolerances) and that optional checks can never mask required failures.
A specification failure here is a real software failure.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from forge_eval_common import (  # noqa: E402
    EXPECTATIONS_PATH,
    MANIFEST_PATH,
    evaluate_check,
    load_expectations,
    load_manifest,
    summarize_results,
    validate_spec,
)


def check(name: str, ok: bool, detail: object = "") -> dict[str, object]:
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))
    return {"name": name, "ok": ok, "detail": detail}


def main() -> int:
    checks: list[dict[str, object]] = []

    manifest = load_manifest()
    expectations = load_expectations()

    errors = validate_spec(manifest, expectations)
    checks.append(check("Committed manifest and expectations validate portably", not errors, errors[:5]))

    doc_count = len(manifest.get("documents", []))
    check_count = len(expectations.get("checks", []))
    required_count = sum(1 for entry in expectations["checks"] if entry.get("required") is True)
    optional_count = check_count - required_count
    checks.append(check("Selection is a fixed non-trivial reviewed set", doc_count >= 4, f"documents={doc_count}"))
    checks.append(
        check(
            "Expectations carry required and explicitly marked optional checks",
            required_count >= 40 and optional_count >= 1,
            f"required={required_count} optional={optional_count}",
        )
    )
    checks.append(
        check(
            "Both report families are covered",
            {doc.get("report_family") for doc in manifest["documents"]} == {"drilling", "completion"},
            sorted({str(doc.get("report_family")) for doc in manifest["documents"]}),
        )
    )

    def rejects(name: str, mutate) -> None:
        bad_manifest = copy.deepcopy(manifest)
        bad_expectations = copy.deepcopy(expectations)
        mutate(bad_manifest, bad_expectations)
        bad_errors = validate_spec(bad_manifest, bad_expectations)
        checks.append(check(name, bool(bad_errors), bad_errors[:2]))

    rejects(
        "Duplicate document ID is rejected",
        lambda m, e: m["documents"].append(copy.deepcopy(m["documents"][0])),
    )
    rejects(
        "Duplicate check ID is rejected",
        lambda m, e: e["checks"].append(copy.deepcopy(e["checks"][0])),
    )
    rejects(
        "Absolute path in manifest is rejected",
        lambda m, e: m["documents"][0].__setitem__("relative_path", "C:/corpus/example.pdf"),
    )
    rejects(
        "Backslash path in manifest is rejected",
        lambda m, e: m["documents"][0].__setitem__("relative_path", "drilling\\example.pdf"),
    )
    rejects(
        "Invalid SHA-256 is rejected",
        lambda m, e: m["documents"][0].__setitem__("sha256", "NOT-A-HASH"),
    )
    rejects(
        "Missing required expectation coverage is rejected",
        lambda m, e: e.__setitem__(
            "checks",
            [c for c in e["checks"] if c["document_id"] != m["documents"][0]["document_id"]],
        ),
    )
    rejects(
        "Orphan expectation is rejected",
        lambda m, e: e["checks"][0].__setitem__("document_id", "forge-unknown-doc"),
    )
    rejects(
        "Unsupported check type is rejected",
        lambda m, e: e["checks"][0].__setitem__("check_type", "run_python"),
    )
    rejects(
        "Negative tolerance is rejected",
        lambda m, e: next(
            c for c in e["checks"] if c["check_type"] == "approximately_equals"
        ).__setitem__("tolerance", -1),
    )
    rejects(
        "SHA mismatch between expectation and manifest is rejected",
        lambda m, e: e["checks"][0].__setitem__("document_sha256", "0" * 64),
    )
    rejects(
        "Out-of-range page number is rejected",
        lambda m, e: e["checks"][0].__setitem__("page", 99),
    )
    rejects(
        "Copied long prose is rejected",
        lambda m, e: e["checks"][0]["review"].__setitem__("review_note", "x" * 500),
    )

    # Check-engine semantics (no corpus needed): tolerance enforcement and
    # the rule that optional checks cannot mask required failures.
    surfaces = {"profile": {"fields": {"tvd_ft": "1,629"}}, "draft": {}}
    tolerant = {
        "check_id": "engine-tolerance",
        "document_id": "doc",
        "page": 1,
        "extractor": "report_profile",
        "check_type": "approximately_equals",
        "target": "profile.fields.tvd_ft",
        "expected": 1629,
        "tolerance": 0,
        "required": True,
        "review": {"review_status": "reviewed", "reviewed_source_page": 1, "review_note": "engine"},
    }
    result_ok = evaluate_check(tolerant, surfaces)
    out_of_band = dict(tolerant, expected=1630)
    result_bad = evaluate_check(out_of_band, surfaces)
    checks.append(
        check(
            "Numeric tolerance is enforced with separator normalization",
            result_ok["result"] == "pass" and result_bad["result"] == "fail",
            {"in_band": result_ok["result"], "out_of_band": result_bad["result"]},
        )
    )

    summary = summarize_results(
        [
            dict(result_bad, required=True),
            dict(result_ok, required=False),
        ]
    )
    checks.append(
        check(
            "Optional pass cannot mask a required failure",
            summary["required_failed"] == 1 and summary["promotion_complete"] is False,
            summary,
        )
    )
    summary_green = summarize_results([dict(result_ok, required=True), dict(result_bad, required=False)])
    checks.append(
        check(
            "Promotion requires exact required-check pass semantics",
            summary_green["promotion_complete"] is True and summary_green["optional_failed"] == 1,
            summary_green,
        )
    )

    failed = [item for item in checks if not item["ok"]]
    print(
        json.dumps(
            {
                "guard": "forge_eval_spec_guard",
                "manifest": MANIFEST_PATH.relative_to(MANIFEST_PATH.parents[2]).as_posix(),
                "expectations": EXPECTATIONS_PATH.relative_to(EXPECTATIONS_PATH.parents[2]).as_posix(),
                "checks": len(checks),
                "failed": len(failed),
            },
            indent=2,
        )
    )
    if failed:
        print(f"\nFORGE evaluation spec guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nFORGE evaluation spec guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
