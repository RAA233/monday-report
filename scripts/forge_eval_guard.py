"""Corpus-backed FORGE evaluation guard (audit:forge-evals).

Evaluates the committed reviewed expectations against the REAL extraction
pipeline: each SHA-pinned corpus PDF is uploaded through the supported upload
route into an isolated temporary workspace, processed by the real worker
entry point, and read back through the resulting parser profile and the
report-draft API. Expected values are reviewed page ground truth and are
never rewritten to match incorrect extractor output; a required failure
records a parser defect and blocks promotion until a separate parser-fix PR
lands and this evaluation is rerun.

Skip semantics: when the local corpus is absent the run reports SKIPPED.
A skipped run is not a pass and never counts as a completed FORGE evaluation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from forge_eval_common import (  # noqa: E402
    EXPECTATIONS_PATH,
    MANIFEST_PATH,
    OUTPUT_DIR,
    ROOT,
    evaluate_check,
    load_expectations,
    load_manifest,
    resolve_corpus_root,
    scan_for_path_leaks,
    summarize_results,
    validate_spec,
)

REPORT_PATH = OUTPUT_DIR / "forge_eval_report.json"
REPORT_SCHEMA_VERSION = "v1"
DEMO_STATE_PATH = ROOT / ".local_data" / "state.json"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(payload: dict[str, Any]) -> None:
    leaks = scan_for_path_leaks(payload)
    if leaks:
        raise SystemExit(f"refusing to write report with path leaks: {leaks[:3]}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def base_report(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_id": manifest.get("corpus_id"),
        "manifest_version": manifest.get("manifest_version"),
        "manifest_sha256": file_sha256(MANIFEST_PATH),
        "expectations_version": "v1",
        "expectations_sha256": file_sha256(EXPECTATIONS_PATH),
        "parser_versions": {
            "pdf_parser": "pdf_text_v1",
            "report_profile": "pdf_report_profile_v1",
            "hydraulics": "deterministic_hydraulics v1",
        },
    }


def main() -> int:
    manifest = load_manifest()
    expectations = load_expectations()

    spec_errors = validate_spec(manifest, expectations)
    if spec_errors:
        for error in spec_errors[:10]:
            print(f"FAIL: {error}")
        write_report(
            dict(
                base_report(manifest),
                status="fail",
                skipped=False,
                skip_reason=None,
                reason="portable specification validation failed",
                errors=spec_errors[:20],
            )
        )
        return 1

    corpus_root = resolve_corpus_root()
    if not corpus_root.exists():
        print(
            "SKIPPED: FORGE corpus is not present on this machine. "
            "The corpus-backed evaluation did not run; this is not a pass and "
            "not a completed FORGE evaluation or promotion."
        )
        write_report(
            dict(
                base_report(manifest),
                status="skipped",
                skipped=True,
                skip_reason="corpus_missing",
                selected_documents=len(manifest["documents"]),
                verified_documents=0,
                checks=[],
                summary=None,
                promotion={"complete": False, "reason": "corpus missing; evaluation skipped"},
            )
        )
        return 0

    # Verify pinned hashes and page counts before touching any pipeline state.
    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError:
        print("FAIL: PyMuPDF is required for corpus verification. Install backend requirements.")
        return 1

    documents = {doc["document_id"]: doc for doc in manifest["documents"]}
    verification_failures: list[str] = []
    file_bytes: dict[str, bytes] = {}
    for doc_id, doc in documents.items():
        source = corpus_root / doc["relative_path"]
        if not source.exists():
            verification_failures.append(f"{doc_id}: missing at corpus-relative path {doc['relative_path']}")
            continue
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != doc["sha256"]:
            verification_failures.append(f"{doc_id}: SHA-256 mismatch against the committed manifest")
            continue
        with fitz.open(source) as pdf:
            if pdf.page_count != doc["page_count"]:
                verification_failures.append(f"{doc_id}: page-count mismatch against the committed manifest")
                continue
        file_bytes[doc_id] = content
    if verification_failures:
        for failure in verification_failures:
            print(f"FAIL: {failure}")
        write_report(
            dict(
                base_report(manifest),
                status="fail",
                skipped=False,
                skip_reason=None,
                reason="corpus verification failed",
                errors=verification_failures,
            )
        )
        return 1

    demo_state_before = DEMO_STATE_PATH.read_bytes() if DEMO_STATE_PATH.exists() else None

    temp_root = Path(tempfile.mkdtemp(prefix="forge-eval-"))
    os.environ.update(
        {
            "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
            "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
            "MONDAY_REPORT_TENANT_SLUG": "forge-eval",
            "MONDAY_REPORT_TENANT_NAME": "FORGE Evaluation",
            "MONDAY_REPORT_USER_EMAIL": "forge-eval@example.test",
            "MONDAY_REPORT_USER_FULL_NAME": "FORGE Evaluation Harness",
            "MONDAY_REPORT_STATE_PATH": str(temp_root / "state.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(temp_root / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(temp_root / "exports"),
        }
    )

    sys.path.insert(0, str(ROOT))

    from fastapi.testclient import TestClient  # noqa: E402

    from backend.app import worker  # noqa: E402
    from backend.app.main import app  # noqa: E402
    from backend.app.store import store  # noqa: E402

    client = TestClient(app)
    results: list[dict[str, Any]] = []
    processed_documents = 0
    pipeline_failures: list[str] = []

    checks_by_doc: dict[str, list[dict[str, Any]]] = {}
    for entry in expectations["checks"]:
        checks_by_doc.setdefault(entry["document_id"], []).append(entry)

    try:
        for doc_id, doc in documents.items():
            workspace = client.post(
                "/workspaces", json={"name": f"forge-eval-{doc_id}", "rig_name": "forge-eval"}
            )
            if workspace.status_code != 201:
                pipeline_failures.append(f"{doc_id}: workspace creation failed ({workspace.status_code})")
                continue
            workspace_id = workspace.json()["id"]
            upload = client.post(
                "/uploads/direct",
                data={
                    "workspace_id": workspace_id,
                    "file_name": f"{doc_id}.pdf",
                    "source_type": "files",
                },
                files={"file": (f"{doc_id}.pdf", file_bytes[doc_id], "application/pdf")},
            )
            if upload.status_code != 201:
                pipeline_failures.append(f"{doc_id}: upload failed ({upload.status_code})")
                continue
            worker_result = worker.run_once()
            if worker_result.get("processed", 0) < 1:
                pipeline_failures.append(f"{doc_id}: worker processed no jobs")
                continue
            parsed = [
                document
                for document in store.parsed_documents.values()
                if str(document.workspace_id) == workspace_id and document.parser_name == "pdf_text_v1"
            ]
            profile = parsed[0].metadata.get("parser", {}).get("report_profile") if parsed else None
            if not profile:
                pipeline_failures.append(f"{doc_id}: no report profile was created")
                continue
            draft_response = client.get(f"/workspaces/{workspace_id}/report-draft")
            if draft_response.status_code != 200:
                pipeline_failures.append(f"{doc_id}: report draft failed ({draft_response.status_code})")
                continue
            processed_documents += 1
            surfaces = {"profile": profile, "draft": draft_response.json()}
            for entry in checks_by_doc.get(doc_id, []):
                results.append(evaluate_check(entry, surfaces))

        isolation = {
            "failure_records": len(store.failures),
            "validation_tasks": len(store.validation_tasks),
            "anomaly_events": len(store.anomaly_events),
            "monday_reports": len(store.monday_reports),
            "recommendation_mutation": len(store.anomaly_events) > 0,
            "benchmarking_mutation": len(store.anomaly_events) > 0
            or len(getattr(store, "benchmark_measurements", {}) or {}) > 0,
        }
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    demo_state_after = DEMO_STATE_PATH.read_bytes() if DEMO_STATE_PATH.exists() else None
    isolation["demo_state_unchanged"] = demo_state_before == demo_state_after

    isolation_ok = (
        isolation["failure_records"] == 0
        and isolation["validation_tasks"] == 0
        and not isolation["recommendation_mutation"]
        and not isolation["benchmarking_mutation"]
        and isolation["monday_reports"] == 0
        and isolation["demo_state_unchanged"]
    )

    summary = summarize_results(results)
    promotion_complete = (
        summary["promotion_complete"]
        and not pipeline_failures
        and isolation_ok
        and processed_documents == len(documents)
    )
    status = "pass" if promotion_complete else "fail"

    write_report(
        dict(
            base_report(manifest),
            status=status,
            skipped=False,
            skip_reason=None,
            selected_documents=len(documents),
            verified_documents=processed_documents,
            pipeline_failures=pipeline_failures,
            isolation=isolation,
            summary=summary,
            checks=results,
            promotion={
                "complete": promotion_complete,
                "reason": (
                    "all required reviewed expectations passed on the real pipeline"
                    if promotion_complete
                    else "required reviewed expectations failed; recorded parser defects "
                    "block promotion until a separate parser-fix PR lands and this "
                    "evaluation is rerun"
                ),
            },
        )
    )

    for item in results:
        if item["result"] == "fail":
            kind = "required" if item["required"] else "optional"
            print(
                f"FAIL({kind}): {item['check_id']} [{item['check_type']} {item['target']}] "
                f"expected={item['expected']!r} extracted={item['extracted']!r}"
            )
    for failure in pipeline_failures:
        print(f"FAIL(pipeline): {failure}")
    if not isolation_ok:
        print(f"FAIL(isolation): {isolation}")

    print(
        json.dumps(
            {
                "guard": "forge_eval_guard",
                "selected_documents": len(documents),
                "verified_documents": processed_documents,
                "summary": summary,
                "isolation_ok": isolation_ok,
                "report": "output/forge-evals/forge_eval_report.json",
            },
            indent=2,
        )
    )

    if promotion_complete:
        print("\nPASS: FORGE corpus evaluation passed every required reviewed expectation. Promotion complete.")
        return 0
    print(
        "\nFAIL: FORGE corpus evaluation recorded required ground-truth failures. "
        "PROMOTION BLOCKED - a separate parser-fix PR is required; do not weaken expectations."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
