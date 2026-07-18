"""Verify the committed FORGE evaluation manifest against the local corpus.

The committed evals/forge/manifest.v1.json is the reviewed authority. This
script never regenerates or rewrites that selection; it locates the local
corpus, verifies relative paths, SHA-256 hashes, and page counts, and emits
an ignored local verification report. A deliberate selection change requires
editing and re-reviewing the committed manifest itself.

Without the local corpus the run reports SKIPPED (never PASS).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from forge_eval_common import (  # noqa: E402
    OUTPUT_DIR,
    load_expectations,
    load_manifest,
    resolve_corpus_root,
    scan_for_path_leaks,
    validate_spec,
)

REPORT_PATH = OUTPUT_DIR / "forge_manifest_verification.json"


def write_report(payload: dict[str, Any]) -> None:
    leaks = scan_for_path_leaks(payload)
    if leaks:
        raise SystemExit(f"refusing to write report with path leaks: {leaks[:3]}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    manifest = load_manifest()
    expectations = load_expectations()
    spec_errors = validate_spec(manifest, expectations)
    if spec_errors:
        for error in spec_errors[:10]:
            print(f"FAIL: {error}")
        write_report(
            {
                "status": "fail",
                "reason": "portable specification validation failed",
                "errors": spec_errors[:20],
            }
        )
        return 1

    corpus_root = resolve_corpus_root()
    if not corpus_root.exists():
        print(
            "SKIPPED: FORGE corpus is not present locally; the committed manifest "
            "cannot be verified against source PDFs on this machine."
        )
        write_report(
            {
                "status": "skipped",
                "reason": "corpus_missing",
                "corpus_root": "<local corpus root not present>",
                "documents": [],
            }
        )
        return 0

    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError:
        print("FAIL: PyMuPDF is required to verify page counts. Install backend requirements.")
        return 1

    results: list[dict[str, Any]] = []
    failures = 0
    for doc in manifest["documents"]:
        relative_path = doc["relative_path"]
        source = corpus_root / relative_path
        entry: dict[str, Any] = {
            "document_id": doc["document_id"],
            "relative_path": relative_path,
        }
        if not source.exists():
            entry.update({"ok": False, "reason": "missing_file"})
            failures += 1
            results.append(entry)
            print(f"FAIL: {doc['document_id']} missing at corpus-relative path {relative_path}")
            continue
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        sha_ok = digest == doc["sha256"]
        with fitz.open(source) as pdf:
            pages_ok = pdf.page_count == doc["page_count"]
            entry["page_count"] = pdf.page_count
        entry.update({"sha256_ok": sha_ok, "page_count_ok": pages_ok, "ok": sha_ok and pages_ok})
        if not entry["ok"]:
            failures += 1
            print(
                f"FAIL: {doc['document_id']} verification mismatch "
                f"(sha256_ok={sha_ok}, page_count_ok={pages_ok})"
            )
        else:
            print(f"PASS: {doc['document_id']} verified ({digest[:12]}…, {entry['page_count']} page)")
        results.append(entry)

    status = "pass" if failures == 0 else "fail"
    write_report(
        {
            "status": status,
            "manifest_version": manifest["manifest_version"],
            "corpus_id": manifest["corpus_id"],
            "selected_documents": len(manifest["documents"]),
            "verified_documents": sum(1 for item in results if item.get("ok")),
            "documents": results,
        }
    )
    if failures:
        print(f"\nFORGE manifest verification failed for {failures} document(s).")
        return 1
    print(f"\nFORGE manifest verification passed for {len(results)} document(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
