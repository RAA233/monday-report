from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "16A(78)-32_Daily_Reports"
OUTPUT_PATH = ROOT / "output" / "forge-corpus" / "forge_corpus_summary.json"


def main() -> int:
    if not CORPUS_ROOT.exists():
        print(
            "WARN: FORGE daily-report corpus folder is not present. "
            "Place 16A(78)-32_Daily_Reports beside the repo root to run the local corpus guard."
        )
        write_summary(
            {
                "status": "missing",
                "corpus_root": str(CORPUS_ROOT),
                "checks": [],
                "samples": [],
            }
        )
        return 0

    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError:
        print("FAIL: PyMuPDF is required to inspect the FORGE PDF corpus. Install backend requirements.")
        return 1

    pdfs = sorted(CORPUS_ROOT.rglob("*.pdf"))
    categories = count_categories(pdfs)
    sample_paths = choose_samples(pdfs)
    samples: list[dict[str, Any]] = []

    for path in sample_paths:
        try:
            with fitz.open(path) as document:
                text = "\n".join(
                    document.load_page(page_index).get_text("text")
                    for page_index in range(min(document.page_count, 2))
                )
                samples.append(
                    {
                        "path": str(path.relative_to(ROOT)),
                        "category": category_for(path),
                        "pages": document.page_count,
                        "chars": len(text),
                        "markers": detect_markers(text),
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive diagnostic for local corpus variation.
            samples.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "category": category_for(path),
                    "error": str(exc),
                    "markers": [],
                }
            )

    checks = [
        check("Corpus has many daily-report PDFs", len(pdfs) >= 50, f"pdf_count={len(pdfs)}"),
        check(
            "Corpus contains drilling and completion reports",
            categories.get("drilling", 0) > 0 and categories.get("completion", 0) > 0,
            categories,
        ),
        check(
            "Drilling samples expose DDR structure",
            any(
                sample_has(sample, ["daily drilling report", "casing", "time breakdown"])
                for sample in samples
                if sample.get("category") == "drilling"
            ),
            drilling_sample_detail(samples),
        ),
        check(
            "Completion samples expose completion structure",
            any(
                sample_has(sample, ["completion", "perforations"])
                or sample_has(sample, ["completion", "cost summary"])
                for sample in samples
                if sample.get("category") == "completion"
            ),
            completion_sample_detail(samples),
        ),
    ]

    write_summary(
        {
            "status": "pass" if all(item["ok"] for item in checks) else "fail",
            "corpus_root": str(CORPUS_ROOT),
            "pdf_count": len(pdfs),
            "categories": categories,
            "checks": checks,
            "samples": samples,
        }
    )

    for item in checks:
        status = "PASS" if item["ok"] else "FAIL"
        print(f"{status}: {item['name']} - {item['detail']}")

    failed = [item for item in checks if not item["ok"]]
    if failed:
        print(f"\nFORGE corpus guard failed with {len(failed)} failing check(s).")
        return 1

    print(f"\nFORGE corpus guard passed. Summary: {OUTPUT_PATH}")
    return 0


def choose_samples(pdfs: list[Path]) -> list[Path]:
    drilling = [path for path in pdfs if category_for(path) == "drilling"][:12]
    completion = [path for path in pdfs if category_for(path) == "completion"][:12]
    other = [path for path in pdfs if category_for(path) == "other"][:4]
    return drilling + completion + other


def count_categories(pdfs: list[Path]) -> dict[str, int]:
    counts = {"drilling": 0, "completion": 0, "other": 0}
    for path in pdfs:
        counts[category_for(path)] += 1
    return counts


def category_for(path: Path) -> str:
    parts = {part.lower() for part in path.parts}
    if "drilling" in parts:
        return "drilling"
    if "completion" in parts:
        return "completion"
    return "other"


def detect_markers(text: str) -> list[str]:
    lower = text.lower()
    candidates = [
        "daily drilling report",
        "well/job info",
        "casing",
        "mud",
        "bha",
        "survey data",
        "time breakdown",
        "completion",
        "perforations",
        "cost summary",
        "present operations",
        "next operations",
    ]
    return [marker for marker in candidates if marker in lower]


def sample_has(sample: dict[str, Any], markers: list[str]) -> bool:
    found = {str(marker).lower() for marker in sample.get("markers", [])}
    return all(marker in found for marker in markers)


def drilling_sample_detail(samples: list[dict[str, Any]]) -> object:
    return [sample for sample in samples if sample.get("category") == "drilling"][:3]


def completion_sample_detail(samples: list[dict[str, Any]]) -> object:
    return [sample for sample in samples if sample.get("category") == "completion"][:3]


def check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


def write_summary(payload: dict[str, Any]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
