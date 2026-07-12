from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATHS = [ROOT / "backend" / "app", ROOT / "src"]
FORBIDDEN_TERMS = (
    "sample" "Failures",
    "North" "Star" " Drilling",
    "Gulf" " Campaign",
    "Demo" " Drilling Engineer",
    "ABC" " Directional Services",
    "engineer@monday-report.local",
    'self.audit("state.seed"',
)
REQUIRED_FRONTEND_TERMS = (
    "getFailures",
    "useState<FailureEvent[]>([])",
)


def main() -> int:
    findings: list[str] = []
    for root in RUNTIME_PATHS:
        for path in root.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for term in FORBIDDEN_TERMS:
                if term in text:
                    findings.append(f"{path.relative_to(ROOT)} contains {term!r}")

    app_text = (ROOT / "src" / "App.tsx").read_text(encoding="utf-8")
    for term in REQUIRED_FRONTEND_TERMS:
        if term not in app_text:
            findings.append(f"src/App.tsx missing {term!r}")

    if findings:
        print("FAIL: Runtime mock data guard")
        for finding in findings[:25]:
            print(f"- {finding}")
        return 1

    print("PASS: Runtime mock data guard - runtime source starts from live API data only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
