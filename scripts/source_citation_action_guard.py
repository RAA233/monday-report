from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    checks = [
        check_file_contains(
            "API signed source helper",
            ROOT / "src/lib/api.ts",
            [
                "export async function createUploadFileSignedUrl",
                "`/upload-files/${fileId}/signed-url`",
            ],
        ),
        check_file_contains(
            "Chat source citation action",
            ROOT / "src/redesign/pages/Ask.tsx",
            [
                "createUploadFileSignedUrl",
                "type ApiCitation",
                "openSourceCitation",
                'window.open(signed.url, "_blank", "noopener,noreferrer")',
                "sourceStatuses",
                "source-link-button",
                "Open source for",
            ],
        ),
        check_file_contains(
            "Source citation action styling",
            ROOT / "src/styles/redesign.css",
            [
                ".citation-item",
                ".citation-line",
                ".source-link-button",
                ".source-status-error",
            ],
        ),
    ]

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")

    if failed:
        print(f"\nSource citation action guard failed with {len(failed)} failing check(s).")
        return 1

    print("\nSource citation action guard passed.")
    return 0


def check_file_contains(name: str, path: Path, expected: list[str]) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    missing = [item for item in expected if item not in text]
    return {
        "name": name,
        "ok": not missing,
        "detail": "all expected wiring present" if not missing else f"missing: {', '.join(missing)}",
    }


if __name__ == "__main__":
    sys.exit(main())
