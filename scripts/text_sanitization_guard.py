from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.store import LocalStateStore, PostgresStateStore


def main() -> int:
    dirty_text = "Drill Bit-Reed Hycalog TKC63 PDC\x00 with control\x07 chars"
    clean_text = LocalStateStore._clean_extracted_text(dirty_text)
    table_text = LocalStateStore._pdf_table_row_text(["Item\x00", "Status"], ["PDC\x00 bit", "OK\x08"])
    payload = PostgresStateStore._postgres_safe_json(
        {"document_chunks": [{"text": dirty_text, "nested": ["alpha\x00beta"]}]}
    )

    checks = [
        {
            "name": "Extracted text scrub",
            "ok": "\x00" not in clean_text and "\x07" not in clean_text and "PDC" in clean_text,
            "detail": clean_text,
        },
        {
            "name": "PDF table row scrub",
            "ok": "\x00" not in table_text and "\x08" not in table_text and "PDC bit" in table_text,
            "detail": table_text,
        },
        {
            "name": "PostgreSQL JSON scrub",
            "ok": "\x00" not in json.dumps(payload) and "\x07" not in json.dumps(payload),
            "detail": payload,
        },
    ]
    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        print(f"{'PASS' if check['ok'] else 'FAIL'}: {check['name']} - {check['detail']}")
    if failed:
        print(f"\nText sanitization guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nText sanitization guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
