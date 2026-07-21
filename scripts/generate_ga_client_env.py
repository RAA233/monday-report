from __future__ import annotations

import argparse
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "ga-readiness"
OUTPUT_ENV = OUTPUT_DIR / "monday_report_ga.env"


def main() -> int:
    args = parse_args()
    output_path = Path(args.output).expanduser().resolve()
    base_dir = Path(args.base_dir).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    base_dir.mkdir(parents=True, exist_ok=True)
    env_text = build_env(base_dir)
    output_path.write_text(env_text, encoding="utf-8")
    print(f"Wrote GA client-mode env file: {output_path}")
    print("This file contains generated secrets and is under output/, which is ignored by Git.")
    print("External services still required: PostgreSQL, Redis, reviewed fixture manifest, parser/OCR eval report.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a local GA client-mode environment file.")
    parser.add_argument("--output", default=str(OUTPUT_ENV), help="Env file to write.")
    parser.add_argument(
        "--base-dir",
        default=str(Path.home() / "AppData" / "Local" / "MondayReport" / "ga"),
        help="Protected local data directory outside the repository.",
    )
    return parser.parse_args()


def build_env(base_dir: Path) -> str:
    api_key = secrets.token_urlsafe(32)
    signing_secret = secrets.token_urlsafe(48)
    # Client mode fails CLOSED without a valid audit HMAC key: main.py refuses every
    # non-public request while ``store._active_audit_key_available()`` is false, and
    # store.audit() raises rather than append an unkeyed event. Omitting this key
    # produced a "GA" env file in which no protected route could be served at all.
    # ``_decode_secret`` accepts a raw string, so token_urlsafe(48) yields well over
    # audit_keys.MIN_KEY_BYTES (32) bytes.
    audit_hmac_key = secrets.token_urlsafe(48)
    lines = [
        "# Monday Report GA client-mode environment",
        "# Generated secrets are local to this machine. Do not commit this file.",
        "",
        "MONDAY_REPORT_API_HOST=127.0.0.1",
        "MONDAY_REPORT_API_PORT=8000",
        "VITE_API_BASE_URL=http://127.0.0.1:8000",
        "",
        "MONDAY_REPORT_CLIENT_DATA_MODE=client",
        f"MONDAY_REPORT_API_KEY={api_key}",
        f"VITE_MONDAY_REPORT_API_KEY={api_key}",
        f"MONDAY_REPORT_SIGNING_SECRET={signing_secret}",
        "",
        "# Keyed audit integrity (HMAC-SHA256). REQUIRED in client mode: without a",
        "# valid active key every protected route fails closed and no audit event can",
        "# be appended. Rotate by moving the current key into",
        "# MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS (verification-only) and issuing a new",
        "# active key with an incremented version.",
        f"MONDAY_REPORT_AUDIT_HMAC_KEY={audit_hmac_key}",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_ID=audit-primary",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION=1",
        "",
        f"MONDAY_REPORT_STATE_PATH={base_dir / 'state' / 'monday_report_state.json'}",
        f"MONDAY_REPORT_STORAGE_ROOT={base_dir / 'storage'}",
        f"MONDAY_REPORT_EXPORT_ROOT={base_dir / 'exports'}",
        "MONDAY_REPORT_MAX_UPLOAD_BYTES=52428800",
        "MONDAY_REPORT_MAX_ZIP_ENTRIES=1000",
        "MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES=104857600",
        "MONDAY_REPORT_RETENTION_DAYS=90",
        "MONDAY_REPORT_MALWARE_SCANNER=builtin",
        "",
        "MONDAY_REPORT_LOCAL_LLM_RUNTIME=ollama",
        "MONDAY_REPORT_LOCAL_LLM_MODEL=gemma4:e2b",
        "OLLAMA_HOST=http://127.0.0.1:11434",
        "MONDAY_REPORT_HOSTED_FALLBACK_ENABLED=false",
        "",
        "MONDAY_REPORT_REPOSITORY_BACKEND=postgres",
        "MONDAY_REPORT_DATABASE_URL=postgresql://monday_report:monday_report_local_only@127.0.0.1:55432/monday_report",
        "MONDAY_REPORT_QUEUE_BACKEND=redis",
        "MONDAY_REPORT_REDIS_URL=redis://127.0.0.1:56379/0",
        "",
        "MONDAY_REPORT_PRODUCTION_PARSERS=true",
        "MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST=output/golden-fixtures/anonymized/golden-fixture-manifest.json",
        "MONDAY_REPORT_PARSER_EVAL_REPORT=output/parser-evals/parser_fixture_eval_report.json",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
