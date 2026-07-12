from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "ga-readiness"
OUTPUT_JSON = OUTPUT_DIR / "Monday_Report_GA_READINESS.json"
OUTPUT_MD = OUTPUT_DIR / "Monday_Report_GA_READINESS.md"

SOFTWARE_CHECK_IDS = {
    "demo_seed_removed",
    "hosted_fallback_disabled",
    "official_export_gate",
    "local_llm_runtime",
    "audit_trail",
    "audit_hash_chain",
    "audit_metadata_redaction",
}
CONFIGURATION_CHECK_IDS = {
    "client_mode",
    "state_path_configured",
    "storage_root_configured",
    "export_root_configured",
    "api_key_configured",
    "signed_url_secret",
    "upload_size_limit",
    "archive_limits",
    "retention_policy",
    "parser_coverage",
    "malware_scanner",
}
INFRASTRUCTURE_CHECK_IDS = {"postgres_repository", "redis_queue"}
EVIDENCE_CHECK_IDS = {"parser_fixture_evals", "golden_fixture_coverage", "reviewed_fixture_attestation"}


def main() -> int:
    args = parse_args()
    command_results = run_software_commands() if not args.skip_commands else []
    readiness, backends, local_ai = read_in_process_readiness()
    result = build_result(command_results, readiness, backends, local_ai)
    write_outputs(result)
    print_result(result)
    if any(not item["ok"] for item in command_results):
        return 1
    if args.strict and not result["ga_ready"]:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Monday Report GA readiness evidence.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero unless all real-client GA checks pass.")
    parser.add_argument("--skip-commands", action="store_true", help="Do not rerun software-owned guard commands.")
    return parser.parse_args()


def run_software_commands() -> list[dict[str, Any]]:
    commands = [
        ("Python compile", "python -m compileall -q backend/app scripts"),
        ("Frontend build", "corepack pnpm run build"),
        ("Report template guard", "python scripts/report_template_guard.py"),
        ("FORGE corpus guard", "python scripts/forge_daily_report_corpus_guard.py"),
        ("Client operation guard", "python scripts/client_data_operation_guard.py"),
        ("Runtime mock-data guard", "python scripts/runtime_mock_data_guard.py"),
    ]
    results: list[dict[str, Any]] = []
    for name, command in commands:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, shell=True)
        results.append(
            {
                "name": name,
                "command": command,
                "ok": completed.returncode == 0,
                "returncode": completed.returncode,
                "stdout_tail": tail(completed.stdout),
                "stderr_tail": tail(completed.stderr),
            }
        )
    return results


def read_in_process_readiness() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from fastapi.testclient import TestClient
    from backend.app.main import app

    client = TestClient(app)
    readiness = response_json(client.get("/readiness/client-data"))
    backends = response_json(client.get("/runtime/backends"))
    local_ai = response_json(client.get("/local-ai/status"))
    return readiness, backends, local_ai


def response_json(response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {"status_code": response.status_code, "detail": response.text}
    return payload if isinstance(payload, dict) else {"payload": payload}


def build_result(
    command_results: list[dict[str, Any]],
    readiness: dict[str, Any],
    backends: dict[str, Any],
    local_ai: dict[str, Any],
) -> dict[str, Any]:
    checks = readiness.get("checks", [])
    non_passing = [check for check in checks if check.get("status") != "pass"]
    categorized = {
        "software": categorize(non_passing, SOFTWARE_CHECK_IDS),
        "configuration": categorize(non_passing, CONFIGURATION_CHECK_IDS),
        "infrastructure": categorize(non_passing, INFRASTRUCTURE_CHECK_IDS),
        "evidence_or_approval": categorize(non_passing, EVIDENCE_CHECK_IDS),
        "uncategorized": [
            check
            for check in non_passing
            if check.get("id") not in SOFTWARE_CHECK_IDS
            | CONFIGURATION_CHECK_IDS
            | INFRASTRUCTURE_CHECK_IDS
            | EVIDENCE_CHECK_IDS
        ],
    }
    software_commands_pass = all(item["ok"] for item in command_results)
    software_readiness_pass = not categorized["software"]
    ga_ready = bool(readiness.get("ready")) and not non_passing and software_commands_pass
    status = "GA_READY" if ga_ready else "GA_BLOCKED"
    return {
        "status": status,
        "ga_ready": ga_ready,
        "software_checks_passed": software_commands_pass and software_readiness_pass,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "readiness": readiness,
        "runtime_backends": backends,
        "local_ai": local_ai,
        "software_commands": command_results,
        "blockers": categorized,
        "summary": summary_text(ga_ready, categorized, software_commands_pass, software_readiness_pass),
    }


def categorize(checks: list[dict[str, Any]], ids: set[str]) -> list[dict[str, Any]]:
    return [
        {
            "id": check.get("id"),
            "label": check.get("label"),
            "status": check.get("status"),
            "detail": check.get("detail"),
            "remediation": check.get("remediation"),
        }
        for check in checks
        if check.get("id") in ids
    ]


def summary_text(
    ga_ready: bool,
    blockers: dict[str, list[dict[str, Any]]],
    software_commands_pass: bool,
    software_readiness_pass: bool,
) -> str:
    if ga_ready:
        return "Monday Report is GA-ready for real client data according to the live readiness checks."
    if software_commands_pass and software_readiness_pass:
        return (
            "Software-owned GA checks pass. Real-client GA remains blocked by configuration, "
            "external infrastructure, or reviewed evidence/approval requirements."
        )
    return (
        "GA readiness is blocked by software-owned checks plus any listed configuration, "
        "infrastructure, or evidence requirements."
    )


def write_outputs(result: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    OUTPUT_MD.write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Monday Report GA Readiness",
        "",
        f"Status: `{result['status']}`",
        f"Generated: `{result['generated_at']}`",
        f"Software checks passed: `{str(result['software_checks_passed']).lower()}`",
        "",
        "## Summary",
        "",
        result["summary"],
        "",
        "## Software Command Checks",
        "",
    ]
    for item in result.get("software_commands", []):
        lines.append(f"- {'PASS' if item['ok'] else 'FAIL'}: `{item['command']}`")

    for title, key in [
        ("Software Blockers", "software"),
        ("Configuration Blockers", "configuration"),
        ("Infrastructure Blockers", "infrastructure"),
        ("Evidence Or Approval Blockers", "evidence_or_approval"),
        ("Uncategorized Blockers", "uncategorized"),
    ]:
        lines.extend(["", f"## {title}", ""])
        checks = result.get("blockers", {}).get(key, [])
        if not checks:
            lines.append("- None.")
            continue
        for check in checks:
            lines.append(
                f"- {str(check.get('status', '')).upper()}: `{check.get('id')}` - "
                f"{check.get('detail')} Remediation: {check.get('remediation')}"
            )
    lines.append("")
    return "\n".join(lines)


def print_result(result: dict[str, Any]) -> None:
    print(f"{result['status']}: {result['summary']}")
    for category, checks in result["blockers"].items():
        print(f"{category}: {len(checks)} blocker(s)")
        for check in checks:
            print(f"  {str(check.get('status', '')).upper()}: {check.get('id')} - {check.get('detail')}")
    print(f"GA JSON: {OUTPUT_JSON}")
    print(f"GA MD: {OUTPUT_MD}")


def tail(value: str, max_chars: int = 1600) -> str:
    value = value.strip()
    return value[-max_chars:] if len(value) > max_chars else value


if __name__ == "__main__":
    sys.exit(main())
