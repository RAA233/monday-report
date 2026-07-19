from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "ga-readiness"
OUTPUT_JSON = OUTPUT_DIR / "Monday_Report_GA_READINESS.json"
OUTPUT_MD = OUTPUT_DIR / "Monday_Report_GA_READINESS.md"
DEFAULT_ENV_FILE = OUTPUT_DIR / "monday_report_ga.env"
FORGE_REPORT_PATH = ROOT / "output" / "forge-evals" / "forge_eval_report.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.ga_readiness import (  # noqa: E402
    blocker_counts,
    check_registry_parity,
    decide_ga,
    evaluate_blockers,
    load_registry,
    payload_sha256,
    registry_sha256,
    validate_registry,
    verify_evidence_hash,
)

EVIDENCE_SCHEMA_VERSION = "ga_readiness_evidence_v1"

# Path/identity redaction: evidence must never carry machine-specific paths.
_PATH_PATTERNS = (
    re.compile(r"[A-Za-z]:\\[^\s\"']*"),
    re.compile(r"\\\\[^\s\"']+"),
    re.compile(r"/(?:Users|home)/[^\s\"']*"),
    re.compile(r"/tmp/[^\s\"']*"),
)
_LEAK_PATTERNS = (
    re.compile(r"[A-Za-z]:\\"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
    re.compile(r"AppData"),
)


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        redacted = value
        for pattern in _PATH_PATTERNS:
            redacted = pattern.sub("<redacted-path>", redacted)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


def _scan_leaks(payload: Any) -> list[str]:
    leaks: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            for pattern in _LEAK_PATTERNS:
                if pattern.search(value):
                    leaks.append(value[:80])
                    return
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)

    walk(payload)
    return leaks


def main() -> int:
    args = parse_args()
    if args.env_file:
        load_env_file(Path(args.env_file))

    registry = load_registry()
    registry_errors = validate_registry(registry)
    if registry_errors:
        for error in registry_errors[:10]:
            print(f"FAIL: registry invalid - {error}")
        return 1

    command_results = [] if args.skip_commands else run_software_commands()
    commands_skipped = args.skip_commands
    commands_passed = (not commands_skipped) and all(item["ok"] for item in command_results)

    readiness, backends, local_ai = read_in_process_readiness()
    readiness_by_id = {check.get("id"): check.get("status") for check in readiness.get("checks", [])}
    forge_report = _load_forge_report()

    ga_checks = evaluate_blockers(readiness_by_id, forge_report=forge_report)
    parity_errors = check_registry_parity(ga_checks)
    parity_ok = not parity_errors
    counts = blocker_counts(ga_checks)
    mode = str(readiness.get("mode", "demo"))

    git_commit, git_tree, worktree_clean = git_binding()

    status, ga_ready = decide_ga(
        mode=mode,
        parity_ok=parity_ok,
        checks=ga_checks,
        commands_skipped=commands_skipped,
        commands_passed=commands_passed,
        worktree_clean=worktree_clean,
    )

    payload = build_payload(
        status=status,
        ga_ready=ga_ready,
        args=args,
        registry=registry,
        ga_checks=ga_checks,
        parity_errors=parity_errors,
        counts=counts,
        commands_skipped=commands_skipped,
        command_results=command_results,
        commands_passed=commands_passed,
        readiness=readiness,
        backends=backends,
        local_ai=local_ai,
        git_commit=git_commit,
        git_tree=git_tree,
        worktree_clean=worktree_clean,
    )

    write_outputs(payload)
    print_result(payload)

    if not commands_skipped and any(not item["ok"] for item in command_results):
        return 1
    if parity_errors:
        return 1
    if args.strict and not ga_ready:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Monday Report registry-backed GA readiness evidence.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero unless a full GA evaluation is GA_READY.")
    parser.add_argument("--skip-commands", action="store_true", help="Do not run the software-owned guard commands.")
    parser.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_FILE),
        help="Optional env file to load before evaluating readiness. Existing process env vars take precedence.",
    )
    return parser.parse_args()


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


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


def _load_forge_report() -> dict | None:
    if not FORGE_REPORT_PATH.exists():
        return None
    try:
        return json.loads(FORGE_REPORT_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def git_binding() -> tuple[str, str, bool]:
    def git(*parts: str) -> tuple[str, int]:
        completed = subprocess.run(["git", *parts], cwd=ROOT, text=True, capture_output=True, check=False)
        return completed.stdout.strip(), completed.returncode

    commit_out, commit_rc = git("rev-parse", "HEAD")
    tree_out, tree_rc = git("rev-parse", "HEAD^{tree}")
    status_out, status_rc = git("status", "--porcelain")
    commit = commit_out if commit_rc == 0 and commit_out else "unknown"
    tree = tree_out if tree_rc == 0 and tree_out else "unknown"
    # Fail-closed: only a *successful* and empty porcelain status counts as a
    # clean worktree. A git error (non-zero exit, e.g. not a repo or an index
    # lock) yields empty stdout, which must never be read as "clean".
    worktree_clean = status_rc == 0 and status_out == ""
    return commit, tree, worktree_clean


def build_payload(**kwargs: Any) -> dict[str, Any]:
    args = kwargs["args"]
    counts = kwargs["counts"]
    ga_checks = _redact(kwargs["ga_checks"])
    readiness = _redact(kwargs["readiness"])
    command_results = _redact(
        [{k: v for k, v in item.items()} for item in kwargs["command_results"]]
    )
    payload: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "status": kwargs["status"],
        "ga_ready": kwargs["ga_ready"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": kwargs["git_commit"],
        "git_tree": kwargs["git_tree"],
        "worktree_clean": kwargs["worktree_clean"],
        "registry_version": kwargs["registry"].get("registry_version"),
        "registry_sha256": registry_sha256(),
        "command": "python scripts/ga_readiness_guard.py",
        "command_arguments": {"strict": args.strict, "skip_commands": args.skip_commands},
        "commands_skipped": kwargs["commands_skipped"],
        "commands_passed": kwargs["commands_passed"],
        "full_ga_evaluation_complete": not kwargs["commands_skipped"],
        "readiness_structure_valid": not kwargs["parity_errors"],
        "parity_errors": _redact(kwargs["parity_errors"]),
        "command_results": command_results,
        "readiness_checks": ga_checks,
        "client_data_readiness": readiness,
        "runtime_backends": _redact(kwargs["backends"]),
        "local_ai": _redact(kwargs["local_ai"]),
        "blocker_counts": counts,
        "top_level_status": kwargs["status"],
        "summary": summary_text(kwargs["status"], counts, kwargs["commands_skipped"]),
        # Legacy-compatible blockers view (grouped registry-backed checks).
        "blockers": _grouped_blockers(ga_checks),
        "software_checks_passed": kwargs["commands_passed"] and counts.get("software", 0) == 0,
    }
    leaks = _scan_leaks(payload)
    if leaks:
        raise SystemExit(f"refusing to write GA evidence with path/identity leaks: {leaks[:3]}")
    payload["payload_sha256"] = payload_sha256(payload)
    # Authoritative integrity seal: the written evidence must carry a verifiable
    # canonical hash. Verify at write time and refuse to emit corrupt evidence.
    if not verify_evidence_hash(payload):
        raise SystemExit("refusing to write GA evidence: canonical payload hash failed self-verification")
    return payload


def _grouped_blockers(ga_checks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for check in ga_checks:
        if check.get("disposition") in {"PASS", "NOT_APPLICABLE"}:
            continue
        grouped.setdefault(str(check.get("category")), []).append(
            {
                "id": check.get("id"),
                "label": check.get("label"),
                "disposition": check.get("disposition"),
                "severity": check.get("severity"),
                "owner_type": check.get("owner_type"),
                "detail": check.get("detail"),
                "resolution_condition": check.get("resolution_condition"),
            }
        )
    return grouped


def summary_text(status: str, counts: dict[str, int], commands_skipped: bool) -> str:
    if status == "GA_READY":
        return "Monday Report is GA-ready: every registry-backed GA blocker is resolved and evidence is bound to a clean commit."
    parts = [f"{category}={counts.get(category, 0)}" for category in
             ("software", "configuration", "infrastructure", "security_review", "data_review_evidence", "client_approval")]
    skipped = " Software commands were skipped (not a full GA evaluation)." if commands_skipped else ""
    return (
        "GA_BLOCKED: registry-backed blockers are unresolved ("
        + ", ".join(parts)
        + f"; total={counts.get('total', 0)})."
        + skipped
    )


def write_outputs(payload: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    OUTPUT_MD.write_text(render_markdown(payload), encoding="utf-8")


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Monday Report GA Readiness",
        "",
        f"Status: `{payload['status']}`",
        f"Generated: `{payload['generated_at']}`",
        f"Commit: `{payload['git_commit']}` Tree: `{payload['git_tree']}` Worktree clean: `{str(payload['worktree_clean']).lower()}`",
        f"Registry: `{payload['registry_version']}` (`{payload['registry_sha256'][:16]}…`)",
        f"Full GA evaluation complete: `{str(payload['full_ga_evaluation_complete']).lower()}`",
        "",
        "## Summary",
        "",
        payload["summary"],
        "",
        "## Blocker counts by category",
        "",
    ]
    for category, count in payload["blocker_counts"].items():
        lines.append(f"- {category}: {count}")
    lines.extend(["", "## Unresolved blockers", ""])
    for category, checks in payload.get("blockers", {}).items():
        for check in checks:
            lines.append(
                f"- [{category}/{check.get('severity')}] `{check.get('id')}` "
                f"({check.get('disposition')}, owner {check.get('owner_type')}): {check.get('detail')}"
            )
    if not payload.get("blockers"):
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def print_result(payload: dict[str, Any]) -> None:
    print(f"{payload['status']}: {payload['summary']}")
    for category, count in payload["blocker_counts"].items():
        if category == "total":
            continue
        print(f"{category}: {count} blocker(s)")
    print(f"total: {payload['blocker_counts'].get('total', 0)} blocker(s)")
    for category, checks in payload.get("blockers", {}).items():
        for check in checks:
            print(f"  {check.get('disposition')}: {check.get('id')} - {check.get('detail')}")
    print(f"GA JSON: {OUTPUT_JSON}")
    print(f"GA MD: {OUTPUT_MD}")


def tail(value: str, max_chars: int = 1600) -> str:
    value = value.strip()
    return value[-max_chars:] if len(value) > max_chars else value


if __name__ == "__main__":
    sys.exit(main())
