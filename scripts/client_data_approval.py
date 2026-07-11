from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phase_audit import API_BASE, request_json


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "client-data"
APPROVAL_JSON = "Monday_Report_Client_Data_APPROVAL.json"
APPROVAL_MD = "Monday_Report_Client_Data_APPROVAL.md"


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser().resolve()

    try:
        readiness = request_json("GET", f"{API_BASE}/readiness/client-data")
        backends = request_json("GET", f"{API_BASE}/runtime/backends")
        local_ai = request_json("GET", f"{API_BASE}/local-ai/status")
    except Exception as exc:  # noqa: BLE001 - approval evidence should capture any endpoint failure.
        result = blocked_result(
            summary=f"Client-data approval could not reach readiness endpoints: {exc}",
            readiness={},
            backends={},
            local_ai={},
        )
    else:
        result = approval_result(readiness, backends, local_ai)

    if not args.verify_only:
        write_outputs(output_dir, result)

    print_result(result)
    return 0 if result["approved"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Approve or block Monday Report real-client data posture.")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Do not write approval artifacts; exit non-zero unless client-data readiness is approved.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Directory for approval JSON and Markdown artifacts.",
    )
    return parser.parse_args()


def approval_result(readiness: dict[str, Any], backends: dict[str, Any], local_ai: dict[str, Any]) -> dict[str, Any]:
    checks = readiness.get("checks", [])
    non_passing = [check for check in checks if check.get("status") != "pass"]
    approved = bool(readiness.get("ready")) and not non_passing
    summary = (
        "Client-data posture is approved by the live readiness endpoint."
        if approved
        else "Client-data posture is blocked; one or more readiness checks are not passing."
    )
    return {
        "approved": approved,
        "status": "APPROVED" if approved else "BLOCKED",
        "scope": "real_client_data",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "readiness": readiness,
        "runtime_backends": backends,
        "local_ai": local_ai,
        "blocking_checks": [
            {
                "id": check.get("id"),
                "label": check.get("label"),
                "status": check.get("status"),
                "detail": check.get("detail"),
                "remediation": check.get("remediation"),
            }
            for check in non_passing
        ],
    }


def blocked_result(
    *,
    summary: str,
    readiness: dict[str, Any],
    backends: dict[str, Any],
    local_ai: dict[str, Any],
) -> dict[str, Any]:
    return {
        "approved": False,
        "status": "BLOCKED",
        "scope": "real_client_data",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "readiness": readiness,
        "runtime_backends": backends,
        "local_ai": local_ai,
        "blocking_checks": [
            {
                "id": "readiness_endpoint",
                "label": "Client data readiness endpoint",
                "status": "fail",
                "detail": summary,
                "remediation": "Start the API and clear all /readiness/client-data checks before approving real client data.",
            }
        ],
    }


def write_outputs(output_dir: Path, result: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / APPROVAL_JSON).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / APPROVAL_MD).write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict[str, Any]) -> str:
    readiness = result.get("readiness", {})
    backends = result.get("runtime_backends", {})
    local_ai = result.get("local_ai", {})
    lines = [
        "# Monday Report Client Data Approval",
        "",
        f"Status: {result['status']}",
        f"Scope: `{result['scope']}`",
        f"Generated: `{result['generated_at']}`",
        "",
        "## Summary",
        "",
        str(result["summary"]),
        "",
        "## Readiness",
        "",
        f"- Mode: `{readiness.get('mode', 'unknown')}`",
        f"- Endpoint status: `{readiness.get('status', 'unknown')}`",
        f"- Approved: `{str(result['approved']).lower()}`",
        "",
        "## Runtime",
        "",
        f"- Repository backend: requested `{backends.get('requested_repository_backend', 'unknown')}`, active `{backends.get('active_repository_backend', 'unknown')}`",
        f"- Queue backend: requested `{backends.get('requested_queue_backend', 'unknown')}`, active `{backends.get('active_queue_backend', 'unknown')}`",
        f"- Local AI: `{local_ai.get('runtime', 'unknown')}` / `{local_ai.get('model', 'unknown')}` / model available `{local_ai.get('model_available', False)}`",
        "",
        "## Blocking Checks",
        "",
    ]
    blockers = result.get("blocking_checks", [])
    if blockers:
        for check in blockers:
            lines.append(
                f"- {check.get('status', 'unknown').upper()}: `{check.get('id', 'unknown')}` - "
                f"{check.get('detail', '')} Remediation: {check.get('remediation', '')}"
            )
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def print_result(result: dict[str, Any]) -> None:
    print(f"{result['status']}: {result['scope']} - {result['summary']}")
    for check in result.get("blocking_checks", []):
        print(f"{str(check.get('status', '')).upper()}: {check.get('id')} - {check.get('detail')}")


if __name__ == "__main__":
    sys.exit(main())
