from __future__ import annotations

import os
import sys
import urllib.error
import json

from phase_audit import API_BASE, request_json


def main() -> int:
    require_ready = os.getenv("MONDAY_REPORT_REQUIRE_CLIENT_READY", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "client",
    }

    try:
        payload = request_json("GET", f"{API_BASE}/readiness/client-data")
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"FAIL: Client data readiness endpoint - {exc}")
        return 1

    ready = bool(payload.get("ready"))
    status = "PASS" if ready else "WATCH"
    checks = payload.get("checks", [])
    failing = [check for check in checks if check.get("status") == "fail"]
    warnings = [check for check in checks if check.get("status") == "warn"]

    print(
        f"{status}: Client data readiness - mode={payload.get('mode')} "
        f"status={payload.get('status')} pass={len(checks) - len(failing) - len(warnings)} "
        f"warn={len(warnings)} fail={len(failing)}"
    )
    for check in checks:
        print(
            f"{str(check.get('status', '')).upper()}: {check.get('label')} - "
            f"{check.get('detail')} Remediation: {check.get('remediation')}"
        )

    if require_ready and not ready:
        print("\nClient data readiness is required and checks are not passing.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
