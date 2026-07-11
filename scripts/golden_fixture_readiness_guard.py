from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.fixtures import REQUIRED_GOLDEN_FIXTURE_FAMILIES  # noqa: E402


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-golden-fixtures-") as tmp:
        tmp_root = Path(tmp)
        configure_guard_env(tmp_root)

        from backend.app.main import app

        client = TestClient(app)

        no_manifest = client.get("/readiness/client-data").json()
        no_manifest_check = readiness_check(no_manifest, "golden_fixture_coverage")
        checks.append(
            assert_check(
                "Golden fixtures block readiness without manifest",
                no_manifest_check.get("status") == "warn"
                and "not configured" in no_manifest_check.get("detail", ""),
                no_manifest_check,
            )
        )

        synthetic_manifest = write_manifest(
            tmp_root,
            "synthetic-fixtures.json",
            "synthetic",
            [("ddr", ["fixtures/ddr.txt"])],
        )
        os.environ["MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST"] = str(synthetic_manifest)
        synthetic = client.get("/readiness/client-data").json()
        synthetic_check = readiness_check(synthetic, "golden_fixture_coverage")
        checks.append(
            assert_check(
                "Synthetic or partial fixtures do not certify readiness",
                synthetic_check.get("status") == "warn"
                and "fixture_mode must be 'anonymized_client'" in synthetic_check.get("detail", "")
                and "missing families" in synthetic_check.get("detail", ""),
                synthetic_check,
            )
        )

        complete_manifest = write_manifest(
            tmp_root,
            "anonymized-fixtures.json",
            "anonymized_client",
            [(fixture_id, [f"fixtures/{fixture_id}.txt"]) for fixture_id, _ in REQUIRED_GOLDEN_FIXTURE_FAMILIES],
        )
        os.environ["MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST"] = str(complete_manifest)
        complete = client.get("/readiness/client-data").json()
        complete_check = readiness_check(complete, "golden_fixture_coverage")
        checks.append(
            assert_check(
                "Complete anonymized fixture manifest passes fixture check",
                complete_check.get("status") == "pass"
                and f"{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}/{len(REQUIRED_GOLDEN_FIXTURE_FAMILIES)}"
                in complete_check.get("detail", ""),
                complete_check,
            )
        )

        client_mode_manifest = write_manifest(
            tmp_root,
            "client-partial-fixtures.json",
            "anonymized_client",
            [("ddr", ["fixtures/ddr.txt"])],
        )
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        os.environ["MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST"] = str(client_mode_manifest)
        client_mode = client.get("/readiness/client-data").json()
        client_mode_check = readiness_check(client_mode, "golden_fixture_coverage")
        checks.append(
            assert_check(
                "Client mode fails closed on incomplete fixtures",
                client_mode_check.get("status") == "fail" and client_mode.get("ready") is False,
                {"ready": client_mode.get("ready"), "check": client_mode_check},
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ.pop("MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST", None)
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Golden Fixture Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "golden-fixture-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Golden Fixture Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Golden fixture readiness guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def write_manifest(
    root: Path,
    name: str,
    fixture_mode: str,
    families: list[tuple[str, list[str]]],
) -> Path:
    for _, evidence_files in families:
        for relative_path in evidence_files:
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("anonymized fixture placeholder for readiness guard\n", encoding="utf-8")
    manifest = {
        "fixture_set": name.replace(".json", ""),
        "fixture_mode": fixture_mode,
        "families": [
            {
                "id": fixture_id,
                "evidence_files": evidence_files,
                "notes": "Guard fixture file; production manifests must reference anonymized client files.",
            }
            for fixture_id, evidence_files in families
        ],
    }
    path = root / name
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def readiness_check(payload: dict, check_id: str) -> dict:
    for check in payload.get("checks", []):
        if check.get("id") == check_id:
            return check
    return {}


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
