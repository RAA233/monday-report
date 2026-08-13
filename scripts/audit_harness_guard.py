from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PHASE_AUDIT_PATH = ROOT / "scripts" / "phase_audit.py"
ROADMAP_GUARD_PATH = ROOT / "scripts" / "roadmap_guard.py"
RELEVANT_ENV_KEYS = [
    "MONDAY_REPORT_API_BASE",
    "MONDAY_REPORT_WEB_BASE",
    "MONDAY_REPORT_STATE_PATH",
    "MONDAY_REPORT_STORAGE_ROOT",
    "MONDAY_REPORT_EXPORT_ROOT",
    "MONDAY_REPORT_REPOSITORY_BACKEND",
    "MONDAY_REPORT_QUEUE_BACKEND",
    "MONDAY_REPORT_API_KEY",
    "MONDAY_REPORT_SIGNING_SECRET",
    "MONDAY_REPORT_AUDIT_HARNESS_SENTINEL",
]


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-audit-harness-") as temporary:
        sandbox = Path(temporary) / "isolated repo"
        scripts_dir = sandbox / "scripts"
        scripts_dir.mkdir(parents=True)
        isolated_phase_audit = scripts_dir / "phase_audit.py"
        shutil.copy2(PHASE_AUDIT_PATH, isolated_phase_audit)

        synthetic_default = sandbox / "output" / "ga-readiness" / "monday_report_ga.env"
        synthetic_default.parent.mkdir(parents=True)
        synthetic_default.write_text(
            "MONDAY_REPORT_AUDIT_HARNESS_SENTINEL=implicit-load-detected\n"
            "MONDAY_REPORT_API_BASE=http://implicit-api.invalid\n",
            encoding="utf-8",
        )

        clean_env = isolated_environment()
        import_payload, import_detail = run_json_snippet(
            """
import json, os, sys
keys = json.loads(sys.argv[2])
before = {key: os.environ.get(key) for key in keys}
sys.path.insert(0, sys.argv[1])
import phase_audit
after = {key: os.environ.get(key) for key in keys}
print(json.dumps({"unchanged": before == after, "sentinel": os.environ.get("MONDAY_REPORT_AUDIT_HARNESS_SENTINEL")}))
""",
            [str(scripts_dir), json.dumps(RELEVANT_ENV_KEYS)],
            clean_env,
        )
        checks.append(
            assert_check(
                "Import preserves relevant environment",
                import_payload is not None and import_payload.get("unchanged") is True,
                import_detail,
            )
        )
        checks.append(
            assert_check(
                "Plain import skips GA sentinel values",
                import_payload is not None and import_payload.get("sentinel") is None,
                import_detail,
            )
        )

        explicit_env = sandbox / "environment files with spaces" / "synthetic ga.env"
        explicit_env.parent.mkdir(parents=True)
        explicit_env.write_text(
            "MONDAY_REPORT_AUDIT_HARNESS_SENTINEL=explicit-load-ok\n"
            "MONDAY_REPORT_API_BASE=http://synthetic-api.invalid\n"
            "MONDAY_REPORT_WEB_BASE=http://synthetic-web.invalid\n",
            encoding="utf-8",
        )
        explicit_payload, explicit_detail = run_json_snippet(
            """
import json, os, sys
sys.path.insert(0, sys.argv[1])
import phase_audit
phase_audit.configure_ga_environment(sys.argv[2])
print(json.dumps({"sentinel": os.environ.get("MONDAY_REPORT_AUDIT_HARNESS_SENTINEL"), "api": phase_audit.API_BASE, "web": phase_audit.WEB_BASE}))
""",
            [str(scripts_dir), str(explicit_env)],
            clean_env,
        )
        checks.append(
            assert_check(
                "Explicit GA environment loading",
                explicit_payload is not None and explicit_payload.get("sentinel") == "explicit-load-ok",
                explicit_detail,
            )
        )
        checks.append(
            assert_check(
                "Environment path containing spaces",
                explicit_payload is not None and explicit_payload.get("sentinel") == "explicit-load-ok",
                str(explicit_env.parent.name),
            )
        )
        checks.append(
            assert_check(
                "Runtime URLs refresh after explicit loading",
                explicit_payload is not None
                and explicit_payload.get("api") == "http://synthetic-api.invalid"
                and explicit_payload.get("web") == "http://synthetic-web.invalid",
                explicit_detail,
            )
        )

        precedence_env = clean_env.copy()
        precedence_env["MONDAY_REPORT_API_BASE"] = "http://existing-api.invalid"
        precedence_payload, precedence_detail = run_json_snippet(
            """
import json, os, sys
sys.path.insert(0, sys.argv[1])
import phase_audit
phase_audit.configure_ga_environment(sys.argv[2])
print(json.dumps({"environment": os.environ.get("MONDAY_REPORT_API_BASE"), "runtime": phase_audit.API_BASE}))
""",
            [str(scripts_dir), str(explicit_env)],
            precedence_env,
        )
        checks.append(
            assert_check(
                "Existing environment values take precedence",
                precedence_payload is not None
                and precedence_payload.get("environment") == "http://existing-api.invalid"
                and precedence_payload.get("runtime") == "http://existing-api.invalid",
                precedence_detail,
            )
        )

        missing_path = sandbox / "missing files" / "missing ga.env"
        missing_result = subprocess.run(
            [sys.executable, str(isolated_phase_audit), "--ga-env-file", str(missing_path)],
            cwd=sandbox,
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        missing_output = f"{missing_result.stdout}\n{missing_result.stderr}".lower()
        checks.append(
            assert_check(
                "Missing explicit environment file fails clearly",
                missing_result.returncode != 0 and "not found" in missing_output,
                f"exit={missing_result.returncode}, clear_message={'not found' in missing_output}",
            )
        )

    roadmap_guard = load_module("monday_report_roadmap_guard", ROADMAP_GUARD_PATH)
    ui_markers = next(
        markers
        for path, markers in roadmap_guard.CHECKS
        if path.name == "ui_redesign_e2e.mjs"
    )
    checks.append(
        assert_check(
            "Roadmap guard pins the Benchmarking route",
            '{ path: "/app/benchmarking", heading: "Benchmarking", label: "benchmarking" }' in ui_markers,
            "active UI markers",
        )
    )
    checks.append(
        assert_check(
            "Roadmap guard pins the Roadmap route",
            '{ path: "/app/roadmap", heading: "Product roadmap", label: "roadmap" }' in ui_markers,
            "active UI markers",
        )
    )
    checks.append(
        assert_check(
            "Roadmap guard route table covers the ported program surfaces",
            ("/app/tracker", "tracker") in roadmap_guard.EXPECTED_UI_ROUTES
            and ("/app/roadmap", "roadmap") in roadmap_guard.EXPECTED_UI_ROUTES,
            "EXPECTED_UI_ROUTES",
        )
    )
    checks.append(
        assert_check(
            "Roadmap guard pins no retired v1 suite",
            all(path.name != "ui_quality_e2e.mjs" for path, _ in roadmap_guard.CHECKS),
            "no ui_quality_e2e.mjs pin remains in roadmap_guard.CHECKS",
        )
    )

    # OFFLINE MEMBERSHIP META-CHECK (re-derived for Offline Edition v2).
    #
    # Redundant assertion, from a guard that is NOT the offline guard, that the
    # Offline Edition effect-proving batteries are pinned into audit:all early
    # and are not hollowed. Removing offline validation therefore requires
    # coordinated edits to package.json, offline_audit_membership_manifest.py,
    # AND this conspicuous step-1 guard -- deterrence, not impossibility.
    membership_manifest = ROOT / "scripts" / "offline_audit_membership_manifest.py"
    if membership_manifest.exists():
        manifest_module = load_module("offline_audit_membership_manifest", membership_manifest)
        reasons = manifest_module.verify_membership()
        checks.append(
            assert_check(
                "Offline Edition batteries pinned into audit:all",
                not reasons,
                reasons or "all pinned offline members present, early, and non-hollowed",
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    if failed:
        print(f"\nAudit harness guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nAudit harness guard passed.")
    return 0


def isolated_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in RELEVANT_ENV_KEYS:
        environment.pop(key, None)
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def run_json_snippet(
    source: str,
    arguments: list[str],
    environment: dict[str, str],
) -> tuple[dict[str, object] | None, str]:
    result = subprocess.run(
        [sys.executable, "-c", source, *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        return None, f"subprocess exit={result.returncode}"
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return None, "subprocess returned invalid JSON"
    return payload, "isolated synthetic environment"


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": bool(ok), "detail": detail}


if __name__ == "__main__":
    raise SystemExit(main())
