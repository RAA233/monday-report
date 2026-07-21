"""Guard for the hard verification-isolation preflight (Part E).

Proves the preflight FAILS CLOSED before any network activity when the
environment is not isolated from the live runtime, and that the manual live
override is honored only outside CI and never excuses a PID collision. Also
proves the wiring: ``phase_audit`` aborts (exit 2) BEFORE contacting the live API
when isolation is not configured.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import verification_isolation as VI  # noqa: E402

checks: list[dict] = []


def record(name: str, ok: bool, detail: object) -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


ISO = {
    "state_path": "/tmp/mr-iso/state.json",
    "storage_root": "/tmp/mr-iso/storage",
    "export_root": "/tmp/mr-iso/exports",
    "api_base": "http://127.0.0.1:8010",
    "web_base": "http://127.0.0.1:8011",
}

# The three persistence roots are configured independently and each defaults into
# the live .local_data, so every one of them is part of the contract.
ISO_ROOTS = ("state_path", "storage_root", "export_root")


def raises(**kw) -> bool:
    try:
        VI.assert_isolated(context="guard", **kw)
        return False
    except VI.VerificationIsolationError:
        return True


def main() -> int:
    # Hermetic baseline: clear every ambient var the preflight reads so this guard
    # is deterministic even when run inside audit:all (which sets the isolation env).
    # "" represents an explicitly-missing dimension (None would fall back to os.environ).
    for key in ("CI", "MONDAY_REPORT_ALLOW_LIVE_TARGET", "MONDAY_REPORT_STATE_PATH",
                "MONDAY_REPORT_STORAGE_ROOT", "MONDAY_REPORT_EXPORT_ROOT",
                "MONDAY_REPORT_API_BASE", "MONDAY_REPORT_WEB_BASE"):
        os.environ.pop(key, None)

    # 1-6: each missing/live-pointing dimension aborts.
    record("01 missing state_path aborts", raises(api_base=ISO["api_base"], web_base=ISO["web_base"], state_path=""),
           "state unset")
    record("02 missing api_base aborts", raises(state_path=ISO["state_path"], web_base=ISO["web_base"], api_base=""),
           "api unset")
    record("03 missing web_base aborts", raises(state_path=ISO["state_path"], api_base=ISO["api_base"], web_base=""),
           "web unset")
    record("04 api_base on live port 8000 aborts",
           raises(state_path=ISO["state_path"], api_base="http://127.0.0.1:8000", web_base=ISO["web_base"]), "8000")
    record("05 web_base on live port 5173 aborts",
           raises(state_path=ISO["state_path"], api_base=ISO["api_base"], web_base="http://127.0.0.1:5173"), "5173")
    record("06 state_path in .local_data aborts",
           raises(state_path="C:/x/.local_data/state.json", api_base=ISO["api_base"], web_base=ISO["web_base"]),
           ".local_data")

    # 7: fully isolated config passes.
    record("07 fully isolated config passes", not raises(**ISO), ISO)

    # 6b-6d: storage/export roots are part of the contract. They are configured
    # independently of the state path and each defaults into the live .local_data,
    # so a run that isolated ONLY the state path still wrote client bytes and
    # generated exports into the live tree.
    for label, key in (("6b", "storage_root"), ("6c", "export_root")):
        missing = dict(ISO); missing[key] = ""
        live = dict(ISO); live[key] = "C:/x/.local_data/" + key
        record(f"{label}-i missing {key} aborts", raises(**missing), f"{key} unset")
        record(f"{label}-ii {key} under .local_data aborts", raises(**live), f"{key} live")
    record("6d every persistence root is enumerated as its own reason",
           all(any(var in r for r in VI.check_isolation(
                   state_path="", storage_root="", export_root="",
                   api_base=ISO["api_base"], web_base=ISO["web_base"]))
               for var in ("MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
                           "MONDAY_REPORT_EXPORT_ROOT")),
           VI.check_isolation(state_path="", storage_root="", export_root="",
                              api_base=ISO["api_base"], web_base=ISO["web_base"]))

    # 8: PID collision aborts (isolated API PID == live API PID).
    record("08 isolated API PID == live API PID aborts",
           raises(**ISO, live_api_pid=4242, self_api_pid=4242), "pid collision")
    record("09 distinct API PIDs pass", not raises(**ISO, live_api_pid=4242, self_api_pid=9999), "distinct pids")

    # 10-12: manual override (non-CI) permits live-pointing, but never PID collision, never under CI.
    os.environ["MONDAY_REPORT_ALLOW_LIVE_TARGET"] = "1"
    os.environ.pop("CI", None)
    record("10 override (non-CI) permits live-pointing",
           not raises(state_path="C:/x/.local_data/state.json", api_base="http://127.0.0.1:8000",
                      web_base="http://127.0.0.1:5173"), "override honored")
    record("11 override never excuses a PID collision",
           raises(**ISO, live_api_pid=4242, self_api_pid=4242), "pid collision not excused")
    os.environ["CI"] = "true"
    record("12 CI ignores the override (still aborts)",
           raises(state_path="C:/x/.local_data/state.json", api_base="http://127.0.0.1:8000",
                  web_base="http://127.0.0.1:5173"), "CI wins")
    os.environ.pop("CI", None)
    os.environ.pop("MONDAY_REPORT_ALLOW_LIVE_TARGET", None)

    # 13: check_isolation reports each specific reason (no network performed).
    reasons = VI.check_isolation(state_path="", api_base="http://127.0.0.1:8000", web_base="http://127.0.0.1:5173")
    record("13 check_isolation enumerates specific reasons",
           any("STATE_PATH" in r for r in reasons) and any("8000" in r for r in reasons) and any("5173" in r for r in reasons),
           reasons)

    # 14: env-based default (all unset) aborts — no implicit live default.
    ISO_ENV_VARS = ("MONDAY_REPORT_STATE_PATH", "MONDAY_REPORT_STORAGE_ROOT",
                    "MONDAY_REPORT_EXPORT_ROOT", "MONDAY_REPORT_API_BASE",
                    "MONDAY_REPORT_WEB_BASE")
    ISO_ENV = {
        "MONDAY_REPORT_STATE_PATH": ISO["state_path"],
        "MONDAY_REPORT_STORAGE_ROOT": ISO["storage_root"],
        "MONDAY_REPORT_EXPORT_ROOT": ISO["export_root"],
        "MONDAY_REPORT_API_BASE": ISO["api_base"],
        "MONDAY_REPORT_WEB_BASE": ISO["web_base"],
    }
    for key in ISO_ENV_VARS:
        os.environ.pop(key, None)
    record("14 all env unset aborts (no implicit live default)", raises(), "unset env")

    # 15: CLI exits nonzero on violation, zero when isolated.
    def cli(env_extra: dict) -> int:
        env = {k: v for k, v in os.environ.items()
               if k not in ISO_ENV_VARS + ("CI", "MONDAY_REPORT_ALLOW_LIVE_TARGET")}
        env.update(env_extra)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "verification_isolation.py"), "--context", "cli"],
                              env=env, capture_output=True, text=True).returncode

    record("15 CLI exit 2 on violation, 0 when fully isolated",
           cli({}) == 2 and cli(dict(ISO_ENV)) == 0, "cli")
    record("15b CLI still exits 2 when only the state path is isolated",
           cli({"MONDAY_REPORT_STATE_PATH": ISO["state_path"],
                "MONDAY_REPORT_API_BASE": ISO["api_base"],
                "MONDAY_REPORT_WEB_BASE": ISO["web_base"]}) == 2,
           "state-only isolation is insufficient")

    # 16: WIRING — phase_audit aborts (exit 2) BEFORE contacting the live API.
    env = {k: v for k, v in os.environ.items()
           if k not in ISO_ENV_VARS + ("CI", "MONDAY_REPORT_ALLOW_LIVE_TARGET")}
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "phase_audit.py")],
                          env=env, capture_output=True, text=True, timeout=60)
    aborted_before_network = (
        proc.returncode == 2
        and "verification isolation" in proc.stdout.lower()
        and "API health" not in proc.stdout  # never reached the HTTP checks
    )
    record("16 phase_audit aborts before any network (no live contact)", aborted_before_network,
           {"rc": proc.returncode, "isolation_msg": "verification isolation" in proc.stdout.lower(),
            "reached_http": "API health" in proc.stdout})

    # 17: WIRING — e2e_mvp aborts (exit 2) before contacting the live API.
    proc2 = subprocess.run([sys.executable, str(ROOT / "scripts" / "e2e_mvp.py")],
                           env=env, capture_output=True, text=True, timeout=60)
    record("17 e2e_mvp aborts before any network", proc2.returncode == 2 and "verification isolation" in proc2.stdout.lower(),
           {"rc": proc2.returncode})

    # 18: WIRING — client_mode_function_guard is the most mutating entry point
    # (uploads fixtures, issues signed URLs, spawns backend.app.worker with
    # os.environ.copy()). It was entirely ungated and defaulted at the LIVE
    # API/web, so it must abort before any request or worker launch.
    proc3 = subprocess.run([sys.executable, str(ROOT / "scripts" / "client_mode_function_guard.py")],
                           env=env, capture_output=True, text=True, timeout=120)
    record("18 client_mode_function_guard aborts before any network or worker launch",
           proc3.returncode == 2 and "verification isolation" in proc3.stdout.lower(),
           {"rc": proc3.returncode, "head": proc3.stdout.strip()[:90]})

    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"checks": checks, "summary": {"passed": len(checks) - len(failed), "failed": len(failed)}},
                     indent=2, default=str))
    if failed:
        print(f"\nVerification isolation guard FAILED: {len(failed)} failing check(s).")
        for c in failed:
            print(f"  FAIL: {c['name']} -> {c['detail']}")
        return 1
    print(f"\nVerification isolation guard passed: {len(checks)} check(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
