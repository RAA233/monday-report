"""Guard for the explicit, fail-closed CORS origin allowlist.

The browser CORS allowlist is the single lever `MONDAY_REPORT_CORS_ORIGINS`.
This guard proves the contract in `backend.app.main.cors_allowed_origins`:

- an explicit allowlist wins in every mode (no implicit dev origin appended), so
  an isolated deployment can allow ONLY its own frontend origin;
- unset in demo/local mode falls back to the localhost:5173 dev origins;
- unset in protected client mode FAILS CLOSED (empty list) -- it never silently
  permits :5173 and never widens to a wildcard;
- a real CORS preflight echoes an allowed origin and refuses an unrelated one.

Both the pure resolver and a real Starlette CORS preflight are exercised, so this
is behavioural, not source-scanning. No live server, database, or network needed.

Run: ``python scripts/cors_origin_guard.py``
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Keep the app's state fully isolated from any real .local_data.
_TMP = tempfile.mkdtemp(prefix="mr-cors-guard-")
os.environ.setdefault("MONDAY_REPORT_STATE_PATH", str(Path(_TMP) / "state.json"))
os.environ.setdefault("MONDAY_REPORT_STORAGE_ROOT", str(Path(_TMP) / "storage"))
os.environ.setdefault("MONDAY_REPORT_EXPORT_ROOT", str(Path(_TMP) / "exports"))
os.environ["CI"] = "true"

checks: list[dict] = []


def record(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))


def _resolve(mode: str, origins_env: str | None) -> list[str]:
    from backend.app import main as app_main

    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = mode
    if origins_env is None:
        os.environ.pop("MONDAY_REPORT_CORS_ORIGINS", None)
    else:
        os.environ["MONDAY_REPORT_CORS_ORIGINS"] = origins_env
    return app_main.cors_allowed_origins()


def _preflight_allows(allow_origins: list[str], origin: str) -> str | None:
    """Return the Access-Control-Allow-Origin a real CORS preflight would emit."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/probe")
    def _probe() -> dict:
        return {"ok": True}

    client = TestClient(app)
    resp = client.options(
        "/probe",
        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
    )
    return resp.headers.get("access-control-allow-origin")


ISO = "http://127.0.0.1:5200"
DEV = "http://127.0.0.1:5173"
EVIL = "https://evil.example.com"


def main() -> int:
    # --- resolver matrix --------------------------------------------------- #
    demo_unset = _resolve("demo", None)
    record("01 demo mode with no configured origins falls back to the :5173 dev origins",
           demo_unset == [DEV, "http://localhost:5173"], {"origins": demo_unset})

    demo_iso = _resolve("demo", ISO)
    record("02 an explicit allowlist wins in demo mode (only the configured origin, no :5173)",
           demo_iso == [ISO], {"origins": demo_iso})

    client_unset = _resolve("client", None)
    record("03 protected client mode with no configured origins FAILS CLOSED (empty allowlist)",
           client_unset == [], {"origins": client_unset})

    client_iso = _resolve("client", ISO)
    record("04 an explicit allowlist wins in protected mode (only the configured origin)",
           client_iso == [ISO], {"origins": client_iso})

    multi = _resolve("client", " http://a:1 , http://b:2 ,")
    record("05 the allowlist is comma-separated, stripped, empties dropped",
           multi == ["http://a:1", "http://b:2"], {"origins": multi})

    record("06 no resolved allowlist ever contains a wildcard",
           all("*" not in o for o in (demo_unset + demo_iso + client_unset + client_iso + multi)),
           True)

    # --- behavioural preflight --------------------------------------------- #
    # Isolated origin allowed; unrelated origin refused; :5173 refused when the
    # allowlist is exactly the isolated origin.
    record("07 preflight ECHOES the configured isolated origin",
           _preflight_allows([ISO], ISO) == ISO, {"acao": _preflight_allows([ISO], ISO)})
    record("08 preflight REFUSES an unrelated origin against an isolated allowlist",
           _preflight_allows([ISO], EVIL) not in (EVIL, "*"),
           {"acao": _preflight_allows([ISO], EVIL)})
    record("09 preflight REFUSES :5173 when only the isolated origin is allowed",
           _preflight_allows([ISO], DEV) not in (DEV, "*"),
           {"acao": _preflight_allows([ISO], DEV)})
    record("10 an empty (fail-closed) allowlist refuses every origin",
           _preflight_allows([], ISO) not in (ISO, "*") and _preflight_allows([], EVIL) not in (EVIL, "*"),
           {"iso": _preflight_allows([], ISO), "evil": _preflight_allows([], EVIL)})
    record("11 a credentialed allowlist never emits a wildcard ACAO",
           _preflight_allows([ISO], ISO) != "*", {"acao": _preflight_allows([ISO], ISO)})

    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"guard": "cors_origin_guard", "checks": len(checks),
                      "failed": len(failed)}, indent=2))
    if failed:
        print(f"\nCORS origin guard FAILED: {len(failed)} failing check(s).")
        return 1
    print(f"\nCORS origin guard passed: {len(passed)} check(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
