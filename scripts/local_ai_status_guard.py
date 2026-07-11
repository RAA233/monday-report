from __future__ import annotations

import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-local-ai-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app

        client = TestClient(app)
        os.environ["MONDAY_REPORT_LOCAL_LLM_RUNTIME"] = "none"
        unconfigured = client.get("/local-ai/status")
        checks.append(
            assert_check(
                "Local AI status can be disabled",
                unconfigured.status_code == 200
                and unconfigured.json().get("runtime") == "unconfigured"
                and unconfigured.json().get("hosted_fallback_enabled") is False,
                response_detail(unconfigured),
            )
        )

        os.environ["MONDAY_REPORT_LOCAL_LLM_RUNTIME"] = "ollama"
        os.environ["OLLAMA_HOST"] = "http://127.0.0.1:9"
        os.environ.pop("MONDAY_REPORT_LOCAL_LLM_MODEL", None)
        configured = client.get("/local-ai/status")
        payload = configured.json()
        checks.append(
            assert_check(
                "Local AI defaults to Gemma 4 E2B offline",
                configured.status_code == 200
                and payload.get("runtime") == "ollama"
                and payload.get("configured") is True
                and payload.get("reachable") is False
                and payload.get("model") == "gemma4:e2b"
                and payload.get("model_available") is False,
                response_detail(configured),
            )
        )

        server = start_fake_ollama_server()
        try:
            os.environ["OLLAMA_HOST"] = f"http://127.0.0.1:{server.server_port}"
            available = client.get("/local-ai/status")
            available_payload = available.json()
            checks.append(
                assert_check(
                    "Local AI verifies pinned Gemma model availability",
                    available.status_code == 200
                    and available_payload.get("runtime") == "ollama"
                    and available_payload.get("reachable") is True
                    and available_payload.get("model") == "gemma4:e2b"
                    and available_payload.get("model_available") is True,
                    response_detail(available),
                )
            )
        finally:
            server.shutdown()
            server.server_close()

        readiness = client.get("/readiness/client-data")
        local_check = next(
            (check for check in readiness.json().get("checks", []) if check.get("id") == "local_llm_runtime"),
            {},
        )
        checks.append(
            assert_check(
                "Readiness reflects local AI offline",
                readiness.status_code == 200 and local_check.get("status") == "warn",
                local_check,
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ.pop("MONDAY_REPORT_LOCAL_LLM_RUNTIME", None)
    os.environ.pop("OLLAMA_HOST", None)
    os.environ.pop("LM_STUDIO_BASE_URL", None)
    os.environ.pop("MONDAY_REPORT_LOCAL_LLM_MODEL", None)
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Local AI Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "local-ai-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Local AI Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client local AI guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def start_fake_ollama_server() -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            if self.path != "/api/tags":
                self.send_response(404)
                self.end_headers()
                return
            payload = b'{"models":[{"name":"gemma4:e2b"},{"name":"other-model:latest"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - matches stdlib signature
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return f"HTTP {response.status_code}"


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
