from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLIENT_API_KEY = "runtime-backend-key-0123456789"
CLIENT_HEADERS = {"X-Monday-Report-Key": CLIENT_API_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-runtime-backends-") as tmp:
        with local_ollama_server() as ollama_url:
            configure_guard_env(Path(tmp), ollama_url)

            from backend.app.main import app
            from backend.app.store import store

            client = TestClient(app)
            unauthenticated_status = client.get("/runtime/backends")
            payload = unauthenticated_status.json()
            checks.append(
                assert_check(
                    "Runtime backend status is operator-readable in client mode",
                    unauthenticated_status.status_code == 200,
                    response_detail(unauthenticated_status),
                )
            )

            blocked_session = client.get("/auth/session")
            checks.append(
                assert_check(
                    "Client auth still protects non-exempt endpoints",
                    blocked_session.status_code == 401,
                    blocked_session.text,
                )
            )

            checks.append(
                assert_check(
                    "Configured URLs do not change active adapters",
                    payload.get("requested_repository_backend") == "postgres"
                    and payload.get("active_repository_backend") == "local_json"
                    and payload.get("database_url_configured") is True
                    and payload.get("repository_ready") is False
                    and payload.get("requested_queue_backend") == "redis"
                    and payload.get("active_queue_backend") == "inline_worker"
                    and payload.get("redis_url_configured") is True
                    and payload.get("queue_ready") is False,
                    payload,
                )
            )

            readiness = client.get("/readiness/client-data").json()
            readiness_blockers = {
                check.get("id") for check in readiness.get("checks", []) if check.get("status") == "fail"
            }
            runtime_blockers = set(payload.get("blocking_checks", []))
            checks.append(
                assert_check(
                    "Runtime blockers mirror readiness blockers",
                    payload.get("client_data_ready") is False
                    and {"postgres_repository", "redis_queue"}.issubset(runtime_blockers)
                    and runtime_blockers == readiness_blockers,
                    {"runtime": sorted(runtime_blockers), "readiness": sorted(readiness_blockers)},
                )
            )

            authorized_status = client.get("/runtime/backends", headers=CLIENT_HEADERS)
            checks.append(
                assert_check(
                    "Runtime backend status accepts authorized requests",
                    authorized_status.status_code == 200 and authorized_status.json() == payload,
                    response_detail(authorized_status),
                )
            )

            integrity = store.audit_integrity_status()
            checks.append(
                assert_check(
                    "Runtime backend status leaves audit chain sealed",
                    integrity.status == "sealed" and integrity.broken_events == 0,
                    integrity.model_dump(mode="json"),
                )
            )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path, ollama_url: str) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    os.environ["MONDAY_REPORT_API_KEY"] = CLIENT_API_KEY
    os.environ["MONDAY_REPORT_SIGNING_SECRET"] = "runtime-backend-secret-0123456789abcdef"
    os.environ["MONDAY_REPORT_MAX_UPLOAD_BYTES"] = "104857600"
    os.environ["MONDAY_REPORT_MAX_ZIP_ENTRIES"] = "200"
    os.environ["MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES"] = "104857600"
    os.environ["MONDAY_REPORT_RETENTION_DAYS"] = "365"
    os.environ["MONDAY_REPORT_MALWARE_SCANNER"] = "builtin"
    os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "postgres"
    os.environ["MONDAY_REPORT_DATABASE_URL"] = "postgresql://monday_report:test@127.0.0.1:5432/monday_report"
    os.environ["MONDAY_REPORT_QUEUE_BACKEND"] = "redis"
    os.environ["MONDAY_REPORT_REDIS_URL"] = "redis://127.0.0.1:6379/0"
    os.environ["MONDAY_REPORT_LOCAL_LLM_RUNTIME"] = "ollama"
    os.environ["MONDAY_REPORT_LOCAL_LLM_MODEL"] = "llama3.1:8b"
    os.environ["OLLAMA_HOST"] = ollama_url
    os.environ["MONDAY_REPORT_PRODUCTION_PARSERS"] = "true"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Runtime Backend Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "runtime-backend-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Runtime Backend Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client runtime backend guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


class _OllamaHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if self.path != "/api/tags":
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps({"models": [{"name": "llama3.1:8b"}]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class local_ollama_server:
    def __enter__(self) -> str:
        self.server = HTTPServer(("127.0.0.1", 0), _OllamaHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return response.text


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
