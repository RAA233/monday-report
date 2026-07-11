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

CLIENT_API_KEY = "infrastructure-readiness-key-012345"
CLIENT_HEADERS = {"X-Monday-Report-Key": CLIENT_API_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-infra-readiness-") as tmp:
        tmp_root = Path(tmp)
        with local_ollama_server() as ollama_url:
            configure_guard_env(tmp_root, ollama_url)

            from backend.app.main import app
            from backend.app.store import store

            client = TestClient(app)
            readiness = client.get("/readiness/client-data").json()
            postgres_check = readiness_check(readiness, "postgres_repository")
            redis_check = readiness_check(readiness, "redis_queue")
            checks.append(
                assert_check(
                    "Client readiness remains blocked by inactive adapters",
                    readiness.get("ready") is False
                    and readiness.get("status") == "not_ready"
                    and postgres_check.get("status") == "fail"
                    and redis_check.get("status") == "fail",
                    {
                        "ready": readiness.get("ready"),
                        "postgres": postgres_check,
                        "redis": redis_check,
                    },
                )
            )
            checks.append(
                assert_check(
                    "Configured URLs do not certify infrastructure",
                    "active adapter is 'local_json'" in postgres_check.get("detail", "")
                    and "active worker is 'inline_worker'" in redis_check.get("detail", ""),
                    {"postgres": postgres_check.get("detail"), "redis": redis_check.get("detail")},
                )
            )

            workspace = next(iter(store.workspaces.values()))
            blocked_chat = client.post(
                "/chat/messages",
                json={"workspace_id": str(workspace.id), "content": "Generate Monday Report", "filters": {}},
                headers=CLIENT_HEADERS,
            )
            checks.append(
                assert_check(
                    "Client operation blocked while adapters inactive",
                    blocked_chat.status_code == 423,
                    blocked_chat.text,
                )
            )

            store.refresh()
            blocked_events = [
                event for event in store.audit_logs if event.action == "client_data.operation_blocked"
            ]
            latest_metadata = blocked_events[-1].metadata if blocked_events else {}
            blocking_checks = set(latest_metadata.get("blocking_checks", []))
            checks.append(
                assert_check(
                    "Inactive adapters included in block audit",
                    {"postgres_repository", "redis_queue"}.issubset(blocking_checks),
                    latest_metadata,
                )
            )

            integrity = store.audit_integrity_status()
            checks.append(
                assert_check(
                    "Infrastructure readiness audit chain sealed",
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
    os.environ["MONDAY_REPORT_SIGNING_SECRET"] = "infra-readiness-secret-0123456789abcdef"
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
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Infrastructure Readiness Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "infrastructure-readiness-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Infrastructure Readiness Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client infrastructure readiness guard"
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


def readiness_check(payload: dict, check_id: str) -> dict:
    for check in payload.get("checks", []):
        if check.get("id") == check_id:
            return check
    return {}


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
