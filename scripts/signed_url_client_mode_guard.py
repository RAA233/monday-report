from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLIENT_API_KEY = "signed-url-test-client-key-012345"
CLIENT_HEADERS = {"X-Monday-Report-Key": CLIENT_API_KEY}


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-signed-url-") as tmp:
        tmp_root = Path(tmp)
        configure_client_mode(tmp_root)

        from backend.app.main import app
        from backend.app.schemas import MondayReportCreate
        from backend.app.store import store

        client = TestClient(app)
        # Client mode rejects the shared key; provision a per-user admin
        # credential and authenticate with it.
        from backend.app.schemas import Role

        _admin = store.create_user("signed-url-admin@example.test", "Signed URL Admin", [Role.ADMIN])
        _cred, _token = store.create_credential(_admin.id)
        client_headers = {"X-Monday-Report-Key": _token}
        workspace = next(iter(store.workspaces.values()))
        report = store.create_monday_report(
            MondayReportCreate(
                workspace_id=workspace.id,
                period_start=date(2026, 7, 6),
                period_end=date(2026, 7, 12),
            )
        )
        export = store.export_monday_report(report.id, "json")
        checks.append(assert_check("Create report", True, str(report.id)))
        checks.append(assert_check("Create export", True, str(export.id)))

        _, file_record, _ = store.create_uploaded_file(
            workspace_id=workspace.id,
            file_name="client/source.txt",
            mime_type="text/plain",
            source_type="files",
            content=b"client source evidence",
        )

        blocked_export_url = client.post(f"/report-exports/{export.id}/signed-url", headers=client_headers)
        checks.append(
            assert_check(
                "Client mode blocks export signed URL without secret",
                blocked_export_url.status_code == 409,
                blocked_export_url.text,
            )
        )
        blocked_file_url = client.post(f"/upload-files/{file_record.id}/signed-url", headers=client_headers)
        checks.append(
            assert_check(
                "Client mode blocks source signed URL without secret",
                blocked_file_url.status_code == 409,
                blocked_file_url.text,
            )
        )

        with local_ollama_server() as ollama_url:
            configure_infrastructure_pending_client_mode(ollama_url)
            export_with_secret = client.post(f"/report-exports/{export.id}/signed-url", headers=client_headers)
            checks.append(
                assert_check(
                    "Client mode reaches readiness gate after signing secret",
                    export_with_secret.status_code == 423,
                    export_with_secret.text,
                )
            )
            source_with_secret = client.post(f"/upload-files/{file_record.id}/signed-url", headers=client_headers)
            checks.append(
                assert_check(
                    "Client source URL reaches readiness gate after signing secret",
                    source_with_secret.status_code == 423,
                    source_with_secret.text,
                )
            )

            os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
            checks.append(
                validate_signed_download(
                    client,
                    client.post(f"/report-exports/{export.id}/signed-url"),
                    b'"title": "Monday Report"',
                )
            )
            checks.append(
                validate_signed_download(
                    client,
                    client.post(f"/upload-files/{file_record.id}/signed-url"),
                    b"client source evidence",
                )
            )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_client_mode(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
    os.environ["MONDAY_REPORT_API_KEY"] = CLIENT_API_KEY
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "signed-url-guard-audit-hmac-key-0123456789ab"
    os.environ.pop("MONDAY_REPORT_SIGNING_SECRET", None)
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Signed URL Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "signed-url-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Signed URL Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client signed URL guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def configure_infrastructure_pending_client_mode(ollama_url: str) -> None:
    os.environ["MONDAY_REPORT_API_KEY"] = CLIENT_API_KEY
    os.environ["MONDAY_REPORT_SIGNING_SECRET"] = "client-mode-test-secret-0123456789abcdef"
    os.environ["MONDAY_REPORT_MAX_UPLOAD_BYTES"] = "104857600"
    os.environ["MONDAY_REPORT_MAX_ZIP_ENTRIES"] = "200"
    os.environ["MONDAY_REPORT_MAX_ZIP_UNCOMPRESSED_BYTES"] = "104857600"
    os.environ["MONDAY_REPORT_RETENTION_DAYS"] = "365"
    os.environ["MONDAY_REPORT_REPOSITORY_BACKEND"] = "postgres"
    os.environ["MONDAY_REPORT_DATABASE_URL"] = "postgresql://monday_report:test@127.0.0.1:5432/monday_report"
    os.environ["MONDAY_REPORT_QUEUE_BACKEND"] = "redis"
    os.environ["MONDAY_REPORT_REDIS_URL"] = "redis://127.0.0.1:6379/0"
    os.environ["MONDAY_REPORT_LOCAL_LLM_RUNTIME"] = "ollama"
    os.environ["MONDAY_REPORT_LOCAL_LLM_MODEL"] = "llama3.1:8b"
    os.environ["OLLAMA_HOST"] = ollama_url
    os.environ["MONDAY_REPORT_PRODUCTION_PARSERS"] = "true"
    os.environ["MONDAY_REPORT_MALWARE_SCANNER"] = "builtin"


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


def validate_signed_download(
    client: TestClient,
    signed_response,
    expected_content: bytes,
) -> dict[str, object]:
    if signed_response.status_code != 200:
        return assert_check("Signed URL with configured secret", False, signed_response.text)
    parsed = urlparse(signed_response.json()["url"])
    download = client.get(f"{parsed.path}?{parsed.query}")
    return assert_check(
        "Signed download with configured secret",
        download.status_code == 200 and expected_content in download.content,
        f"HTTP {download.status_code} bytes={len(download.content)}",
    )


def response_detail(response) -> str:
    if response.status_code >= 400:
        return response.text
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    return str(payload.get("id", f"HTTP {response.status_code}"))


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
