from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from phase_audit import build_zip_fixture


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "output" / "ga-readiness" / "monday_report_ga.env"
API_BASE = os.getenv("MONDAY_REPORT_API_BASE", "http://127.0.0.1:8000")
WEB_BASE = os.getenv("MONDAY_REPORT_WEB_BASE", "http://127.0.0.1:5173")


def main() -> int:
    load_env_file(ENV_FILE)
    checks: list[dict[str, object]] = []
    try:
        checks.extend(run_guard())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        checks.append({"name": "Client function HTTP exception", "ok": False, "detail": f"HTTP {exc.code}: {detail[:500]}"})
    except Exception as exc:  # noqa: BLE001 - guard must report any failing boundary.
        checks.append({"name": "Client function exception", "ok": False, "detail": repr(exc)})

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")

    summary_path = ROOT / "output" / "qa" / "client_mode_function_guard.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({"status": "fail" if failed else "pass", "checks": checks}, indent=2), encoding="utf-8")

    if failed:
        print(f"\nClient-mode function guard failed with {len(failed)} failing check(s).")
        return 1

    print(f"\nClient-mode function guard passed. Summary: {summary_path}")
    return 0


def run_guard() -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    health = request_json("GET", "/health", auth=False)
    readiness = request_json("GET", "/readiness/client-data", auth=False)
    backends = request_json("GET", "/runtime/backends", auth=False)
    local_ai = request_json("GET", "/local-ai/status", auth=False)

    checks.append(assert_check("API health", health.get("status") == "ok", health))
    checks.append(assert_check("Client readiness", readiness.get("ready") is True and readiness.get("status") == "ready", readiness.get("status")))
    checks.append(assert_check("PostgreSQL repository", backends.get("active_repository_backend") == "postgres" and backends.get("repository_ready") is True, backends))
    checks.append(assert_check("Redis worker queue", backends.get("active_queue_backend") == "redis" and backends.get("queue_ready") is True, backends))
    checks.append(assert_check("Local AI default", local_ai.get("runtime") == "ollama" and local_ai.get("model") == "gemma4:e2b" and local_ai.get("model_available") is True, local_ai.get("detail")))
    checks.append(assert_check("Frontend reachable", http_status(WEB_BASE) == 200, WEB_BASE))

    session = request_json("GET", "/auth/session")
    workspace = request_json(
        "POST",
        "/workspaces",
        {
            "name": f"Client QA workspace {uuid4().hex[:8]}",
            "asset": "Client QA Rig",
            "campaign": "Client-mode full function guard",
            "period_start": "2026-07-06",
            "period_end": "2026-07-12",
        },
    )
    workspace_id = workspace["id"]
    checks.append(assert_check("Authenticated session", session.get("tenant", {}).get("name") == "Monday Report Tenant", session.get("tenant", {}).get("name")))
    checks.append(assert_check("Workspace create", bool(workspace_id), workspace_id))

    content = build_zip_fixture()
    upload = request_multipart(
        "/uploads/direct",
        {
            "workspace_id": workspace_id,
            "file_name": "qa/client_mode_function_package.zip",
            "source_type": "zip",
        },
        "file",
        "client_mode_function_package.zip",
        content,
        "application/zip",
    )
    upload_id = upload["upload"]["id"]
    checks.append(assert_check("Direct ZIP upload", upload["file"]["sha256"] == sha256(content).hexdigest(), upload_id))
    checks.append(validate_malware_block(workspace_id))

    worker_env = os.environ.copy()
    worker_env["MONDAY_REPORT_WORKER_UPLOAD_ID"] = upload_id
    worker = subprocess.run(
        [sys.executable, "-m", "backend.app.worker"],
        cwd=ROOT,
        env=worker_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    worker_detail = worker.stdout.strip() or worker.stderr.strip() or f"returncode={worker.returncode}"
    checks.append(assert_check("Worker run", worker.returncode == 0 and "Processed" in worker_detail, worker_detail))

    jobs = request_json("GET", f"/processing-jobs?upload_id={upload_id}")
    files = request_json("GET", f"/uploads/{upload_id}/files")
    documents = [item for item in request_json("GET", f"/documents?workspace_id={workspace_id}") if item.get("upload_id") == upload_id]
    chunks = []
    for document in documents:
        chunks.extend(request_json("GET", f"/documents/{document['id']}/chunks"))
    failures = request_json("GET", f"/failures?workspace_id={workspace_id}")
    matching_failures = [
        failure
        for failure in failures
        if any(citation.get("locator", {}).get("upload_id") == upload_id for citation in failure.get("citations", []))
    ]
    parser_names = {item.get("parser_name") for item in documents}

    checks.append(assert_check("Processing jobs complete", jobs and all(item.get("status") == "complete" for item in jobs), f"{len(jobs)} job(s)"))
    checks.append(assert_check("Upload files listed", len(files) >= 7, f"{len(files)} file(s)"))
    checks.append(assert_check("Documents parsed", len(documents) >= 5, f"{len(documents)} document(s)"))
    checks.append(
        assert_check(
            "Parser coverage",
            {"csv_text_v1", "xlsx_text_v1", "docx_text_v1", "email_text_v1", "pdf_text_v1", "ocr_route_v1"}.issubset(parser_names),
            ", ".join(sorted(str(item) for item in parser_names)),
        )
    )
    checks.append(assert_check("Document chunks", len(chunks) >= 2, f"{len(chunks)} chunk(s)"))
    checks.append(
        assert_check(
            "Failure extraction",
            any(item.get("event_type") == "MWD signal loss" for item in matching_failures),
            f"{len(matching_failures)} matching failure(s)",
        )
    )

    downloadable_files = [item for item in files if item.get("malware_status") == "clean" and str(item.get("storage_uri", "")).startswith("object://")][:2]
    source_downloads = [validate_signed_upload_file_download(item) for item in downloadable_files]
    checks.append(assert_check("Signed source downloads", len(source_downloads) == 2 and all(item["ok"] for item in source_downloads), "; ".join(item["detail"] for item in source_downloads)))

    validation_tasks = request_json("GET", "/validation-tasks")
    failure_ids = {failure["id"] for failure in matching_failures}
    open_tasks = [task for task in validation_tasks if task.get("target_id") in failure_ids and task.get("status") == "open"]
    checks.append(assert_check("Validation tasks created", len(open_tasks) >= 1, f"{len(open_tasks)} open task(s)"))

    blocked_report = request_json("POST", "/monday-reports", {"workspace_id": workspace_id, "period_start": "2026-07-06", "period_end": "2026-07-12"})
    blocked_export = request_json_expect_error("POST", f"/monday-reports/{blocked_report['id']}/exports/pdf", 409)
    checks.append(assert_check("Official export gate", blocked_export["ok"] and "unresolved validation" in str(blocked_export["detail"]).lower(), blocked_export["detail"]))

    updated = [
        request_json(
            "PATCH",
            f"/validation-tasks/{task['id']}",
            {"status": "validated", "resolution_note": "Client-mode QA accepted cited extraction for export testing."},
        )
        for task in open_tasks
    ]
    checks.append(assert_check("Validation updates", updated and all(task.get("status") == "validated" for task in updated), f"{len(updated)} task(s)"))

    report = request_json("POST", "/monday-reports", {"workspace_id": workspace_id, "period_start": "2026-07-06", "period_end": "2026-07-12"})
    report_id = report["id"]
    checks.append(assert_check("Monday Report create", bool(report.get("report_json", {}).get("failure_summary")), report_id))

    exports = [request_json("POST", f"/monday-reports/{report_id}/exports/{fmt}") for fmt in ["json", "csv", "html", "pdf", "xlsx"]]
    checks.append(
        assert_check(
            "Report exports",
            {item.get("format") for item in exports} == {"json", "csv", "html", "pdf", "xlsx"} and all(item.get("byte_size", 0) > 0 and len(item.get("sha256", "")) == 64 for item in exports),
            ", ".join(str(item.get("format")) for item in exports),
        )
    )
    export_downloads = [validate_signed_export_download(item) for item in exports]
    checks.append(assert_check("Signed export downloads", all(item["ok"] for item in export_downloads), "; ".join(f"{item['format']}={item['detail']}" for item in export_downloads)))

    chat = request_json(
        "POST",
        "/chat/messages",
        {
            "workspace_id": workspace_id,
            "content": "Generate this week's Monday Report executive summary.",
            "filters": {},
        },
    )
    checks.append(assert_check("Chat answer and actions", "extracted failures" in chat.get("answer", "") and "monday_report_pdf" in chat.get("export_actions", []), chat.get("answer", "")))

    dashboard = request_json("GET", f"/dashboards/summary?workspace_id={workspace_id}")
    checks.append(assert_check("Dashboard summary", dashboard.get("total_failures", 0) >= 1 and dashboard.get("validation_backlog", 0) >= 0, dashboard))

    integrity = request_json("GET", "/audit-logs/integrity", auth=False)
    checks.append(assert_check("Audit integrity", integrity.get("broken_events") == 0 and integrity.get("status") in {"sealed", "empty"}, integrity))

    audit_logs = request_json("GET", "/audit-logs?limit=200")
    actions = {item.get("action") for item in audit_logs}
    expected_actions = {
        "upload.create",
        "upload.blocked",
        "upload_file.signed_url",
        "upload_file.download",
        "archive.expand_complete",
        "document.parse_complete",
        "failure.extract_complete",
        "validation_task.update",
        "monday_report.create",
        "monday_report.export_blocked",
        "monday_report.export",
        "report_export.signed_url",
        "report_export.download",
        "chat.message",
    }
    checks.append(assert_check("Audit coverage", expected_actions.issubset(actions), ", ".join(sorted(expected_actions & actions))))

    return checks


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def api_key() -> str:
    return os.environ.get("MONDAY_REPORT_API_KEY", "")


def request_json(method: str, path: str, body: dict[str, object] | None = None, auth: bool = True) -> object:
    data = None
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth:
        headers["X-Monday-Report-Key"] = api_key()
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(f"{API_BASE}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def request_json_expect_error(method: str, path: str, expected_status: int, body: dict[str, object] | None = None) -> dict[str, object]:
    try:
        result = request_json(method, path, body)
        return {"ok": False, "status": 200, "detail": result}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"ok": exc.code == expected_status, "status": exc.code, "detail": detail}


def request_multipart(
    path: str,
    fields: dict[str, object],
    file_field: str,
    file_name: str,
    file_content: bytes,
    mime_type: str,
) -> object:
    boundary = f"----MondayReportClientGuard{uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(f"{value}\r\n".encode("utf-8"))
    chunks.append(f"--{boundary}\r\n".encode("utf-8"))
    chunks.append(
        (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name.replace(chr(34), "")}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(file_content)
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=b"".join(chunks),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "X-Monday-Report-Key": api_key()},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def validate_malware_block(workspace_id: str) -> dict[str, object]:
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        request_multipart(
            "/uploads/direct",
            {"workspace_id": workspace_id, "file_name": "qa/eicar_test.txt", "source_type": "files"},
            "file",
            "eicar_test.txt",
            eicar_content,
            "text/plain",
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return assert_check("Malware upload blocked", exc.code == 422 and "malware" in detail.lower(), f"HTTP {exc.code}: {detail}")
    return assert_check("Malware upload blocked", False, "upload unexpectedly accepted")


def validate_signed_upload_file_download(file_record: dict[str, object]) -> dict[str, object]:
    signed = request_json("POST", f"/upload-files/{file_record['id']}/signed-url")
    data = download_signed(str(signed.get("url", "")), f"/signed/upload-files/{file_record['id']}")
    digest = sha256(data).hexdigest()
    ok = digest == file_record.get("sha256") and len(data) == file_record.get("byte_size")
    return {"ok": ok, "detail": str(file_record.get("original_path", "source")) if ok else "digest mismatch"}


def validate_signed_export_download(export: dict[str, object]) -> dict[str, object]:
    fmt = str(export.get("format"))
    signed = request_json("POST", f"/report-exports/{export['id']}/signed-url")
    data = download_signed(str(signed.get("url", "")), f"/signed/report-exports/{export['id']}")
    digest = sha256(data).hexdigest()
    ok = digest == export.get("sha256") and len(data) == export.get("byte_size") and validate_export_bytes(fmt, data)
    return {"format": fmt, "ok": ok, "detail": "download ok" if ok else "signature or format mismatch"}


def download_signed(url: str, expected_path: str) -> bytes:
    parsed = urlparse(url)
    if parsed.path != expected_path or "token=" not in parsed.query:
        raise ValueError(f"Unexpected signed URL shape: {url}")
    with urllib.request.urlopen(url, timeout=20) as response:
        return response.read()


def validate_export_bytes(fmt: str, data: bytes) -> bool:
    if fmt == "json":
        json.loads(data.decode("utf-8"))
        return True
    if fmt == "csv":
        return data.decode("utf-8").startswith("event_type,severity,company")
    if fmt == "html":
        return data.startswith(b"<!doctype html>") and b"<table>" in data
    if fmt == "pdf":
        return data.startswith(b"%PDF") and data.rstrip().endswith(b"%%EOF")
    if fmt == "xlsx":
        with zipfile.ZipFile(Path(write_temp_export(data, "xlsx"))) as workbook:
            return {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"}.issubset(set(workbook.namelist()))
    return False


def write_temp_export(data: bytes, suffix: str) -> Path:
    path = ROOT / "output" / "qa" / f"download_check_{uuid4().hex}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def http_status(url: str) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status
    except urllib.error.URLError:
        return None


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": bool(ok), "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
