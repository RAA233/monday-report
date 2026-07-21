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

from phase_audit import API_BASE, ROOT, WEB_BASE, build_zip_fixture, create_test_workspace, request_json, request_multipart


def main() -> int:
    checks: list[dict[str, object]] = []
    # Hard verification-isolation gate (Part E): fail closed before any request.
    from verification_isolation import VerificationIsolationError, assert_isolated

    try:
        assert_isolated(context="e2e_mvp", api_base=API_BASE, web_base=WEB_BASE)
    except VerificationIsolationError as exc:
        print(f"FAIL: verification isolation - {exc}")
        return 2
    try:
        checks.extend(run_e2e())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        checks.append(
            {
                "name": "E2E HTTP exception",
                "ok": False,
                "detail": f"HTTP {exc.code} {exc.url}: {detail[:500]}",
            }
        )
    except Exception as exc:  # noqa: BLE001 - E2E output should capture any failing boundary.
        checks.append({"name": "E2E exception", "ok": False, "detail": repr(exc)})

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")

    if failed:
        print(f"\nE2E failed with {len(failed)} failing check(s).")
        return 1

    print("\nE2E passed.")
    return 0


def run_e2e() -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    health = request_json("GET", f"{API_BASE}/health")
    checks.append(assert_check("API health", health.get("status") == "ok", str(health)))

    frontend_status = http_status(WEB_BASE)
    checks.append(assert_check("Frontend reachable", frontend_status == 200, f"HTTP {frontend_status}"))

    workspace = create_test_workspace("E2E workspace")
    workspace_id = workspace["id"]
    checks.append(assert_check("Isolated test workspace created", bool(workspace_id), workspace_id))
    content = build_zip_fixture()
    upload = request_multipart(
        f"{API_BASE}/uploads/direct",
        {
            "workspace_id": workspace_id,
            "file_name": "e2e/monday_report_package.zip",
            "source_type": "zip",
        },
        "file",
        "monday_report_package.zip",
        content,
        "application/zip",
    )
    upload_id = upload["upload"]["id"]
    checks.append(assert_check("ZIP upload created", upload["file"]["byte_size"] == len(content), upload_id))
    checks.append(validate_blocked_upload(workspace_id))

    worker_env = os.environ.copy()
    worker_env["MONDAY_REPORT_WORKER_UPLOAD_ID"] = upload_id
    worker = subprocess.run(
        [sys.executable, "-m", "backend.app.worker"],
        cwd=ROOT,
        env=worker_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    worker_detail = worker.stdout.strip() or worker.stderr.strip() or f"returncode={worker.returncode}"
    checks.append(assert_check("Worker completed", worker.returncode == 0, worker_detail))

    files = request_json("GET", f"{API_BASE}/uploads/{upload_id}/files")
    documents = [
        document
        for document in request_json("GET", f"{API_BASE}/documents?workspace_id={workspace_id}")
        if document.get("upload_id") == upload_id
    ]
    parser_names = {document.get("parser_name") for document in documents}
    chunks = []
    for document in documents:
        chunks.extend(request_json("GET", f"{API_BASE}/documents/{document['id']}/chunks"))
    checks.append(assert_check("ZIP child files", len(files) >= 7, f"{len(files)} file(s)"))
    downloadable_files = [
        item
        for item in files
        if item.get("malware_status") == "clean" and str(item.get("storage_uri", "")).startswith("object://")
    ][:2]
    signed_file_downloads = [validate_signed_upload_file_download(item) for item in downloadable_files]
    checks.append(
        assert_check(
            "Signed source downloads",
            len(signed_file_downloads) >= 2 and all(item["ok"] for item in signed_file_downloads),
            "; ".join(f"{item['path']}={item['detail']}" for item in signed_file_downloads),
        )
    )
    checks.append(assert_check("Parsed documents", len(documents) >= 5, f"{len(documents)} document(s)"))
    checks.append(
        assert_check(
            "Office, PDF, and email parsers",
            {"csv_text_v1", "xlsx_text_v1", "docx_text_v1", "email_text_v1", "pdf_text_v1", "ocr_route_v1"}.issubset(
                parser_names
            ),
            ", ".join(sorted(str(item) for item in parser_names)),
        )
    )
    checks.append(assert_check("Parsed chunks", len(chunks) >= 2, f"{len(chunks)} chunk(s)"))

    failures = request_json("GET", f"{API_BASE}/failures?workspace_id={workspace_id}")
    matching_failures = [
        failure
        for failure in failures
        if any(citation.get("locator", {}).get("upload_id") == upload_id for citation in failure.get("citations", []))
    ]
    checks.append(
        assert_check(
            "Failure extracted",
            any(failure.get("event_type") == "MWD signal loss" for failure in matching_failures),
            f"{len(matching_failures)} matching failure(s)",
        )
    )
    if not matching_failures:
        return checks
    failure = matching_failures[0]

    validation_tasks = request_json("GET", f"{API_BASE}/validation-tasks")
    matching_tasks = [task for task in validation_tasks if task.get("target_id") == failure["id"]]
    checks.append(assert_check("Validation task created", len(matching_tasks) == 1, f"{len(matching_tasks)} task(s)"))

    blocked_report = request_json(
        "POST",
        f"{API_BASE}/monday-reports",
        {
            "workspace_id": workspace_id,
            "period_start": "2026-07-06",
            "period_end": "2026-07-12",
        },
    )
    blocked_export = request_json_expect_error(
        "POST",
        f"{API_BASE}/monday-reports/{blocked_report['id']}/exports/pdf",
        409,
    )
    checks.append(
        assert_check(
            "Report export validation gate",
            blocked_export["ok"] and "unresolved validation" in str(blocked_export["detail"]).lower(),
            f"HTTP {blocked_export['status']}: {blocked_export['detail']}",
        )
    )

    failure_ids = {item["id"] for item in failures}
    open_workspace_tasks = [
        task
        for task in validation_tasks
        if task.get("target_id") in failure_ids and task.get("status") == "open"
    ]
    updated_tasks = [
        request_json(
            "PATCH",
            f"{API_BASE}/validation-tasks/{task['id']}",
            {
                "status": "validated",
                "resolution_note": "E2E accepted cited failure extraction for official export.",
            },
        )
        for task in open_workspace_tasks
    ]
    checks.append(
        assert_check(
            "Validation updates",
            len(updated_tasks) >= 1 and all(task.get("status") == "validated" for task in updated_tasks),
            f"{len(updated_tasks)} task(s) updated",
        )
    )

    refreshed_failures = [
        item
        for item in request_json("GET", f"{API_BASE}/failures?workspace_id={workspace_id}")
        if item.get("id") == failure["id"]
    ]
    if not refreshed_failures:
        checks.append(assert_check("Failure validation status", False, "failure disappeared after validation update"))
        return checks
    refreshed_failure = refreshed_failures[0]
    checks.append(
        assert_check(
            "Failure validation status",
            refreshed_failure.get("validation_status") == "validated",
            refreshed_failure.get("validation_status"),
        )
    )

    report = request_json(
        "POST",
        f"{API_BASE}/monday-reports",
        {
            "workspace_id": workspace_id,
            "period_start": "2026-07-06",
            "period_end": "2026-07-12",
        },
    )
    report_id = report["id"]
    checks.append(assert_check("Report created", report["report_json"]["failure_summary"], report_id))

    exports = [
        request_json("POST", f"{API_BASE}/monday-reports/{report_id}/exports/{export_format}")
        for export_format in ["json", "csv", "html", "pdf", "xlsx"]
    ]
    export_formats = {item["format"] for item in exports}
    checks.append(
        assert_check(
            "Report exports",
            export_formats == {"json", "csv", "html", "pdf", "xlsx"}
            and all(item.get("byte_size", 0) > 0 and len(item.get("sha256", "")) == 64 for item in exports),
            ", ".join(item["format"] for item in exports),
        )
    )
    artifact_checks = [validate_export_artifact(item) for item in exports]
    checks.append(
        assert_check(
            "Export artifact signatures",
            all(item["ok"] for item in artifact_checks),
            "; ".join(f"{item['format']}={item['detail']}" for item in artifact_checks),
        )
    )
    signed_downloads = [validate_signed_download(item) for item in exports]
    checks.append(
        assert_check(
            "Signed export downloads",
            all(item["ok"] for item in signed_downloads),
            "; ".join(f"{item['format']}={item['detail']}" for item in signed_downloads),
        )
    )

    chat = request_json(
        "POST",
        f"{API_BASE}/chat/messages",
        {
            "workspace_id": workspace_id,
            "content": "Generate this week's Monday Report executive summary.",
            "filters": {},
        },
    )
    checks.append(
        assert_check(
            "Chat report answer",
            "extracted failures" in chat.get("answer", "")
            and "monday_report_pdf" in chat.get("export_actions", [])
            and "monday_report_xlsx" in chat.get("export_actions", []),
            chat.get("answer", ""),
        )
    )

    audit_logs = request_json("GET", f"{API_BASE}/audit-logs?limit=120")
    audit_actions = {event.get("action") for event in audit_logs}
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
    checks.append(
        assert_check(
            "Audit coverage",
            expected_actions.issubset(audit_actions),
            ", ".join(sorted(expected_actions & audit_actions)),
        )
    )

    return checks


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


def http_status(url: str) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status
    except urllib.error.URLError:
        return None


def request_json_expect_error(
    method: str,
    url: str,
    expected_status: int,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    api_key = os.getenv("MONDAY_REPORT_API_KEY", "")
    if api_key:
        headers["X-Monday-Report-Key"] = api_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            detail = response.read().decode("utf-8", errors="replace")
            return {"ok": False, "status": response.status, "detail": detail}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"ok": exc.code == expected_status, "status": exc.code, "detail": detail}


def validate_export_artifact(export: dict[str, object]) -> dict[str, object]:
    export_format = str(export.get("format", ""))
    try:
        path = export_file_path(str(export.get("storage_uri", "")))
        data = path.read_bytes()
        if export_format == "json":
            json.loads(data.decode("utf-8"))
            return {"format": export_format, "ok": True, "detail": "valid JSON"}
        if export_format == "csv":
            ok = data.decode("utf-8").startswith("event_type,severity,company")
            return {"format": export_format, "ok": ok, "detail": "header ok" if ok else "missing header"}
        if export_format == "html":
            ok = data.startswith(b"<!doctype html>") and b"<table>" in data
            return {"format": export_format, "ok": ok, "detail": "html ok" if ok else "missing table"}
        if export_format == "pdf":
            ok = data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
            return {"format": export_format, "ok": ok, "detail": "pdf ok" if ok else "bad pdf signature"}
        if export_format == "xlsx":
            with zipfile.ZipFile(path) as workbook:
                names = set(workbook.namelist())
            ok = {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"}.issubset(names)
            return {"format": export_format, "ok": ok, "detail": "xlsx ok" if ok else "missing workbook parts"}
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        return {"format": export_format, "ok": False, "detail": repr(exc)}

    return {"format": export_format, "ok": False, "detail": "unknown format"}


def export_file_path(storage_uri: str) -> Path:
    if not storage_uri.startswith("export://"):
        raise ValueError(f"Unsupported export URI: {storage_uri}")
    root = Path(os.getenv("MONDAY_REPORT_EXPORT_ROOT", str(ROOT / ".local_data" / "exports"))).resolve()
    path = root
    for part in [item for item in storage_uri.removeprefix("export://").split("/") if item]:
        path /= part
    resolved = path.resolve()
    resolved.relative_to(root)
    return resolved


def validate_signed_download(export: dict[str, object]) -> dict[str, object]:
    export_format = str(export.get("format", ""))
    try:
        signed = request_json("POST", f"{API_BASE}/report-exports/{export['id']}/signed-url")
        url = str(signed.get("url", ""))
        parsed = urlparse(url)
        if parsed.path != f"/signed/report-exports/{export['id']}" or "token=" not in parsed.query:
            return {"format": export_format, "ok": False, "detail": "bad signed URL shape"}
        with urllib.request.urlopen(url, timeout=5) as response:
            data = response.read()
        digest = sha256(data).hexdigest()
        ok = digest == export.get("sha256") and len(data) == export.get("byte_size")
        return {"format": export_format, "ok": ok, "detail": "download ok" if ok else "digest mismatch"}
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        return {"format": export_format, "ok": False, "detail": repr(exc)}


def validate_signed_upload_file_download(file_record: dict[str, object]) -> dict[str, object]:
    original_path = str(file_record.get("original_path", "unknown"))
    try:
        signed = request_json("POST", f"{API_BASE}/upload-files/{file_record['id']}/signed-url")
        url = str(signed.get("url", ""))
        parsed = urlparse(url)
        if parsed.path != f"/signed/upload-files/{file_record['id']}" or "token=" not in parsed.query:
            return {"path": original_path, "ok": False, "detail": "bad signed URL shape"}
        with urllib.request.urlopen(url, timeout=5) as response:
            data = response.read()
        digest = sha256(data).hexdigest()
        ok = digest == file_record.get("sha256") and len(data) == file_record.get("byte_size")
        return {"path": original_path, "ok": ok, "detail": "download ok" if ok else "digest mismatch"}
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        return {"path": original_path, "ok": False, "detail": repr(exc)}


def validate_blocked_upload(workspace_id: str) -> dict[str, object]:
    eicar_content = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    try:
        request_multipart(
            f"{API_BASE}/uploads/direct",
            {
                "workspace_id": workspace_id,
                "file_name": "e2e/eicar_test.txt",
                "source_type": "files",
            },
            "file",
            "eicar_test.txt",
            eicar_content,
            "text/plain",
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return assert_check(
            "Malware upload blocked",
            exc.code == 422 and "malware" in detail.lower(),
            f"HTTP {exc.code}: {detail}",
        )
    except urllib.error.URLError as exc:
        return assert_check("Malware upload blocked", False, repr(exc))
    return assert_check("Malware upload blocked", False, "upload unexpectedly accepted")


if __name__ == "__main__":
    sys.exit(main())
