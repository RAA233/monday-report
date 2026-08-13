from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from urllib.parse import urlsplit
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from uuid import uuid4
from xml.sax.saxutils import escape as xml_escape


def load_env_file(path: Path, *, required: bool = False) -> int:
    if not path.exists():
        if required:
            raise FileNotFoundError(f"requested GA environment file not found: {path}")
        return 0
    loaded = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        os.environ.setdefault(key, value.strip())
        loaded += 1
    return loaded


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / "output" / "ga-readiness" / "monday_report_ga.env"
DEFAULT_API_BASE = "http://127.0.0.1:8000"
DEFAULT_WEB_BASE = "http://127.0.0.1:5173"
API_BASE = os.getenv("MONDAY_REPORT_API_BASE", DEFAULT_API_BASE)
WEB_BASE = os.getenv("MONDAY_REPORT_WEB_BASE", DEFAULT_WEB_BASE)


def refresh_runtime_configuration() -> None:
    global API_BASE, WEB_BASE
    API_BASE = os.getenv("MONDAY_REPORT_API_BASE", DEFAULT_API_BASE)
    WEB_BASE = os.getenv("MONDAY_REPORT_WEB_BASE", DEFAULT_WEB_BASE)


def resolve_ga_env_file(path: str | Path | None = None) -> Path:
    candidate = Path(path).expanduser() if path is not None else DEFAULT_ENV_FILE
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    return candidate.resolve()


def configure_ga_environment(path: str | Path | None = None) -> Path:
    env_file = resolve_ga_env_file(path)
    load_env_file(env_file, required=True)
    refresh_runtime_configuration()
    return env_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Monday Report phase audit.")
    parser.add_argument(
        "--load-ga-env",
        action="store_true",
        help="Explicitly load the default output/ga-readiness/monday_report_ga.env file.",
    )
    parser.add_argument(
        "--ga-env-file",
        help="Explicitly load a GA environment file; relative paths resolve from the repository root.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.load_ga_env or args.ga_env_file:
        try:
            env_file = configure_ga_environment(args.ga_env_file)
        except OSError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"Loaded GA environment file: {env_file}")

    # Hard verification-isolation gate (Part E): fail closed BEFORE any request
    # so a misconfigured run can never touch the live API/web/state.
    from verification_isolation import (
        VerificationIsolationError,
        assert_isolated,
        resolve_listen_pid,
    )

    try:
        api_port = urlsplit(API_BASE).port
        assert_isolated(
            context="phase_audit",
            api_base=API_BASE,
            web_base=WEB_BASE,
            live_api_pid=resolve_listen_pid(8000) if api_port and api_port != 8000 else None,
            self_api_pid=resolve_listen_pid(api_port) if api_port and api_port != 8000 else None,
        )
    except VerificationIsolationError as exc:
        print(f"FAIL: verification isolation - {exc}")
        return 2

    checks = [
        check_required_files(),
        check_no_stale_branding(),
        check_http("Frontend dev server", WEB_BASE),
        check_json("API health", f"{API_BASE}/health", "status", "ok"),
        check_json("API session", f"{API_BASE}/auth/session", "tenant.name", "Monday Report Tenant"),
        check_json("Client data readiness endpoint", f"{API_BASE}/readiness/client-data", "status", {"ready", "not_ready"}),
        check_json("Local AI status endpoint", f"{API_BASE}/local-ai/status", "hosted_fallback_enabled", False),
        check_json("Audit integrity endpoint", f"{API_BASE}/audit-logs/integrity", "broken_events", 0),
        check_processing_workflow(),
        check_json("API audit logs", f"{API_BASE}/audit-logs", None, None),
    ]

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")

    if failed:
        print(f"\nPhase audit failed with {len(failed)} failing check(s).")
        return 1

    print("\nPhase audit passed.")
    return 0


def check_required_files() -> dict[str, object]:
    required = [
        "README.md",
        "docs/MONDAY_REPORT_EXECUTION_PLAN.md",
        "docs/MONDAY_REPORT_IMPLEMENTATION_SPEC.md",
        "docs/PROJECT_TRACKER.md",
        "backend/app/main.py",
        "backend/app/schemas.py",
        "index.html",
        "src/redesign/main.tsx",
        "src/redesign/pages/Tracker.tsx",
        "src/data/projectTracker.ts",
        "db/migrations/0001_foundation.sql",
    ]
    missing = [path for path in required if not (ROOT / path).exists()]
    return {
        "name": "Required project artifacts",
        "ok": not missing,
        "detail": "all present" if not missing else f"missing {', '.join(missing)}",
    }


def check_no_stale_branding() -> dict[str, object]:
    stale_terms = ("Ara" + "mco", "Rig" + "Intel", "rig-report-" + "intelligence-saas")
    ignored_parts = {"node_modules", ".git", "dist"}
    matches: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for term in stale_terms:
            if term in text:
                matches.append(f"{path.relative_to(ROOT)}:{term}")

    return {
        "name": "Stale branding scan",
        "ok": not matches,
        "detail": "clean" if not matches else "; ".join(matches[:10]),
    }


def check_http(name: str, url: str) -> dict[str, object]:
    try:
        request = urllib.request.Request(url, headers=auth_headers(include_content_type=False), method="GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            return {"name": name, "ok": 200 <= response.status < 400, "detail": f"HTTP {response.status}"}
    except urllib.error.URLError as exc:
        return {"name": name, "ok": False, "detail": str(exc)}


def check_json(name: str, url: str, key_path: str | None, expected: object | None) -> dict[str, object]:
    try:
        request = urllib.request.Request(url, headers=auth_headers(), method="GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"name": name, "ok": False, "detail": str(exc)}

    if key_path is None:
        return {"name": name, "ok": True, "detail": "JSON response received"}

    value: object = payload
    for key in key_path.split("."):
        if not isinstance(value, dict) or key not in value:
            return {"name": name, "ok": False, "detail": f"missing {key_path}"}
        value = value[key]

    return {
        "name": name,
        "ok": value in expected if isinstance(expected, set) else value == expected,
        "detail": f"{key_path}={value!r}",
    }


def create_test_workspace(name_prefix: str) -> dict[str, object]:
    suffix = str(uuid4())[:8]
    return request_json(
        "POST",
        f"{API_BASE}/workspaces",
        {
            "name": f"{name_prefix} {suffix}",
            "asset": "Audit Rig",
            "campaign": "Automated gate",
            "period_start": "2026-07-06",
            "period_end": "2026-07-12",
        },
    )


def check_processing_workflow() -> dict[str, object]:
    try:
        workspace_id = create_test_workspace("Phase audit workspace")["id"]
        content = build_zip_fixture()
        expected_digest = sha256(content).hexdigest()
        upload = request_multipart(
            f"{API_BASE}/uploads/direct",
            {
                "workspace_id": workspace_id,
                "file_name": "audit/phase_audit_package.zip",
                "source_type": "zip",
            },
            "file",
            "phase_audit_package.zip",
            content,
            "application/zip",
        )
        jobs_before = request_json("GET", f"{API_BASE}/processing-jobs?upload_id={upload['upload']['id']}")
        worker = run_worker_until_progress(upload["upload"]["id"])
        jobs_after = request_json("GET", f"{API_BASE}/processing-jobs?upload_id={upload['upload']['id']}")
        files_after = request_json("GET", f"{API_BASE}/uploads/{upload['upload']['id']}/files")
        documents = request_json("GET", f"{API_BASE}/documents?workspace_id={workspace_id}")
        matching_documents = [
            document for document in documents if document.get("upload_id") == upload["upload"]["id"]
        ]
        parser_names = {document.get("parser_name") for document in matching_documents}
        chunks = []
        for document in matching_documents:
            chunks.extend(request_json("GET", f"{API_BASE}/documents/{document['id']}/chunks"))
        failures = request_json("GET", f"{API_BASE}/failures?workspace_id={workspace_id}")
        matching_failures = [
            failure
            for failure in failures
            if any(
                citation.get("locator", {}).get("upload_id") == upload["upload"]["id"]
                for citation in failure.get("citations", [])
            )
        ]
        validation_tasks = request_json("GET", f"{API_BASE}/validation-tasks")
        matching_validation_tasks = [
            task
            for task in validation_tasks
            if any(task.get("target_id") == failure.get("id") for failure in matching_failures)
        ]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, subprocess.SubprocessError) as exc:
        return {"name": "Audited processing workflow", "ok": False, "detail": str(exc)}

    completed_jobs = [job for job in jobs_after if job.get("status") == "complete"]
    file_record = upload["file"]
    ok = (
        upload["upload"].get("status") == "processing"
        and file_record.get("sha256") == expected_digest
        and file_record.get("byte_size") == len(content)
        and len(jobs_before) > 0
        and len(completed_jobs) == len(jobs_after)
        and len(files_after) >= 6
        and len(matching_documents) >= 5
        and {
            "plain_text_v1",
            "csv_text_v1",
            "xlsx_text_v1",
            "docx_text_v1",
            "email_text_v1",
            "pdf_text_v1",
            "ocr_route_v1",
        }.issubset(parser_names)
        and sum(document.get("chunk_count", 0) for document in matching_documents) == len(chunks)
        and any(
            failure.get("event_type") == "MWD signal loss"
            and failure.get("company") == "Anonymized Directional Services"
            and abs(float(failure.get("npt_hours", 0)) - 8.5) < 0.01
            for failure in matching_failures
        )
        and len(matching_validation_tasks) >= 1
        and worker.returncode == 0
    )

    return {
        "name": "Audited processing workflow",
        "ok": ok,
        "detail": (
            f"upload {upload['upload'].get('id')} sha={file_record.get('sha256')[:12]} "
            f"bytes={file_record.get('byte_size')} jobs_before={len(jobs_before)} "
            f"jobs_complete={len(completed_jobs)} files={len(files_after)} docs={len(matching_documents)} "
            f"chunks={len(chunks)} parsers={','.join(sorted(str(item) for item in parser_names))} failures={len(matching_failures)} "
            f"validation={len(matching_validation_tasks)} worker_rc={worker.returncode} "
            f"worker_output={(worker.stdout.strip() or worker.stderr.strip())[:160]}"
        ),
    }


def _send_with_conflict_retry(request: "urllib.request.Request", *, timeout: float = 5.0,
                              attempts: int = 6) -> object:
    """Send a request, retrying ONLY the documented *retryable* snapshot conflict.

    The PostgreSQL store maps a RETRYABLE compare-and-swap collision (lock timeout /
    serialization failure) to HTTP 503; a definite non-retryable loss is 409 (which
    the caller must observe as-is). The local backend has no CAS boundary, so neither
    occurs there. We retry the 503 with a short backoff; 409 and every other status
    propagate unchanged so callers still see the real result.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 503:
                last_error = exc
                time.sleep(0.15 * (attempt + 1))
                continue
            raise
    if last_error is not None:
        raise last_error
    raise RuntimeError("request did not complete")


def idempotency_key(
    *,
    scenario: str,
    operation: str,
    tenant: str,
    actor: str,
    target: str,
    attempt: str = "initial",
) -> str:
    """Deterministic, API-safe Idempotency-Key for an E2E mutation.

    Deterministic for an EXACT replay (same inputs -> same key) and stable across a
    lost-response retry (reuse the same ``attempt``); DISTINCT for any different
    tenant/actor/operation/target/attempt. Contains only ``[A-Za-z0-9._~-]`` and is
    8..200 chars. Carries no credentials, private data, or secrets.
    """
    material = "|".join(str(part) for part in (scenario, operation, tenant, actor, target, attempt))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    label = re.sub(r"[^A-Za-z0-9._~-]", "-", f"{scenario}.{operation}")[:40].strip("-") or "e2e"
    return f"{label}-{digest}"[:200]


def request_json(
    method: str, url: str, body: dict | None = None, *, idempotency_key: str | None = None
) -> object:
    data = None
    headers = auth_headers()
    if idempotency_key is not None:
        # Never weaken the API contract; the harness now SUPPLIES the required header.
        headers["Idempotency-Key"] = idempotency_key
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    return _send_with_conflict_retry(request)


def run_worker_until_progress(upload_id: str | None = None, max_attempts: int = 4) -> subprocess.CompletedProcess[str]:
    last_result: subprocess.CompletedProcess[str] | None = None
    for attempt in range(max_attempts):
        worker_env = os.environ.copy()
        if upload_id:
            worker_env["MONDAY_REPORT_WORKER_UPLOAD_ID"] = upload_id
        last_result = subprocess.run(
            [sys.executable, "-m", "backend.app.worker"],
            cwd=ROOT,
            env=worker_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        output = last_result.stdout.strip() or last_result.stderr.strip()
        if last_result.returncode != 0 or "Processed 0 " not in output:
            return last_result
        if attempt + 1 < max_attempts:
            time.sleep(0.75)
    return last_result if last_result is not None else subprocess.CompletedProcess([], 1, "", "worker did not run")


def auth_headers(include_content_type: bool = True) -> dict[str, str]:
    headers: dict[str, str] = {}
    if include_content_type:
        headers["Content-Type"] = "application/json"
    api_key = os.getenv("MONDAY_REPORT_API_KEY", "")
    if api_key:
        headers["X-Monday-Report-Key"] = api_key
    return headers


def build_zip_fixture() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "reports/ddr_2026_07_06.txt",
            "DDR: Monday Report audit package. MWD signal loss at 10342 ft MD. POOH and replace MWD tool.",
        )
        archive.writestr(
            "tables/npt_events.csv",
            "date,company,event,npt_hours\n2026-07-06,Anonymized Directional Services,MWD signal loss,8.5\n",
        )
        archive.writestr(
            "tables/service_quality.xlsx",
            build_xlsx_fixture(
                [
                    ["date", "company", "event", "npt_hours"],
                    ["2026-07-06", "Anonymized Directional Services", "MWD signal loss", "8.5"],
                ]
            ),
        )
        archive.writestr(
            "reports/daily_summary.docx",
            build_docx_fixture(
                "Daily summary confirms MWD signal loss and pull out of hole to replace the tool."
            ),
        )
        archive.writestr(
            "reports/pdf_ddr_2026_07_06.pdf",
            build_pdf_fixture(
                "PDF DDR confirms Anonymized Directional Services MWD signal loss with npt_hours 8.5."
            ),
        )
        archive.writestr(
            "emails/ops_update.eml",
            (
                "From: ops@example.test\r\n"
                "To: drilling@example.test\r\n"
                "Subject: Monday Report MWD update\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "\r\n"
                "Email note: Anonymized Directional Services reported MWD signal loss with 8.5 NPT hours.\r\n"
            ).encode("utf-8"),
        )
        archive.writestr("images/scanned_ddr_page.png", build_png_fixture())
        archive.writestr("images/scan_placeholder.bin", b"\x00\x01unsupported")
    return buffer.getvalue()


def build_docx_fixture(text: str) -> bytes:
    escaped = xml_escape(text)
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{escaped}</w:t></w:r></w:p></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as document:
        document.writestr("[Content_Types].xml", content_types)
        document.writestr("_rels/.rels", rels)
        document.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


def build_xlsx_fixture(rows: list[list[str]]) -> bytes:
    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for column_index, value in enumerate(row, start=1):
            ref = f"{xlsx_column_name(column_index)}{row_index}"
            cells.append(
                f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(value)}</t></is></c>'
            )
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    worksheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="NPT" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/></Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as workbook_zip:
        workbook_zip.writestr("[Content_Types].xml", content_types)
        workbook_zip.writestr("_rels/.rels", rels)
        workbook_zip.writestr("xl/workbook.xml", workbook)
        workbook_zip.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        workbook_zip.writestr("xl/worksheets/sheet1.xml", worksheet)
    return buffer.getvalue()


def build_pdf_fixture(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT\n/F1 12 Tf\n50 760 Td\n14 TL\n({escaped}) Tj\nET".encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = [0]
    for index, item in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{index} 0 obj\n".encode("ascii") + item + b"\nendobj\n"
    xref_offset = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    pdf += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n".encode("ascii")
    pdf += (
        b"trailer\n"
        + f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
        + b"startxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return pdf


def build_png_fixture() -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe"
        b"\xdc\xccY\xe7"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def xlsx_column_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def request_multipart(
    url: str,
    fields: dict[str, object],
    file_field: str,
    file_name: str,
    file_content: bytes,
    mime_type: str,
) -> object:
    boundary = f"----MondayReportAudit{uuid4().hex}"
    chunks: list[bytes] = []

    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(f"{value}\r\n".encode("utf-8"))

    safe_file_name = file_name.replace('"', "")
    chunks.append(f"--{boundary}\r\n".encode("utf-8"))
    chunks.append(
        (
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{safe_file_name}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(file_content)
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))

    request = urllib.request.Request(
        url,
        data=b"".join(chunks),
        headers={
            **auth_headers(include_content_type=False),
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    return _send_with_conflict_retry(request)


if __name__ == "__main__":
    sys.exit(main())
