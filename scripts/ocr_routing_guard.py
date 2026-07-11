from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-ocr-routing-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import app
        from backend.app.store import store

        client = TestClient(app)
        workspace = next(iter(store.workspaces.values()))

        image_upload = upload_file(
            client,
            workspace.id,
            "ocr/image_scan.png",
            build_png_fixture(),
            "image/png",
        )
        scanned_pdf_upload = upload_file(
            client,
            workspace.id,
            "ocr/scanned_ddr.pdf",
            build_scanned_pdf_fixture(),
            "application/pdf",
        )
        checks.append(
            assert_check(
                "OCR candidate uploads accepted",
                image_upload.status_code == 201 and scanned_pdf_upload.status_code == 201,
                {"image": response_detail(image_upload), "pdf": response_detail(scanned_pdf_upload)},
            )
        )

        processed = store.process_queued_jobs()
        checks.append(assert_check("OCR route jobs processed", processed == 2, f"processed={processed}"))

        store.refresh()
        ocr_documents = [
            document
            for document in store.parsed_documents.values()
            if document.workspace_id == workspace.id and document.parser_name == "ocr_route_v1"
        ]
        route_reasons = {
            document.metadata.get("parser", {}).get("routing_reason")
            for document in ocr_documents
        }
        checks.append(
            assert_check(
                "Image and scanned PDF route to OCR",
                len(ocr_documents) == 2
                and {"image_file", "scanned_pdf_or_image_only"}.issubset(route_reasons)
                and all(document.status.value == "queued" and document.chunk_count == 0 for document in ocr_documents),
                [document.model_dump(mode="json") for document in ocr_documents],
            )
        )

        ocr_file_ids = {document.file_id for document in ocr_documents}
        ocr_tasks = [
            task
            for task in store.validation_tasks.values()
            if task.target_type == "file" and task.target_id in ocr_file_ids
        ]
        checks.append(
            assert_check(
                "OCR routing creates file-level review tasks",
                len(ocr_tasks) == 2 and all(task.status.value == "open" for task in ocr_tasks),
                [task.model_dump(mode="json") for task in ocr_tasks],
            )
        )

        route_events = [event for event in store.audit_logs if event.action == "ocr.route"]
        parse_events = [
            event
            for event in store.audit_logs
            if event.action == "document.parse_complete" and event.metadata.get("parser_name") == "ocr_route_v1"
        ]
        checks.append(
            assert_check(
                "OCR routing is audited",
                len(route_events) == 2 and len(parse_events) == 2,
                {
                    "route_events": [event.metadata for event in route_events],
                    "parse_events": [event.metadata for event in parse_events],
                },
            )
        )

        upload_statuses = {upload.status for upload in store.uploads.values() if upload.workspace_id == workspace.id}
        checks.append(
            assert_check(
                "OCR routing leaves uploads terminal",
                {status.value for status in upload_statuses} == {"complete"},
                [status.value for status in upload_statuses],
            )
        )

        integrity = store.audit_integrity_status()
        checks.append(
            assert_check(
                "OCR routing audit chain sealed",
                integrity.status == "sealed" and integrity.broken_events == 0,
                integrity.model_dump(mode="json"),
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "OCR Routing Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "ocr-routing-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "OCR Routing Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Client OCR routing guard"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")


def upload_file(client: TestClient, workspace_id, file_name: str, content: bytes, mime_type: str):
    return client.post(
        "/uploads/direct",
        data={
            "workspace_id": str(workspace_id),
            "file_name": file_name,
            "source_type": "files",
        },
        files={"file": (Path(file_name).name, content, mime_type)},
    )


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


def build_scanned_pdf_fixture() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
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


def response_detail(response) -> object:
    try:
        return response.json()
    except ValueError:
        return response.text


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
