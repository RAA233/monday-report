"""Behavioral guard for the field-level correction & review-provenance foundation.

Exercises the real API (upload -> worker -> report-draft plus the correction
routes) in isolated temporary state and asserts:

- a reviewer correction records who/what/from-to/when/why with the reviewer's
  identity, preserving the source value and never mutating source lineage;
- re-correcting the same field supersedes the prior record (append-only version
  history) and reverting flips status without destroying history;
- the correction audit events attribute the actor and never leak raw source,
  corrected, or reason text into the redacted, hash-chained audit log;
- active corrections surface in the report draft as review-required overlays
  without overwriting source-derived values;
- recording corrections creates no anomaly events, benchmark measurements,
  failures, or validation tasks (recommendation/Benchmarking boundary intact);
- corrections are tenant/workspace scoped and survive a state reload.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

TEMP_DIR = tempfile.TemporaryDirectory(prefix="field-correction-guard-")
os.environ.update(
    {
        "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
        "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
        "MONDAY_REPORT_TENANT_SLUG": "field-correction-guard",
        "MONDAY_REPORT_TENANT_NAME": "Field Correction Guard",
        "MONDAY_REPORT_USER_EMAIL": "reviewer@example.test",
        "MONDAY_REPORT_USER_FULL_NAME": "Field Correction Reviewer",
        "MONDAY_REPORT_STATE_PATH": str(Path(TEMP_DIR.name) / "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(Path(TEMP_DIR.name) / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(Path(TEMP_DIR.name) / "exports"),
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from backend.app import worker  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.store import store  # noqa: E402
from pdf_parser_guard import build_pdf_fixture  # noqa: E402

client = TestClient(app)


def check(name: str, ok: bool, detail: object = "") -> dict[str, object]:
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))
    return {"name": name, "ok": ok, "detail": str(detail)[:300]}


def new_workspace(name: str) -> str:
    return client.post("/workspaces", json={"name": name, "rig_name": "guard"}).json()["id"]


def main() -> int:
    checks: list[dict[str, object]] = []

    ws = new_workspace("corrections-primary")

    # 1. Record a correction: reviewer identity + provenance captured.
    record = client.post(
        f"/workspaces/{ws}/field-corrections",
        json={
            "target_type": "report_field",
            "field_key": "well",
            "source_value": "SENTINELSRC 0091",
            "corrected_value": "ALPINE 22B [45]-07",
            "correction_reason": "Restore the bracketed pad code dropped in extraction.",
        },
    )
    first = record.json() if record.status_code == 201 else {}
    checks.append(
        check(
            "Recording a correction captures reviewer identity and provenance",
            record.status_code == 201
            and first.get("reviewer_email") == "reviewer@example.test"
            and bool(first.get("reviewer_user_id"))
            and first.get("reviewer_roles")
            and first.get("status") == "active"
            and first.get("source_value") == "SENTINELSRC 0091"
            and first.get("corrected_value") == "ALPINE 22B [45]-07"
            and bool(first.get("created_at"))
            and bool(first.get("tenant_id")),
            {"status": record.status_code, "reviewer": first.get("reviewer_email")},
        )
    )

    # 2. Audit event attributes the actor and leaks no raw values.
    audit_logs = client.get("/audit-logs").json()
    record_events = [e for e in audit_logs if e.get("action") == "field_correction.record"]
    audit_blob = json.dumps(audit_logs)
    checks.append(
        check(
            "A redacted, hash-chained audit event records the correction (no raw source/corrected/reason)",
            len(record_events) == 1
            and record_events[0].get("actor_user_id")
            and "SENTINELSRC 0091" not in audit_blob  # raw source value never in the audit log
            and "ALPINE 22B [45]-07" not in audit_blob  # raw corrected value never in the audit log
            and "Restore the bracketed pad code" not in audit_blob,  # raw reason text never in the audit log
            {"events": len(record_events)},
        )
    )
    integrity = client.get("/audit-logs/integrity").json()
    checks.append(
        check(
            "Audit chain remains sealed after recording a correction",
            integrity.get("status") == "sealed" and integrity.get("broken_events") == 0,
            integrity.get("status"),
        )
    )

    # 3. Re-correcting the same field supersedes the prior record (history).
    second = client.post(
        f"/workspaces/{ws}/field-corrections",
        json={
            "target_type": "report_field",
            "field_key": "well",
            "source_value": "ALPINE 22B",
            "corrected_value": "ALPINE 22B [45]-07 (revised)",
            "correction_reason": "Reviewer refined the identifier.",
        },
    ).json()
    history = client.get(f"/workspaces/{ws}/field-corrections").json()
    prior = next((c for c in history if c["id"] == first["id"]), {})
    checks.append(
        check(
            "Re-correcting the same field supersedes the prior record with a version chain",
            len(history) == 2
            and prior.get("status") == "superseded"
            and prior.get("superseded_by_id") == second["id"]
            and second.get("supersedes_id") == first["id"]
            and second.get("status") == "active",
            {"history": len(history), "prior_status": prior.get("status")},
        )
    )

    # 4. active_only filter returns only the live correction.
    active = client.get(f"/workspaces/{ws}/field-corrections?active_only=true").json()
    checks.append(
        check(
            "active_only filter returns only the current correction",
            len(active) == 1 and active[0]["id"] == second["id"],
            {"active": len(active)},
        )
    )

    # 5. Revert flips status without destroying history; non-active revert 409s.
    reverted = client.post(
        f"/field-corrections/{second['id']}/revert",
        json={"revert_reason": "Reviewer withdrew the correction."},
    )
    reverted_body = reverted.json()
    re_revert = client.post(
        f"/field-corrections/{first['id']}/revert",
        json={"revert_reason": "already superseded"},
    )
    post_history = client.get(f"/workspaces/{ws}/field-corrections").json()
    checks.append(
        check(
            "Revert flips status and history is preserved; a non-active revert is rejected",
            reverted.status_code == 200
            and reverted_body.get("status") == "reverted"
            and re_revert.status_code == 409
            and len(post_history) == 2,
            {"revert": reverted.status_code, "non_active_revert": re_revert.status_code},
        )
    )

    revert_events = [
        e for e in client.get("/audit-logs").json() if e.get("action") == "field_correction.revert"
    ]
    checks.append(
        check(
            "Revert emits its own audit event with no raw reason text",
            len(revert_events) == 1
            and "Reviewer withdrew the correction." not in json.dumps(revert_events),
            {"events": len(revert_events)},
        )
    )

    # 6. Report draft surfaces active corrections without overwriting source.
    ws2 = new_workspace("corrections-draft")
    drilling_pdf = build_pdf_fixture(
        [
            "DAILY DRILLING REPORT\n"
            "WELL NAME: ALPINE 22B [45]-07\n"
            "Rig: Vector Test Rig 7\n"
            "MD: 8620 ft\n"
            "TVD: 7980 ft\n"
            "24 hr activity summary with NPT notes."
        ]
    )
    upload = client.post(
        "/uploads/direct",
        data={"workspace_id": ws2, "file_name": "vector-ddr.pdf", "source_type": "files"},
        files={"file": ("vector-ddr.pdf", drilling_pdf, "application/pdf")},
    )
    worker.run_once()
    def source_fields() -> dict[str, object]:
        docs = [
            d.metadata.get("parser", {}).get("report_profile", {}).get("fields", {})
            for d in store.parsed_documents.values()
            if str(d.workspace_id) == ws2 and d.parser_name == "pdf_text_v1"
        ]
        return docs[0] if docs else {}

    source_before = source_fields()
    draft_before = client.get(f"/workspaces/{ws2}/report-draft").json()
    client.post(
        f"/workspaces/{ws2}/field-corrections",
        json={
            "target_type": "report_field",
            "field_key": "tvd_ft",
            "source_value": str(source_before.get("tvd_ft")),
            "corrected_value": "7985",
            "correction_reason": "Reviewer reconciled the TVD against the survey.",
        },
    )
    draft = client.get(f"/workspaces/{ws2}/report-draft").json()
    source_after = source_fields()
    overlays = draft.get("field_corrections", [])
    checks.append(
        check(
            "Active corrections surface in the draft as overlays without overwriting source values",
            upload.status_code == 201
            and worker is not None
            and source_before == source_after  # source extraction untouched by the overlay
            and source_after.get("well") == "ALPINE 22B [45]-07"
            and len(overlays) == 1
            and overlays[0]["field_key"] == "tvd_ft"
            and overlays[0]["corrected_value"] == "7985"
            and draft.get("tvd_ft") == draft_before.get("tvd_ft"),  # deterministic source value unchanged
            {
                "overlays": len(overlays),
                "source_unchanged": source_before == source_after,
                "draft_tvd_stable": draft.get("tvd_ft") == draft_before.get("tvd_ft"),
            },
        )
    )

    # 7. Isolation: no recommendation/Benchmarking/failure/validation mutation.
    checks.append(
        check(
            "Recording corrections creates no anomalies, measurements, failures, or validation tasks",
            len(store.anomaly_events) == 0
            and len(getattr(store, "benchmark_measurements", {})) == 0
            and len(store.failures) == 0
            and len(store.validation_tasks) == 0,
            {
                "anomalies": len(store.anomaly_events),
                "measurements": len(getattr(store, "benchmark_measurements", {})),
                "failures": len(store.failures),
                "validation_tasks": len(store.validation_tasks),
            },
        )
    )

    # 8. Tenant/workspace scoping.
    other = client.get(f"/workspaces/{ws2}/field-corrections").json()
    checks.append(
        check(
            "Corrections are workspace scoped",
            all(c["workspace_id"] == ws2 for c in other) and len(other) == 1,
            {"other_ws_corrections": len(other)},
        )
    )

    # 9. Least-privilege hook present in the permission map.
    permissions = store.benchmark_permissions()
    checks.append(
        check(
            "Correction permissions expose a reviewer-only write hook",
            permissions.get("record_field_corrections") is True
            and permissions.get("view_field_corrections") is True,
            {k: permissions.get(k) for k in ("record_field_corrections", "view_field_corrections")},
        )
    )

    # 10. Persistence round-trip.
    before = len(store.field_corrections)
    store.refresh()
    checks.append(
        check(
            "Corrections persist across a state reload",
            len(store.field_corrections) == before and before == 3,
            {"before": before, "after": len(store.field_corrections)},
        )
    )

    failed = [item for item in checks if not item["ok"]]
    print(
        json.dumps(
            {"guard": "field_correction_guard", "checks": len(checks), "failed": len(failed)},
            indent=2,
        )
    )
    if failed:
        print(f"\nField correction guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nField correction guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
