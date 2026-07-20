"""Behavioral guard for API-layer per-request tenant resource authorization.

Proves the tenant-ownership boundary is enforced at the API layer: the request
tenant is resolved only from the server-side identity; every resource route
compares a looked-up resource's ``tenant_id`` to the request tenant; a resource
that belongs to another tenant is treated EXACTLY like a missing one
(existence-hiding 404); list/aggregate reads are tenant-filtered; signed
capabilities bind the owning tenant; cross-tenant denials are audited with
request-tenant context and no foreign detail; and the increment closes no other
GA blocker (``tenant-authorization-enforcement`` stays BLOCKED, GA stays
GA_BLOCKED) while leaving route-level RBAC intact.

The single-tenant JSON store is exercised with INJECTED foreign tenant-B fixtures
so the boundary can be tested without multi-tenant storage (which is out of scope
and remains a declared blocker).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

checks: list[dict[str, object]] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def _configure(tmp: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ.pop("MONDAY_REPORT_API_KEY", None)
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "tenant-authz-guard"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Tenant Authz Guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "bootstrap@tenant-authz.local"
    os.environ["MONDAY_REPORT_SIGNING_SECRET"] = "tenant-authz-guard-signing-secret-0123456789"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp / "exports")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="monday-report-tenant-authz-") as tmp_dir:
        tmp = Path(tmp_dir)
        _configure(tmp)

        from fastapi.testclient import TestClient

        from backend.app import main as m
        from backend.app import tenant_authorization as ta
        from backend.app import ga_readiness as gar
        from backend.app.identity import (
            get_current_identity,
            reset_current_identity,
            set_current_identity,
        )
        from backend.app.readiness import evaluate_client_data_readiness
        from backend.app.signed_urls import create_signed_token, verify_signed_token
        from backend.app.schemas import (
            AnomalyEvent,
            AuthenticatedIdentity,
            BenchmarkMeasurement,
            BenchmarkMeasurementCreate,
            BenchmarkValue,
            DiagnosticAction,
            DocumentChunk,
            FailureRecord,
            FieldCorrection,
            MondayReport,
            MondayReportCreate,
            ParsedDocument,
            ProcessingJob,
            ProcessingStatus,
            Role,
            Upload,
            UploadFileRecord,
            ValidationTask,
            Workspace,
            WorkspaceCreate,
        )
        from backend.app.store import store

        client = TestClient(m.app, raise_server_exceptions=False)

        def hdr(token):
            return {"X-Monday-Report-Key": token} if token else {}

        def status_of(method, path, token, **kw):
            return client.request(method, path, headers=hdr(token), **kw).status_code

        # Tenant A == the process's configured tenant; admin is a tenant-A user.
        tenant_a = store.tenant.id
        tenant_b = uuid.uuid4()
        admin = store.create_user("admin@tenant-authz.test", "Admin A", [Role.ADMIN])
        _, admin_tok = store.create_credential(admin.id)

        # ---- Tenant-A resources (created through the store -> stamped tenant_a) ----
        wa = store.create_workspace(WorkspaceCreate(name="Tenant A Workspace"))
        up_a, file_a, _ = store.create_uploaded_file(wa.id, "a.txt", "text/plain", "files", b"hello-tenant-a")
        up_a = store.complete_upload(up_a.id, [file_a.id])
        rep_a = store.create_monday_report(
            MondayReportCreate(workspace_id=wa.id, period_start=date(2026, 1, 1), period_end=date(2026, 1, 2))
        )
        exp_a = store.export_monday_report(rep_a.id, "json")
        store.record_benchmark_measurement(
            wa.id,
            BenchmarkMeasurementCreate(metric="feet_drilled_per_day", value=600.0, unit="ft/day", data_source="guard-a"),
        )
        bv_a = next(iter(store.benchmark_values.values()))  # a seeded tenant-A benchmark value

        # Injected tenant-A extras (symmetric same-tenant reads/mutations)
        doc_a = ParsedDocument(tenant_id=tenant_a, workspace_id=wa.id, upload_id=up_a.id, file_id=file_a.id,
                               title="Doc A", parser_name="guard")
        store.parsed_documents[doc_a.id] = doc_a
        store.document_chunks[uuid.uuid4()] = DocumentChunk(
            tenant_id=tenant_a, workspace_id=wa.id, upload_id=up_a.id, file_id=file_a.id,
            document_id=doc_a.id, ordinal=0, text="chunk-a", locator_type="page")
        vt_a = ValidationTask(tenant_id=tenant_a, target_type="citation", target_id=uuid.uuid4(), reason="a")
        store.validation_tasks[vt_a.id] = vt_a
        an_a = AnomalyEvent(tenant_id=tenant_a, workspace_id=wa.id, metric="feet_drilled_per_day", severity="Warning",
                            performance_status="Below benchmark", current_value=400.0, unit="ft/day",
                            threshold_value=528.0, threshold_unit="ft/day", rule_id=uuid.uuid4(), rule_name="ra",
                            summary="sa", diagnostic_actions=[DiagnosticAction(module="Hydraulics", reason="ta")])
        store.anomaly_events[an_a.id] = an_a

        # ---- Injected tenant-B (foreign) resources ----
        wb = Workspace(tenant_id=tenant_b, name="TENANT-B-SECRET-WELL")
        store.workspaces[wb.id] = wb
        ub = Upload(tenant_id=tenant_b, workspace_id=wb.id, submitted_by=uuid.uuid4(), source_type="files")
        store.uploads[ub.id] = ub
        fb = UploadFileRecord(tenant_id=tenant_b, upload_id=ub.id, original_path="b.txt",
                              storage_uri="object://tenant-b/uploads/x/b.txt", sha256="1" * 64,
                              mime_type="text/plain", byte_size=5, status=ProcessingStatus.COMPLETE,
                              malware_status="clean")
        store.files[fb.id] = fb
        docb = ParsedDocument(tenant_id=tenant_b, workspace_id=wb.id, upload_id=ub.id, file_id=fb.id,
                              title="TENANT-B-DOC", parser_name="guard")
        store.parsed_documents[docb.id] = docb
        store.document_chunks[uuid.uuid4()] = DocumentChunk(
            tenant_id=tenant_b, workspace_id=wb.id, upload_id=ub.id, file_id=fb.id,
            document_id=docb.id, ordinal=0, text="chunk-b", locator_type="page")
        jb = ProcessingJob(tenant_id=tenant_b, upload_id=ub.id, job_type="parse")
        store.jobs[jb.id] = jb
        failb = FailureRecord(tenant_id=tenant_b, workspace_id=wb.id, event_type="stuck_pipe", severity="Critical",
                              summary="TENANT-B-FAILURE", confidence=0.9, npt_hours=12.0)
        store.failures[failb.id] = failb
        vtb = ValidationTask(tenant_id=tenant_b, target_type="citation", target_id=uuid.uuid4(), reason="b")
        store.validation_tasks[vtb.id] = vtb
        repb = MondayReport(tenant_id=tenant_b, workspace_id=wb.id, period_start=date(2026, 1, 1),
                            period_end=date(2026, 1, 2), report_json={"secret": "tenant-b-only"})
        store.monday_reports[repb.id] = repb
        expb = ReportExport = None
        from backend.app.schemas import ReportExport as _ReportExport
        expb = _ReportExport(tenant_id=tenant_b, report_id=repb.id, format="json",
                             storage_uri="export://tenant-b/reports/x/monday_report.json",
                             sha256="0" * 64, byte_size=10)
        store.report_exports[expb.id] = expb
        bvb = BenchmarkValue(tenant_id=tenant_b, benchmark_name="Foreign B", metric="feet_drilled_per_day",
                             value=1.0, unit="ft/day", performance_category="x", data_source="d",
                             effective_date=date(2026, 1, 1), dataset_version="v1")
        store.benchmark_values[bvb.id] = bvb
        measb = BenchmarkMeasurement(tenant_id=tenant_b, workspace_id=wb.id, metric="feet_drilled_per_day",
                                     value=999.0, unit="ft/day", data_source="TENANT-B-MEASUREMENT",
                                     data_timestamp=datetime.now(timezone.utc))
        store.benchmark_measurements[measb.id] = measb
        anb = AnomalyEvent(tenant_id=tenant_b, workspace_id=wb.id, metric="feet_drilled_per_day", severity="Critical",
                           performance_status="Critical deviation", current_value=100.0, unit="ft/day",
                           threshold_value=528.0, threshold_unit="ft/day", rule_id=uuid.uuid4(), rule_name="rb",
                           summary="sb", diagnostic_actions=[DiagnosticAction(module="Hydraulics", reason="tb")])
        store.anomaly_events[anb.id] = anb
        fcb = FieldCorrection(tenant_id=tenant_b, workspace_id=wb.id, target_type="report_field", field_key="well",
                              correction_reason="b", actor_user_id=uuid.uuid4(), actor_email="b@tenant-b.test",
                              status="active")
        store.field_corrections[fcb.id] = fcb
        store.save()

        rnd = uuid.uuid4()  # a resource id that exists in no tenant

        # =========================================================================
        # 1-12: tenant_authorization module (the single ownership authority)
        # =========================================================================
        check("1 request_tenant_id is None with no request identity", ta.request_tenant_id() is None)
        # Set an explicit request identity and confirm the tenant is read from it.
        fake = AuthenticatedIdentity(user_id=uuid.uuid4(), tenant_id=tenant_a, email="x@y.z", display_name="X",
                                     roles=[Role.ADMIN], authentication_source="api_token", actor_source="authenticated")
        _tok = set_current_identity(fake)
        try:
            check("2 request_tenant_id reads identity.tenant_id (server-side only)", ta.request_tenant_id() == tenant_a)
            other = AuthenticatedIdentity(user_id=uuid.uuid4(), tenant_id=tenant_b, email="x@y.z", display_name="X",
                                          roles=[Role.ADMIN], authentication_source="api_token", actor_source="authenticated")
            _tok2 = set_current_identity(other)
            check("3 request_tenant_id follows the switched identity", ta.request_tenant_id() == tenant_b)
            reset_current_identity(_tok2)
        finally:
            reset_current_identity(_tok)
        check("4 request_tenant_id None again after reset (no leak)", ta.request_tenant_id() is None)
        check("5 owns() true for same-tenant resource", ta.owns(wa, tenant_a) is True)
        check("6 owns() false for cross-tenant resource", ta.owns(wb, tenant_a) is False)
        check("7 owns(None) is default-deny", ta.owns(None, tenant_a) is False)
        check("8 owns(resource, None tenant) is default-deny", ta.owns(wa, None) is False)
        check("9 resource_tenant_id reads the stamp", ta.resource_tenant_id(wa) == tenant_a)
        check("10 tenant_visible filters to the request tenant", [x.id for x in ta.tenant_visible([wa, wb], tenant_a)] == [wa.id])
        check("11 tenant_visible(None tenant) is empty (default-deny)", ta.tenant_visible([wa, wb], None) == [])
        try:
            ta.system_tenant_context(tenant_a, "")
            _sys_ok = False
        except ValueError:
            _sys_ok = True
        sysctx = ta.system_tenant_context(tenant_a, "worker.parse")
        check("12 explicit system context requires an operation label and is actor_source=system",
              _sys_ok and sysctx.actor_source == "system" and sysctx.tenant_id == tenant_a)

        # =========================================================================
        # 13-40: single-resource cross-tenant access is an existence-hiding 404,
        #         same-tenant access succeeds
        # =========================================================================
        check("13 same-tenant workspace report-draft -> 200", status_of("GET", f"/workspaces/{wa.id}/report-draft", admin_tok) == 200)
        check("14 cross-tenant workspace report-draft -> 404", status_of("GET", f"/workspaces/{wb.id}/report-draft", admin_tok) == 404)
        check("15 missing workspace report-draft -> 404 (same as cross-tenant)", status_of("GET", f"/workspaces/{rnd}/report-draft", admin_tok) == 404)
        r_foreign = client.get(f"/workspaces/{wb.id}/report-draft", headers=hdr(admin_tok))
        r_missing = client.get(f"/workspaces/{rnd}/report-draft", headers=hdr(admin_tok))
        check("16 cross-tenant and missing 404 bodies are identical (no existence oracle)", r_foreign.json() == r_missing.json())
        check("17 cross-tenant field-corrections list -> 404", status_of("GET", f"/workspaces/{wb.id}/field-corrections", admin_tok) == 404)
        check("18 cross-tenant create field-correction -> 404",
              status_of("POST", f"/workspaces/{wb.id}/field-corrections", admin_tok,
                        json={"target_type": "report_field", "field_key": "well", "correction_reason": "x"}) == 404)
        check("19 cross-tenant create monday-report -> 404",
              status_of("POST", "/monday-reports", admin_tok,
                        json={"workspace_id": str(wb.id), "period_start": "2026-01-01", "period_end": "2026-01-02"}) == 404)
        check("20 cross-tenant create upload -> 404",
              status_of("POST", "/uploads", admin_tok,
                        json={"workspace_id": str(wb.id), "file_name": "x.txt", "byte_size": 4, "mime_type": "text/plain", "source_type": "files"}) == 404)
        check("21 same-tenant upload files -> 200", status_of("GET", f"/uploads/{up_a.id}/files", admin_tok) == 200)
        check("22 cross-tenant upload files -> 404", status_of("GET", f"/uploads/{ub.id}/files", admin_tok) == 404)
        check("23 cross-tenant upload complete -> 404",
              status_of("POST", f"/uploads/{ub.id}/complete", admin_tok, json={"file_ids": [str(fb.id)]}) == 404)
        check("24 same-tenant document chunks -> 200", status_of("GET", f"/documents/{doc_a.id}/chunks", admin_tok) == 200)
        check("25 cross-tenant document chunks -> 404", status_of("GET", f"/documents/{docb.id}/chunks", admin_tok) == 404)
        check("26 same-tenant validation-task patch -> not 404", status_of("PATCH", f"/validation-tasks/{vt_a.id}", admin_tok, json={"status": "validated"}) != 404)
        check("27 cross-tenant validation-task patch -> 404", status_of("PATCH", f"/validation-tasks/{vtb.id}", admin_tok, json={"status": "validated"}) == 404)
        check("28 cross-tenant monday-report export -> 404", status_of("POST", f"/monday-reports/{repb.id}/exports/json", admin_tok) == 404)
        check("29 same-tenant report-export signed-url -> 200", status_of("POST", f"/report-exports/{exp_a.id}/signed-url", admin_tok) == 200)
        check("30 cross-tenant report-export signed-url -> 404", status_of("POST", f"/report-exports/{expb.id}/signed-url", admin_tok) == 404)
        check("31 cross-tenant upload-file signed-url -> 404", status_of("POST", f"/upload-files/{fb.id}/signed-url", admin_tok) == 404)
        check("32 same-tenant upload-file signed-url -> 200", status_of("POST", f"/upload-files/{file_a.id}/signed-url", admin_tok) == 200)
        check("33 same-tenant benchmark value patch -> 200", status_of("PATCH", f"/benchmarking/values/{bv_a.id}", admin_tok, json={"reason": "guard", "value": 530.0}) == 200)
        check("34 cross-tenant benchmark value patch -> 404", status_of("PATCH", f"/benchmarking/values/{bvb.id}", admin_tok, json={"reason": "guard", "value": 2.0}) == 404)
        check("35 cross-tenant anomaly diagnostic dismiss -> 404",
              status_of("PATCH", f"/benchmarking/anomalies/{anb.id}/diagnostics/{anb.diagnostic_actions[0].id}/dismiss", admin_tok, json={"reason": "x"}) == 404)
        check("36 cross-tenant field-correction revert -> 404",
              status_of("POST", f"/field-corrections/{fcb.id}/revert", admin_tok, json={"revert_reason": "x"}) == 404)
        check("37 cross-tenant create benchmark measurement -> 404",
              status_of("POST", f"/workspaces/{wb.id}/benchmarking/measurements", admin_tok,
                        json={"metric": "feet_drilled_per_day", "value": 10.0, "unit": "ft/day", "data_source": "x"}) == 404)
        # benchmarking status: foreign workspace is treated like missing (config-only 200, NO foreign data)
        rb_bench = client.get(f"/workspaces/{wb.id}/benchmarking", headers=hdr(admin_tok))
        _bench_blob = json.dumps(rb_bench.json())
        check("38 cross-tenant benchmarking status is config-only 200 (existence-hiding)", rb_bench.status_code == 200)
        check("39 cross-tenant benchmarking status leaks no tenant-B measurement", "TENANT-B-MEASUREMENT" not in _bench_blob and rb_bench.json().get("current_ft_per_day") is None)
        check("40 same-tenant benchmarking status -> 200 with own data", client.get(f"/workspaces/{wa.id}/benchmarking", headers=hdr(admin_tok)).status_code == 200)

        # =========================================================================
        # 41-52: list/aggregate reads are tenant-filtered (no cross-tenant leak)
        # =========================================================================
        ws_ids = {w["id"] for w in client.get("/workspaces", headers=hdr(admin_tok)).json()}
        check("41 GET /workspaces includes tenant-A workspace", str(wa.id) in ws_ids)
        check("42 GET /workspaces excludes tenant-B workspace", str(wb.id) not in ws_ids)
        rep_ids = {x["id"] for x in client.get("/monday-reports", headers=hdr(admin_tok)).json()}
        check("43 GET /monday-reports excludes tenant-B report", str(repb.id) not in rep_ids and str(rep_a.id) in rep_ids)
        vt_ids = {x["id"] for x in client.get("/validation-tasks", headers=hdr(admin_tok)).json()}
        check("44 GET /validation-tasks excludes tenant-B task", str(vtb.id) not in vt_ids and str(vt_a.id) in vt_ids)
        fail_blob = json.dumps(client.get("/failures", headers=hdr(admin_tok)).json())
        check("45 GET /failures excludes tenant-B failure", "TENANT-B-FAILURE" not in fail_blob)
        job_ids = {x["id"] for x in client.get("/processing-jobs", headers=hdr(admin_tok)).json()}
        check("46 GET /processing-jobs excludes tenant-B job", str(jb.id) not in job_ids)
        doc_blob = json.dumps(client.get("/documents", headers=hdr(admin_tok)).json())
        check("47 GET /documents excludes tenant-B document", "TENANT-B-DOC" not in doc_blob)
        audit_blob = json.dumps(client.get("/audit-logs?limit=200", headers=hdr(admin_tok)).json())
        check("48 GET /audit-logs is tenant-scoped (every entry is tenant-A)",
              all(e["tenant_id"] == str(tenant_a) for e in client.get("/audit-logs?limit=200", headers=hdr(admin_tok)).json()))
        summ = client.get("/dashboards/summary", headers=hdr(admin_tok)).json()
        check("49 dashboard summary excludes tenant-B failure/NPT", summ["total_npt_hours"] < 12.0)
        cfg_blob = json.dumps(client.get("/benchmarking/config", headers=hdr(admin_tok)).json())
        check("50 GET /benchmarking/config excludes tenant-B benchmark value", "Foreign B" not in cfg_blob)
        chat = client.post("/chat/messages", headers=hdr(admin_tok), json={"workspace_id": str(wb.id), "content": "what failed"}).json()
        check("51 chat on tenant-B workspace surfaces no tenant-B failures", "0 extracted failure" in chat.get("answer", "") or "0 extracted" in chat.get("answer", ""))
        docs_wsb = json.dumps(client.get(f"/documents?workspace_id={wb.id}", headers=hdr(admin_tok)).json())
        check("52 GET /documents?workspace_id=<tenant-B> returns nothing", "TENANT-B-DOC" not in docs_wsb)

        # =========================================================================
        # 53-60: signed capabilities bind the owning tenant
        # =========================================================================
        good_a, _ = create_signed_token(exp_a.id, "report_export_download", tenant_id=tenant_a)
        check("53 tenant-bound token verifies with the correct tenant", verify_signed_token(good_a, exp_a.id, "report_export_download", tenant_id=tenant_a) is True)
        check("54 tenant-bound token fails with the wrong tenant", verify_signed_token(good_a, exp_a.id, "report_export_download", tenant_id=tenant_b) is False)
        check("55 tenant-bound token still resource/purpose-bound", verify_signed_token(good_a, uuid.uuid4(), "report_export_download", tenant_id=tenant_a) is False)
        legacy, _ = create_signed_token(exp_a.id, "report_export_download")  # no tenant binding
        check("56 legacy token (no binding) fails a tenant-checked verification", verify_signed_token(legacy, exp_a.id, "report_export_download", tenant_id=tenant_a) is False)
        # End-to-end: mint via the API for a tenant-A export, then redeem the signed link.
        signed = client.post(f"/report-exports/{exp_a.id}/signed-url", headers=hdr(admin_tok)).json()
        dl_path = signed["url"].split("/signed/", 1)[1]
        check("57 tenant-A signed download of own export succeeds", client.get("/signed/" + dl_path).status_code == 200)
        # A token crafted (server-side) for the FOREIGN export but bound to tenant-A must not redeem it.
        mismatched, _ = create_signed_token(expb.id, "report_export_download", tenant_id=tenant_a)
        check("58 download-side tenant binding rejects a tenant-mismatched token -> 404",
              client.get(f"/signed/report-exports/{expb.id}?token={mismatched}").status_code == 404)
        check("59 tenant-A cannot mint a signed URL for a tenant-B export (issuance gate)",
              status_of("POST", f"/report-exports/{expb.id}/signed-url", admin_tok) == 404)
        check("60 tenant-A cannot mint a signed URL for a tenant-B upload file (issuance gate)",
              status_of("POST", f"/upload-files/{fb.id}/signed-url", admin_tok) == 404)

        # =========================================================================
        # 61-64: cross-tenant denials audited with request-tenant context, no leak
        # =========================================================================
        store.refresh()
        before = len(store.audit_logs)
        client.get(f"/workspaces/{wb.id}/report-draft", headers=hdr(admin_tok))  # cross-tenant hit
        store.refresh()
        denials = [e for e in store.audit_logs if e.action == "authz.cross_tenant_denied"]
        check("61 cross-tenant access writes a cross_tenant_denied audit event", len(denials) >= 1)
        last = denials[-1]
        check("62 denial audit tenant + actor are the REQUEST's (tenant-A)", str(last.tenant_id) == str(tenant_a) and str(last.actor_user_id) == str(admin.id))
        meta_blob = json.dumps(last.metadata)
        check("63 denial metadata discloses no foreign tenant / owner detail", str(tenant_b) not in meta_blob and "owner" not in meta_blob and last.metadata.get("reason") == "resource_not_in_request_tenant")
        before2 = len(store.audit_logs)
        client.get(f"/workspaces/{rnd}/report-draft", headers=hdr(admin_tok))  # truly-missing resource
        store.refresh()
        new_cross = [e for e in store.audit_logs[before2:] if e.action == "authz.cross_tenant_denied"]
        check("64 a truly-missing resource writes no cross_tenant_denied event", len(new_cross) == 0)

        # =========================================================================
        # 65-70: readiness / GA disposition (blocker stays BLOCKED, GA_BLOCKED)
        # =========================================================================
        readiness_by_id = {c.id: c.status for c in evaluate_client_data_readiness(store).checks}
        ga_checks = {c["id"]: c for c in gar.evaluate_blockers(readiness_by_id, forge_report=None)}
        ta_check = ga_checks["ga_tenant_authorization"]
        check("65 tenant-authorization-enforcement remains BLOCKED", ta_check["disposition"] == "BLOCKED")
        check("66 tenant-authorization detail is evidence-driven (API-layer implemented, RLS pending)",
              "API-layer" in ta_check["detail"] and "RLS" in ta_check["detail"])
        check("67 verified-reviewer + audit-integrity blockers stay BLOCKED",
              gar.is_blocking(ga_checks["ga_verified_reviewer_identity"]) and ga_checks["ga_audit_keyed_integrity"]["disposition"] == "BLOCKED")
        check("68 RBAC role-separation still evidence-driven PASS (no route regression)", ga_checks["ga_rbac_role_separation"]["disposition"] == "PASS")
        check("69 route policy remains fully enforced (RBAC intact)", m.route_policy_fully_enforced() is True)
        status_ga, ready_ga = gar.decide_ga(mode="client", parity_ok=not gar.check_registry_parity(list(ga_checks.values())),
                                             checks=list(ga_checks.values()), commands_skipped=False, commands_passed=True, worktree_clean=True)
        check("70 GA remains GA_BLOCKED", status_ga == "GA_BLOCKED" and ready_ga is False)
        check("70b No stale request identity after the guard run", get_current_identity() is None)

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(json.dumps({"guard": "tenant_authorization_guard", "checks": len(checks), "failed": len(failed)}))
    if failed:
        print(f"\nTenant authorization guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nTenant authorization guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
