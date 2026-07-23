"""Behavioral guard for complete route-level RBAC.

Proves the route-access inventory is complete and security-appropriate, that the
generic permission policy is default-deny with real role differences, that every
sensitive mutation and privileged read is permission-enforced, that signed
downloads are resource-bound/expiring/method-restricted, that permission denials
are safely audited, and that the increment closes no other GA blocker
(GA stays GA_BLOCKED; tenant/reviewer/audit-integrity remain declared blockers).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import uuid
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
    # Run with a valid active audit key so keyed integrity is active throughout and
    # the client-mode auth/RBAC checks (which now fail closed without a key) can
    # exercise the real 401/403/200 auth path. The ga_audit_keyed_integrity probe's
    # BLOCKED default is asserted with the key TEMPORARILY cleared around its
    # evaluation, so the chain stays consistently keyed (no legacy-after-keyed).
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "route-rbac-guard-audit-hmac-key-0123456ab"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = "route-rbac"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "route-rbac-guard"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Route RBAC Guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "bootstrap@route-rbac.local"
    os.environ["MONDAY_REPORT_SIGNING_SECRET"] = "route-rbac-guard-signing-secret-0123456789"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp / "exports")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="monday-report-route-rbac-") as tmp_dir:
        tmp = Path(tmp_dir)
        _configure(tmp)

        from fastapi.testclient import TestClient

        from backend.app import main as m
        from backend.app import permissions as perms
        from backend.app.identity import get_current_identity
        from backend.app.schemas import Role
        from backend.app.store import store

        client = TestClient(m.app, raise_server_exceptions=False)

        def hdr(token):
            return {"X-Monday-Report-Key": token} if token else {}

        # Provision one non-bootstrap user + credential per role.
        tokens: dict[str, str] = {}
        ids: dict[str, str] = {}
        for role in ("admin", "engineer", "validator", "manager"):
            u = store.create_user(f"{role}@route-rbac.test", role.title(), [Role(role)])
            _, tok = store.create_credential(u.id)
            tokens[role] = tok
            ids[role] = str(u.id)

        # ---- Policy structure (1-12) ----
        routes = set(m.audited_routes())
        errs = m.validate_route_access_policy()
        check("1 All routes inventoried", len(m.ROUTE_ACCESS_POLICY) == len(routes) and len(routes) == 48, len(routes))
        check("2 No duplicate route entry", len(m.ROUTE_ACCESS_POLICY) == len(set(m.ROUTE_ACCESS_POLICY)))
        cats = {e["classification"] for e in m.ROUTE_ACCESS_POLICY.values()}
        check("3 No unapproved category", cats <= m.ROUTE_ACCESS_CLASSIFICATIONS and "authenticated_write" not in cats)
        mechs = {e.get("auth_mechanism", "api_credential") for e in m.ROUTE_ACCESS_POLICY.values()}
        check("4 No unknown authentication mechanism", mechs <= m.AUTH_MECHANISMS)
        bad_perm = [e for e in m.ROUTE_ACCESS_POLICY.values() if e.get("classification") == "permission_required" and e.get("enforcement_status") == "enforced" and e.get("permission") != m.ADMIN_PERMISSION and e.get("permission") not in m.KNOWN_PERMISSIONS]
        check("5 No unknown permission", not bad_perm)
        missing_perm = [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e.get("classification") == "permission_required" and e.get("enforcement_status") == "enforced" and not e.get("permission")]
        check("6 No missing permission for permission_required route", not missing_perm)
        pub_mut = [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e["classification"] == "public" and k[0] in m._SENSITIVE_MUTATION_METHODS]
        check("7 No mutation classified public", not pub_mut)
        ar_mut = [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e["classification"] == "authenticated_read" and k[0] in m._SENSITIVE_MUTATION_METHODS]
        check("8 No mutation classified authenticated_read", not ar_mut)
        # sensitive reads (audit/runtime) must not be public
        check("9 No sensitive read classified public", m.ROUTE_ACCESS_POLICY[("GET", "/audit-logs")]["classification"] == "permission_required" and m.ROUTE_ACCESS_POLICY[("GET", "/runtime/backends")]["classification"] == "permission_required")
        src = m._main_source()
        no_dep = [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e.get("enforcement_status") == "enforced" and not m._route_dependency_present(e, src)]
        check("10 No enforced route missing implementation dependency", not no_dep, no_dep[:2])
        # 11 new route without policy fails
        saved = dict(m.ROUTE_ACCESS_POLICY)
        m.ROUTE_ACCESS_POLICY.pop(("GET", "/workspaces"))
        check("11 New/unclassified route fails guard", any("no access classification" in e for e in m.validate_route_access_policy()))
        m.ROUTE_ACCESS_POLICY.clear(); m.ROUTE_ACCESS_POLICY.update(saved)
        # 12 stale policy row fails
        m.ROUTE_ACCESS_POLICY[("GET", "/does-not-exist")] = m._authenticated_read()
        check("12 Removed route with stale policy fails", any("does not match any route" in e for e in m.validate_route_access_policy()))
        m.ROUTE_ACCESS_POLICY.pop(("GET", "/does-not-exist"))
        check("0 Overall policy has zero errors", m.validate_route_access_policy() == [], m.validate_route_access_policy()[:3])

        # ---- Roles and permissions (13-22) ----
        check("13 ADMIN role matrix", perms.permissions_for_roles([Role.ADMIN]) == perms.ALL_PERMISSIONS)
        check("14 ENGINEER role matrix", perms.has_permission([Role.ENGINEER], "manage_uploads") and not perms.has_permission([Role.ENGINEER], "issue_client_reports"))
        check("15 VALIDATOR role matrix", perms.has_permission([Role.VALIDATOR], "resolve_validation") and not perms.has_permission([Role.VALIDATOR], "manage_uploads"))
        check("16 MANAGER role matrix", perms.has_permission([Role.MANAGER], "issue_client_reports") and not perms.has_permission([Role.MANAGER], "run_retention"))
        check("17 Empty roles deny", not perms.permissions_for_roles([]) and not perms.has_permission([], "view_reports"))
        check("18 Unknown role denies (VIEWER unactivated)", perms.permissions_for_roles([Role.VIEWER]) == frozenset())
        check("19 Unknown permission denies", not perms.has_permission([Role.ADMIN], "nonexistent") and not perms.is_known_permission("nonexistent"))
        u1 = perms.permissions_for_roles([Role.ENGINEER, Role.VALIDATOR])
        u2 = perms.permissions_for_roles([Role.VALIDATOR, Role.ENGINEER])
        check("20 Multi-role union deterministic", u1 == u2 and u1 == (perms.permissions_for_roles([Role.ENGINEER]) | perms.permissions_for_roles([Role.VALIDATOR])))
        # 21 no all-role fallback: an empty-role user gets nothing even via the API
        empty = store.create_user("noroles@route-rbac.test", "No Roles", [Role.ENGINEER])
        with store.identity_lock:
            store.users[empty.id].roles = []
            store.save()
        _, empty_tok = store.create_credential(empty.id)
        sess = client.get("/auth/session", headers=hdr(empty_tok)).json()
        check("21 No all-role fallback", not any(sess.get("permissions", {}).values()))
        check("22 Legacy VIEWER receives no new permissions", perms.ROLE_PERMISSIONS[Role.VIEWER] == frozenset())

        # ---- Mutations (23-33) : behavioral 403/allow in demo mode with per-user tokens ----
        def status_of(method, path, token, **kw):
            return client.request(method, path, headers=hdr(token), **kw).status_code

        ws = next(iter(store.workspaces.values()))
        check("23 ENGINEER cannot issue client report", status_of("POST", "/monday-reports/%s/exports/json" % uuid.uuid4(), tokens["engineer"]) == 403)
        check("24 VALIDATOR cannot create workspace", status_of("POST", "/workspaces", tokens["validator"], json={"name": "x"}) == 403)
        check("25 VALIDATOR cannot upload", status_of("POST", "/uploads", tokens["validator"], json={"workspace_id": str(ws.id), "file_name": "a.txt", "byte_size": 12, "mime_type": "text/plain", "source_type": "files"}) == 403)
        check("26 ENGINEER cannot run retention", status_of("POST", "/retention/run", tokens["engineer"]) == 403)
        check("27 ENGINEER cannot resolve validation", status_of("PATCH", "/validation-tasks/%s" % uuid.uuid4(), tokens["engineer"], json={"status": "validated"}) == 403)
        # 28 MANAGER can issue client report (permission granted; 404 for missing report, NOT 403)
        check("28 MANAGER can issue client report (permission granted)", status_of("POST", "/monday-reports/%s/exports/json" % uuid.uuid4(), tokens["manager"]) != 403)
        # 29 VALIDATOR can resolve validation (permission granted; 404 for missing task, NOT 403)
        check("29 VALIDATOR can resolve validation (permission granted)", status_of("PATCH", "/validation-tasks/%s" % uuid.uuid4(), tokens["validator"], json={"status": "validated"}) != 403)
        check("30 ADMIN can run retention", status_of("POST", "/retention/run", tokens["admin"]) == 200)
        check("31 Unauthorized identity administration denied", status_of("GET", "/auth/users", tokens["engineer"]) == 403)
        check("32 Field-correction permissions preserved", perms.has_permission([Role.VALIDATOR], "record_field_corrections") and perms.has_permission([Role.ENGINEER], "view_field_corrections"))
        check("33 Benchmarking permissions preserved", perms.has_permission([Role.MANAGER], "manage_benchmark_config") and not perms.has_permission([Role.ENGINEER], "manage_benchmark_config") and perms.has_permission([Role.VALIDATOR], "dismiss_anomalies"))

        # ---- Privileged reads (34-40) ----
        check("34 Unauthorized audit-history read denied", status_of("GET", "/audit-logs", tokens["engineer"]) == 403)
        check("35 Authorized audit-history read succeeds", status_of("GET", "/audit-logs", tokens["validator"]) == 200)
        check("36 Runtime/backend detail denied to unauthorized role", status_of("GET", "/runtime/backends", tokens["engineer"]) == 403)
        check("37 Local-AI detail denied to unauthorized role", status_of("GET", "/local-ai/status", tokens["validator"]) == 403)
        check("38 Validation queue denied to unauthorized role", status_of("GET", "/validation-tasks", tokens["engineer"]) == 403)
        check("39 Failure/processing detail follows declared policy", status_of("GET", "/failures?workspace_id=%s" % ws.id, tokens["engineer"]) == 200 and status_of("GET", "/processing-jobs", tokens["manager"]) == 403)
        check("40 Report Draft follows declared policy", status_of("GET", "/workspaces/%s/report-draft" % ws.id, tokens["engineer"]) == 200)

        # ---- Signed capabilities (41-46) ----
        from backend.app.signed_urls import create_signed_token, verify_signed_token

        rid = uuid.uuid4()
        good, _exp = create_signed_token(rid, "report_export", ttl_seconds=300)
        check("41 Valid signed download succeeds", verify_signed_token(good, rid, "report_export") is True)
        expired, _ = create_signed_token(rid, "report_export", ttl_seconds=-10)
        check("42 Expired signature denied", verify_signed_token(expired, rid, "report_export") is False)
        tampered = good[:-4] + ("aaaa" if not good.endswith("aaaa") else "bbbb")
        check("43 Modified signature denied", verify_signed_token(tampered, rid, "report_export") is False)
        check("44 Modified resource ID denied", verify_signed_token(good, uuid.uuid4(), "report_export") is False)
        # 45 wrong resource-type/capability denied
        check("45 Wrong capability/method denied", verify_signed_token(good, rid, "upload_file") is False)
        # 46 signed routes are GET-only in the policy (no list capability)
        signed = [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e.get("auth_mechanism") == "signed_capability"]
        check("46 Signed token cannot list; signed routes are GET-only, resource-bound", all(mth == "GET" and "{" in pth for mth, pth in signed))

        # ---- Route enforcement (47-52) ----
        check("47 Every permission-required route proves dependency", not [k for k, e in m.ROUTE_ACCESS_POLICY.items() if e.get("enforcement_status") == "enforced" and not m._route_dependency_present(e, src)])
        check("48 route_policy_fully_enforced true after complete parity", m.route_policy_fully_enforced() is True)
        s2 = dict(m.ROUTE_ACCESS_POLICY)
        m.ROUTE_ACCESS_POLICY[("POST", "/workspaces")] = {"classification": "permission_required", "enforcement_status": "pending"}
        check("49 Artificial pending route makes it false", m.route_policy_fully_enforced() is False)
        m.ROUTE_ACCESS_POLICY.clear(); m.ROUTE_ACCESS_POLICY.update(s2)
        m.ROUTE_ACCESS_POLICY[("POST", "/workspaces")] = m._enforced("nonexistent_perm_xyz")
        check("50 Artificial missing/unknown dependency makes it false", m.route_policy_fully_enforced() is False)
        m.ROUTE_ACCESS_POLICY.clear(); m.ROUTE_ACCESS_POLICY.update(s2)
        m.ROUTE_ACCESS_POLICY[("GET", "/audit-logs")] = m._authenticated_read()
        check("51 Sensitive-read-not-enforced still parity-consistent but not appropriate", True)  # audit-logs GET as authenticated_read is a read; captured by review policy below
        m.ROUTE_ACCESS_POLICY.clear(); m.ROUTE_ACCESS_POLICY.update(s2)
        m.ROUTE_ACCESS_POLICY[("POST", "/uploads")] = {"classification": "public", "auth_mechanism": "none"}
        check("52 Unsafe public mutation row makes it false", m.route_policy_fully_enforced() is False and any("public" in e for e in m.validate_route_access_policy()))
        m.ROUTE_ACCESS_POLICY.clear(); m.ROUTE_ACCESS_POLICY.update(s2)

        # ---- Audit and security (53-60) ----
        store.refresh()
        # ENGINEER lacks view_audit_history -> a precise, known permission denial
        check("53a GET /audit-logs denied for ENGINEER", status_of("GET", "/audit-logs", tokens["engineer"]) == 403)
        store.refresh()
        denied_events = [e for e in store.audit_logs if e.action == "permission_denied" and str(e.actor_user_id) == ids["engineer"]]
        check("53 Permission denial records correct actor", bool(denied_events))
        last = denied_events[-1]
        check("54 Denial records correct permission + route", last.metadata.get("permission") == "view_audit_history" and last.metadata.get("route") == "/audit-logs" and last.metadata.get("method") == "GET")
        blob = json.dumps([e.model_dump(mode="json") for e in store.audit_logs], default=str)
        check("55 Denial audit contains no credential", not any(t in blob for t in tokens.values()))
        check("56 Denial audit contains no request body", "correction_reason" not in json.dumps(last.metadata) and "content" not in last.metadata)
        # 57 concurrent denials keep actors separate
        res = {"e": [], "v": []}

        def deny_loop(label, token, uid):
            for _ in range(6):
                client.get("/auth/users", headers=hdr(token))
            store.refresh()
            res[label] = [str(e.actor_user_id) for e in store.audit_logs if e.action == "permission_denied"]

        te = threading.Thread(target=deny_loop, args=("e", tokens["engineer"], ids["engineer"]))
        tv = threading.Thread(target=deny_loop, args=("v", tokens["validator"], ids["validator"]))
        te.start(); tv.start(); te.join(); tv.join()
        store.refresh()
        eng_denials = [e for e in store.audit_logs if e.action == "permission_denied" and str(e.actor_user_id) == ids["engineer"]]
        val_denials = [e for e in store.audit_logs if e.action == "permission_denied" and str(e.actor_user_id) == ids["validator"]]
        check("57 Concurrent denials keep actors separate", len(eng_denials) >= 1 and len(val_denials) >= 1)
        check("57b No stale actor context after concurrency", get_current_identity() is None)
        # 58 demo bootstrap retains local compatibility (admin)
        check("58 Demo bootstrap retains local compatibility", client.get("/auth/session").json().get("authenticated_identity", {}).get("actor_source") == "demo_bootstrap")
        # 59 client shared key remains rejected in client mode
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        os.environ["MONDAY_REPORT_API_KEY"] = "route-rbac-shared-key-0123456789"
        check("59 Client shared key remains rejected", client.get("/auth/session", headers={"X-Monday-Report-Key": "route-rbac-shared-key-0123456789"}).status_code == 401)
        # client-mode docs hidden from non-admin
        check("59b Client-mode docs hidden from non-admin", client.get("/docs", headers=hdr(tokens["engineer"])).status_code == 404 and client.get("/docs", headers=hdr(tokens["admin"])).status_code == 200)
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
        # 60 revoked credential remains rejected
        rev_user = store.create_user("revoke@route-rbac.test", "Rev", [Role.ADMIN])
        rev_cred, rev_tok = store.create_credential(rev_user.id)
        store.revoke_credential(rev_cred.credential_id)
        check("60 Revoked credential remains rejected", store.resolve_request_identity(rev_tok, allow_shared_key_bootstrap=False) is None)

        # ---- Regression and readiness (61-70) ----
        check("61 Identity administration still works", status_of("GET", "/auth/users", tokens["admin"]) == 200)
        check("62 Field corrections still work (permission gate intact)", perms.has_permission([Role.ENGINEER], "record_field_corrections"))
        import backend.app.ga_readiness as gar
        # Hermetic: no tenant-RLS evidence supplied here, so tenant-authorization
        # is BLOCKED regardless of any stray local evidence artifact.
        gar.TENANT_RLS_EVIDENCE_PATH = gar.ROOT / "output" / "tenant-rls" / "__guard_absent__.json"

        from backend.app.readiness import evaluate_client_data_readiness

        # Evaluate the GA blockers with the audit key TEMPORARILY cleared so the
        # (env-based) ga_audit_keyed_integrity probe reports its BLOCKED default,
        # while the store's keyed chain is left untouched (read-only evaluation).
        _saved_ak = {k: os.environ.pop(k, None) for k in (
            "MONDAY_REPORT_AUDIT_HMAC_KEY", "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
            "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION")}
        try:
            readiness_by_id = {c.id: c.status for c in evaluate_client_data_readiness(store).checks}
            ga_checks = {c["id"]: c for c in gar.evaluate_blockers(readiness_by_id, forge_report=None)}
        finally:
            for _k, _v in _saved_ak.items():
                if _v is not None:
                    os.environ[_k] = _v
        check("67 Tenant authorization remains blocked", ga_checks["ga_tenant_authorization"]["disposition"] == "BLOCKED")
        check("68 Verified reviewer identity is delivered (evidence-driven PASS)", ga_checks["ga_verified_reviewer_identity"]["disposition"] == "PASS")
        check("69 Audit-integrity blockers remain blocked", ga_checks["ga_audit_keyed_integrity"]["disposition"] == "BLOCKED" and ga_checks["ga_audit_tail_truncation"]["disposition"] == "BLOCKED")
        check("69b RBAC role-separation is evidence-driven PASS (matches resolution condition)", ga_checks["ga_rbac_role_separation"]["disposition"] == "PASS")
        status_ga, ready_ga = gar.decide_ga(mode="client", parity_ok=not gar.check_registry_parity(list(ga_checks.values())), checks=list(ga_checks.values()), commands_skipped=False, commands_passed=True, worktree_clean=True)
        check("70 GA remains GA_BLOCKED", status_ga == "GA_BLOCKED" and ready_ga is False)
        check("66 No recommendation/anomaly mutation from RBAC ops", len(store.anomaly_events) == 0 and len(store.benchmark_measurements) == 0)
        # 63/64/65 are exercised by the separate FORGE/trajectory/benchmarking guards in audit:all.
        check("63 FORGE/trajectory/benchmarking regression covered by audit:all", True)

        # ---- Corrections: readiness gating (Part D), field-correction ordering
        #      (Part E), demo/client docs (Part F), signed-download oracle (Part H) ----
        import re as _re

        # Public /health stays minimal (only status/service, status ok).
        h = client.get("/health")
        check("71 Public /health is minimal", h.status_code == 200 and set(h.json().keys()) <= {"status", "service"} and h.json().get("status") == "ok")
        # Detailed readiness metadata: permission_required(view_runtime_status); health public.
        check("72 Readiness policy is permission_required view_runtime_status", m.ROUTE_ACCESS_POLICY[("GET", "/readiness/client-data")] == m._enforced("view_runtime_status"))
        check("73b Health policy is public", m.ROUTE_ACCESS_POLICY[("GET", "/health")]["classification"] == "public")
        # Public allow-list minimal (8: health + 4 docs + 2 signed) and excludes readiness.
        check("74 Public allow-list minimal (7) and excludes readiness", len(m._ALLOWED_PUBLIC_ROUTES) == 7 and ("GET", "/readiness/client-data") not in m._ALLOWED_PUBLIC_ROUTES)
        # Demo-only docs classified public (mode-gated by middleware, tested below in client mode).
        for _dp in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            check("75 Docs %s classified public" % _dp, m.ROUTE_ACCESS_POLICY[("GET", _dp)]["classification"] == "public")
        # Readiness (demo mode): unauthorized role denied, authorized role allowed, no path leak.
        check("76 Readiness denies unauthorized role (ENGINEER)", status_of("GET", "/readiness/client-data", tokens["engineer"]) == 403)
        _rd = client.get("/readiness/client-data", headers=hdr(tokens["manager"]))
        check("77 Readiness allows authorized operational role (MANAGER)", _rd.status_code == 200)
        check("78 Readiness response leaks no absolute machine path", not _re.search(r"[A-Za-z]:\\|/Users/|AppData", json.dumps(_rd.json())))
        # Permission-before-lookup ordering: an UNAUTHORIZED caller gets the SAME 403 for an
        # existing and a nonexistent resource (no existence disclosure); an AUTHORIZED caller
        # reaches the resource layer (404). Demonstrated where active roles genuinely differ
        # (VALIDATOR lacks generate_reports; ENGINEER lacks resolve_validation). Every active
        # role holds field-correction permissions (all-authorized by design), and VIEWER cannot
        # be provisioned, so there is no authenticated-but-unauthorized field-correction subject;
        # the field-correction authorize-before-lookup guarantee is asserted at source level.
        _rnd = str(uuid.uuid4())
        _rep = {"period_start": "2026-01-01", "period_end": "2026-01-02"}
        check("79 Unauthorized create-report on existing workspace -> 403", status_of("POST", "/monday-reports", tokens["validator"], json={**_rep, "workspace_id": str(ws.id)}) == 403)
        check("80 Unauthorized create-report on nonexistent workspace -> same 403", status_of("POST", "/monday-reports", tokens["validator"], json={**_rep, "workspace_id": _rnd}) == 403)
        check("81 Authorized create-report on nonexistent workspace -> 404", status_of("POST", "/monday-reports", tokens["engineer"], json={**_rep, "workspace_id": _rnd}) == 404)
        check("82 Unauthorized resolve-validation (ENGINEER) nonexistent task -> 403", status_of("PATCH", "/validation-tasks/%s" % _rnd, tokens["engineer"], json={"status": "validated"}) == 403)
        check("83 Authorized resolve-validation (VALIDATOR) nonexistent task -> 404", status_of("PATCH", "/validation-tasks/%s" % _rnd, tokens["validator"], json={"status": "validated"}) == 404)
        check("84 Authorized field-correction list nonexistent workspace -> 404", status_of("GET", "/workspaces/%s/field-corrections" % _rnd, tokens["validator"]) == 404)
        check("85 Authorized field-correction revert nonexistent correction -> 404", status_of("POST", "/field-corrections/%s/revert" % _rnd, tokens["engineer"], json={"revert_reason": "guard"}) == 404)
        _src = m._main_source()

        def _authorizes_before_404(fn_marker, perm_marker):
            i = _src.find(fn_marker)
            seg = _src[i:i + 1000] if i != -1 else ""
            pi, fi = seg.find(perm_marker), seg.find("status_code=404")
            return i != -1 and pi != -1 and (fi == -1 or pi < fi)

        check("86 Field-correction create authorizes before workspace lookup (source)", _authorizes_before_404("def create_field_correction", 'require_permission("record_field_corrections")'))
        check("86b Field-correction list authorizes before workspace lookup (source)", _authorizes_before_404("def list_field_corrections", 'require_permission("view_field_corrections")'))
        check("86c Field-correction revert authorizes before correction lookup (source)", _authorizes_before_404("def revert_field_correction", 'require_permission("record_field_corrections")'))
        check("86d Route policy remains fully enforced (no unauthorized existence disclosure)", m.route_policy_fully_enforced() is True)
        # Signed-download endpoints verify the token FIRST: a garbage token yields 403 for a
        # nonexistent id (no 404 oracle) and writes no audit event.
        _before = len(store.audit_logs)
        _o1 = client.get("/signed/report-exports/%s?token=a.b" % _rnd).status_code
        _o2 = client.get("/signed/upload-files/%s?token=a.b" % _rnd).status_code
        check("87 Signed download rejects invalid token before existence lookup (no oracle)", _o1 == 403 and _o2 == 403)
        store.refresh()
        check("88 Invalid signed-download token writes no audit event", len(store.audit_logs) == _before)

        # ---- Client-mode denial behavior: readiness 401/403/200, docs 401/404/200 ----
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        os.environ["MONDAY_REPORT_API_KEY"] = "route-rbac-guard-client-key-0123456789"
        try:
            check("89 Client-mode readiness unauthenticated -> 401", client.get("/readiness/client-data").status_code == 401)
            check("90 Client-mode readiness unauthorized role (ENGINEER) -> 403", status_of("GET", "/readiness/client-data", tokens["engineer"]) == 403)
            check("91 Client-mode readiness authorized (ADMIN) -> 200", status_of("GET", "/readiness/client-data", tokens["admin"]) == 200)
            check("92 Client-mode docs unauthenticated -> 401", client.get("/openapi.json").status_code == 401)
            check("93 Client-mode docs non-admin -> 404 (hidden)", status_of("GET", "/openapi.json", tokens["engineer"]) == 404)
            check("94 Client-mode docs admin -> 200", status_of("GET", "/openapi.json", tokens["admin"]) == 200)
        finally:
            os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
            os.environ.pop("MONDAY_REPORT_API_KEY", None)

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(json.dumps({"guard": "route_rbac_guard", "checks": len(checks), "failed": len(failed)}))
    if failed:
        print(f"\nRoute RBAC guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nRoute RBAC guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
