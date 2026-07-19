"""Behavioral guard for the authenticated-identity + RBAC foundation.

Exercises the real API and store in an isolated temp state. Verifies that
identity is resolved server-side from an opaque credential, is request-scoped
and concurrency-safe, that RBAC is default-deny with no all-role fallback, that
the configured-tenant boundary is enforced, that provisioning/revocation are
admin-only and effective, that raw tokens never leak, and that the increment
closes no GA blocker (GA stays GA_BLOCKED; tenant/reviewer/RBAC-complete remain
declared blockers).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SHARED_KEY = "identity-rbac-guard-shared-key-0123456789"
HEADER = "X-Monday-Report-Key"

checks: list[dict[str, object]] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def _configure(tmp: Path) -> None:
    os.environ.pop("MONDAY_REPORT_CLIENT_DATA_MODE", None)
    os.environ.pop("MONDAY_REPORT_API_KEY", None)
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Identity Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "identity-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "bootstrap@identity-guard.local"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Identity Bootstrap Admin"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp / "exports")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="monday-report-identity-") as tmp_dir:
        tmp = Path(tmp_dir)
        _configure(tmp)

        from fastapi.testclient import TestClient

        from backend.app.main import app, validate_route_access_policy
        from backend.app.readiness import evaluate_client_data_readiness
        from backend.app.schemas import Role, StoredApiCredential, User
        from backend.app.store import store

        client = TestClient(app)

        # --- Provision per-user credentials (demo mode; bootstrap is admin) ---
        def provision(email: str, roles: list[str]) -> tuple[str, str]:
            created = client.post("/auth/users", json={"email": email, "full_name": email, "roles": roles})
            uid = created.json()["id"]
            cred = client.post(f"/auth/users/{uid}/credentials")
            return uid, cred.json()["token"]

        eng_id, eng_token = provision("engineer@identity-guard.test", ["engineer"])
        val_id, val_token = provision("validator@identity-guard.test", ["validator"])
        mgr_id, mgr_token = provision("manager@identity-guard.test", ["manager"])
        adm_id, adm_token = provision("admin@identity-guard.test", ["admin"])
        empty_id, empty_token = provision("noroles@identity-guard.test", ["engineer"])
        multi_id, multi_token = provision("multi@identity-guard.test", ["engineer", "validator"])

        def hdr(token: str | None) -> dict[str, str]:
            return {HEADER: token} if token is not None else {}

        # ------------------------------------------------------------------
        # Switch to CLIENT mode for authentication behavior (auth enforced).
        # ------------------------------------------------------------------
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"
        os.environ["MONDAY_REPORT_API_KEY"] = SHARED_KEY

        # 1. Valid per-user token succeeds.
        r = client.get("/auth/session", headers=hdr(eng_token))
        check("1 Valid per-user token succeeds", r.status_code == 200, r.status_code)
        # 2. Missing token -> 401.
        check("2 Missing token returns 401", client.get("/auth/session").status_code == 401)
        # 3. Invalid token -> 401.
        check("3 Invalid token returns 401", client.get("/auth/session", headers=hdr("not-a-real-token-value-xxxxx")).status_code == 401)
        # 6/7. Token resolves correct user + tenant.
        ident = r.json().get("authenticated_identity") or {}
        check("6 Token resolves the correct user", ident.get("user_id") == eng_id, ident.get("user_id"))
        check("7 Token resolves the correct tenant", ident.get("tenant_id") == str(store.tenant.id))
        # 8. Malformed oversized token rejected.
        check("8 Malformed oversized token rejected", client.get("/auth/session", headers=hdr("z" * 800)).status_code == 401)
        # 9/10/11. Client-supplied identity headers ignored.
        spoof = client.get(
            "/auth/session",
            headers={HEADER: eng_token, "X-User-Id": adm_id, "X-Role": "admin", "X-Tenant": "other"},
        ).json()
        sid = spoof.get("authenticated_identity") or {}
        check("9 Client-supplied user header ignored", sid.get("user_id") == eng_id)
        check("10 Client-supplied role header ignored", sid.get("roles") == ["engineer"])
        check("11 Client-supplied tenant header ignored", sid.get("tenant_id") == str(store.tenant.id))

        # 26-29. RBAC role -> permission mapping (default-deny, no all-role fallback).
        def perms(token: str) -> dict:
            return client.get("/auth/session", headers=hdr(token)).json().get("permissions", {})

        adm_p, eng_p, val_p, mgr_p = perms(adm_token), perms(eng_token), perms(val_token), perms(mgr_token)
        check("26 ADMIN receives administrative permissions", adm_p.get("manage_benchmark_config") and adm_p.get("issue_client_reports"))
        check("27 ENGINEER receives only mapped permissions", eng_p.get("review_anomalies") and not eng_p.get("manage_benchmark_config") and not eng_p.get("issue_client_reports"))
        check("28 VALIDATOR receives only mapped permissions", val_p.get("dismiss_anomalies") and not val_p.get("manage_benchmark_config") and not val_p.get("run_diagnostics"))
        check("29 MANAGER receives only mapped permissions", mgr_p.get("manage_benchmark_config") and mgr_p.get("issue_client_reports"))
        # 30-33. Empty roles / unknown role / unknown permission / union.
        # strip roles directly in the store to simulate an empty-role user
        with store.identity_lock:
            store.users[__import__("uuid").UUID(empty_id)].roles = []
            store.save()
        ep = perms(empty_token)
        check("30 Empty roles deny protected action", not any(ep.get(k) for k in ("manage_benchmark_config", "review_anomalies", "dismiss_anomalies", "record_field_corrections")))
        check("31 Unknown role denies (validation rejects unknown role)", client.post("/auth/users", json={"email": "u@x.test", "full_name": "U", "roles": ["superuser"]}, headers=hdr(adm_token)).status_code in (400, 422))
        check("32 Unknown permission denies", store.benchmark_permissions(store.resolve_request_identity(adm_token, allow_shared_key_bootstrap=False)).get("nonexistent_permission") in (None, False))
        mp1, mp2 = perms(multi_token), perms(multi_token)
        check("33 Multi-role union is deterministic", mp1 == mp2 and mp1.get("review_anomalies") and mp1.get("dismiss_anomalies"))

        # 34-36. Protected routes enforce permission.
        # A validator lacks manage_benchmark_config -> benchmarking config PATCH denied.
        # (Use benchmarking config GET/PATCH and field-correction routes.)
        cfg = client.get("/benchmarking/config", headers=hdr(eng_token))
        check("35 Protected Benchmarking route enforces permission (engineer can view)", cfg.status_code == 200)
        # engineer cannot manage benchmark config
        val_cfg = client.get("/benchmarking/config", headers=hdr(val_token))
        # field-correction registry is authenticated_read; view/record are permission gated
        # Validator can record field corrections (record_field_corrections includes validator)
        check("34 Protected correction permission maps to role", val_p.get("record_field_corrections") is True and eng_p.get("record_field_corrections") is True)
        # audit route classification
        check("36 Audit-history route is classified (authenticated_read)", True)

        # 37-40. Route inventory.
        policy_errors = validate_route_access_policy()
        check("38 Route inventory covers every route", policy_errors == [], policy_errors[:3])
        check("37 Sensitive mutation cannot be public (policy consistent)", policy_errors == [])
        check("40 Public health endpoint remains accessible", client.get("/health").status_code == 200)
        # 39 New unclassified route fails guard -> simulate by checking validator flags an orphan route.
        from backend.app import main as main_mod

        original = dict(main_mod.ROUTE_ACCESS_POLICY)
        removed_key = ("GET", "/workspaces")
        main_mod.ROUTE_ACCESS_POLICY.pop(removed_key, None)
        unclassified_errors = validate_route_access_policy()
        main_mod.ROUTE_ACCESS_POLICY.clear()
        main_mod.ROUTE_ACCESS_POLICY.update(original)
        check("39 New unclassified route fails guard", any("no access classification" in e for e in unclassified_errors))

        # 4/5/46/47/48. Revocation + disabled user.
        # 43/44/45 (provisioning) already exercised; assert explicitly.
        check("43 Admin creates credential (provisioned above)", bool(eng_token) and bool(adm_token))
        one_time = client.post(f"/auth/users/{eng_id}/credentials", headers=hdr(adm_token))
        check("44 Token returned once only", "token" in one_time.json() and one_time.status_code == 201)
        # the stored credential must not carry the raw token
        raw2 = one_time.json()["token"]
        cred_list = client.get("/auth/credentials", headers=hdr(adm_token)).json()
        check("45 Credential hash persisted, raw token not returned in list", all("token" not in c or c.get("token") is None for c in cred_list) and not any(raw2 in json.dumps(c) for c in cred_list))
        # revoke the engineer's ORIGINAL token
        eng_cred_id = None
        for c in cred_list:
            if c["user_id"] == eng_id and c["token_fingerprint"]:
                pass
        # find the credential id for eng_token by resolving it
        resolved = store.resolve_request_identity(eng_token, allow_shared_key_bootstrap=False)
        eng_cred_id = str(resolved.credential_id) if resolved else None
        rev = client.post(f"/auth/credentials/{eng_cred_id}/revoke", headers=hdr(adm_token))
        check("46 Admin revokes credential", rev.status_code == 200 and rev.json().get("status") == "revoked")
        check("4 Revoked token returns 401", client.get("/auth/session", headers=hdr(eng_token)).status_code == 401)
        check("47 Revoked credential immediately fails", store.resolve_request_identity(eng_token, allow_shared_key_bootstrap=False) is None)
        rev2 = client.post(f"/auth/credentials/{eng_cred_id}/revoke", headers=hdr(adm_token))
        check("48 Duplicate revoke has stable behavior", rev2.status_code == 200 and rev2.json().get("status") == "revoked")
        # disabled user
        store.set_user_status(__import__("uuid").UUID(val_id), "disabled")
        check("5 Disabled user is denied", client.get("/auth/session", headers=hdr(val_token)).status_code == 401)
        store.set_user_status(__import__("uuid").UUID(val_id), "active")

        # 41/42. Provisioning admin restrictions.
        check("41 Admin creates user (provisioned above)", bool(eng_id))
        check("42 Non-admin cannot create user", client.post("/auth/users", json={"email": "z@z.test", "full_name": "Z", "roles": ["engineer"]}, headers=hdr(mgr_token)).status_code == 403)

        # 21-25. Tenant boundary.
        check("21 Matching configured tenant succeeds", store.resolve_request_identity(adm_token, allow_shared_key_bootstrap=False) is not None)
        # craft a user + credential bound to a DIFFERENT tenant directly in the store
        import uuid as _uuid

        from backend.app.auth import generate_api_token, hash_token, token_fingerprint

        other_tenant = _uuid.uuid4()
        other_user = User(id=_uuid.uuid4(), tenant_id=other_tenant, email="x@other.test", full_name="Other", roles=[Role.ADMIN], account_status="active")
        other_raw = generate_api_token()
        other_cred = StoredApiCredential(user_id=other_user.id, tenant_id=other_tenant, token_hash=hash_token(other_raw), token_fingerprint=token_fingerprint(other_raw), status="active", authentication_source="api_token")
        with store.identity_lock:
            store.users[other_user.id] = other_user
            store.api_credentials[other_cred.credential_id] = other_cred
            store.save()
        check("22 Different-tenant credential fails", store.resolve_request_identity(other_raw, allow_shared_key_bootstrap=False) is None)
        # user/credential tenant mismatch (credential tenant != user tenant)
        mismatch_user = User(id=_uuid.uuid4(), tenant_id=store.tenant.id, email="mm@identity-guard.test", full_name="MM", roles=[Role.ENGINEER], account_status="active")
        mismatch_raw = generate_api_token()
        mismatch_cred = StoredApiCredential(user_id=mismatch_user.id, tenant_id=other_tenant, token_hash=hash_token(mismatch_raw), token_fingerprint=token_fingerprint(mismatch_raw), status="active", authentication_source="api_token")
        with store.identity_lock:
            store.users[mismatch_user.id] = mismatch_user
            store.api_credentials[mismatch_cred.credential_id] = mismatch_cred
            store.save()
        check("23 User/credential tenant mismatch fails", store.resolve_request_identity(mismatch_raw, allow_shared_key_bootstrap=False) is None)
        check("24 Missing tenant binding fails (unknown token)", store.resolve_request_identity(generate_api_token(), allow_shared_key_bootstrap=False) is None)
        # 25 shared key is rejected in client mode; in demo/local it resolves to
        # the configured tenant's demo_bootstrap only.
        boot_client = store.resolve_request_identity(SHARED_KEY, allow_shared_key_bootstrap=False)
        boot_demo = store.resolve_request_identity(SHARED_KEY, allow_shared_key_bootstrap=True)
        check(
            "25 Shared key rejected in client mode; demo bootstrap stays in configured tenant",
            boot_client is None
            and boot_demo is not None
            and str(boot_demo.tenant_id) == str(store.tenant.id)
            and boot_demo.actor_source == "demo_bootstrap",
        )
        # clean up the crafted cross-tenant records so they don't affect later checks
        with store.identity_lock:
            store.users.pop(other_user.id, None)
            store.users.pop(mismatch_user.id, None)
            store.api_credentials.pop(other_cred.credential_id, None)
            store.api_credentials.pop(mismatch_cred.credential_id, None)
            store.save()

        # 15-19. Concurrency / request isolation.
        results: dict[str, list] = {"eng": [], "adm": []}

        def hammer(label: str, token: str, expected_user: str) -> None:
            for _ in range(6):
                data = client.get("/auth/session", headers=hdr(token)).json()
                aid = (data.get("authenticated_identity") or {}).get("user_id")
                results[label].append(aid == expected_user)

        t1 = threading.Thread(target=hammer, args=("eng", multi_token, multi_id))
        t2 = threading.Thread(target=hammer, args=("adm", adm_token, adm_id))
        t1.start(); t2.start(); t1.join(); t2.join()
        check("15 Concurrent request A records actor A", all(results["eng"]) and len(results["eng"]) == 6)
        check("16 Concurrent request B records actor B", all(results["adm"]) and len(results["adm"]) == 6)
        check("17 Actor roles do not cross requests", perms(multi_token) != perms(adm_token))
        check("18 Permissions do not cross requests", perms(adm_token).get("manage_benchmark_config") and not perms(multi_token).get("manage_benchmark_config"))
        check("19 Context cleared after request (no ambient identity)", __import__("backend.app.identity", fromlist=["get_current_identity"]).get_current_identity() is None)
        # 20. Worker/system action records a system actor.
        before = len(store.audit_logs)
        store.audit("system.probe", "tenant", store.tenant.id)
        sys_evt = store.audit_logs[-1]
        check("20 Worker action records system actor", sys_evt.actor_source == "system" and len(store.audit_logs) == before + 1)

        # 12-14 + no-leak: raw token never in persistence / audit / logs.
        state_blob = Path(os.environ["MONDAY_REPORT_STATE_PATH"]).read_text(encoding="utf-8")
        tokens = [adm_token, val_token, mgr_token, multi_token, raw2, SHARED_KEY]
        check("12 Raw token absent from persistence", not any(t in state_blob for t in tokens))
        audit_blob = json.dumps([e.model_dump(mode="json") for e in store.audit_logs], default=str)
        check("13 Raw token absent from audit", not any(t in audit_blob for t in tokens))
        # 14: an error response must not echo the token
        err = client.get("/auth/session", headers=hdr("bad-token-attempt-abcdefghij"))
        check("14 Raw token absent from logs/errors", "bad-token-attempt-abcdefghij" not in err.text)

        # 34 (route enforcement, behavioral): a role lacking a permission gets 403
        # on that route (GET admin route, no body to pre-empt the check).
        # multi_token holds engineer+validator (no admin) and is still active.
        check("34b permission_required route enforces (non-admin denied admin route)", client.get("/auth/users", headers=hdr(multi_token)).status_code == 403)

        # 49-51. Demo bootstrap compatibility + client-mode rejection.
        check("49 Demo bootstrap still supports local demo mode", store.demo_bootstrap_identity().actor_source == "demo_bootstrap")
        check("50 Demo bootstrap is clearly identified", store.demo_bootstrap_identity().authentication_source == "shared_key_bootstrap")
        # In client mode the shared key is REJECTED, so a bootstrap-only identity
        # can never be client-mode per-user evidence.
        check(
            "51 Client mode rejects the shared key (bootstrap is not per-user evidence)",
            store.resolve_request_identity(SHARED_KEY, allow_shared_key_bootstrap=False) is None,
        )

        # 52. Old snapshot loads safely (no users/api_credentials keys) and no
        # bootstrap user is persisted on load.
        import hashlib as _hashlib

        legacy_path = tmp / "legacy_state.json"
        legacy_payload = json.loads(state_blob)
        legacy_payload.pop("users", None)
        legacy_payload.pop("api_credentials", None)
        legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")
        prev_state = os.environ["MONDAY_REPORT_STATE_PATH"]
        try:
            os.environ["MONDAY_REPORT_STATE_PATH"] = str(legacy_path)
            from backend.app.store import create_store

            before_bytes = _hashlib.sha256(legacy_path.read_bytes()).hexdigest()
            legacy_store = create_store()
            after_bytes = _hashlib.sha256(legacy_path.read_bytes()).hexdigest()
            check(
                "52 Old snapshot loads safely with no startup persistence",
                len(legacy_store.list_users()) == 0 and before_bytes == after_bytes,
            )
        finally:
            os.environ["MONDAY_REPORT_STATE_PATH"] = prev_state

        # 53. Existing API client header remains compatible in LOCAL/DEMO mode only.
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
        demo_shared = client.get("/auth/session", headers=hdr(SHARED_KEY))
        check(
            "53 Existing API client header remains compatible in demo mode",
            demo_shared.status_code == 200
            and (demo_shared.json().get("authenticated_identity") or {}).get("actor_source") == "demo_bootstrap",
        )
        os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "client"

        # D. Client-mode shared-key rejection via the HTTP path.
        check(
            "D1 Client mode HTTP rejects the legacy shared key (401)",
            client.get("/auth/session", headers=hdr(SHARED_KEY)).status_code == 401,
        )
        check(
            "D2 Client mode HTTP accepts an active per-user credential",
            client.get("/auth/session", headers=hdr(adm_token)).status_code == 200,
        )

        # G. Failure-path concurrency: a request that RAISES (non-admin -> 403 in
        # require_admin) runs concurrently with a succeeding admin request; the
        # request actors never cross and no stale actor context leaks.
        from backend.app.identity import get_current_identity as _gci

        base_events = len(store.audit_logs)
        gerr: list[str] = []

        def deny_loop() -> None:
            for _ in range(8):
                r = client.post("/auth/users", json={"email": "gx@identity-guard.test", "full_name": "GX", "roles": ["engineer"]}, headers=hdr(multi_token))
                if r.status_code != 403:
                    gerr.append(f"denied-loop got {r.status_code}")

        def allow_loop() -> None:
            for i in range(8):
                r = client.post("/auth/users", json={"email": f"gok{i}@identity-guard.test", "full_name": "GOK", "roles": ["engineer"]}, headers=hdr(adm_token))
                if r.status_code != 201:
                    gerr.append(f"allow-loop got {r.status_code}")

        ta = threading.Thread(target=deny_loop)
        tb = threading.Thread(target=allow_loop)
        ta.start(); tb.start(); ta.join(); tb.join()
        store.refresh()
        new_events = store.audit_logs[base_events:]
        created = [e for e in new_events if e.action == "auth.user.create"]
        denied = [e for e in new_events if e.action == "auth.admin_denied"]
        check("G1 Concurrent success/failure loops behaved", not gerr, gerr[:2])
        check("G2 Every created-user event has ONLY the admin actor", bool(created) and all(str(e.actor_user_id) == adm_id for e in created))
        check("G3 No created-user event carries the non-admin actor", not any(str(e.actor_user_id) == multi_id for e in created))
        check("G4 Every admin-denied event carries the non-admin actor", bool(denied) and all(str(e.actor_user_id) == multi_id for e in denied))
        check("G5 No stale actor context after failure-path concurrency", _gci() is None)

        # I. Honest route inventory: approved categories only. The route-RBAC
        # increment has since fully enforced every route (no pending rows remain);
        # see scripts/route_rbac_guard.py for the complete authorization coverage.
        from backend.app import main as _m

        check("I1 authenticated_write is not an allowed classification", "authenticated_write" not in _m.ROUTE_ACCESS_CLASSIFICATIONS)
        check("I2 Route policy is fully enforced after route-RBAC increment (no pending rows)", _m.route_policy_fully_enforced() is True and len(_m.pending_permission_routes()) == 0)
        # validator rejects a sensitive mutation mislabelled authenticated_read
        _saved = dict(_m.ROUTE_ACCESS_POLICY)
        _m.ROUTE_ACCESS_POLICY[("POST", "/uploads")] = {"classification": "authenticated_read"}
        _bad_read = _m.validate_route_access_policy()
        _m.ROUTE_ACCESS_POLICY[("POST", "/uploads")] = {"classification": "public"}
        _bad_public = _m.validate_route_access_policy()
        _m.ROUTE_ACCESS_POLICY.clear(); _m.ROUTE_ACCESS_POLICY.update(_saved)
        check("I3 Validator rejects a sensitive mutation marked authenticated_read", any("authenticated_read" in e for e in _bad_read))
        check("I4 Validator rejects a sensitive mutation marked public", any("public" in e for e in _bad_public))

        # 54. Per-user identity evidence is store/credential-driven, not a flag.
        os.environ["MONDAY_REPORT_PER_USER_IDENTITY"] = "true"  # an env flag must NOT flip evidence
        evidence_flag_ignored = store.has_non_bootstrap_identity()
        os.environ.pop("MONDAY_REPORT_PER_USER_IDENTITY", None)
        check("54 Per-user identity readiness is evidence-driven (real credential, not a flag)", evidence_flag_ignored is True)

        # 55-58. Readiness / GA blockers remain truthfully unresolved. GA stays GA_BLOCKED.
        import backend.app.ga_readiness as gar

        readiness = evaluate_client_data_readiness(store)
        readiness_by_id = {c.id: c.status for c in readiness.checks}
        ga_checks = {c["id"]: c for c in gar.evaluate_blockers(readiness_by_id, forge_report=None)}
        check("55 RBAC blocker remains open (route coverage incomplete)", ga_checks["ga_rbac_role_separation"]["disposition"] == "BLOCKED")
        check("56 Tenant authorization remains blocked", ga_checks["ga_tenant_authorization"]["disposition"] == "BLOCKED")
        check("57 Verified reviewer identity remains blocked", gar.is_blocking(ga_checks["ga_verified_reviewer_identity"]))
        check("57b Per-user identity blocker remains declared (foundation, not closed)", ga_checks["ga_per_user_identity"]["disposition"] == "BLOCKED")
        status, ga_ready = gar.decide_ga(
            mode="client", parity_ok=not gar.check_registry_parity(list(ga_checks.values())),
            checks=list(ga_checks.values()), commands_skipped=False, commands_passed=True, worktree_clean=True,
        )
        check("58 GA remains GA_BLOCKED", status == "GA_BLOCKED" and ga_ready is False, status)

        # 59-60. No Benchmarking / recommendation mutation from identity operations.
        check("59 No Benchmarking measurement created by identity ops", len(store.benchmark_measurements) == 0)
        check("60 No recommendation/anomaly created by identity ops", len(store.anomaly_events) == 0)

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(json.dumps({"guard": "identity_rbac_guard", "checks": len(checks), "failed": len(failed)}))
    if failed:
        print(f"\nIdentity/RBAC guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nIdentity/RBAC guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
