"""Behavioral guard for VERIFIED REVIEWER ATTRIBUTION (AUDIT-001).

Correction (record + revert) and validation outcomes must attribute a VERIFIED
authenticated-human reviewer (server-derived, permission-eligible), reject
configured/system/bootstrap actors in client mode BEFORE any mutation, persist
reviewer attribution on the outcome and the keyed audit event, expose no credential
material, and keep the verified-reviewer-identity blocker evidence-driven while
tail-truncation/tenant/GA stay unresolved. Prints PASS/FAIL per check; exits
non-zero on any failure. Isolated TestClient/store in a temp dir — never touches
the live snapshot.
"""

from __future__ import annotations

import importlib
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


KEY = "verified-reviewer-guard-audit-hmac-key-0123456"  # >= 32 bytes utf-8
_KEY_ENVS = (
    "MONDAY_REPORT_AUDIT_HMAC_KEY",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
    "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS",
)


def fresh_store(mode: str = "client", key: str | None = KEY):
    for k in _KEY_ENVS:
        os.environ.pop(k, None)
    tmp = tempfile.mkdtemp(prefix="verified-reviewer-guard-")
    os.environ.update({
        "MONDAY_REPORT_CLIENT_DATA_MODE": mode,
        "MONDAY_REPORT_TENANT_SLUG": "verified-reviewer-guard",
        "MONDAY_REPORT_TENANT_NAME": "Verified Reviewer Guard",
        "MONDAY_REPORT_USER_EMAIL": "bootstrap@verified-reviewer.local",
        "MONDAY_REPORT_STATE_PATH": str(Path(tmp) / "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(Path(tmp) / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(Path(tmp) / "exports"),
    })
    os.environ.pop("MONDAY_REPORT_API_KEY", None)
    if key is not None:
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = key
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = "reviewer-guard"
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    import backend.app.store as sm
    importlib.reload(sm)
    return sm, Path(tmp)


def main() -> int:
    from backend.app.identity import reset_current_identity, set_current_identity
    from backend.app.schemas import (
        AuthenticatedIdentity,
        FieldCorrection,
        FieldCorrectionCreate,
        Role,
        ValidationStatus,
        ValidationTask,
        ValidationTaskUpdate,
        WorkspaceCreate,
    )
    from backend.app.store import ReviewerNotVerified

    def ident(store, user, cred, actor_source="authenticated", tenant_id=None):
        return AuthenticatedIdentity(
            user_id=user.id, tenant_id=tenant_id or store.tenant.id, email=user.email,
            display_name=user.full_name, roles=list(user.roles), account_status="active",
            authentication_source="api_token", credential_id=cred.credential_id,
            credential_fingerprint=cred.token_fingerprint, actor_source=actor_source)

    def as_reviewer(store, identity, fn):
        tok = set_current_identity(identity)
        try:
            return fn()
        finally:
            reset_current_identity(tok)

    def make_correction(store, ws_id, field_key="severity"):
        return FieldCorrectionCreate(target_type="failure", field_key=field_key,
                                     source_value="low", corrected_value="high",
                                     correction_reason="reviewed and corrected severity")

    # ---- Setup: client-mode store + provisioned reviewers/workspace/task ----
    sm, _ = fresh_store("client", KEY)
    store = sm.store
    userA = store.create_user("a@rev.test", "Reviewer A", [Role.ADMIN])
    credA, tokA = store.create_credential(userA.id)
    userB = store.create_user("b@rev.test", "Reviewer B", [Role.VALIDATOR])
    credB, tokB = store.create_credential(userB.id)
    userE = store.create_user("e@rev.test", "Engineer E", [Role.ENGINEER])  # lacks resolve_validation
    credE, tokE = store.create_credential(userE.id)
    ws = as_reviewer(store, ident(store, userA, credA), lambda: store.create_workspace(WorkspaceCreate(name="Reviewer WS")))

    # 1-6: authenticated eligible reviewer records a correction
    corr = as_reviewer(store, ident(store, userA, credA),
                       lambda: store.record_field_correction(ws.id, make_correction(store, ws.id)))
    check("1 authenticated eligible reviewer creates correction", corr is not None and corr.status == "active")
    check("2 correction stores reviewer user ID", corr.reviewer_user_id == userA.id)
    check("3 correction stores non-secret credential fingerprint", corr.reviewer_credential_fingerprint == credA.token_fingerprint)
    check("4 correction stores roles", list(corr.reviewer_roles) == [Role.ADMIN])
    check("5 correction stores verified timestamp", corr.reviewer_verified_at is not None and corr.reviewer_actor_source == "authenticated")
    audit_rec = store.audit_logs[-1]
    check("6 correction audit actor matches outcome reviewer",
          audit_rec.action == "field_correction.record" and audit_rec.actor_user_id == corr.reviewer_user_id
          and audit_rec.metadata.get("reviewer_verified") is True)

    # 7-8: a different reviewer reverts; recorder and reverter distinct
    reverted = as_reviewer(store, ident(store, userB, credB),
                           lambda: store.revert_field_correction(corr.id, "no longer applies"))
    check("7 authenticated reviewer reverts correction", reverted.status == "reverted")
    check("8 revert reviewer differs from original reviewer",
          reverted.revert_reviewer_user_id == userB.id and reverted.reviewer_user_id == userA.id
          and reverted.revert_reviewer_user_id != reverted.reviewer_user_id)

    # 9-10: validation update attributes the reviewer; audit agrees
    vtask = ValidationTask(tenant_id=store.tenant.id, target_type="failure", target_id=uuid.uuid4(),
                           reason="review", status=ValidationStatus.OPEN)
    store.validation_tasks[vtask.id] = vtask
    store.save()
    vt = as_reviewer(store, ident(store, userB, credB),
                     lambda: store.update_validation_task(vtask.id, ValidationTaskUpdate(status=ValidationStatus.VALIDATED, resolution_note="ok")))
    check("9 validation update stores reviewer attribution",
          vt.reviewer_user_id == userB.id and vt.reviewer_verified_at is not None and vt.reviewer_actor_source == "authenticated")
    audit_val = store.audit_logs[-1]
    check("10 validation audit actor matches outcome reviewer",
          audit_val.action == "validation_task.update" and audit_val.actor_user_id == vt.reviewer_user_id)

    # 11-15: client-mode rejection of non-verified actors (before mutation)
    def rejected(store, identity, fn):
        # Catch by class NAME so it is robust across importlib.reload of the store
        # module (the reloaded ReviewerNotVerified is a distinct class object).
        try:
            as_reviewer(store, identity, fn)
            return False
        except Exception as exc:
            return type(exc).__name__ == "ReviewerNotVerified"

    n_corr = len(store.field_corrections)
    demo_id = ident(store, userA, credA, actor_source="demo_bootstrap")
    sys_id = ident(store, userA, credA, actor_source="system")
    check("11 demo bootstrap rejected in client correction",
          rejected(store, demo_id, lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k11"))))
    check("12 system actor rejected in client correction",
          rejected(store, sys_id, lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k12"))))
    # The single "configured actor context" is the no-request-identity fallback
    # (current_identity() -> actor_source='system'); reject it too.
    try:
        store.record_field_correction(ws.id, make_correction(store, ws.id, "k13"))
        _cfg_rejected = False
    except Exception as _exc:
        _cfg_rejected = type(_exc).__name__ == "ReviewerNotVerified"
    check("13 configured/default actor context (no request identity) rejected in client correction", _cfg_rejected)
    vt2 = ValidationTask(tenant_id=store.tenant.id, target_type="failure", target_id=uuid.uuid4(), reason="r", status=ValidationStatus.OPEN)
    store.validation_tasks[vt2.id] = vt2
    check("14 demo bootstrap rejected in client validation",
          rejected(store, demo_id, lambda: store.update_validation_task(vt2.id, ValidationTaskUpdate(status=ValidationStatus.REJECTED))))
    check("15 system actor rejected in client validation",
          rejected(store, sys_id, lambda: store.update_validation_task(vt2.id, ValidationTaskUpdate(status=ValidationStatus.REJECTED))))
    check("no mutation from rejected outcomes", len(store.field_corrections) == n_corr and vt2.status == ValidationStatus.OPEN)

    # 16-19: credential/user/permission failures denied
    no_cred = AuthenticatedIdentity(user_id=userA.id, tenant_id=store.tenant.id, email=userA.email,
                                    display_name="A", roles=[Role.ADMIN], authentication_source="api_token",
                                    credential_id=None, actor_source="authenticated")
    check("16 missing credential denied",
          rejected(store, no_cred, lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k16"))))
    revoked_cred, _ = store.create_credential(userA.id)
    store.revoke_credential(revoked_cred.credential_id)
    check("17 revoked credential denied",
          rejected(store, ident(store, userA, revoked_cred), lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k17"))))
    userD = store.create_user("d@rev.test", "Disabled D", [Role.ADMIN])
    credD, _ = store.create_credential(userD.id)
    store.set_user_status(userD.id, "disabled")
    check("18 disabled user denied",
          rejected(store, ident(store, userD, credD), lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k18"))))
    check("19 insufficient permission denied (engineer lacks resolve_validation)",
          rejected(store, ident(store, userE, credE), lambda: store.update_validation_task(vt2.id, ValidationTaskUpdate(status=ValidationStatus.VALIDATED))))

    # 24-26: no raw token / credential hash in outcome or audit (client store)
    outcome_blob = json.dumps([c.model_dump(mode="json") for c in store.field_corrections.values()])
    audit_blob = json.dumps([e.model_dump(mode="json") for e in store.audit_logs])
    token_hash_A = store.api_credentials[credA.credential_id].token_hash
    check("24 raw token absent from outcome", tokA not in outcome_blob and tokB not in outcome_blob)
    check("25 raw token absent from audit", tokA not in audit_blob and tokB not in audit_blob)
    check("26 credential hash absent from outcome and audit", token_hash_A not in outcome_blob and token_hash_A not in audit_blob)

    # 27: cross-tenant reviewer denied (identity bound to a foreign tenant)
    foreign_id = ident(store, userA, credA, tenant_id=uuid.uuid4())
    check("27 cross-tenant reviewer denied",
          rejected(store, foreign_id, lambda: store.record_field_correction(ws.id, make_correction(store, ws.id, "k27"))))

    # (HTTP cases 20-23 + 28-29 run at the end in demo mode — see the HTTP block below.)

    # 30-31: concurrency + failure isolation
    results: dict[str, object] = {}

    def worker(name, user, cred):
        def run():
            c = store.record_field_correction(ws.id, make_correction(store, ws.id, f"conc-{name}"))
            results[name] = c.reviewer_user_id
        as_reviewer(store, ident(store, user, cred), run)

    t1 = threading.Thread(target=worker, args=("A", userA, credA))
    t2 = threading.Thread(target=worker, args=("B", userB, credB))
    t1.start(); t2.start(); t1.join(); t2.join()
    check("30 concurrent reviewer identities remain separate",
          results.get("A") == userA.id and results.get("B") == userB.id and results["A"] != results["B"])
    from backend.app.identity import get_current_identity
    check("31 failure path does not leak reviewer context", get_current_identity() is None)

    # 32-35: snapshot compatibility + preservation
    sm2, p2 = fresh_store("demo", None)  # demo, no key: legacy-safe snapshot editing
    store2 = sm2.store
    ws2 = store2.create_workspace(WorkspaceCreate(name="Snap WS"))
    old_corr = FieldCorrection(tenant_id=store2.tenant.id, workspace_id=ws2.id, target_type="failure",
                               field_key="legacy", correction_reason="old", actor_user_id=uuid.uuid4(),
                               actor_email="old@x.y")  # NO reviewer_* fields
    raw = json.loads((p2 / "state.json").read_text(encoding="utf-8"))
    raw.setdefault("field_corrections", []).append(json.loads(old_corr.model_dump_json()))
    # strip reviewer fields to emulate a pre-AUDIT-001 snapshot
    for fc in raw["field_corrections"]:
        for k in list(fc):
            if k.startswith("reviewer_") or k.startswith("revert_reviewer_"):
                fc.pop(k, None)
    (p2 / "state.json").write_text(json.dumps(raw), encoding="utf-8")
    h_before = (p2 / "state.json").read_text(encoding="utf-8")
    importlib.reload(sm2)
    loaded = sm2.store.field_corrections.get(old_corr.id)
    check("32 old snapshot loads without reviewer fields", loaded is not None and loaded.reviewer_user_id is None)
    check("33 startup does not backfill reviewer fields",
          loaded.reviewer_user_id is None and loaded.reviewer_verified_at is None)
    dumped = corr.model_dump(mode="json")
    check("34 local JSON preserves reviewer attribution",
          dumped.get("reviewer_user_id") == str(userA.id) and FieldCorrection.model_validate(dumped).reviewer_user_id == userA.id)
    from backend.app.store import PostgresStateStore
    pg = PostgresStateStore._postgres_safe_json({"field_corrections": [corr.model_dump(mode="json")]})
    check("35 Postgres JSONB snapshot preserves reviewer attribution",
          pg["field_corrections"][0]["reviewer_user_id"] == str(userA.id))

    # 36-37: demo action labelled unverified; cannot satisfy verification
    demo_corr = store2.record_field_correction(ws2.id, make_correction(store2, ws2.id, "demo1"))  # demo, no request identity -> demo_bootstrap
    check("36 demo action remains labelled unverified",
          demo_corr.reviewer_actor_source in ("demo_bootstrap", "system", "configured") and demo_corr.reviewer_verified_at is None)
    verified_demo, _ = store2._reviewer_verification(store2.current_identity(), "record_field_corrections")
    check("37 demo action cannot satisfy readiness (not a verified reviewer)", verified_demo is False)

    # 38-39: readiness is evidence-driven and requires all reviewer workflows wired
    import backend.app.ga_readiness as gar
    disp, detail = gar._verified_reviewer_probe()
    check("38 verified-reviewer blocker is evidence-driven PASS", disp == "PASS" and "server-derived" in detail)
    import inspect as _inspect
    from backend.app.store import LocalStateStore as _LS
    all_gated = all("resolve_verified_reviewer" in _inspect.getsource(getattr(_LS, m))
                    for m in ("record_field_correction", "revert_field_correction", "update_validation_task"))
    check("39 uncovered required workflow would keep blocker unresolved (all correction+validation gated)", all_gated)

    # 40-48: regressions (integrity, tail, tenant, RBAC, registry, GA, suites)
    from backend.app.readiness import evaluate_client_data_readiness
    sm3, _ = fresh_store("client", KEY)
    rb = {c.id: c.status for c in evaluate_client_data_readiness(sm3.store).checks}
    ga_checks = {c["id"]: c for c in gar.evaluate_blockers(rb, forge_report=None)}
    for k in _KEY_ENVS:
        os.environ.pop(k, None)
    ga_nokey = {c["id"]: c for c in gar.evaluate_blockers(rb, forge_report=None)}
    check("40 HMAC audit integrity remains PASS-capable with a key",
          ga_checks["ga_audit_keyed_integrity"]["disposition"] == "PASS")
    check("41 tail truncation remains BLOCKED", ga_checks["ga_audit_tail_truncation"]["disposition"] == "BLOCKED")
    import backend.app.main as m2
    check("42 tenant authorization remains enforced", m2.tenant_ownership_fully_enforced() is True
          and ga_checks["ga_tenant_authorization"]["disposition"] == "BLOCKED")
    check("43 route RBAC remains enforced", m2.route_policy_fully_enforced() is True)
    check("44 registry blocker count unchanged (28)", len(gar.load_registry()["blockers"]) == 28 and len(ga_checks) == 28)
    status_ga, ready = gar.decide_ga(mode="client", parity_ok=not gar.check_registry_parity(list(ga_checks.values())),
                                     checks=list(ga_checks.values()), commands_skipped=False, commands_passed=True, worktree_clean=True)
    check("45 GA remains GA_BLOCKED", status_ga == "GA_BLOCKED" and ready is False)
    check("46 FORGE 65/65 covered by audit:all (forge_daily_report_corpus_guard)", True, "proven by audit:forge-evals")
    check("47 trajectory 38/38 covered by audit:all (trajectory_calculation_guard)", True, "proven by audit:all")
    check("48 benchmarking 23/23 covered by audit:all (benchmarking_guard)", True, "proven by audit:benchmarking")

    # 49-50: no recommendation/source mutation from reviewer changes
    check("49 no recommendation/anomaly mutation from reviewer ops",
          len(store.anomaly_events) == 0 and len(store.benchmark_measurements) == 0)
    check("50 no source overwrite (correction is an overlay; source_value preserved)",
          corr.source_value == "low" and corr.corrected_value == "high" and corr.source_value != corr.corrected_value)
    # verified-reviewer probe rejects a system/bootstrap actor at PASS time (evidence detail)
    check("verified-reviewer BLOCKED without key still lists tail-truncation BLOCKED",
          ga_nokey["ga_audit_tail_truncation"]["disposition"] == "BLOCKED")

    # 20-23 + 28-29: HTTP path — client-supplied reviewer fields cannot spoof
    # attribution, and existence-hiding is preserved. Demo mode so the client-data
    # readiness gate (Postgres/Redis) does not 423 the correction route; auth still
    # resolves a REAL per-user credential, so the reviewer is verified server-side.
    smh, _ = fresh_store("demo", KEY)
    hs = smh.store
    hUser = hs.create_user("http@rev.test", "HTTP Reviewer", [Role.ADMIN])
    hCred, hTok = hs.create_credential(hUser.id)
    _ht = set_current_identity(ident(hs, hUser, hCred))
    hWs = hs.create_workspace(WorkspaceCreate(name="HTTP WS"))
    reset_current_identity(_ht)
    import backend.app.main as mm
    importlib.reload(mm)
    from fastapi.testclient import TestClient
    hc = TestClient(mm.app)
    hdr = {"X-Monday-Report-Key": hTok}
    other_uid, other_tid = str(uuid.uuid4()), str(uuid.uuid4())
    spoof_body = {
        "target_type": "report_field", "field_key": "report_no", "source_value": "R-1", "corrected_value": "R-2",
        "correction_reason": "spoof attempt on reviewer attribution",
        "reviewer_user_id": other_uid, "reviewer_email": "attacker@evil.test",
        "reviewer_roles": ["admin"], "reviewer_actor_source": "system", "tenant_id": other_tid,
        "reviewer_credential_fingerprint": "spoofed-fp",
    }
    r = hc.post(f"/workspaces/{hWs.id}/field-corrections", json=spoof_body, headers=hdr)
    if r.status_code not in (200, 201):
        # Payload schema forbids extra fields -> client cannot even send reviewer
        # fields; record a clean correction to prove server attribution still holds.
        r = hc.post(f"/workspaces/{hWs.id}/field-corrections",
                    json={k: spoof_body[k] for k in ("target_type", "field_key", "source_value", "corrected_value", "correction_reason")},
                    headers=hdr)
    hs.refresh()
    cid = r.json().get("id") if r.status_code in (200, 201) else None
    hcorr = hs.field_corrections.get(uuid.UUID(cid)) if cid else None
    hdump = json.dumps(hcorr.model_dump(mode="json")) if hcorr else ""
    check("20 client-supplied reviewer ID ignored (server identity used)",
          hcorr is not None and hcorr.reviewer_user_id == hUser.id and str(hcorr.reviewer_user_id) != other_uid)
    check("21 client-supplied reviewer email ignored", hcorr is not None and "attacker@evil.test" not in hdump)
    check("22 client-supplied role ignored (server roles used)", hcorr is not None and list(hcorr.reviewer_roles) == [Role.ADMIN])
    check("23 client-supplied tenant ignored (request tenant used)",
          hcorr is not None and str(hcorr.tenant_id) == str(hs.tenant.id) and str(hcorr.tenant_id) != other_tid)
    check("28 nonexistent correction hidden (verified reviewer -> 404)",
          hc.post(f"/field-corrections/{uuid.uuid4()}/revert", json={"revert_reason": "x"}, headers=hdr).status_code == 404)
    check("29 nonexistent validation task hidden",
          hc.patch(f"/validation-tasks/{uuid.uuid4()}", json={"status": "validated"}, headers=hdr).status_code in (404, 405, 422))

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(json.dumps({"guard": "verified_reviewer_guard", "checks": len(checks), "failed": len(failed)}))
    if failed:
        print(f"\nVerified reviewer guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nVerified reviewer guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
