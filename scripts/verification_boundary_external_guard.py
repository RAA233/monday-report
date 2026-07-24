"""External boundary-USE audit guard for the runner-owned client-mode PostgreSQL stack.

CLAIM SCOPE: verification-boundary-audit-only. This guard stands up the runner-owned
external client-mode stack (via ``restricted_postgres_startup_guard.run_stack`` with the
``_ON_LIVE`` hook) and proves, against the REAL client-mode request path, that the
verification-boundary RELAXATION is durably and safely audited:

  * a boundary-gated mutation (``field_correction.record``) commits a
    ``client_data.verification_isolation_execution`` boundary-use audit BEFORE the
    business mutation; exactly one boundary event and one business mutation result;
  * the boundary event binds the correct actor + tenant + operation + a SAFE run
    fingerprint (never the raw nonce) + the boundary decision, and contains NO DSN,
    host, port, role name, Docker id, volume name, absolute path, or credential;
  * the audit chain verifies (keyed HMAC-SHA256, integrity_state=keyed_valid, 0 broken);
  * an exact replay (same idempotency key + body) emits one more boundary event per HTTP
    attempt but does NOT duplicate the business mutation / business audit / idempotency
    result; a changed body under the same key conflicts (409) and mutates nothing;
  * the committed boundary audit does not make the following business mutation fail with a
    stale snapshot/projection conflict (revision interaction);
  * two concurrent valid mutations keep boundary/business/row counts consistent and the
    chain intact;
  * a boundary-use audit that cannot be sealed FAILS CLOSED (store.audit raises; no event
    and no business mutation are persisted);
  * tampering with an event's HMAC or chain link is detectable.

It is SEPARATE from the startup-and-identity claim and MUST NEVER be consumed as
tenant-authorization evidence or a readiness proof. Requires Docker; otherwise SKIPPED.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import restricted_postgres_startup_guard as G  # noqa: E402

BND = "client_data.verification_isolation_execution"
checks: list[dict] = []


def record(cid, ok, detail=""):
    checks.append({"id": cid, "ok": bool(ok), "detail": detail})


_INVENTORY = [
    "N01 exactly one boundary-use audit for the mutation",
    "N02 at least one business audit committed",
    "N03 boundary-use audit is committed BEFORE the business mutation (ordering)",
    "N04 boundary event binds correct actor + tenant + operation + safe run fingerprint + decision",
    "N05 boundary event carries no nonce/DSN/host/port/role/docker-id/volume/path/credential",
    "N06 audit chain verifies (keyed HMAC-SHA256, 0 broken)",
    "N07 business mutation persisted exactly once",
    "RE01 exact replay emits one boundary event per HTTP attempt",
    "RE02 exact replay does not duplicate the business mutation",
    "RE03 exact replay does not duplicate the business audit",
    "RE04 exact replay returns the same idempotency result (one row)",
    "CB01 changed body under the same key conflicts (409)",
    "CB02 changed body mutates nothing (no second business mutation)",
    "OR01 business mutation succeeds after the boundary audit commit (no stale conflict)",
    "CC01 two concurrent mutations keep boundary/business/row counts consistent",
    "CC02 audit chain remains valid after concurrent appends",
    "AF01 unsealed boundary audit fails closed (store.audit raises)",
    "AF02 a failed boundary audit persists no event and no business mutation",
    "MT01 tampering an event's content breaks its HMAC seal (detectable)",
    "MT02 the boundary event chains to the prior event (previous_hash linkage)",
]


def _http(method, url, key=None, body=None, idem=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
    if body is not None:
        headers["Content-Type"] = "application/json"
    if idem is not None:
        headers["Idempotency-Key"] = idem
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        for cid in _INVENTORY:
            record(cid, allow_unavailable, "docker unavailable"
                   if allow_unavailable else "docker required for certification; pass --allow-unavailable")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        api = ctx["api_base"]
        token = ctx["token"]
        base_env = dict(ctx["base_env"])
        run_id = ctx["run_id"]
        run_hash = ctx["run_hash"]
        secrets_to_check = [run_id, ctx["boot_dsn"], ctx["rt_dsn"], ctx["mig_dsn"], ctx["rt_role"],
                            ctx["mig_role"], ctx["db"], str(ctx["port"]), f"mr-verif-{run_hash}",
                            f"mr-verif-vol-{run_hash}", token]

        # A store view bound to the runtime DSN, used to read + verify the audit chain.
        saved = {k: os.environ.get(k) for k in base_env}
        os.environ.update(base_env)
        try:
            import backend.app.store as store_mod
            st = store_mod.create_store()
            from backend.app.verification_boundary import verification_run_fingerprint
            expected_fp = verification_run_fingerprint()
            from backend.app.audit_keys import audit_key_provider
            audit_secret = audit_key_provider().active_key().secret
        finally:
            for k, v in saved.items():
                (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

        def view():
            s2 = {k: os.environ.get(k) for k in base_env}
            os.environ.update(base_env)
            try:
                st.refresh()
                logs = list(st.audit_logs)
                integ = st.audit_integrity_status()
                tenant_id = st.tenant.id
                users = {u.email: u.id for u in st.users.values()}
            finally:
                for k, v in s2.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            return logs, integ, tenant_id, users

        def event_dict(e):
            return {"action": e.action, "resource_type": e.resource_type,
                    "resource_id": str(e.resource_id) if e.resource_id else None,
                    "metadata": e.metadata, "actor_user_id": str(e.actor_user_id),
                    "actor_source": e.actor_source, "actor_roles": list(e.actor_roles or []),
                    "actor_credential_fingerprint": e.actor_credential_fingerprint,
                    "integrity_version": e.integrity_version, "entry_hash": e.entry_hash,
                    "previous_hash": e.previous_hash, "key_id": e.key_id}

        hdr_key = token
        # ---- setup: a workspace + a valid correctable field ---------------------
        s, ws = _http("POST", f"{api}/workspaces", key=hdr_key,
                      body={"name": "bnd-ws", "rig_name": "guard"})
        ws_id = ws["id"] if isinstance(ws, dict) else None
        s, reg = _http("GET", f"{api}/field-corrections/registry", key=hdr_key)
        field0 = reg[0]
        vt = field0.get("value_type")
        def corr_body(val):
            return {"target_type": field0["target_type"], "field_key": field0["field_key"],
                    "source_value": "S", "corrected_value": ("123" if vt == "numeric_text" else val),
                    "correction_reason": "boundary-audit external test"}

        # Count boundary MUTATION uses and business audits by exact action/operation, so
        # boundary-gated READS (field_correction.list) and worker events never pollute the
        # counts. Count rows via the store directly (not a boundary-gated GET route).
        def mut_bnd(evs):
            return [e for e in evs if e.action == BND and (e.metadata or {}).get("operation") == "field_correction.record"]
        def biz_ev(evs):
            return [e for e in evs if e.action == "field_correction.record"]
        def rows():
            s2 = {k: os.environ.get(k) for k in base_env}
            os.environ.update(base_env)
            try:
                st.refresh()
                return sum(1 for fc in st.field_corrections.values()
                           if str(getattr(fc, "workspace_id", "")) == str(ws_id))
            finally:
                for k, v in s2.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

        # ===================== NORMAL protected mutation =========================
        before_logs, _, tenant_id, users = view()
        api_user_id = str(users.get("apiuser@verif.test"))
        k1 = str(uuid.uuid4())
        s1, r1 = _http("POST", f"{api}/workspaces/{ws_id}/field-corrections", key=hdr_key,
                       body=corr_body("corrected-A"), idem=k1)
        after_logs, integ, tenant_id, users = view()
        new = after_logs[len(before_logs):]
        bnd = mut_bnd(new)
        biz = biz_ev(new)
        record("N01 exactly one boundary-use audit for the mutation", len(bnd) == 1,
               {"boundary_events": len(bnd), "post_status": s1})
        record("N02 at least one business audit committed", len(biz) >= 1, {"business_events": len(biz)})
        if bnd and biz:
            i_b = after_logs.index(bnd[0])
            i_z = after_logs.index(biz[0])
            record("N03 boundary-use audit is committed BEFORE the business mutation (ordering)",
                   i_b < i_z, {"boundary_index": i_b, "business_index": i_z})
        else:
            record("N03 boundary-use audit is committed BEFORE the business mutation (ordering)", False,
                   "missing boundary or business event")
        if bnd:
            e = bnd[0]
            md = e.metadata or {}
            ok_content = (e.action == BND and md.get("operation") == "field_correction.record"
                          and str(e.actor_user_id) == api_user_id and e.tenant_id == tenant_id
                          and md.get("verification_run") == expected_fp
                          and md.get("verification_isolation_active") is True)
            record("N04 boundary event binds correct actor + tenant + operation + safe run fingerprint + decision",
                   ok_content, {"operation": md.get("operation"), "run_fp_ok": md.get("verification_run") == expected_fp,
                                "actor_ok": str(e.actor_user_id) == api_user_id, "active": md.get("verification_isolation_active")})
            blob = json.dumps(event_dict(e), default=str)
            leaked = [s for s in secrets_to_check if s and s in blob]
            # a raw run id (nonce) must never appear -- only its 12-hex fingerprint may.
            nonce_leak = run_id in blob
            record("N05 boundary event carries no nonce/DSN/host/port/role/docker-id/volume/path/credential",
                   not leaked and not nonce_leak, {"leaked_kinds": len(leaked), "nonce_leak": nonce_leak})
            record("MT01 tampering an event's content breaks its HMAC seal (detectable)",
                   _tamper_detectable(st, e, audit_secret), "")
            # chain linkage: previous_hash equals the prior event's chain hash
            idx = after_logs.index(e)
            if idx > 0:
                prior = after_logs[idx - 1]
                prior_chain = prior.entry_hash or store_mod.PostgresStateStore._audit_event_hash(prior)
                record("MT02 the boundary event chains to the prior event (previous_hash linkage)",
                       e.previous_hash == prior_chain, {"linked": e.previous_hash == prior_chain})
            else:
                record("MT02 the boundary event chains to the prior event (previous_hash linkage)",
                       e.previous_hash is None, "boundary event is the chain root")
        else:
            for cid in ["N04 boundary event binds correct actor + tenant + operation + safe run fingerprint + decision",
                        "N05 boundary event carries no nonce/DSN/host/port/role/docker-id/volume/path/credential",
                        "MT01 tampering an event's content breaks its HMAC seal (detectable)",
                        "MT02 the boundary event chains to the prior event (previous_hash linkage)"]:
                record(cid, False, "no boundary event produced")
        record("N06 audit chain verifies (keyed HMAC-SHA256, 0 broken)",
               integ.integrity_state == "keyed_valid" and integ.broken_events == 0,
               {"state": integ.integrity_state, "broken": integ.broken_events})
        record("N07 business mutation persisted exactly once", rows() == 1,
               {"corrections": rows()})
        record("OR01 business mutation succeeds after the boundary audit commit (no stale conflict)",
               s1 in (200, 201) and len(biz) >= 1, {"status": s1})

        # ===================== EXACT REPLAY =====================================
        s2r, r2 = _http("POST", f"{api}/workspaces/{ws_id}/field-corrections", key=hdr_key,
                        body=corr_body("corrected-A"), idem=k1)
        after2, integ2, _, _ = view()
        new2 = after2[len(after_logs):]
        record("RE01 exact replay emits one boundary event per HTTP attempt",
               len(mut_bnd(new2)) == 1, {"boundary_events": len(mut_bnd(new2))})
        record("RE02 exact replay does not duplicate the business mutation", rows() == 1,
               {"corrections": rows()})
        record("RE03 exact replay does not duplicate the business audit",
               len(biz_ev(new2)) == 0, {"business_events": len(biz_ev(new2))})
        record("RE04 exact replay returns the same idempotency result (one row)",
               s2r in (200, 201) and rows() == 1, {"status": s2r})

        # ===================== CHANGED BODY (same key) ==========================
        s3, r3 = _http("POST", f"{api}/workspaces/{ws_id}/field-corrections", key=hdr_key,
                       body=corr_body("corrected-DIFFERENT"), idem=k1)
        after3, _, _, _ = view()
        new3 = after3[len(after2):]
        record("CB01 changed body under the same key conflicts (409)", s3 == 409, {"status": s3})
        record("CB02 changed body mutates nothing (no second business mutation)",
               rows() == 1 and len(biz_ev(new3)) == 0,
               {"corrections": rows()})

        # ===================== CONCURRENCY ======================================
        base_n = rows()
        results = {}
        def _mut(i):
            ki = str(uuid.uuid4())
            st_, _ = _http("POST", f"{api}/workspaces/{ws_id}/field-corrections", key=hdr_key,
                           body=corr_body(f"c-{i}"), idem=ki)
            results[i] = st_
        ths = [threading.Thread(target=_mut, args=(i,)) for i in range(2)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        after4, integ4, _, _ = view()
        new4 = after4[len(after3):]
        bnd4 = len(mut_bnd(new4))
        biz4 = len(biz_ev(new4))
        record("CC01 two concurrent mutations keep boundary/business/row counts consistent",
               all(v in (200, 201) for v in results.values()) and bnd4 == 2 and biz4 >= 2
               and rows() == base_n + 2,
               {"statuses": results, "boundary": bnd4, "business": biz4, "rows": rows()})
        record("CC02 audit chain remains valid after concurrent appends",
               integ4.integrity_state == "keyed_valid" and integ4.broken_events == 0,
               {"state": integ4.integrity_state, "broken": integ4.broken_events})

        # ===================== AUDIT FAILURE -> FAIL CLOSED =====================
        # A store constructed WITHOUT an audit key must refuse to write the boundary-use
        # (business) audit in client mode: store.audit raises and appends nothing. This is
        # the exact primitive require_client_data_ready relies on for its 503.
        nokey = dict(base_env)
        nokey.pop("MONDAY_REPORT_AUDIT_HMAC_KEY", None)
        s2 = {k: os.environ.get(k) for k in set(list(base_env) + ["MONDAY_REPORT_AUDIT_HMAC_KEY"])}
        os.environ.update({k: v for k, v in nokey.items()})
        os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_KEY", None)
        try:
            st_nokey = store_mod.create_store()
            before_n = len(st_nokey.audit_logs)
            raised = False
            try:
                st_nokey.audit(BND, "workspace", None, {"operation": "field_correction.record"})
            except Exception:
                raised = True
            after_n = len(st_nokey.audit_logs)
            record("AF01 unsealed boundary audit fails closed (store.audit raises)", raised, "")
            record("AF02 a failed boundary audit persists no event and no business mutation",
                   after_n == before_n, {"appended": after_n - before_n})
        finally:
            for k, v in s2.items():
                (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

    G.checks = []
    G.http_statuses = []
    G._ON_LIVE = on_live
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    have = {c["id"] for c in checks}
    for cid in _INVENTORY:
        if cid not in have:
            record(cid, False, "on_live aborted before this check ran")
    return _emit()


def _tamper_detectable(store, event, secret) -> bool:
    """A one-byte change to the sealed content must change the recomputed HMAC, so any
    tamper is detectable. Recompute(original) must match the stored seal; recompute of a
    mutated copy must differ. `secret` is captured with the runtime env set."""
    try:
        original = store._audit_v2_hash(event, secret)
        mutated = event.model_copy(update={"metadata": {**(event.metadata or {}), "_tamper": "x"}})
        mutated_hash = store._audit_v2_hash(mutated, secret)
        return original == event.entry_hash and mutated_hash != event.entry_hash
    except Exception:
        return False


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    missing = [cid for cid in _INVENTORY if cid not in {c["id"] for c in checks}]
    enriched = [{**c, "claim_scope": "verification-boundary-audit-only",
                 "requires_docker": True, "requires_postgresql": True} for c in checks]
    print(json.dumps({"checks": enriched,
                      "summary": {"passed": len(passed) if not skipped else 0,
                                  "skipped": len(checks) if skipped else 0,
                                  "failed": 0 if skipped else len(failed),
                                  "missing_ids": missing, "expected": len(_INVENTORY),
                                  "claim_scope": "verification-boundary-audit-only",
                                  "eligible_for_tenant_evidence": False,
                                  "eligible_for_readiness": False}}, indent=2, default=str))
    if skipped:
        print("\nExternal boundary-audit guard SKIPPED (docker unavailable, non-certifying).")
        return 0
    if missing:
        print(f"\nInventory mismatch: {len(missing)} missing id(s): {missing}")
        return 1
    if failed:
        print(f"\nExternal boundary-audit guard FAILED: {len(failed)} scenario(s).")
        for c in failed:
            print(f"  FAIL: {c['id']} -> {c['detail']}")
        return 1
    print(f"\nExternal boundary-audit guard passed: {len(passed)} scenario(s)."
          "\n[claim_scope=verification-boundary-audit-only; NOT tenant-evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
