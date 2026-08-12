"""Restricted-PostgreSQL functional-CORE mutation battery (non-vacuity for the -core guard).

Proves the restricted-runtime functional-CORE guard's assertions (audit:restricted-postgres-runtime-
core) are NON-VACUOUS: for each core functional invariant the runtime-core guard checks (RLS
isolation, audit integrity, malware blocking, idempotency dedup, credential auth, fail-closed
persistence), this guard injects a REAL fault into the LIVE runner-owned stack, confirms the invariant
FLIPS (the regression is caught), then REVERTS the fault. It reuses the ACCEPTED foundation
(restricted_postgres_startup_guard.run_stack + its _ON_LIVE hook -- the foundation is unchanged) and
drives the real client-mode HTTP API + the live PostgreSQL. Command: audit:restricted-postgres-
runtime-core-faults (the unqualified -faults name is RESERVED for the future COMPLETE guard's battery).

Each mutation is self-contained: it captures the prior state, injects the fault, asserts the
flip, and restores in a finally block so no fault outlives its check and the stack stays intact
for later checks. A positive control accompanies each negative proof (e.g. same-tenant success
next to cross-tenant denial; post-revert RLS restored to exactly one row).

HONEST SCOPE. This is the functional mutation battery, not a whole-stack fault battery (that is
scripts/restricted_postgres_startup_fault_guard.py). It emits per-check execution_level, and
  claim_scope = restricted-runtime-functional-core-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import restricted_postgres_startup_guard as G  # noqa: E402

STATE_TABLE = "monday_report_state_snapshots"
APP_GROUP = "monday_report_app"  # NOLOGIN least-priv group from migration 0007
checks: list[dict] = []
# High-entropy run secrets (nonces, DSNs, roles, db, container names, token); populated from ctx.
# The final emitted JSON is scrubbed against these so no check detail can leak one into the verdict.
LEAK_TERMS: list[str] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def record(cid, ok, area, detail="", level="live HTTP mutation"):
    checks.append({"id": cid, "ok": bool(ok), "area": area, "execution_level": level, "detail": detail})


def safe(cid, area, fn, level="live HTTP mutation"):
    try:
        ok, detail = fn()
        record(cid, ok, area, detail, level)
    except Exception as exc:  # noqa: BLE001
        # Emit only the exception TYPE (a message may embed a DSN/port/role/path); the final
        # JSON is additionally _scrub-ed against LEAK_TERMS.
        import traceback
        print(f"CHECK {cid} raised: {traceback.format_exc()[-800:]}", file=sys.stderr)
        record(cid, False, area, f"error: {type(exc).__name__}", level)


def _http(method, url, key=None, body=None, idem=None, raw=None, ctype=None):
    headers = {}
    if key:
        headers["X-Monday-Report-Key"] = key
    if idem is not None:
        headers["Idempotency-Key"] = idem
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    elif raw is not None:
        headers["Content-Type"] = ctype or "application/octet-stream"
        data = raw
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            b = r.read()
            try:
                return r.status, json.loads(b or b"null")
            except Exception:
                return r.status, b
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _multipart_upload(ws_id, filename, content, include_ws=True):
    boundary = "----mrfault" + secrets.token_hex(6)
    b = f"--{boundary}".encode()
    parts = b""
    if include_ws:
        parts += (b + b"\r\nContent-Disposition: form-data; name=\"workspace_id\"\r\n\r\n"
                  + str(ws_id).encode() + b"\r\n")
    parts += (b + f"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n".encode()
              + b"Content-Type: text/plain\r\n\r\n" + content + b"\r\n" + b + b"--\r\n")
    return parts, f"multipart/form-data; boundary={boundary}"


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        record("setup", allow_unavailable, "setup",
               "docker unavailable" if allow_unavailable else "docker required; pass --allow-unavailable",
               level="structural source check")
        return _emit(skipped=allow_unavailable)

    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role

        api_a = ctx["api_base"]
        token_a = ctx["token"]
        boot = ctx["boot_dsn"]        # superuser DSN (alter role / grant / revoke)
        rt = ctx["rt_dsn"]            # restricted runtime login DSN
        rt_role = ctx["rt_role"]
        base_env = dict(ctx["base_env"])
        run_hash = ctx["run_hash"]
        legacy_key = base_env["MONDAY_REPORT_API_KEY"]
        # Safety-net scrub set: HIGH-ENTROPY run terms only (never the low-entropy port). Longest
        # first so a DSN is redacted before the bare db/role substrings it contains.
        LEAK_TERMS[:] = sorted(
            {str(t) for t in [ctx["run_id"], run_hash, rt_role, ctx["mig_role"], boot, rt,
                              ctx["mig_dsn"], ctx["db"], token_a, legacy_key,
                              f"mr-verif-{run_hash}", f"mr-verif-vol-{run_hash}"] if t},
            key=len, reverse=True)

        # --- run fn(store) with an env ACTIVE (create_store + refresh), then restore env ---
        def with_env(env, fn):
            sv = {k: os.environ.get(k) for k in env}
            # keys we may DELETE for a check must be tracked even if absent in env
            os.environ.update({k: v for k, v in env.items() if v is not None})
            for k, v in env.items():
                if v is None:
                    os.environ.pop(k, None)
            try:
                st = store_mod.create_store()
                st.refresh()
                return fn(st)
            finally:
                for k in env:
                    v = sv.get(k)
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))

        # ---- provision a SECOND tenant snapshot row (needed to show an RLS leak) ----
        b_scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-rtf-b-{run_hash}"
        for sub in ("state", "storage", "exports"):
            (b_scratch / sub).mkdir(parents=True, exist_ok=True)
        b_env = dict(base_env)
        b_env.update({
            "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name=mr-fault-b-{run_hash}",
            "MONDAY_REPORT_TENANT_SLUG": "verif-b",
            "MONDAY_REPORT_TENANT_NAME": "Verification Tenant B",
            "MONDAY_REPORT_USER_EMAIL": "reviewer-b@verif.test",
            "MONDAY_REPORT_USER_FULL_NAME": "Verif Reviewer B",
            "MONDAY_REPORT_STATE_PATH": str(b_scratch / "state" / "s.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(b_scratch / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(b_scratch / "exports"),
        })
        # create a user in tenant B (audit-saves the snapshot) so a 2nd snapshot row exists
        with_env(b_env, lambda st: st.create_user("apiuser-b@verif.test", "API User B", [_Role.ADMIN]))

        try:
            # a workspace in tenant A for corrections/uploads
            _, wsA = _http("POST", f"{api_a}/workspaces", key=token_a, body={"name": "fault-a", "rig_name": "g"})
            wsA_id = wsA["id"] if isinstance(wsA, dict) else None
            _, reg = _http("GET", f"{api_a}/field-corrections/registry", key=token_a)
            f0 = reg[0]
            vt = f0.get("value_type")

            def corr_body(val):
                return {"target_type": f0["target_type"], "field_key": f0["field_key"], "source_value": "S",
                        "corrected_value": ("123" if vt == "numeric_text" else val),
                        "correction_reason": "mutation battery"}

            def blocked_files():
                return with_env(base_env, lambda st: len(
                    [f for f in st.files.values() if getattr(f, "malware_status", "") == "blocked"]))

            def norm_count():
                # DIRECT committed count as the restricted role (RLS-scoped to verif-a). Unlike a
                # create_store projection, a direct SELECT never lags the live API's refresh
                # generations, so correction counts are deterministic across the shared tenant row.
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", ("verif-a",))
                    return int(c.execute(
                        "select count(*) from monday_report_norm_field_corrections").fetchone()[0])

            # ================= POSITIVE CONTROL: same-tenant success =================
            base_rows = norm_count()
            s09, _ = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a,
                           body=corr_body("pc"), idem=str(uuid.uuid4()))
            r09, _ = _http("GET", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a)
            record("FM09 same-tenant correction create + read SUCCEED (denials are not blanket)",
                   s09 in (200, 201) and norm_count() == base_rows + 1 and r09 == 200,
                   "positive-control", {"create": s09, "read": r09, "row_delta": norm_count() - base_rows},
                   level="live HTTP mutation")

            # ================= MALWARE specificity =================
            def clean_upload():
                before = blocked_files()
                payload, ctype = _multipart_upload(wsA_id, "clean.txt", b"benign drilling note, no malware here")
                st, _b = _http("POST", f"{api_a}/uploads/direct", key=token_a, raw=payload, ctype=ctype)
                after = blocked_files()
                return (st in (200, 201) and after == before,
                        {"status": st, "blocked_delta": after - before})
            safe("FM04 a CLEAN upload is NOT blocked (the 422 block is EICAR-specific)", "malware-specificity",
                 clean_upload, level="live HTTP mutation")

            def malformed_upload():
                # missing the required workspace_id Form field -> FastAPI 422 VALIDATION error,
                # which must NOT create a blocked malware row (distinct from a real malware 422).
                before = blocked_files()
                payload, ctype = _multipart_upload(wsA_id, "x.txt", b"data", include_ws=False)
                st, _b = _http("POST", f"{api_a}/uploads/direct", key=token_a, raw=payload, ctype=ctype)
                after = blocked_files()
                return (st == 422 and after == before, {"status": st, "blocked_delta": after - before})
            safe("FM12 a malformed (no workspace_id) upload 422s WITHOUT a blocked row (validation != malware)",
                 "malware-specificity", malformed_upload, level="live HTTP mutation")

            # ================= IDEMPOTENCY is the dedup, not an accident =================
            def distinct_keys_duplicate():
                start = norm_count()
                _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a,
                      body=corr_body("k1"), idem=str(uuid.uuid4()))
                _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a,
                      body=corr_body("k2"), idem=str(uuid.uuid4()))
                return (norm_count() == start + 2, {"delta": norm_count() - start})
            safe("FM05 two corrections under DIFFERENT idempotency keys create TWO rows (dedup is by key)",
                 "idempotency-nonvacuity", distinct_keys_duplicate, level="live HTTP mutation")

            # ================= CREDENTIAL AUTH is a real hash compare =================
            # NB: credential revocation / user-disable non-vacuity is proven by the functional
            # guard's auth matrix (RT02-08: active authenticates; missing/invalid/legacy/
            # wrong-tenant denied). Provisioning throwaway credentials out-of-band INTO the
            # live tenant-A snapshot is a shared-writer race with the running API process (two
            # independent CAS writers on one tenant row), so it is deliberately NOT done here.
            # This race-free proof mutates only the presented token, never the store.
            def token_bytes_matter():
                good, _ = _http("GET", f"{api_a}/monday-reports", key=token_a)
                # flip one interior character of a VALID token -> the hash no longer matches
                mid = len(token_a) // 2
                flipped = token_a[:mid] + ("a" if token_a[mid] != "a" else "b") + token_a[mid + 1:]
                bad, _ = _http("GET", f"{api_a}/monday-reports", key=flipped)
                return (good == 200 and flipped != token_a and bad in (401, 403),
                        {"intact": good, "byte_flipped": bad})
            safe("FM06 a byte-flipped valid credential is rejected; the intact credential authenticates",
                 "credential-auth", token_bytes_matter, level="live HTTP mutation")

            # ================= AUDIT INTEGRITY detects key loss / tamper =================
            def audit_key_absent():
                env = dict(base_env)
                env["MONDAY_REPORT_AUDIT_HMAC_KEY"] = None  # remove -> provider cannot resolve
                state = with_env(env, lambda st: st.audit_integrity_status().integrity_state)
                return (state == "key_unavailable", {"state": state})
            safe("FM02a with the audit HMAC key ABSENT, integrity reads key_unavailable (not keyed_valid)",
                 "audit-integrity-nonvacuity", audit_key_absent, level="direct component integration")

            def audit_key_wrong():
                env = dict(base_env)
                # same key id/version but a DIFFERENT secret -> HMAC recompute mismatches -> broken
                env["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "wrong-secret-" + secrets.token_hex(24)
                st = with_env(env, lambda s: s.audit_integrity_status())
                return (st.integrity_state == "broken" and st.broken_events >= 1,
                        {"state": st.integrity_state, "broken": st.broken_events})
            safe("FM02b with a WRONG audit HMAC secret, sealed events verify as broken (tamper-evident)",
                 "audit-integrity-nonvacuity", audit_key_wrong, level="direct component integration")

            # ================= RLS ISOLATION depends on NOT-bypassrls =================
            def rls_leak_under_bypassrls():
                with psycopg.connect(boot, autocommit=True) as sup:
                    sup.execute(f"alter role {rt_role} bypassrls")
                try:
                    with psycopg.connect(rt, autocommit=True) as c:  # fresh session picks up the attribute
                        c.execute("select set_config('app.tenant_slug', %s, false)", ("verif-a",))
                        leaked = c.execute(f"select count(*) from {STATE_TABLE}").fetchone()[0]
                finally:
                    with psycopg.connect(boot, autocommit=True) as sup:
                        sup.execute(f"alter role {rt_role} nobypassrls")
                return (int(leaked) >= 2, {"rows_seen_as_slug_A_with_bypassrls": int(leaked)})
            safe("FM01 granting the runtime login BYPASSRLS LEAKS both tenants' rows (isolation needs NOBYPASSRLS)",
                 "rls-nonvacuity", rls_leak_under_bypassrls, level="live PostgreSQL mutation")

            def rls_restored_after_revert():
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug', %s, false)", ("verif-a",))
                    rows = c.execute(f"select count(*) from {STATE_TABLE}").fetchone()[0]
                return (int(rows) == 1, {"rows_after_revert": int(rows)})
            safe("FM10 after reverting BYPASSRLS, slug=verif-a again sees EXACTLY its own row (revert verified)",
                 "rls-nonvacuity", rls_restored_after_revert, level="live PostgreSQL mutation")

            # ================= FAIL-CLOSED persistence: revoke runtime write -> 503 =================
            # norm_count() (a DIRECT committed SELECT as the restricted role) makes "no partial
            # write" authoritative -- it never lags the live API's refresh generations.
            def revoke_write_fails_closed():
                before = norm_count()
                with psycopg.connect(boot, autocommit=True) as sup:
                    sup.execute(f"revoke update on {STATE_TABLE} from {APP_GROUP}")
                try:
                    st_code, _ = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a,
                                       body=corr_body("fc"), idem=str(uuid.uuid4()))
                    mid = norm_count()  # read path (SELECT) still works; only writes are revoked
                finally:
                    with psycopg.connect(boot, autocommit=True) as sup:
                        sup.execute(f"grant update on {STATE_TABLE} to {APP_GROUP}")
                # after re-grant, a correction succeeds again (positive control that revert worked)
                st_ok, _ = _http("POST", f"{api_a}/workspaces/{wsA_id}/field-corrections", key=token_a,
                                 body=corr_body("fc2"), idem=str(uuid.uuid4()))
                after = norm_count()
                return (st_code in (500, 502, 503) and mid == before
                        and st_ok in (200, 201) and after == before + 1,
                        {"blocked_status": st_code, "norm_before": before, "norm_during_fault": mid,
                         "post_regrant_status": st_ok, "norm_after": after})
            safe("FM08 revoking runtime UPDATE fails the mutation closed (no 2xx, no row written); re-grant restores it",
                 "fail-closed-persistence", revoke_write_fails_closed, level="live HTTP + PostgreSQL mutation")

            # legacy shared key must still be rejected (auth negative, independent of the mutations above)
            safe("FM11 the legacy shared key remains rejected in client mode", "credential-auth",
                 lambda: (_http("GET", f"{api_a}/monday-reports", key=legacy_key)[0] in (401, 403), ""),
                 level="live HTTP mutation")

        finally:
            import shutil
            shutil.rmtree(b_scratch, ignore_errors=True)

    G.checks = []
    G.http_statuses = []
    err = {}

    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            # Only the exception TYPE reaches the certifying JSON output; the full message
            # (which may embed a DSN/path) stays on stderr, never in the emitted verdict.
            err["type"] = type(exc).__name__
            err["msg"] = f"{type(exc).__name__}: {str(exc)[:160]}"
            err["tb"] = traceback.format_exc()[-1600:]
    G._ON_LIVE = wrapped
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    # F6: the mutation narrative rests on a healthy restricted stack. run_stack() raises only on
    # HARD failures; a SOFT-failed foundation check (e.g. API not on the restricted login) records
    # False without raising. Fail closed if any foundation check is not ok.
    foundation_fail = [c["id"] for c in getattr(G, "checks", []) if not c.get("ok", True) and not c.get("skipped", False)]
    if foundation_fail:
        record("foundation", False, "setup",
               f"foundation checks not ok: {sorted(foundation_fail)[:8]}", level="structural source check")
    # F1: an on_live abort AFTER some checks recorded must NOT read as passed. Record a failure
    # UNCONDITIONALLY (not only when zero checks ran), so _emit computes battery=failed / exit 1.
    if err:
        print("ON_LIVE ERROR:", err.get("msg"), file=sys.stderr)
        print(err.get("tb", ""), file=sys.stderr)
        record("on_live_abort", False, "setup",
               f"mutation on_live aborted with {err.get('type')} after {len(checks)} checks (see stderr)",
               level="structural source check")
    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    battery = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    enriched = [{**c, "claim_scope": "restricted-runtime-functional-core-faults-only"} for c in checks]
    # _scrub the ENTIRE verdict as a safety net against any nonce/DSN/role/db/token in a detail.
    print(_scrub(json.dumps({"checks": enriched,
                      "summary": {"passed": len(passed) if not skipped else 0,
                                  "skipped": len(checks) if skipped else 0,
                                  "failed": 0 if skipped else len(failed),
                                  "execution_level_totals": exec_totals,
                                  "claim_scope": "restricted-runtime-functional-core-faults-only",
                                  "mutation_battery": battery,
                                  "eligible_for_tenant_evidence": False,
                                  "eligible_for_readiness": False,
                                  "production_parity": False,
                                  "migration_principal_class": "test-only-bootstrap-migration-admin"}},
                     indent=2, default=str)))
    if skipped:
        print("\nRestricted-runtime mutation battery SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nRestricted-runtime mutation battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['id']} -> {c['detail']}"))
        return 1
    print(f"\nRestricted-runtime mutation battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-functional-core-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
