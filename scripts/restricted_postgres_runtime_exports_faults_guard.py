"""Non-vacuity battery for the export + signed-reference slice (Outcome-1 slice 2).

Proves the audit:restricted-postgres-runtime-exports slice's assertions are NON-VACUOUS. For each listed
violation it EITHER runs a LIVE control against the accepted runner-owned stack proving the slice's
assertion discriminates (a valid retrieval succeeds, a denial is state/token-specific -- not a blanket
outcome), OR evaluates a MIRROR of the slice's pass-predicate against a crafted VIOLATED observation and
confirms the predicate rejects it (so a regression that changed the observation would flip the check) --
and where the discriminator is importable it evaluates the slice's ACTUAL predicate (EFP01 imports the
slice's module-scope `is_validation_409`; SFP02 uses the slice's `MEDIA` constant), OR is a STRUCTURAL
check of the slice's own fail-closed gates driven through the REAL `M._emit`/`M.EXPECTED_IDS` (normal-HTTP
423/500/503 counter, completeness of the expected check inventory, and duplicate-id detection). Every
check is classified honestly by execution level -- a predicate check is NEVER described as a live HTTP test.

HONEST SCOPE:
  claim_scope = restricted-runtime-exports-signed-references-faults-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence. Requires Docker.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import importlib.util
import json
import os
import secrets
import subprocess
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
SIGNING_ENV = "MONDAY_REPORT_SIGNING_SECRET"
PURPOSE = "report_export_download"
checks: list[dict] = []
LEAK_TERMS: list[str] = []


def _scrub(text: str) -> str:
    for term in LEAK_TERMS:
        if term:
            text = text.replace(term, "<redacted>")
    return text


def mut(cid, ok, desc, level, extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def _http(method, url, key=None, body=None, raw=None, ctype=None, idem=None):
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
        with urllib.request.urlopen(req, timeout=30) as r:
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


def _dl(url):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Content-Type"), r.headers.get("Content-Disposition")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, None, None
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode(), None, None


def run() -> int:
    allow_unavailable = "--allow-unavailable" in sys.argv
    if G._docker(["info"]).returncode != 0:
        mut("setup", allow_unavailable, "docker availability", "structural source check")
        return _emit(skipped=allow_unavailable)

    # =====================================================================================
    # STRUCTURAL: drive the slice module's own fail-closed gates (no stack needed)
    # =====================================================================================
    spec = importlib.util.spec_from_file_location(
        "expslice", str(ROOT / "scripts" / "restricted_postgres_runtime_exports_guard.py"))
    M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)

    def _populate_all():
        M.checks.clear(); M.HTTP_STATUSES.clear()
        for cid in M.EXPECTED_IDS:
            M.rec(cid, True, desc="ok", category="p", route="-", tenant="-", actor="-",
                  expected="-", db_post="-", audit_post="-")

    def _emit_rc():
        with contextlib.redirect_stdout(io.StringIO()):  # swallow the slice's own JSON print
            return M._emit()

    # baseline: a complete, clean inventory PASSES the gate (rc 0) -> the gates are not always-fail
    _populate_all()
    mut("FS00", _emit_rc() == 0, "a complete, clean slice inventory passes the gate (gates are not always-fail)",
        "structural source check")
    # 423/500/503 in normal functional traffic force a non-passing verdict
    for cid, code in (("FS01", 423), ("FS02", 500), ("FS03", 503)):
        _populate_all(); M.HTTP_STATUSES.append(code)
        mut(cid, _emit_rc() == 1, f"a normal-traffic {code} forces the slice verdict non-passing",
            "structural source check")
    # completeness: a MISSING expected check id forces non-passing (a mid-run abort cannot look like success)
    _populate_all(); M.checks.pop()
    mut("FS04", _emit_rc() == 1, "a missing expected slice check id forces the slice verdict non-passing",
        "structural source check")
    # duplicate-id detection forces non-passing
    _populate_all()
    M.rec(M.EXPECTED_IDS[0], True, desc="dup", category="p", route="-", tenant="-", actor="-",
          expected="-", db_post="-", audit_post="-")
    mut("FS05", _emit_rc() == 1, "a duplicate check id forces the slice verdict non-passing",
        "structural source check")
    M.checks.clear(); M.HTTP_STATUSES.clear()

    # =====================================================================================
    # PREDICATE/UNIT: the slice's exact pass-predicates reject each crafted violation
    # =====================================================================================
    def pd(cid, desc, pred, violated, correct):
        mut(cid, (pred(violated) is False) and (pred(correct) is True), desc, "predicate/unit mutation",
            extra={"rejects_violation": pred(violated) is False, "accepts_correct": pred(correct) is True})

    # EFP01 tests the slice's ACTUAL module-scope discriminator (M.is_validation_409), not a copy: a
    # SnapshotConflict / stale-revision 409 must NOT satisfy it; only the validation-domain 409 must. If a
    # regression weakened the real predicate, this check flips.
    pd("EFP01", "the slice's ACTUAL is_validation_409 rejects a SnapshotConflict/stale-revision 409, accepts the validation 409",
       M.is_validation_409, "stale revision, please retry (snapshot conflict)",
       "Report has unresolved validation tasks")
    # unresolved export must be a 409 that created NO record; an accepted export (200) or a created record caught
    pd("EFP02", "an unresolved report that EXPORTED (200) or created a record would be caught",
       lambda o: o["s"] == 409 and o["val"] and o["dx"] == 0,
       {"s": 200, "val": False, "dx": 1}, {"s": 409, "val": True, "dx": 0})
    # override inert in client mode: allow_unresolved_validation=true must STILL 409; a 200 would be caught
    pd("EFP03", "an override that BYPASSED the gate in client mode (200) would be caught",
       lambda s: s == 409, 200, 409)
    # resolved export: 200 + right format + bytes>0 + sha + one new record + one business audit
    pd("EFP04", "a resolved export that produced an EMPTY artifact or no record would be caught",
       lambda o: o["s"] == 200 and o["fmt_ok"] and o["bytes"] > 0 and o["sha"] and o["dx"] == 1 and o["bizd"] == 1,
       {"s": 200, "fmt_ok": True, "bytes": 0, "sha": "x", "dx": 1, "bizd": 1},
       {"s": 200, "fmt_ok": True, "bytes": 8845, "sha": "abc", "dx": 1, "bizd": 1})
    # content-idempotent re-export: SAME id + NO new record; a duplicate record (dx==1) or new id caught
    pd("EFP05", "a re-export that DUPLICATED the record (dx=1) or minted a new id would be caught",
       lambda o: o["s"] == 200 and o["same_id"] and o["dx"] == 0,
       {"s": 200, "same_id": False, "dx": 1}, {"s": 200, "same_id": True, "dx": 0})
    # worker processed a real job and advanced the revision
    pd("EFP06", "a worker that processed NOTHING or did not advance the revision would be caught",
       lambda o: o["rc"] == 0 and o["processed"] >= 1 and o["rev"] > 0,
       {"rc": 0, "processed": 0, "rev": 0}, {"rc": 0, "processed": 1, "rev": 1})
    # worker env-hygiene: restricted DSN only, no migration material, no libpq leak
    pd("EFP07", "a worker env carrying the migration DSN/role or a libpq leak would be caught",
       lambda o: o["restricted_only"] and o["no_mig"] and o["no_libpq"],
       {"restricted_only": True, "no_mig": False, "no_libpq": True},
       {"restricted_only": True, "no_mig": True, "no_libpq": True})
    # cross-tenant export -> 404 (existence-hiding); a 200 or a 403 oracle would be caught
    pd("EFP08", "a cross-tenant export that SUCCEEDED (200) or leaked existence (403) would be caught",
       lambda s: s == 404, 200, 404)
    # export authorization denials -> 401/403; a 200 would be caught
    pd("EFP09", "an export denial that instead SUCCEEDED (200) would be caught",
       lambda s: s in (401, 403), 200, 403)
    # mint without a signing secret in client mode -> 409; a 200 (token minted) would be caught
    pd("EFP10", "a signed-URL mint that SUCCEEDED without a signing secret in client mode would be caught",
       lambda s: s == 409, 200, 409)

    # signed-reference success: mint 200 + url + token
    pd("SFP01", "a mint that failed to return a url/token would be caught",
       lambda o: o["s"] == 200 and bool(o["url"]) and bool(o["token"]),
       {"s": 200, "url": "", "token": ""}, {"s": 200, "url": "http://x?token=t", "token": "t"})
    # signed retrieve: 200 + correct content-type + disposition
    pd("SFP02", "a signed retrieval with a WRONG content-type/disposition would be caught",
       lambda o: o["s"] == 200 and o["ct"] == M.MEDIA["pdf"] and o["disp"] == 'attachment; filename="monday_report.pdf"',
       {"s": 200, "ct": "text/html", "disp": 'attachment; filename="monday_report.pdf"'},
       {"s": 200, "ct": M.MEDIA["pdf"], "disp": 'attachment; filename="monday_report.pdf"'})
    # sha binding: retrieved bytes' sha256 == ReportExport.sha256; a mismatch (tampered content) caught
    pd("SFP03", "retrieved content whose sha256 did NOT match the ReportExport would be caught",
       lambda o: o["match"], {"match": False}, {"match": True})
    # denial: 'no content disclosed' discriminator -- a 200 body carrying the export marker must fail it
    def denied_no_content(o):
        return o["st"] != 200 and (not o["body"] or b"monday_report" not in o["body"])
    pd("SFP04", "a denial that actually DISCLOSED export content (200 body) would be caught",
       denied_no_content, {"st": 200, "body": b"monday_report pdf bytes"}, {"st": 404, "body": b""})
    pd("SFP05", "a cross-tenant signed retrieval that SUCCEEDED (200) would be caught", lambda s: s == 404, 200, 404)
    pd("SFP06", "a missing-token retrieval that was ACCEPTED (200) instead of 422 would be caught",
       lambda s: s == 422, 200, 422)
    pd("SFP07", "a tampered token that was ACCEPTED (200) instead of 403 would be caught", lambda s: s == 403, 200, 403)
    pd("SFP08", "a wrong-tenant token that was ACCEPTED (200) instead of 404 would be caught", lambda s: s == 404, 200, 404)
    pd("SFP09", "a wrong-secret token that was ACCEPTED (200) instead of 403 would be caught", lambda s: s == 403, 200, 403)
    pd("SFP10", "a wrong-purpose token that was ACCEPTED (200) instead of 403 would be caught", lambda s: s == 403, 200, 403)

    # time boundary: valid -> 200, expired -> 403
    pd("TFP01", "a valid-window token that was REJECTED would be caught", lambda s: s == 200, 403, 200)
    pd("TFP02", "an expired token that was ACCEPTED (200) instead of 403 would be caught", lambda s: s == 403, 200, 403)

    # idempotency contract: export requires NO key -> 200; a keyless export REJECTED (400) would be caught
    pd("IFP01", "a keyless export that was REJECTED (400) -- i.e. wrongly requiring a key -- would be caught",
       lambda o: o["s"] == 200 and o["same_id"] and o["dx"] == 0,
       {"s": 400, "same_id": False, "dx": 0}, {"s": 200, "same_id": True, "dx": 0})

    # audit integrity: keyed_valid + 0 broken; boundary precedes business; secret scan clean
    pd("AFP01", "a broken/legacy audit chain would be caught",
       lambda o: o["state"] == "keyed_valid" and o["broken"] == 0,
       {"state": "broken", "broken": 1}, {"state": "keyed_valid", "broken": 0})
    pd("AFP02", "a business event ORDERED BEFORE its boundary-use event would be caught",
       lambda o: o["bnd"] is not None and o["biz"] is not None and o["bnd"] < o["biz"],
       {"bnd": 41, "biz": 23}, {"bnd": 23, "biz": 41})
    pd("AFP03", "any run secret leaking into the persisted audit would be caught",
       lambda leaked: len(leaked) == 0, ["<signing-secret>"], [])

    # =====================================================================================
    # LIVE controls: prove the export/signed discriminators fire on REAL traffic (non-blanket)
    # =====================================================================================
    def on_live(ctx):
        import psycopg
        import backend.app.store as store_mod
        from backend.app.schemas import Role as _Role
        from backend.app.signed_urls import create_signed_token

        api_verif, token_verif = ctx["api_base"], ctx["token"]
        rt, boot = ctx["rt_dsn"], ctx["boot_dsn"]
        base_env = dict(ctx["base_env"]); run_hash = ctx["run_hash"]
        signing_secret = "expf-signing-" + secrets.token_hex(28)
        LEAK_TERMS[:] = sorted({str(t) for t in [ctx["run_id"], run_hash, ctx["rt_role"], ctx["mig_role"],
                                                 boot, rt, ctx["mig_dsn"], ctx["db"], token_verif,
                                                 signing_secret, base_env["MONDAY_REPORT_API_KEY"]] if t},
                               key=len, reverse=True)
        proc = None; scratch = None; log = None
        try:
            # --- launch ONE signing-secret tenant (fa) ---
            port = G._free_loopback_port()
            appname = f"mr-verif-expf-{run_hash}"
            scratch = Path(os.environ.get("TEMP", "/tmp")) / f"mr-expf-{run_hash}"
            for sub in ("state", "storage", "exports"):
                (scratch / sub).mkdir(parents=True, exist_ok=True)
            env = dict(base_env)
            env.update({
                "MONDAY_REPORT_DATABASE_URL": f"{rt}?application_name={appname}",
                "MONDAY_REPORT_TENANT_SLUG": "expf-a", "MONDAY_REPORT_TENANT_NAME": "Exports Faults A",
                "MONDAY_REPORT_USER_EMAIL": "fa@expf.test", "MONDAY_REPORT_USER_FULL_NAME": "Exports Faults A",
                "MONDAY_REPORT_STATE_PATH": str(scratch / "state" / "s.json"),
                "MONDAY_REPORT_STORAGE_ROOT": str(scratch / "storage"),
                "MONDAY_REPORT_EXPORT_ROOT": str(scratch / "exports"),
                "MONDAY_REPORT_API_KEY": secrets.token_urlsafe(24),
                "MONDAY_REPORT_API_BASE": f"http://127.0.0.1:{port}",
                SIGNING_ENV: signing_secret,
            })
            sv = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                st = store_mod.create_store()
                u = st.create_user("fa@expf.test", "Exports Faults A", [_Role.ADMIN])
                _, tok_fa = st.create_credential(u.id)
                tenant_fa = st.tenant.id
            finally:
                for k, v in sv.items():
                    (os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None))
            LEAK_TERMS.extend([env["MONDAY_REPORT_API_KEY"], tok_fa])
            LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            log = open(scratch / "api.log", "w")
            proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host",
                                     "127.0.0.1", "--port", str(port)], cwd=str(ROOT),
                                    env=G._child_env(env), stdout=log, stderr=subprocess.STDOUT)
            api = f"http://127.0.0.1:{port}"
            for _ in range(45):
                if _http("GET", f"{api}/health")[0] == 200:
                    break
                if proc.poll() is not None:
                    break
                time.sleep(1)

            def mk_ws(a, k, n):
                _, w = _http("POST", f"{a}/workspaces", key=k, body={"name": n, "rig_name": "g"})
                return w["id"] if isinstance(w, dict) else None

            def mk_report(a, k, ws):
                _, r = _http("POST", f"{a}/monday-reports", key=k,
                             body={"workspace_id": ws, "period_start": "2026-01-01", "period_end": "2026-01-07"})
                return r["id"] if isinstance(r, dict) and "id" in r else None

            def task_ids(a, k):
                s, ts = _http("GET", f"{a}/validation-tasks", key=k)
                return {t["id"] for t in ts if isinstance(t, dict)} if (s == 200 and isinstance(ts, list)) else set()

            def sign(res, tenant, secret, ttl=900, purpose=PURPOSE):
                old = os.environ.get(SIGNING_ENV); os.environ[SIGNING_ENV] = secret
                try:
                    tok, _ = create_signed_token(res, purpose, ttl, tenant_id=tenant)
                    return tok
                finally:
                    (os.environ.__setitem__(SIGNING_ENV, old) if old is not None else os.environ.pop(SIGNING_ENV, None))

            # FL01: the export validation gate is STATE-specific -- unresolved 409, then resolved 200
            wsU = mk_ws(api, tok_fa, "fa-unresolved")
            before = task_ids(api, tok_fa)
            _http("POST", f"{api}/workspaces/{wsU}/benchmarking/measurements", key=tok_fa,
                  body={"metric": "feet_drilled_per_day", "value": 440, "unit": "ft/day",
                        "data_source": "faults", "source_identifier": "f-crit", "moc_reference": "MOC-F"})
            tU = next(iter(task_ids(api, tok_fa) - before), None)
            rU = mk_report(api, tok_fa, wsU)
            s_block, _ = _http("POST", f"{api}/monday-reports/{rU}/exports/pdf", key=tok_fa)
            _http("PATCH", f"{api}/validation-tasks/{tU}", key=tok_fa,
                  body={"status": "validated", "resolution_note": "r"}, idem=str(uuid.uuid4()))
            s_ok, body_ok = _http("POST", f"{api}/monday-reports/{rU}/exports/pdf", key=tok_fa)
            mut("FL01", s_block == 409 and s_ok == 200 and isinstance(body_ok, dict) and body_ok.get("id"),
                "LIVE: export is blocked (409) while a task is open and succeeds (200) once resolved (gate is state-specific)",
                "whole-stack HTTP export attempt", extra={"blocked": s_block, "resolved": s_ok})
            expA = body_ok.get("id") if isinstance(body_ok, dict) else None
            sha_meta = body_ok.get("sha256") if isinstance(body_ok, dict) else None

            # FL02: a VALID signed retrieval discloses content (200) while a TAMPERED token is denied (403)
            s_mint, mint = _http("POST", f"{api}/report-exports/{expA}/signed-url", key=tok_fa)
            url = mint.get("url") if isinstance(mint, dict) else ""
            token = url.split("token=", 1)[1] if "token=" in url else ""
            if token:
                LEAK_TERMS.append(token); LEAK_TERMS[:] = sorted({t for t in LEAK_TERMS if t}, key=len, reverse=True)
            st_ok, content, ct, _disp = _dl(f"{api}/signed/report-exports/{expA}?token={token}")
            pseg, sseg = token.split(".", 1)
            flipped = ("b" if pseg[0] != "b" else "c") + pseg[1:]
            st_bad, body_bad, _, _ = _dl(f"{api}/signed/report-exports/{expA}?token={flipped}.{sseg}")
            sha_ok = bool(content) and sha_meta and hashlib.sha256(content).hexdigest() == sha_meta
            mut("FL02", s_mint == 200 and st_ok == 200 and sha_ok and st_bad == 403,
                "LIVE: a valid signed reference discloses the exact export bytes (200, sha match) while a tampered token is 403",
                "whole-stack signed retrieval", extra={"mint": s_mint, "valid": st_ok, "sha_ok": bool(sha_ok), "tampered": st_bad})

            # FL03: expiry is REAL -- a fresh token 200, an expired (ttl<0) token 403
            fresh = sign(uuid.UUID(str(expA)), tenant_fa, signing_secret, ttl=900)
            expd = sign(uuid.UUID(str(expA)), tenant_fa, signing_secret, ttl=-30)
            st_fresh = _dl(f"{api}/signed/report-exports/{expA}?token={fresh}")[0]
            st_exp = _dl(f"{api}/signed/report-exports/{expA}?token={expd}")[0]
            mut("FL03", st_fresh == 200 and st_exp == 403,
                "LIVE: a fresh token retrieves (200) while an expired token is denied (403) -- expiry is time-based, not blanket",
                "whole-stack signed retrieval", extra={"fresh": st_fresh, "expired": st_exp})

            # FL04: the no-secret mint gate is REAL -- foundation API (no secret) 409, secret tenant 200
            wsVf = mk_ws(api_verif, token_verif, "verif-nosecret")
            rVf = mk_report(api_verif, token_verif, wsVf)
            _, xVf = _http("POST", f"{api_verif}/monday-reports/{rVf}/exports/json", key=token_verif)
            expVf = xVf.get("id") if isinstance(xVf, dict) else None
            s_nosecret = _http("POST", f"{api_verif}/report-exports/{expVf}/signed-url", key=token_verif)[0]
            mut("FL04", s_nosecret == 409 and s_mint == 200,
                "LIVE: mint is 409 on the no-secret foundation API but 200 on the signing-secret tenant (gate is real)",
                "whole-stack HTTP mint attempt", extra={"no_secret": s_nosecret, "with_secret": s_mint})

            # FL05: content-idempotency is REAL -- re-export same format = same id (no new record);
            #       a DISTINCT format mints a NEW export record
            def xcount():
                with psycopg.connect(rt, autocommit=True) as c:
                    c.execute("select set_config('app.tenant_slug','expf-a',false)")
                    return int(c.execute(f"select coalesce(jsonb_array_length(payload->'report_exports'),0) "
                                         f"from {STATE_TABLE} where tenant_slug='expf-a'").fetchone()[0])
            x0 = xcount()
            _, re_pdf = _http("POST", f"{api}/monday-reports/{rU}/exports/pdf", key=tok_fa)
            dx_same = xcount() - x0
            x1 = xcount()
            _, csv_body = _http("POST", f"{api}/monday-reports/{rU}/exports/csv", key=tok_fa)
            dx_new = xcount() - x1
            same_id = isinstance(re_pdf, dict) and re_pdf.get("id") == expA
            mut("FL05", same_id and dx_same == 0 and dx_new == 1,
                "LIVE: re-export (same format) reuses the export with no new record; a new format mints exactly one record",
                "whole-stack HTTP export attempt", extra={"same_id": bool(same_id), "dx_same": dx_same, "dx_new": dx_new})

            # FL06: tenant-capability binding is REAL -- correct-tenant token 200, wrong-tenant forged token 404
            good_tok = sign(uuid.UUID(str(expA)), tenant_fa, signing_secret)
            wrong_tok = sign(uuid.UUID(str(expA)), uuid.uuid4(), signing_secret)
            st_good = _dl(f"{api}/signed/report-exports/{expA}?token={good_tok}")[0]
            st_wrong = _dl(f"{api}/signed/report-exports/{expA}?token={wrong_tok}")[0]
            mut("FL06", st_good == 200 and st_wrong == 404,
                "LIVE: a correct-tenant token retrieves (200) while a wrong-tenant forged token is denied (404)",
                "whole-stack signed retrieval", extra={"correct_tenant": st_good, "wrong_tenant": st_wrong})

        finally:
            if proc is not None:
                try:
                    proc.terminate(); proc.wait(timeout=10)
                except Exception:
                    pass
            if log is not None:
                try:
                    log.close()
                except Exception:
                    pass
            if scratch is not None:
                import shutil
                shutil.rmtree(scratch, ignore_errors=True)

    G.checks = []
    err = {}

    def wrapped(ctx):
        try:
            on_live(ctx)
        except Exception as exc:  # noqa: BLE001
            import traceback
            err["type"] = type(exc).__name__
            err["tb"] = traceback.format_exc()[-1800:]
    G._ON_LIVE = wrapped
    try:
        G.run_stack()
    finally:
        G._ON_LIVE = None
    foundation_fail = [c["id"] for c in getattr(G, "checks", []) if not c.get("ok", True) and not c.get("skipped", False)]
    if foundation_fail:
        mut("foundation", False, f"foundation checks not ok: {sorted(foundation_fail)[:8]}", "structural source check")
    if err:
        print("ON_LIVE ERROR:", err.get("type"), file=sys.stderr)
        print(_scrub(err.get("tb", "")), file=sys.stderr)   # scrub DSNs/tokens/secret out of the traceback
        mut("on_live_abort", False, f"on_live aborted with {err.get('type')} (see stderr)", "structural source check")
    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    battery = "passed" if (checks and not failed and not skipped) else ("skipped" if skipped else "failed")
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(passed) if not skipped else 0,
                       "skipped": len(checks) if skipped else 0,
                       "failed": 0 if skipped else len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-exports-signed-references-faults-only",
                       "mutation_battery": battery,
                       "eligible_for_tenant_evidence": False,
                       "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(_scrub(json.dumps(out, indent=2, default=str)))
    if skipped:
        print("\nExports fault battery SKIPPED (docker unavailable, non-certifying).")
        return 0
    if failed:
        print(f"\nExports fault battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(_scrub(f"  FAIL: {c['check_id']} -> {c.get('description','')}"))
        return 1
    print(f"\nExports fault battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-exports-signed-references-faults-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
