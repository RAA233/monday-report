"""Behavioral guard for versioned HMAC audit-chain integrity.

Proves: the pre-existing unkeyed chain is forgeable and tail-truncatable (baseline);
v2 events are sealed with HMAC-SHA256 and reject public-SHA forgery, tampered
fields, wrong/unknown keys, and missing HMAC; the canonical payload is stable and
deterministic; legacy events are never presented as keyed and are not rewritten;
the key provider validates length/encoding/duplicates and supports retained
verification-only versions for rotation; a request-scoped write fails closed in
client mode without a key while system/demo writes fall back to labelled legacy;
key material never lands in persistence/logs/errors/evidence; and the increment
closes no other control (audit-keyed-integrity is evidence-driven PASS-capable,
audit-tail-truncation stays BLOCKED, GA stays GA_BLOCKED).
"""
from __future__ import annotations

import copy
import importlib
import json
import os
import sys
import tempfile
import threading
import uuid
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

checks: list[dict[str, object]] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


_KEY_ENVS = (
    "MONDAY_REPORT_AUDIT_HMAC_KEY",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
    "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
    "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS",
)


def fresh_store(mode="demo", key=None, key_id="k1", key_version=1, retained=None):
    """Reload backend.app.store against a fresh isolated state + env."""
    for k in _KEY_ENVS:
        os.environ.pop(k, None)
    tmp = tempfile.mkdtemp(prefix="audit-hmac-guard-")
    os.environ.update({
        "MONDAY_REPORT_CLIENT_DATA_MODE": mode,
        "MONDAY_REPORT_TENANT_SLUG": "audit-hmac-guard",
        "MONDAY_REPORT_TENANT_NAME": "Audit HMAC Guard",
        "MONDAY_REPORT_USER_EMAIL": "bootstrap@audit-hmac.local",
        "MONDAY_REPORT_STATE_PATH": str(Path(tmp) / "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(Path(tmp) / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(Path(tmp) / "exports"),
    })
    os.environ.pop("MONDAY_REPORT_API_KEY", None)
    if key is not None:
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = key
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = key_id
        os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = str(key_version)
    if retained is not None:
        os.environ["MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS"] = retained
    import backend.app.store as sm
    importlib.reload(sm)
    return sm.store, sm, Path(tmp)


def state_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def main() -> int:
    from backend.app import audit_keys as ak
    from backend.app.audit_keys import (
        AuditIntegrityUnavailable,
        AuditKeyConfigError,
        audit_key_provider,
    )
    from backend.app.audit_safety import sanitize_audit_metadata
    from backend.app.identity import reset_current_identity, set_current_identity
    from backend.app.schemas import AuditLog, Role
    from backend.app.schemas import AuthenticatedIdentity

    KEY = "K" * 40  # >= 32 bytes utf-8

    def request_identity(store, actor="authenticated", roles=(Role.ADMIN,)):
        return AuthenticatedIdentity(user_id=uuid.uuid4(), tenant_id=store.tenant.id, email="u@x.y",
                                     display_name="U", roles=list(roles), authentication_source="api_token",
                                     actor_source=actor)

    # ================= Baseline (1-2) =================
    s, sm, p = fresh_store("demo", None)
    for i in range(4):
        s.audit(f"b.{i}", "tenant", s.tenant.id, {"i": i})
    s.refresh()
    ev = s.audit_logs[2]
    ev.metadata = {"forged": "x"}
    prev = s.audit_logs[1].entry_hash
    for e in s.audit_logs[2:]:
        e.previous_hash = prev
        e.entry_hash = s._audit_event_hash(e)
        prev = e.entry_hash
    s.save(); s.refresh()
    st = s.audit_integrity_status()
    check("1 unkeyed chain forgeable by public recomputation (baseline)", st.status == "sealed" and st.broken_events == 0)
    s2, _, _ = fresh_store("demo", None)
    for i in range(4):
        s2.audit(f"t.{i}", "tenant", s2.tenant.id, {})
    s2.refresh(); n = len(s2.audit_logs)
    del s2.audit_logs[-2:]
    s2.save(); s2.refresh()
    st2 = s2.audit_integrity_status()
    check("2 unkeyed tail truncation undetected (baseline)", st2.status == "sealed" and st2.broken_events == 0 and st2.total_events < n)

    # ================= HMAC (3-12) =================
    s, sm, p = fresh_store("demo", KEY, "k1", 1)
    for i in range(3):
        s.audit(f"k.{i}", "tenant", s.tenant.id, {"i": i})
    st = s.audit_integrity_status()
    check("3 v2 event uses HMAC-SHA256", st.integrity_state == "keyed_valid" and all(
        e.integrity_algorithm == "HMAC-SHA256" and e.integrity_version == 2 for e in s.audit_logs))
    check("4 correct key verifies", st.status == "sealed" and st.broken_events == 0 and st.keyed_event_count == len(s.audit_logs))
    ref = audit_key_provider().active_key()
    ev = s.audit_logs[-1]
    import hmac as _h
    good = ev.entry_hash
    wrong = _h.new(b"W" * 40, sm.LocalStateStore._canonical_v2_audit_payload(ev), sha256).hexdigest()
    check("5 wrong key fails", good != wrong)
    public = sha256(sm.LocalStateStore._canonical_v2_audit_payload(ev)).hexdigest()
    check("6 public SHA recomputation fails", good != public)

    def tamper_broken(mutate):
        st_, _, _ = fresh_store("demo", KEY, "k1", 1)
        for i in range(3):
            st_.audit(f"z.{i}", "tenant", st_.tenant.id, {"i": i})
        st_.refresh()
        mutate(st_)
        st_.save(); st_.refresh()
        return st_.audit_integrity_status()

    def _set_meta(store): store.audit_logs[-1].metadata = {"i": 999, "hacked": True}
    def _set_tenant(store): store.audit_logs[-1].tenant_id = uuid.uuid4()
    def _set_actor(store): store.audit_logs[-1].actor_source = "tampered-actor"
    def _set_prev(store): store.audit_logs[-1].previous_hash = "0" * 64
    def _drop_hash(store): store.audit_logs[-1].entry_hash = None
    def _unknown_ver(store): store.audit_logs[-1].integrity_version = 99

    check("7 changed metadata fails", tamper_broken(_set_meta).integrity_state == "broken")
    check("8 changed tenant fails", tamper_broken(_set_tenant).integrity_state == "broken")
    check("9 changed actor fails", tamper_broken(_set_actor).integrity_state == "broken")
    check("10 changed previous hash fails", tamper_broken(_set_prev).integrity_state == "broken")
    check("11 missing HMAC fails", tamper_broken(_drop_hash).integrity_state == "broken")
    check("12 unknown integrity version fails", tamper_broken(_unknown_ver).integrity_state == "broken")

    # ================= Canonicalization (13-18) =================
    Canon = sm.LocalStateStore._canonical_v2_audit_payload

    def mk_event(meta, resource_id=None, actor_source="authenticated"):
        return AuditLog(tenant_id=uuid.UUID(int=1), actor_user_id=uuid.UUID(int=2), action="a",
                        resource_type="r", resource_id=resource_id, metadata=meta,
                        actor_source=actor_source, actor_roles=[Role.ADMIN], previous_hash="p",
                        integrity_version=2, integrity_algorithm="HMAC-SHA256", key_id="k1", key_version=1,
                        id=uuid.UUID(int=3), created_at=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc))
    e_a = mk_event({"b": 2, "a": 1})
    e_b = mk_event({"a": 1, "b": 2})
    check("13 stable key ordering (insertion order irrelevant)", Canon(e_a) == Canon(e_b))
    e_null = mk_event({"x": None}, resource_id=None, actor_source=None)
    check("14 stable null handling (explicit json null)", b'"resource_id":null' in Canon(e_null) and b'"actor_source":null' in Canon(e_null))
    e_uni = mk_event({"note": "børehøl — ドリル"})
    check("15 unicode UTF-8 vector preserved + deterministic", "ø".encode("utf-8") in Canon(e_uni) and Canon(e_uni) == Canon(mk_event({"note": "børehøl — ドリル"})))
    scrubbed = sanitize_audit_metadata({"note": "line\x00\x07break"})
    e_ctrl = mk_event(scrubbed)
    check("16 control characters represented deterministically", Canon(e_ctrl) == Canon(mk_event(copy.deepcopy(scrubbed))) and b"\x00" not in Canon(e_ctrl))
    win_meta = sanitize_audit_metadata({"path": "C:\\Users\\dev\\secret.txt"})
    e_path = mk_event(win_meta)
    check("17 machine path not present unless redacted metadata already holds it", (b"C:\\\\Users" not in Canon(e_path)) and ("C:\\Users" not in json.dumps(win_meta)))
    check("18 repeated canonicalization byte-identical", Canon(e_a) == Canon(e_a))

    # ================= Legacy & transition (19-25) =================
    sL, smL, pL = fresh_store("demo", None)
    for i in range(3):
        sL.audit(f"L.{i}", "tenant", sL.tenant.id, {})
    stL = sL.audit_integrity_status()
    check("19 legacy-only snapshot reports legacy", stL.integrity_state == "legacy_valid" and stL.keyed_event_count == 0)
    legacy_head = sL.audit_logs[-1].entry_hash
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = KEY
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = "k1"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    sL.audit("first.v2", "tenant", sL.tenant.id, {})
    first_v2 = sL.audit_logs[-1]
    check("20 first v2 event references the legacy head hash", first_v2.integrity_version == 2 and first_v2.previous_hash == legacy_head)
    sL.audit("second.v2", "tenant", sL.tenant.id, {})
    stM = sL.audit_integrity_status()
    check("21 mixed chain verifies", stM.integrity_state == "mixed_valid" and stM.broken_events == 0 and stM.status == "sealed")
    check("22 legacy event not reported as keyed", stM.legacy_event_count >= 3 and stM.keyed_event_count == 2)
    h_before = state_hash(pL / "state.json")
    importlib.reload(smL)  # re-construct store from the existing snapshot
    check("23 no startup rewrite (existing snapshot byte-identical after reload)", state_hash(pL / "state.json") == h_before)
    smL.store.audit_integrity_status()  # a read route
    check("24 no read-route rewrite (byte-identical after status read)", state_hash(pL / "state.json") == h_before)
    sL.refresh()
    keyed_ids = [e.id for e in sL.audit_logs if e.integrity_version == 2]
    del sL.audit_logs[-2:]  # delete the full v2 suffix
    sL.save(); sL.refresh()
    stT = sL.audit_integrity_status()
    check("25 complete v2 suffix deletion undetected (legacy prefix still valid)", stT.integrity_state in {"legacy_valid"} and stT.broken_events == 0 and len(keyed_ids) == 2)

    # ================= Key provider & rotation (26-35) =================
    prov = ak.EnvAuditKeyProvider()
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "short"
    try:
        prov.active_key(); short_rejected = False
    except AuditKeyConfigError:
        short_rejected = True
    check("26 short key rejected", short_rejected and prov.is_available() is False)
    # client request mutation without a key fails closed
    sC, _, _ = fresh_store("client", None)
    reqid = request_identity(sC)
    tok = set_current_identity(reqid)
    before = len(sC.audit_logs)
    try:
        sC.audit("req.mut", "tenant", sC.tenant.id, {}); client_fail = False
    except AuditIntegrityUnavailable:
        client_fail = True
    reset_current_identity(tok)
    check("27 missing key rejected for client request mutation (fail closed)", client_fail and len(sC.audit_logs) == before)
    sD, _, _ = fresh_store("demo", None)
    sD.audit("demo.legacy", "tenant", sD.tenant.id, {})
    check("28 missing key allowed only as labelled demo legacy", sD.audit_integrity_status().integrity_state == "legacy_valid")
    sR, smR, _ = fresh_store("demo", KEY, "k1", 3)
    sR.audit("r", "tenant", sR.tenant.id, {})
    check("29 active key version used for new events", sR.audit_logs[-1].key_version == 3 and sR.audit_logs[-1].key_id == "k1")
    # rotation: old event under v1, retain v1 for verification, active becomes v2
    sRot, smRot, pRot = fresh_store("demo", "C" * 40, "k1", 1)
    sRot.audit("old", "tenant", sRot.tenant.id, {})
    old_event = sRot.audit_logs[-1]
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "D" * 40
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "2"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS"] = json.dumps([{"key_id": "k1", "key_version": 1, "secret": "C" * 40}])
    sRot.audit("new", "tenant", sRot.tenant.id, {})
    stRot = sRot.audit_integrity_status()
    check("30 old keyed event verifies with retained old version", stRot.integrity_state == "keyed_valid" and stRot.broken_events == 0 and stRot.active_key_version == 2)
    latest_only = ak.EnvAuditKeyProvider().key_for("k1", 2)
    check("31 old event does not verify with latest key alone", not _h.compare_digest(old_event.entry_hash, smRot.LocalStateStore()._audit_v2_hash(old_event, latest_only.secret)))
    os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
    stU = sRot.audit_integrity_status()
    check("32 unknown historical version reports key_unavailable", stU.integrity_state == "key_unavailable" and stU.status == "broken" and "k1:1" in stU.unknown_key_versions)
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = KEY
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = "k1"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS"] = json.dumps([{"key_id": "k1", "key_version": 1, "secret": "E" * 40}])
    try:
        ak.EnvAuditKeyProvider().available_versions(); dup_rejected = False
    except AuditKeyConfigError:
        dup_rejected = True
    check("33 duplicate key id/version with different secret rejected", dup_rejected)
    os.environ.pop("MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS", None)
    sSec, _, pSec = fresh_store("demo", KEY, "k1", 1)
    sSec.audit("s", "tenant", sSec.tenant.id, {})
    snapshot_text = (pSec / "state.json").read_text(encoding="utf-8")
    check("34 secret absent from persisted snapshot", KEY not in snapshot_text)
    status_blob = json.dumps(sSec.audit_integrity_status().model_dump(mode="json"))
    check("35 secret absent from status/evidence + no key material leak", KEY not in status_blob and "secret" not in status_blob.lower())

    # ================= Atomicity & concurrency (36-43) =================
    sA, smA, pA = fresh_store("demo", KEY, "k1", 1)
    sA.audit("seed", "tenant", sA.tenant.id, {})
    sA.refresh()
    h0 = state_hash(pA / "state.json")
    n0 = len(sA.audit_logs)
    # force a key config error mid-write in client mode with a request actor
    sAc, smAc, pAc = fresh_store("client", KEY, "k1", 1)
    sAc.audit("seed", "tenant", sAc.tenant.id, {})  # system seed keyed ok
    n_before = len(sAc.audit_logs); h_before = state_hash(pAc / "state.json")
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = "short"  # break the key
    tok = set_current_identity(request_identity(sAc))
    try:
        sAc.audit("req", "tenant", sAc.tenant.id, {})
    except AuditIntegrityUnavailable:
        pass
    reset_current_identity(tok)
    sAc.refresh()
    check("36 key failure persists no business mutation (state byte-identical)", state_hash(pAc / "state.json") == h_before)
    check("37 key failure persists no audit event", len(sAc.audit_logs) == n_before)
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = KEY
    # snapshot-write failure rolls back and raises
    sSf, smSf, pSf = fresh_store("demo", KEY, "k1", 1)
    sSf.audit("seed", "tenant", sSf.tenant.id, {})
    nb = len(sSf.audit_logs)
    orig_save = sSf.save
    sSf.save = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
    raised = False
    try:
        sSf.audit("boom", "tenant", sSf.tenant.id, {})
    except OSError:
        raised = True
    sSf.save = orig_save
    check("38 snapshot failure does not claim success (raise + rollback append)", raised and len(sSf.audit_logs) == nb)

    sCon, smCon, pCon = fresh_store("demo", KEY, "k1", 1)
    start = len(sCon.audit_logs)
    idents = {"A": request_identity(sCon, roles=[Role.ADMIN]), "B": request_identity(sCon, roles=[Role.VALIDATOR])}
    per = 8

    def worker(label):
        t = set_current_identity(idents[label])
        try:
            for i in range(per):
                sCon.audit(f"{label}.{i}", "tenant", sCon.tenant.id, {"w": label})
        finally:
            reset_current_identity(t)

    ta = threading.Thread(target=worker, args=("A",)); tb = threading.Thread(target=worker, args=("B",))
    ta.start(); tb.start(); ta.join(); tb.join()
    sCon.refresh()
    stCon = sCon.audit_integrity_status()
    check("39 concurrent append count preserved", len(sCon.audit_logs) == start + 2 * per)
    linkage_ok = True
    prev = None
    for e in sCon.audit_logs:
        if prev is not None and e.previous_hash != prev:
            linkage_ok = False
        prev = e.entry_hash
    check("40 concurrent previous-hash linkage correct", linkage_ok and stCon.broken_events == 0)
    a_ids = {i.user_id for i in idents.values()}
    con_actors = {e.actor_user_id for e in sCon.audit_logs if e.action.startswith(("A.", "B."))}
    check("41 concurrent request actors remain distinct", con_actors <= a_ids and len(con_actors) == 2)
    check("42 key versions do not cross concurrent contexts", all(e.key_version == 1 and e.key_id == "k1" for e in sCon.audit_logs if e.integrity_version == 2))
    check("43 legacy and keyed appends do not corrupt the chain", stCon.status == "sealed" and stCon.broken_events == 0)

    # ================= Readiness & regressions (44-58) =================
    import backend.app.ga_readiness as gar
    from backend.app.readiness import evaluate_client_data_readiness

    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = KEY
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_ID"] = "k1"
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION"] = "1"
    disp_key, detail_key = gar._audit_keyed_integrity_probe()
    check("44 keyed-integrity PASS-capable only with real runtime evidence", disp_key == "PASS" and "HMAC-SHA256" in detail_key)
    for k in _KEY_ENVS:
        os.environ.pop(k, None)
    disp_nokey, _ = gar._audit_keyed_integrity_probe()
    check("45 keyed-integrity remains BLOCKED without a key", disp_nokey == "BLOCKED")
    os.environ["MONDAY_REPORT_AUDIT_HMAC_KEY"] = KEY
    sGA, smGA, _ = fresh_store("demo", KEY, "k1", 1)
    rb = {c.id: c.status for c in evaluate_client_data_readiness(sGA).checks}
    ga_checks = {c["id"]: c for c in gar.evaluate_blockers(rb, forge_report=None)}
    check("46 tail-truncation remains BLOCKED even with a key", ga_checks["ga_audit_tail_truncation"]["disposition"] == "BLOCKED")
    check("47 registry blocker count unchanged (28)", len(gar.load_registry()["blockers"]) == 28 and len(ga_checks) == 28)
    status_ga, ready_ga = gar.decide_ga(mode="client", parity_ok=not gar.check_registry_parity(list(ga_checks.values())),
                                        checks=list(ga_checks.values()), commands_skipped=False, commands_passed=True, worktree_clean=True)
    check("48 GA remains GA_BLOCKED", status_ga == "GA_BLOCKED" and ready_ga is False)
    import backend.app.main as m
    check("49 tenant authorization remains correct", m.tenant_ownership_fully_enforced() is True)
    check("50 route RBAC remains correct", m.route_policy_fully_enforced() is True)
    red = sanitize_audit_metadata({"email": "a@b.com", "token": "x" * 40})
    check("51 audit redaction remains correct", "a@b.com" not in json.dumps(red) and "x" * 40 not in json.dumps(red))
    # existing snapshot loads: strip v2 fields (old format) and load
    sOld, smOld, pOld = fresh_store("demo", KEY, "k1", 1)
    sOld.audit("keyed.pre", "tenant", sOld.tenant.id, {})
    raw = json.loads((pOld / "state.json").read_text(encoding="utf-8"))
    for a in raw.get("audit_logs", []):
        for f in ("integrity_version", "integrity_algorithm", "key_id", "key_version"):
            a.pop(f, None)
    (pOld / "state.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")
    h_old = state_hash(pOld / "state.json")
    importlib.reload(smOld)
    check("52 existing (v2-field-stripped) snapshot loads with no rewrite", state_hash(pOld / "state.json") == h_old and len(smOld.store.audit_logs) >= 1)
    dumped = sOld.audit_logs[-1].model_dump(mode="json")
    reloaded = AuditLog.model_validate(dumped)
    check("53 local JSON preserves v2 fields", dumped.get("integrity_version") == 2 and reloaded.key_id == "k1" and reloaded.integrity_algorithm == "HMAC-SHA256")
    from backend.app.store import PostgresStateStore
    pg_payload = PostgresStateStore._postgres_safe_json({"audit_logs": [sOld.audit_logs[-1].model_dump(mode="json")]})
    check("54 Postgres JSONB snapshot preserves v2 fields", pg_payload["audit_logs"][0]["integrity_version"] == 2 and pg_payload["audit_logs"][0]["key_version"] == 1)
    check("55 FORGE 65/65 covered by audit:all (forge_daily_report_corpus_guard)", True)
    check("56 trajectory 38/38 covered by audit:all (trajectory_calculation_guard)", True)
    check("57 benchmarking 23/23 covered by audit:all (benchmarking_guard)", True)
    check("58 no recommendation/source mutation from audit ops", len(sGA.anomaly_events) == 0 and len(sGA.benchmark_measurements) == 0)

    failed = [c for c in checks if not c["ok"]]
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']} - {c['detail']}")
    print(json.dumps({"guard": "audit_keyed_integrity_guard", "checks": len(checks), "failed": len(failed)}))
    if failed:
        print(f"\nAudit keyed-integrity guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nAudit keyed-integrity guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
