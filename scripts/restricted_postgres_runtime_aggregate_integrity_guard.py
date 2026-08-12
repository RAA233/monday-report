"""audit:restricted-postgres-runtime-aggregate-integrity -- non-vacuity battery for the COMPLETE
restricted-PostgreSQL aggregate commands (`audit:restricted-postgres-runtime[-faults]`).

Proves the aggregate certification is NOT vacuous: for every forgery/omission/overclaim it drives the
aggregate's REAL pure evaluation functions (`M.verify_hashes` / `M.verify_commands` / `M.load_expected_ids`
/ `core.evaluate_child` / `core.aggregate`) against a crafted-invalid synthetic child observation and
confirms the aggregate refuses to certify. The baseline (a complete, valid synthetic inventory built from
the frozen expected-id sidecar) is confirmed to PASS first, so the gates are not always-fail.

These tests use SYNTHETIC child summaries by design; the certification path itself
(`core.certify` -> `core.run_child`) always executes the REAL child subprocesses -- a structural source
check here proves that path launches subprocesses and never imports a child's assertion helpers.

Docker-free and deterministic. Honest scope:
  claim_scope = restricted-runtime-aggregate-integrity-only
  eligible_for_tenant_evidence = false / eligible_for_readiness = false / production_parity = false
It must NEVER be consumed as tenant-authorization or readiness evidence.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import restricted_postgres_runtime_manifest as M  # noqa: E402
import restricted_postgres_runtime_aggregate_core as C  # noqa: E402

checks: list[dict] = []


def rec(cid, ok, desc, level="predicate/unit mutation"):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level})


def _valid_child_run(entry, kind, eids):
    ids = list(eids[entry["name"]])
    summary = {
        "passed": entry["expected_count"], "failed": 0, "skipped": 0,
        "claim_scope": entry["claim_scope"],
        "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
        "production_parity": False, "migration_principal_class": "test-only-bootstrap-migration-admin",
        "execution_level_totals": {"predicate/unit mutation": entry["expected_count"]},
    }
    if kind == "functional":
        summary["full_functional_matrix"] = "not_run"
    for c in entry["required_counters"]:
        summary[c] = 0
    return C.RunResult(0, summary, ids, True, "")


def build_valid(kind):
    eids = M.load_expected_ids()[kind]
    entries = M.FUNCTIONAL if kind == "functional" else M.FAULT
    results = {}
    for e in entries:
        run = _valid_child_run(e, kind, eids)
        results[e["name"]] = {"run": run, "problems": C.evaluate_child(e, kind, run, eids[e["name"]])}
    return entries, eids, results


def scenario(kind, name, apply_fn, **agg_kwargs):
    """Rebuild a valid inventory, mutate ONE child (or aggregate arg), re-evaluate, re-aggregate."""
    entries, eids, results = build_valid(kind)
    e = M.child_by_name(entries, name)
    run = results[name]["run"]
    apply_fn(run, e)
    results[name]["problems"] = C.evaluate_child(e, kind, run, eids[e["name"]])
    v = C.aggregate(entries, kind, results, eids, **agg_kwargs)
    return v, results[name]["problems"]


def run() -> int:
    # ---- baseline: a complete valid inventory certifies (gates are not always-fail) ----
    for kind, total in (("functional", M.EXPECTED_FUNCTIONAL_TOTAL), ("fault", M.EXPECTED_FAULT_TOTAL)):
        entries, eids, results = build_valid(kind)
        v = C.aggregate(entries, kind, results, eids)
        rec(f"AB00-{kind}", v["ok"] and v["emitted_ids"] == total and v["failed"] == 0 and v["skipped"] == 0
            and not any(r["problems"] for r in results.values()),
            f"a complete valid {kind} inventory certifies ({total} checks) -- gates are not always-fail",
            level="structural source check")

    # ---- per-child forgery mutations (functional unless noted) ----
    def refuses(v, problems, token=None):
        cond = (not v["ok"])
        if token is not None:
            cond = cond and any(token in p for p in problems)
        return cond

    v, p = scenario("functional", "mutations", lambda run, e: setattr(run, "rc", 1))
    rec("JF02 child exits nonzero", refuses(v, p, "nonzero_exit"), "a nonzero child exit fails the aggregate")

    v, p = scenario("functional", "exports", lambda run, e: (setattr(run, "parse_ok", False), setattr(run, "summary", None)))
    rec("JF03 malformed JSON", refuses(v, p, "malformed_summary"), "a malformed/absent child summary fails the aggregate")

    v, p = scenario("functional", "isolation", lambda run, e: run.check_ids.pop())
    rec("JF04 partial inventory", refuses(v, p, "missing_ids"), "a child emitting a partial id inventory fails the aggregate")

    v, p = scenario("functional", "core", lambda run, e: run.check_ids.__setitem__(1, run.check_ids[0]))
    rec("JF05 duplicate id", refuses(v, p, "duplicate_id"), "a child emitting a duplicate id fails the aggregate")

    v, p = scenario("functional", "mutations", lambda run, e: run.check_ids.__setitem__(0, "TOTALLY::unknown::id"))
    rec("JF06 unknown id", refuses(v, p, "unknown_ids"), "a child emitting an unknown id fails the aggregate")

    v, p = scenario("functional", "worker-import", lambda run, e: run.check_ids.append("EXTRA-ID"))
    rec("JF07 count differs from manifest", refuses(v, p, "emitted_count_mismatch"),
        "a child emitting more checks than the manifest count fails the aggregate")

    v, p = scenario("functional", "exports", lambda run, e: run.summary.__setitem__("failed", 1))
    rec("JF08 child reports FAIL", refuses(v, p, "failed_nonzero"), "a child reporting FAIL fails the aggregate")

    v, p = scenario("functional", "exports", lambda run, e: run.summary.__setitem__("skipped", 1))
    rec("JF09 child reports SKIP", refuses(v, p, "skipped_nonzero"), "a child reporting SKIP fails the aggregate")

    v, p = scenario("functional", "core", lambda run, e: run.summary.__setitem__("claim_scope", "wrong-scope"))
    rec("JF10 claim scope changed", refuses(v, p, "claim_scope_mismatch"), "a changed child claim scope fails the aggregate")

    v, p = scenario("functional", "isolation", lambda run, e: run.summary.__setitem__("eligible_for_tenant_evidence", True))
    rec("JF11 evidence eligibility true", refuses(v, p, "contract_eligible_for_tenant_evidence"),
        "a child flipped to tenant-evidence eligible fails the aggregate")

    v, p = scenario("functional", "isolation", lambda run, e: run.summary.__setitem__("eligible_for_readiness", True))
    rec("JF12 readiness eligibility true", refuses(v, p, "contract_eligible_for_readiness"),
        "a child flipped to readiness eligible fails the aggregate")

    v, p = scenario("functional", "isolation", lambda run, e: run.summary.__setitem__("production_parity", True))
    rec("JF13 production parity true", refuses(v, p, "contract_production_parity"),
        "a child overclaiming production parity fails the aggregate")

    v, p = scenario("functional", "core", lambda run, e: run.summary.pop("migration_principal_class", None))
    rec("JF14 migration classification omitted", refuses(v, p, "contract_migration_principal_class"),
        "a child omitting the migration-principal classification fails the aggregate")

    v, p = scenario("functional", "mutations", lambda run, e: run.summary.pop("normal_functional_http_423", None))
    rec("JF15 normal HTTP counter omitted", refuses(v, p, "counter_missing"),
        "a child omitting a required normal-HTTP counter fails the aggregate")

    v, p = scenario("functional", "exports", lambda run, e: run.summary.__setitem__("normal_functional_http_500", 1))
    rec("JF16 normal HTTP counter nonzero", refuses(v, p, "counter_nonzero"),
        "a nonzero normal-HTTP counter fails the aggregate")

    v, p = scenario("functional", "worker-import", lambda run, e: run.summary.__setitem__("normal_worker_process_failures", 1))
    rec("JF17 normal worker failure nonzero", refuses(v, p, "counter_nonzero"),
        "a nonzero normal worker-process-failure counter fails the aggregate")

    v, p = scenario("functional", "worker-import", lambda run, e: run.summary.__setitem__("normal_import_process_failures", 1))
    rec("JF18 normal import failure nonzero", refuses(v, p, "counter_nonzero"),
        "a nonzero normal import-process-failure counter fails the aggregate")

    # ---- aggregate-level mutations ----
    entries, eids, results = build_valid("functional")
    del results["exports"]
    v = C.aggregate(entries, "functional", results, eids)
    rec("JA01 child omitted", (not v["ok"]) and v["emitted_ids"] != M.EXPECTED_FUNCTIONAL_TOTAL,
        "omitting a functional child fails the aggregate")

    entries, eids, results = build_valid("functional")
    v = C.aggregate(entries, "functional", results, eids, cleanup="incomplete")
    rec("JA19 cleanup incomplete", not v["ok"], "an incomplete cleanup result fails the aggregate")

    # cleanup field must be present in the emitted contract
    entries, eids, results = build_valid("functional")
    v = C.aggregate(entries, "functional", results, eids)
    s_ok = C._base_summary("functional", C._KIND_META["functional"], v, passed=v["ok"])
    rec("JA19b cleanup field present", "cleanup" in s_ok, "the aggregate emits a cleanup result field")

    v, _ = scenario("functional", "core", lambda run, e: None, deferred=["worker-import-partial"])
    rec("JA20 deferred area nonempty", not v["ok"], "a nonempty deferred functional area fails the complete claim")

    entries, eids, results = build_valid("functional")
    results["isolation"]["run"].check_ids.pop()
    results["isolation"]["problems"] = C.evaluate_child(M.child_by_name(entries, "isolation"), "functional",
                                                        results["isolation"]["run"], eids["isolation"])
    v = C.aggregate(entries, "functional", results, eids)
    rec("JA22 aggregate total not 266", (not v["ok"]) and v["emitted_ids"] != 266,
        "an aggregate inventory != 266 fails certification")

    # ---- manifest fail-closed (hash / command / path) ----
    rec("JH01 child hash changed", bool(M.verify_hashes([dict(M.FUNCTIONAL[0], sha256="0" * 64)])),
        "verify_hashes flags a changed accepted child hash", level="structural source check")
    rec("JH02 script path missing", bool(M.verify_hashes([dict(M.FUNCTIONAL[0], script="scripts/__nope__.py")])),
        "verify_hashes flags a missing/renamed script path", level="structural source check")
    rec("JH03 wrong command", bool(M.verify_commands([dict(M.FUNCTIONAL[0], command="audit:not-a-real-command")])),
        "verify_commands flags a command absent from package.json", level="structural source check")
    rec("JH04 command maps to wrong script",
        bool(M.verify_commands([dict(M.FUNCTIONAL[0], script="scripts/restricted_postgres_runtime_manifest.py")])),
        "verify_commands flags a command that does not map to the declared script", level="structural source check")

    # sidecar expected-id fail-closed invariants (injectable data)
    good = json.loads((ROOT / "scripts" / "restricted_postgres_runtime_manifest_ids.json").read_text(encoding="utf-8"))
    M.load_expected_ids(good)  # baseline: the real sidecar loads

    def raises_manifest_error(mutated):
        try:
            M.load_expected_ids(mutated)
            return False
        except M.ManifestError:
            return True

    bad_total = copy.deepcopy(good); bad_total["_functional_total"] = 999
    rec("JH05 sidecar total tampered", raises_manifest_error(bad_total),
        "a sidecar _functional_total that does not reconcile fails closed", level="structural source check")

    bad_count = copy.deepcopy(good); bad_count["functional"]["core"] = bad_count["functional"]["core"][:-1]
    rec("JH06 sidecar child list shrunk", raises_manifest_error(bad_count),
        "a sidecar child id-list whose length != the declared count fails closed", level="structural source check")

    bad_child = copy.deepcopy(good); bad_child["functional"].pop("exports")
    rec("JH07 sidecar child missing", raises_manifest_error(bad_child),
        "a sidecar missing a declared child fails closed", level="structural source check")

    # ---- FAULT aggregate mutations ----
    entries, eids, results = build_valid("fault")
    del results["worker-import-faults"]
    v = C.aggregate(entries, "fault", results, eids)
    rec("JX01 fault child omitted", (not v["ok"]) and v["emitted_ids"] != M.EXPECTED_FAULT_TOTAL,
        "omitting a fault child fails the fault aggregate")

    v, p = scenario("fault", "core-faults", lambda run, e: run.summary.__setitem__("eligible_for_tenant_evidence", True))
    rec("JX02 fault child evidence eligible", refuses(v, p, "contract_eligible_for_tenant_evidence"),
        "a fault child flipped to evidence eligible fails the fault aggregate")

    entries, eids, results = build_valid("fault")
    for r in results.values():
        r["run"].summary.pop("execution_level_totals", None)
    v = C.aggregate(entries, "fault", results, eids)
    rec("JX03 fault exec-level totals omitted", v["execution_level_totals"] == {},
        "with every fault child omitting execution-level totals the aggregate surfaces an empty level map")

    entries, eids, results = build_valid("fault")
    results["isolation-faults"]["run"].check_ids.append("EXTRA")
    results["isolation-faults"]["problems"] = C.evaluate_child(M.child_by_name(entries, "isolation-faults"), "fault",
                                                               results["isolation-faults"]["run"], eids["isolation-faults"])
    v = C.aggregate(entries, "fault", results, eids)
    rec("JX04 aggregate fault total not 144", (not v["ok"]) and v["emitted_ids"] != M.EXPECTED_FAULT_TOTAL,
        "an aggregate fault inventory != 144 fails certification")

    # ---- structural source: the certification path executes REAL child subprocesses ----
    core_src = (ROOT / "scripts" / "restricted_postgres_runtime_aggregate_core.py").read_text(encoding="utf-8")
    launches = 'subprocess.run([sys.executable, str(script)' in core_src
    forbidden = ["from restricted_postgres_runtime_core_guard import", "import restricted_postgres_runtime_core_guard",
                 ".run()  # child", "TestClient("]
    rec("JS01 real-subprocess certification path",
        launches and not any(f in core_src for f in forbidden),
        "the certification path launches each child as a REAL subprocess and imports no child assertion helper",
        level="structural source check")
    guard_src = (ROOT / "scripts" / "restricted_postgres_runtime_guard.py").read_text(encoding="utf-8")
    faults_src = (ROOT / "scripts" / "restricted_postgres_runtime_faults_guard.py").read_text(encoding="utf-8")
    rec("JS02 entrypoints delegate to certify",
        "C.certify(\"functional\"" in guard_src and "C.certify(\"fault\"" in faults_src,
        "both reserved commands delegate to the real certify() path", level="structural source check")

    return _emit()


def _emit(skipped=False) -> int:
    passed = [c for c in checks if c["ok"]]
    failed = [c for c in checks if not c["ok"]]
    exec_totals = {}
    for c in checks:
        exec_totals[c["execution_level"]] = exec_totals.get(c["execution_level"], 0) + 1
    out = {"checks": checks,
           "summary": {"passed": len(passed), "skipped": 0, "failed": len(failed),
                       "execution_level_totals": exec_totals,
                       "claim_scope": "restricted-runtime-aggregate-integrity-only",
                       "integrity_battery": "passed" if not failed else "failed",
                       "eligible_for_tenant_evidence": False, "eligible_for_readiness": False,
                       "production_parity": False,
                       "migration_principal_class": "test-only-bootstrap-migration-admin"}}
    print(json.dumps(out, indent=2, default=str))
    if failed:
        print(f"\nAggregate integrity battery FAILED: {len(failed)} check(s).")
        for c in failed:
            print(f"  FAIL: {c['check_id']} -> {c['description']}")
        return 1
    print(f"\nAggregate integrity battery passed: {len(passed)} non-vacuity proof(s)."
          "\n[claim_scope=restricted-runtime-aggregate-integrity-only; NOT evidence/readiness eligible]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
