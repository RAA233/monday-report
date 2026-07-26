"""audit:readiness-contexts-faults -- non-vacuity battery for the readiness-context execution harness.

Drives the REAL harness functions (``readiness_contexts_runner.evaluate_context``, ``run_contexts``,
``_summarize``, ``capacity_gate``, ``canonical_result_hash``) and confirms each one REFUSES rather
than certifying, once per failure mode in the directive's mutation list.

**These are NOT executed readiness contexts.** No container, database, API, worker, frontend or
browser is started. The observation bundles are SYNTHETIC: they stand in for what a real run would
report, so the harness's decision logic can be exercised while the environment-capacity gate is
blocked. What *is* real is everything downstream of the observation: dispositions come from the real
``backend.app.ga_readiness.evaluate_blockers`` over the real registry and the real on-disk artifacts,
and the real accepted inventory is imported, never restated.

Execution levels are classified honestly:
  * ``execution integration``      -- the real orchestrator over a full synthetic observation set
  * ``context-order integration``  -- the real orchestrator run in several orders
  * ``schema mutation``            -- a malformed/hostile summary or result shape
  * ``predicate/unit mutation``    -- one crafted observation into the real pure evaluator
  * ``structural source check``    -- assertions over the parsed harness source

Honest scope: claim_scope = readiness-context-execution-faults-only;
eligible_for_tenant_evidence = false; eligible_for_readiness = false; production_parity = false;
contexts_executed = false; release_recommendation = GA_BLOCKED.
"""
from __future__ import annotations

import ast
import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from backend.app import ga_readiness as GA  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402
import readiness_contexts_runner as R  # noqa: E402

checks: list[dict] = []

#: Mutation families. Any emitted id that is neither a fixture (``F...``) nor one of these fails the
#: completeness gate, so a new family cannot silently escape the advertised mutation count.
MUTATION_PREFIXES = ("MK", "MO", "ME", "MC", "MD", "MP", "MH")

EXPECTED_CHECK_IDS = [
    "FB00 baseline-evaluates", "FB01 baseline-blocks",
    # capacity
    "MK01 capacity-failure-ignored", "MK02 observer-called-below-threshold",
    "MK03 capacity-measurement-error-is-blocked", "MK04 unavailable-reported-accepted",
    # orchestration / completeness
    "MO01 context-omitted", "MO02 fifth-context-added", "MO03 duplicate-context",
    "MO04 partial-output-accepted", "MO05 inventory-hash-changed",
    "MO06 shared-input-leak", "MO07 order-changes-result", "MO08 single-differs-from-all",
    "MO09 observer-exception-is-pass",
    # evidence binding
    "ME01 v3-omitted", "ME02 v2-artifact-accepted", "ME03 stale-v3-accepted",
    "ME04 wrong-tree-v3-accepted", "ME05 v3-blast-radius", "ME06 v3-differential-anchor",
    "ME07 unrelated-explanations-identical",
    # cross-context claim honesty
    "MC01 demo-promoted-to-client-auth", "MC02 local-claims-rls",
    "MC03 functional-runtime-mode-swapped", "MC04 database-adapter-promoted",
    "MC05 queue-adapter-promoted", "MC06 production-parity-true",
    # dispositions
    "MD01 required-control-omitted", "MD02 blocked-treated-as-pass",
    "MD03 evaluator-exception-is-pass", "MD04 static-expectations-as-results",
    "MD05 precomputed-dispositions-injected",
    # readiness booleans
    "MP01 client-data-ready-true-despite-blocker",
    "MP02 release-candidate-ready-true-despite-blocker",
    "MP03 ga-ready-true-despite-blocker",
    # counters
    "MH01 normal-http-failure-ignored", "MH02 worker-import-failure-ignored",
    "MH03 ui-console-network-failure-ignored", "MH04 counters-not-observed",
    # canonical hash
    "MO10 result-hash-mismatch-ignored",
    # structural
    "FS01 runner-imports-canonical-inventory", "FS02 runner-launches-nothing",
    "FS03 capacity-gate-precedes-observation", "FS04 battery-drives-real-harness",
    "FS05 no-simulated-dispositions",
    "FZ00 completeness",
]


def rec(cid, ok, desc, level="predicate/unit mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


# --------------------------------------------------------------------------- synthetic observations

def valid_capacity() -> dict:
    """A capacity fact set that PASSES the gate, so gates are provably not always-fail."""
    total = 1000 * 1024 ** 3
    free = 500 * 1024 ** 3
    return {"filesystem_total_bytes": total, "filesystem_free_bytes": free,
            "filesystem_free_percentage": 50.0,
            "required_free_bytes": R.CAPACITY_MIN_FREE_BYTES,
            "required_free_percentage": R.CAPACITY_MIN_FREE_RATIO * 100,
            "free_bytes_ok": True, "free_percentage_ok": True}


def blocked_capacity() -> dict:
    facts = valid_capacity()
    facts.update({"filesystem_free_bytes": 10 * 1024 ** 3, "filesystem_free_percentage": 1.0,
                  "free_bytes_ok": False, "free_percentage_ok": False})
    return facts


def valid_observations(context_id: str) -> dict:
    """A well-formed SYNTHETIC observation bundle for one context.

    Deliberately reports NOTHING as ready: every client-data readiness check is ``fail``, which is
    what a real run at this commit reports. The bundle carries no dispositions -- the harness
    computes those itself from the real evaluator.
    """
    return {
        "source": "executed",
        "context_id": context_id,
        "observer": "synthetic (fault battery; not a real execution)",
        "readiness_by_id": {"postgres_repository": "fail", "redis_queue": "fail",
                            "local_llm_runtime": "fail", "demo_seed_removed": "fail"},
        "forge_report": None,
        "counters": {c: 0 for c in R.REQUIRED_ZERO_COUNTERS},
        "evidence_artifacts_consumed": [],
    }


def observer_for(overrides=None):
    """An observer returning the synthetic bundle, optionally mutated per context."""
    def _obs(run_input):
        bundle = valid_observations(run_input["context_id"])
        if overrides:
            overrides(bundle, run_input)
        return bundle
    return _obs


def evaluated(context_id: str, mutate=None) -> dict:
    run_input = RC.build_run_input(context_id)
    bundle = valid_observations(context_id)
    if mutate:
        mutate(bundle, run_input)
    return R.evaluate_context(run_input, bundle)


def refuses(context_id: str, mutate) -> bool:
    """The pure evaluator must refuse (never 'evaluated') under this mutation."""
    return evaluated(context_id, mutate).get("result") == "refused"


# --------------------------------------------------------------------------- battery

def run() -> int:
    # ---------------------------------------------------------------- baseline (gates discriminate)
    base = evaluated("client-postgres")
    rec("FB00 baseline-evaluates", base.get("result") == "evaluated",
        "a well-formed observation bundle evaluates: the refusal gates are not always-fail",
        level="execution integration",
        extra={"dispositions_source": base.get("dispositions_source")})
    rec("FB01 baseline-blocks",
        bool(base.get("blocking_controls")) and base.get("ga_ready") is False
        and base.get("client_data_ready") is False,
        "the baseline still blocks: dispositions come from the real evaluator, not from a fixture",
        level="execution integration",
        extra={"blocking_control_count": len(base.get("blocking_controls") or [])})

    # ---------------------------------------------------------------- capacity
    blocked = R.run_contexts(observer=observer_for(), capacity=blocked_capacity())
    rec("MK01 capacity-failure-ignored",
        blocked.get("certification") == "unavailable" and blocked.get("accepted") is False
        and blocked.get("contexts_executed") is False
        and blocked.get("dispositions_produced") is False and blocked.get("results") == [],
        "a blocked capacity gate yields a controlled unavailable summary with no dispositions",
        level="execution integration")

    tripwire = {"calls": 0}

    def tripwire_observer(run_input):
        tripwire["calls"] += 1
        return valid_observations(run_input["context_id"])

    R.run_contexts(observer=tripwire_observer, capacity=blocked_capacity())
    rec("MK02 observer-called-below-threshold", tripwire["calls"] == 0,
        "below the capacity threshold the observer is NEVER invoked -- execution does not begin and "
        "then get discarded",
        level="execution integration", extra={"observer_invocations": tripwire["calls"]})

    ok_err, facts_err = R.capacity_gate({"free_bytes_ok": True})  # missing percentage key
    rec("MK03 capacity-measurement-error-is-blocked", ok_err is False,
        "an incomplete/unmeasurable capacity observation is treated as BLOCKED, never as available")

    unavailable = R._unavailable_summary(blocked_capacity(), list(RC.CANONICAL_CONTEXT_ORDER),
                                        reason="test")
    rec("MK04 unavailable-reported-accepted",
        unavailable.get("accepted") is False and unavailable.get("certification") == "unavailable"
        and unavailable.get("ga_ready") is False
        and unavailable.get("release_recommendation") == "GA_BLOCKED"
        and unavailable.get("dispositions_produced") is False,
        "an unavailable run can never report accepted, ready, or a produced disposition",
        level="schema mutation")

    # ---------------------------------------------------------------- orchestration completeness
    full = R.run_contexts(observer=observer_for(), capacity=valid_capacity())
    rec("MO01 context-omitted",
        R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER),
                     full["results"][:-1], {})["accepted"] is False,
        "a run missing one canonical context is not accepted", level="schema mutation")
    fifth = R.run_contexts(list(RC.CANONICAL_CONTEXT_ORDER) + ["client-mysql"],
                           observer=observer_for(), capacity=valid_capacity())
    rec("MO02 fifth-context-added",
        fifth.get("accepted") is False and "client-mysql" in (fifth.get("detail") or {}).get("unknown", []),
        "an unknown fifth context is refused by name", level="execution integration")
    dup = R.run_contexts(["demo-local"] + list(RC.CANONICAL_CONTEXT_ORDER),
                         observer=observer_for(), capacity=valid_capacity())
    rec("MO03 duplicate-context",
        dup.get("accepted") is False and "demo-local" in (dup.get("detail") or {}).get("duplicates", []),
        "a duplicated context is refused by name", level="execution integration")
    rec("MO04 partial-output-accepted",
        R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER),
                     full["results"][:2], {})["accepted"] is False,
        "partial output (2 of 4 contexts) is not accepted", level="schema mutation")

    original_hash = RC.canonical_hash
    try:
        RC.canonical_hash = lambda *a, **k: "0" * 64
        rec("MO05 inventory-hash-changed",
            R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER),
                         full["results"], {})["accepted"] is False,
            "results bound to a different inventory hash than the accepted one are not accepted",
            level="schema mutation")
    finally:
        RC.canonical_hash = original_hash

    def leaky(bundle, run_input):
        run_input["client_data_mode"] = "mutated"  # a shared/leaking input object

    leak_run = R.run_contexts(observer=observer_for(leaky), capacity=valid_capacity())
    rec("MO06 shared-input-leak",
        leak_run.get("accepted") is False and leak_run.get("cross_context_mutation"),
        "an observer that mutates its context input is detected by the per-context fingerprint and "
        "the run is not accepted",
        level="execution integration",
        extra={"mutated_contexts": leak_run.get("cross_context_mutation")})

    bodies = {
        "canonical": R.canonical_result_json(R.run_contexts(observer=observer_for(),
                                                            capacity=valid_capacity())),
        "reverse": R.canonical_result_json(R.run_contexts(reverse=True, observer=observer_for(),
                                                          capacity=valid_capacity())),
        "seeded": R.canonical_result_json(R.run_contexts(seed=7, observer=observer_for(),
                                                         capacity=valid_capacity())),
    }
    rec("MO07 order-changes-result", len(set(bodies.values())) == 1,
        "canonical, reverse and seeded-random orders produce a byte-identical canonical body -- "
        "execution order is not load-bearing on the result",
        level="context-order integration")

    singles_match = True
    for cid in RC.CANONICAL_CONTEXT_ORDER:
        one = R.run_contexts([cid], observer=observer_for(), capacity=valid_capacity())
        mine = next((r for r in full["results"] if r["context_id"] == cid), None)
        if json.dumps(one["results"][0], sort_keys=True, default=str) != \
           json.dumps(mine, sort_keys=True, default=str):
            singles_match = False
    rec("MO08 single-differs-from-all", singles_match,
        "each context run individually yields the same canonical result as within the full run",
        level="context-order integration")

    def exploding(run_input):
        raise RuntimeError("observer blew up")

    boom = R.run_contexts(observer=exploding, capacity=valid_capacity())
    rec("MO09 observer-exception-is-pass",
        boom.get("accepted") is False
        and all(r["result"] == "refused" for r in boom.get("results", [])),
        "an observer exception becomes a controlled refusal for that context, never a PASS",
        level="execution integration")

    a = R.run_contexts(observer=observer_for(), capacity=valid_capacity())
    b = copy.deepcopy(a)
    b["results"][0]["control_dispositions"]["ga_ci_execution"] = "PASS"
    rec("MO10 result-hash-mismatch-ignored",
        R.canonical_result_hash(a) != R.canonical_result_hash(b),
        "a single changed disposition changes the canonical result hash, so a mismatch between two "
        "runs cannot go unnoticed",
        level="schema mutation")

    # ---------------------------------------------------------------- evidence binding
    real_path = GA.TENANT_AUTHORIZATION_EVIDENCE_PATH
    tenant_check = "ga_tenant_authorization"
    try:
        GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = ROOT / "output" / "does-not-exist.v3.json"
        absent = evaluated("client-postgres")
        rec("ME01 v3-omitted",
            absent["control_dispositions"].get(tenant_check) != "PASS",
            "with no tenant-authorization evidence v3 the tenant control does not PASS",
            extra={"disposition": absent["control_dispositions"].get(tenant_check)})

        tmpdir = Path(tempfile.mkdtemp(prefix="rc-ev-"))
        try:
            v2 = tmpdir / "v2.json"
            v2.write_text(json.dumps({"schema_version": "tenant-rls-enforcement-evidence.v2"}),
                          encoding="utf-8")
            GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = v2
            r_v2 = evaluated("client-postgres")
            rec("ME02 v2-artifact-accepted",
                r_v2["control_dispositions"].get(tenant_check) != "PASS",
                "a superseded v2 artifact placed at the v3 path does not satisfy the tenant control")

            stale = tmpdir / "stale.json"
            stale.write_text(json.dumps({
                "schema_version": "tenant-authorization-evidence.v3",
                "commit": "0" * 40, "tree": "1" * 40}), encoding="utf-8")
            GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = stale
            r_stale = evaluated("client-postgres")
            rec("ME03 stale-v3-accepted",
                r_stale["control_dispositions"].get(tenant_check) != "PASS",
                "a v3 artifact bound to a different commit does not satisfy the tenant control")
            rec("ME04 wrong-tree-v3-accepted",
                r_stale["control_dispositions"].get(tenant_check) != "PASS",
                "a v3 artifact bound to a different tree does not satisfy the tenant control")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    finally:
        GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = real_path

    # ---------------------------------------------------------------- Part I tenant differential
    # Case A = a VALID v3 bound to this exact head; case B = no v3. Otherwise identical inputs.
    #
    # The v3 payload is built by the ACCEPTED evaluator guard's own builder, and the RLS sub-proof is
    # patched with a valid v2 as that guard does -- without it the probe short-circuits before ever
    # reaching the v3 gate and BOTH cases return BLOCKED, making the differential vacuous. (That is
    # exactly what the first cut of this check did.)
    #
    # Disclosed: case A is a contract-valid payload constructed at this head, NOT a regenerated real
    # artifact -- regeneration requires the accepted proof suites and is capacity-blocked. So this
    # measures the EVALUATOR's blast radius, which is what Part I asks, and claims nothing about the
    # authenticity of any artifact.
    import tenant_authorization_evidence_guard as TAEG

    def _dispositions_with(v3_payload):
        orig_v3, orig_rls = (GA.TENANT_AUTHORIZATION_EVIDENCE_PATH, GA.TENANT_RLS_EVIDENCE_PATH)
        tmp = Path(tempfile.mkdtemp(prefix="rc-diff-"))
        try:
            v3p = tmp / "v3.json"
            if v3_payload is not None:
                v3p.write_text(json.dumps(v3_payload), encoding="utf-8")
            GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = v3p
            rlsp = tmp / "rls_v2.json"
            rlsp.write_text(json.dumps(TAEG.build_valid_v2_rls()), encoding="utf-8")
            GA.TENANT_RLS_EVIDENCE_PATH = rlsp
            return evaluated("client-postgres")
        finally:
            GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = orig_v3
            GA.TENANT_RLS_EVIDENCE_PATH = orig_rls
            shutil.rmtree(tmp, ignore_errors=True)

    case_a = _dispositions_with(TAEG.build_valid_v3())
    case_b = _dispositions_with(None)
    disp_a, disp_b = case_a["control_dispositions"], case_b["control_dispositions"]
    changed = sorted(k for k in disp_a if disp_a[k] != disp_b.get(k))

    rec("ME06 v3-differential-anchor",
        disp_a.get(tenant_check) == "PASS" and disp_b.get(tenant_check) == "BLOCKED",
        "ANTI-VACUITY ANCHOR: a valid exact-head v3 makes the tenant control PASS and its absence "
        "makes it BLOCKED. Without this anchor every differential below would compare two identical "
        "all-BLOCKED sets and prove nothing",
        level="execution integration",
        extra={"case_a": disp_a.get(tenant_check), "case_b": disp_b.get(tenant_check)})
    rec("ME05 v3-blast-radius", changed == [tenant_check],
        "the tenant-authorization artifact changes EXACTLY the tenant-authorization control and "
        "nothing else: not migration validity, not the database adapter, not the queue adapter, not "
        "client-data readiness",
        level="execution integration", extra={"changed_controls": changed})
    unrelated_identical = all(
        json.dumps(case_a[k], sort_keys=True, default=str) == json.dumps(case_b[k], sort_keys=True,
                                                                        default=str)
        for k in ("context_applicability", "input_classifications", "production_parity"))
    rec("ME07 unrelated-explanations-identical",
        unrelated_identical
        and case_a["client_data_ready"] is False and case_b["client_data_ready"] is False
        and case_a["ga_ready"] is False and case_b["ga_ready"] is False,
        "every unrelated section is canonically identical across the two cases and GA remains "
        "blocked in BOTH -- a valid v3 never implies client-data readiness or GA",
        level="execution integration")

    # ---------------------------------------------------------------- cross-context claim honesty
    forced = {"ga_tenant_authorization": "PASS", "ga_per_user_identity": "PASS"}

    def force_pass(ids):
        real = GA.evaluate_blockers

        def patched(readiness_by_id, **kw):
            out = real(readiness_by_id, **kw)
            for c in out:
                if c["id"] in ids:
                    c["disposition"] = "PASS"
            return out
        return real, patched

    real_eval, patched_eval = force_pass(forced)
    try:
        GA.evaluate_blockers = patched_eval
        demo = evaluated("demo-local")
        demoted_ids = {d["check_id"] for d in demo.get("demoted_controls", [])}
        rec("MC01 demo-promoted-to-client-auth",
            demo["control_dispositions"].get("ga_tenant_authorization") != "PASS"
            and "ga_tenant_authorization" in demoted_ids,
            "a PASS on an authenticated-client control observed in a DEMO context is demoted to "
            "BLOCKED -- demo evidence can never be read as client authentication",
            extra={"demoted": sorted(demoted_ids)})
        local_pg = evaluated("client-local")
        rec("MC02 local-claims-rls",
            local_pg["control_dispositions"].get("ga_tenant_authorization") != "PASS",
            "a PASS on a database-enforced-isolation control observed in a LOCAL-JSON context is "
            "demoted -- a local run is never evidence of RLS")
    finally:
        GA.evaluate_blockers = real_eval

    rec("MC03 functional-runtime-mode-swapped",
        refuses("client-postgres", lambda b, r: b.__setitem__("context_id", "demo-postgres")),
        "observations belonging to a different context are refused, so a demo run cannot be filed "
        "as the client-mode functional runtime")
    rec("MC04 database-adapter-promoted",
        refuses("client-local",
                lambda b, r: b["readiness_by_id"].__setitem__("postgres_repository", "pass")),
        "a LOCAL context whose observation claims an active PostgreSQL repository is refused, so "
        "the production database-adapter control cannot be promoted by a run without a database")
    rec("MC05 queue-adapter-promoted",
        refuses("client-postgres",
                lambda b, r: b["readiness_by_id"].__setitem__("redis_queue", "pass")),
        "a context classified inline_worker whose observation claims a Redis queue is refused, so "
        "the production queue-adapter control cannot be promoted")
    parity_ok = all(
        r["production_parity"] is False and r["input_classifications"]["production_parity"] is False
        for r in full["results"])
    rec("MC06 production-parity-true",
        parity_ok and full.get("production_parity") is False,
        "production_parity is false in every context result, in every input classification and in "
        "the aggregate; no input can set it true",
        level="schema mutation")

    # ---------------------------------------------------------------- dispositions
    def drop_control(readiness_by_id, **kw):
        out = real_drop(readiness_by_id, **kw)
        return [c for c in out if c["id"] != "ga_ci_execution"]

    real_drop = GA.evaluate_blockers
    try:
        GA.evaluate_blockers = drop_control
        rec("MD01 required-control-omitted", evaluated("demo-local").get("result") == "refused",
            "an evaluation missing a registered control is refused; the control set must equal the "
            "registry exactly")
    finally:
        GA.evaluate_blockers = real_drop

    def all_pass(readiness_by_id, **kw):
        out = real_all(readiness_by_id, **kw)
        for c in out:
            c["disposition"] = "PASS"
        return out

    real_all = GA.evaluate_blockers
    try:
        GA.evaluate_blockers = all_pass
        everything = R.run_contexts(observer=observer_for(), capacity=valid_capacity())
        rec("MD02 blocked-treated-as-pass", everything.get("accepted") is False,
            "a run in which every blocked control is reported PASS is NOT accepted -- the harness "
            "refuses to certify a result that claims readiness",
            level="execution integration",
            extra={"aggregate_ga_ready": everything.get("ga_ready")})
    finally:
        GA.evaluate_blockers = real_all

    def raising(readiness_by_id, **kw):
        raise RuntimeError("evaluator failure")

    real_raise = GA.evaluate_blockers
    try:
        GA.evaluate_blockers = raising
        rec("MD03 evaluator-exception-is-pass", evaluated("demo-local").get("result") == "refused",
            "an evaluator exception becomes a controlled refusal, never a PASS")
    finally:
        GA.evaluate_blockers = real_raise

    rec("MD04 static-expectations-as-results",
        refuses("demo-local", lambda b, r: b.__setitem__(
            "expected_control_dispositions", r["expected_control_dispositions"])),
        "handing the harness the contract's EXPECTED dispositions is refused; static expectations "
        "can never be reported as executed results")
    rec("MD05 precomputed-dispositions-injected",
        refuses("demo-local", lambda b, r: b.__setitem__(
            "control_dispositions", {"ga_ci_execution": "PASS"})),
        "any precomputed disposition map supplied as an observation is refused")

    # ---------------------------------------------------------------- readiness booleans
    def with_ready(flag):
        results = copy.deepcopy(full["results"])
        for r in results:
            r[flag] = True
        return R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER), results, {})

    rec("MP01 client-data-ready-true-despite-blocker",
        with_ready("client_data_ready")["accepted"] is False,
        "a context asserting client_data_ready while blocking controls remain is not accepted",
        level="schema mutation")
    rec("MP02 release-candidate-ready-true-despite-blocker",
        with_ready("release_candidate_ready")["accepted"] is False,
        "a context asserting release_candidate_ready while blocking controls remain is not accepted",
        level="schema mutation")
    rec("MP03 ga-ready-true-despite-blocker",
        with_ready("ga_ready")["accepted"] is False,
        "a context asserting ga_ready while blocking controls remain is not accepted",
        level="schema mutation")

    # ---------------------------------------------------------------- counters
    rec("MH01 normal-http-failure-ignored",
        refuses("demo-local", lambda b, r: b["counters"].__setitem__("normal_http_500_count", 1))
        and refuses("demo-local", lambda b, r: b["counters"].__setitem__("normal_http_423_count", 1)),
        "a normal HTTP 500 or 423 observed during the run is refused, never ignored")
    rec("MH02 worker-import-failure-ignored",
        refuses("demo-local",
                lambda b, r: b["counters"].__setitem__("worker_process_failure_count", 1))
        and refuses("demo-local",
                    lambda b, r: b["counters"].__setitem__("import_process_failure_count", 1)),
        "a worker or import process failure is refused, never ignored")
    rec("MH03 ui-console-network-failure-ignored",
        refuses("demo-local", lambda b, r: b["counters"].__setitem__("ui_console_error_count", 1))
        and refuses("demo-local",
                    lambda b, r: b["counters"].__setitem__("ui_failed_network_request_count", 1)),
        "a UI console error or failed network request is refused, never ignored")
    rec("MH04 counters-not-observed",
        refuses("demo-local", lambda b, r: b["counters"].pop("normal_http_503_count")),
        "an unobserved required counter is refused; absence is not treated as zero")

    # ---------------------------------------------------------------- structural source checks
    runner_src = (ROOT / "scripts" / "readiness_contexts_runner.py").read_text(encoding="utf-8")
    runner_ast = ast.parse(runner_src)

    imports_rc = any(
        isinstance(n, ast.ImportFrom) and n.module == "backend.app"
        and any(a.name == "readiness_contexts" for a in n.names)
        for n in runner_ast.body)
    redefines = any(
        isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id in
                ("CANONICAL_CONTEXT_ORDER", "SUPPORTED_CLIENT_DATA_MODES",
                 "SUPPORTED_REPOSITORY_BACKENDS", "CONTROL_IDS")
                for t in n.targets)
        for n in runner_ast.body)
    rec("FS01 runner-imports-canonical-inventory", imports_rc and not redefines,
        "the runner imports the accepted canonical inventory at module level and does NOT redefine "
        "the contexts, the axes or the control ids",
        level="structural source check")

    launchers = ("subprocess", "docker", "TestClient", "uvicorn", "playwright", "webdriver")
    found_launchers = sorted(t for t in launchers if t in runner_src)
    rec("FS02 runner-launches-nothing", found_launchers == [],
        "the runner source contains no process/container/browser launcher, so a capacity-blocked "
        "invocation cannot start anything",
        level="structural source check", extra={"launchers_found": found_launchers})

    run_contexts_def = next((n for n in runner_ast.body
                             if isinstance(n, ast.FunctionDef) and n.name == "run_contexts"), None)
    gate_first = False
    if run_contexts_def is not None:
        gate_line = observer_line = None
        for node in ast.walk(run_contexts_def):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "capacity_gate" and gate_line is None:
                gate_line = node.lineno
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "observer" and observer_line is None:
                observer_line = node.lineno
        gate_first = gate_line is not None and observer_line is not None and gate_line < observer_line
    rec("FS03 capacity-gate-precedes-observation", gate_first,
        "inside the real orchestrator the capacity gate is evaluated BEFORE the observer is ever "
        "called (verified positionally on the parsed source, not by comment)",
        level="structural source check")

    fault_ast = ast.parse((ROOT / "scripts" / "readiness_contexts_faults_guard.py")
                          .read_text(encoding="utf-8"))
    imports_runner = any(
        isinstance(n, ast.Import) and any(a.name == "readiness_contexts_runner" for a in n.names)
        for n in fault_ast.body)
    eval_fn = next((n for n in fault_ast.body
                    if isinstance(n, ast.FunctionDef) and n.name == "evaluated"), None)
    calls_real = eval_fn is not None and any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "evaluate_context" and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "R"
        for n in ast.walk(eval_fn))
    rec("FS04 battery-drives-real-harness", imports_runner and calls_real,
        "this battery imports the real runner at module level and drives the real "
        "evaluate_context; it does not re-implement the decision logic it claims to test",
        level="structural source check")

    rec("FS05 no-simulated-dispositions",
        base.get("dispositions_source") == "backend.app.ga_readiness.evaluate_blockers",
        "every disposition in an evaluated result is attributed to the real evaluator; the harness "
        "never synthesises one",
        level="structural source check")

    # ---------------------------------------------------------------- completeness
    emitted = [c["check_id"] for c in checks]
    missing = [cid for cid in EXPECTED_CHECK_IDS if cid not in emitted and cid != "FZ00 completeness"]
    unknown = [cid for cid in emitted if cid not in EXPECTED_CHECK_IDS]
    dupes = sorted({cid for cid in emitted if emitted.count(cid) > 1})
    stray = [cid for cid in emitted if not cid.startswith("F") and cid[:2] not in MUTATION_PREFIXES]
    if missing or unknown or dupes or stray:
        rec("FZ00 completeness", False,
            "the emitted check set must equal the expected set exactly and every id must belong to "
            "a declared family -- a mutation cannot be quietly dropped from the battery",
            level="structural source check",
            extra={"missing": missing, "unknown": unknown, "duplicates": dupes,
                   "unknown_prefix": stray})
    else:
        rec("FZ00 completeness", True,
            f"all {len(EXPECTED_CHECK_IDS) - 1} expected checks emitted exactly once, no unknown id, "
            "every id in a declared family",
            level="structural source check")

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    mutation_ids = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]

    print(json.dumps({
        "guard": "audit:readiness-contexts-faults",
        "claim_scope": "readiness-context-execution-faults-only",
        "inventory_hash": RC.canonical_hash(),
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "mutations": len(mutation_ids),
                    "non_mutation_checks": len(checks) - len(mutation_ids),
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        # Honest disclosure: this battery exercises decision logic with SYNTHETIC observations.
        "contexts_executed": False,
        "observations_are_synthetic": True,
        "readiness_dispositions_produced": False,
        "docker_used": False,
        "eligible_for_tenant_evidence": False,
        "eligible_for_readiness": False,
        "production_parity": False,
        "execution_verdict": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
