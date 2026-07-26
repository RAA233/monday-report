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
import tenant_authorization_evidence_guard as TAEG  # noqa: E402

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
    "MO09 observer-exception-is-pass", "MO11 module-state-leak",
    "MO12 inventory-hash-not-pinned", "MO13 fingerprints-dropped",
    "MO14 aggregate-ready-copied-from-results", "MO15 synthetic-observer-certified",
    # evidence binding
    "ME01 v3-omitted", "ME02 v2-artifact-accepted", "ME03 stale-v3-accepted",
    "ME04 wrong-tree-v3-accepted", "ME05 v3-blast-radius", "ME06 v3-differential-anchor",
    "ME07 unrelated-explanations-identical",
    # cross-context claim honesty
    "MC01 demo-promoted-to-client-auth", "MC02 local-claims-rls",
    "MC03 functional-runtime-mode-swapped", "MC04 database-adapter-promoted",
    "MC04b postgres-context-promotes-database-adapter", "MC05 queue-adapter-promoted",
    "MC05b inline-context-promotes-queue-adapter", "MC06 production-parity-true",
    "MC07 client-mode-claimed-in-demo-context",
    # dispositions
    "MD01 required-control-omitted", "MD02 blocked-treated-as-pass",
    "MD03 evaluator-exception-is-pass", "MD04 static-expectations-as-results",
    "MD05 precomputed-dispositions-injected", "MD06 forged-forge-report",
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
    "FS05 no-simulated-dispositions", "FS06 accepted-hash-pinned-literally",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]

#: Pinned battery size. Without these, deleting a mutation TOGETHER WITH its expected-list entry
#: leaves the completeness gate satisfied and the battery silently shrinks (the reviewer's V2 probe:
#: 46 passed / 38 mutations, still certifying).
EXPECTED_TOTAL_CHECKS = 58
EXPECTED_MUTATION_COUNT = 48


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

    # Point at the real `except` branch this check is named for, and at the lie the gate must not
    # believe: facts whose BOOLEANS claim ok while the numbers say otherwise.
    real_measure = R.measure_capacity
    try:
        R.measure_capacity = lambda *a, **k: (_ for _ in ()).throw(OSError("unmeasurable"))
        raised_ok, _ = R.capacity_gate()
    finally:
        R.measure_capacity = real_measure
    lying = valid_capacity()
    lying.update({"filesystem_free_bytes": 1, "filesystem_total_bytes": 1000 * 1024 ** 3,
                  "free_bytes_ok": True, "free_percentage_ok": True})
    lie_ok, _ = R.capacity_gate(lying)
    incomplete_ok, _ = R.capacity_gate({"free_bytes_ok": True})
    rec("MK03 capacity-measurement-error-is-blocked",
        raised_ok is False and lie_ok is False and incomplete_ok is False,
        "the gate is BLOCKED when measurement raises, when facts omit the byte counts, AND when the "
        "supplied booleans claim ok while the raw numbers say otherwise -- the verdict is re-derived "
        "from the numbers, never trusted from a caller",
        extra={"raised": raised_ok, "lying_booleans": lie_ok, "incomplete": incomplete_ok})

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

    # Watching only run_input misses the more damaging leak: an observer that rewrites the CONTRACT
    # module's control sets silently disables applicability demotion for every later context.
    def module_leak(bundle, run_input):
        RC.CLIENT_IDENTITY_CONTROLS = frozenset()

    saved_controls = RC.CLIENT_IDENTITY_CONTROLS
    try:
        leaked = R.run_contexts(observer=observer_for(module_leak), capacity=valid_capacity())
        rec("MO11 module-state-leak",
            leaked.get("accepted") is False and leaked.get("cross_context_mutation"),
            "an observer that mutates the CONTRACT module's control sets -- disabling applicability "
            "demotion for every later context -- is caught by the contract-state fingerprint and "
            "the run is not accepted",
            level="execution integration",
            extra={"detected_contexts": leaked.get("cross_context_mutation")})
    finally:
        RC.CLIENT_IDENTITY_CONTROLS = saved_controls

    saved_hash = RC.canonical_hash
    try:
        RC.canonical_hash = lambda *a, **k: "f" * 64
        pinned = R.run_contexts(observer=observer_for(), capacity=valid_capacity())
        rec("MO12 inventory-hash-not-pinned",
            pinned.get("accepted") is False,
            "a mutated contract whose canonical hash differs from the PINNED accepted literal is "
            "refused -- comparing results against whatever the module computes right now would only "
            "ever prove self-consistency",
            level="execution integration",
            extra={"accepted_literal": R.ACCEPTED_INVENTORY_HASH[:16] + "..."})
    finally:
        RC.canonical_hash = saved_hash

    rec("MO13 fingerprints-dropped",
        R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER),
                     full["results"], {})["accepted"] is False,
        "a run with NO recorded fingerprints is refused; otherwise 'no cross-context mutation' is "
        "vacuously true whenever recording is dropped",
        level="schema mutation")

    tampered = copy.deepcopy(full["results"])
    for r in tampered:
        r["client_data_ready"] = True
        r["ga_ready"] = True
    agg = R._summarize(valid_capacity(), list(RC.CANONICAL_CONTEXT_ORDER), tampered,
                       {r["context_id"]: ["x", "x"] for r in tampered})
    rec("MO14 aggregate-ready-copied-from-results",
        agg.get("accepted") is False and agg.get("client_data_ready") is False
        and agg.get("ga_ready") is False and agg.get("self_inconsistent_results"),
        "results asserting readiness while their own blocking sets are non-empty are flagged "
        "self-inconsistent AND the aggregate stays false -- the aggregate is derived from the "
        "blocking sets, never copied from the per-context booleans",
        level="schema mutation",
        extra={"self_inconsistent": agg.get("self_inconsistent_results")})

    # This battery's own observations are SYNTHETIC, so no run it performs may ever be certifiable --
    # otherwise the `observer=` test seam would be a route to an accepted verdict without a real run.
    rec("MO15 synthetic-observer-certified",
        full.get("accepted") is False
        and full.get("observations_from_recognised_observer") is False
        and full.get("execution_verdict") == "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "a run built from SYNTHETIC observations is never accepted, whatever else is consistent: "
        "certification requires observations from one of the runner's own recognised observers, so "
        "the mutation-testing seam cannot mint an accepted verdict",
        level="execution integration", extra={"observers": full.get("observers")})

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
            # Its OWN artifact with the CORRECT commit and a wrong tree -- otherwise this merely
            # re-asserts ME03's expression on an object whose commit is also wrong, isolating nothing.
            wrong_tree = tmpdir / "wrong_tree.json"
            wrong_tree.write_text(json.dumps({
                "schema_version": "tenant-authorization-evidence.v3",
                "commit": TAEG.COMMIT, "git_commit": TAEG.COMMIT,
                "tree": "1" * 40, "git_tree": "1" * 40}), encoding="utf-8")
            GA.TENANT_AUTHORIZATION_EVIDENCE_PATH = wrong_tree
            r_tree = evaluated("client-postgres")
            rec("ME04 wrong-tree-v3-accepted",
                r_tree["control_dispositions"].get(tenant_check) != "PASS",
                "a v3 artifact carrying the CORRECT commit but a wrong tree does not satisfy the "
                "tenant control -- the tree half of the binding is load-bearing on its own")
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
    # The PG direction of the adapter question. readiness.postgres_repository passes on exactly the
    # accepted RESTRICTED runtime, which is explicitly not a production adapter -- so a PG context
    # observing it must NOT promote the universal GA blocker production-database-adapter.
    pg_promote = evaluated("client-postgres",
                           lambda b, r: b["readiness_by_id"].__setitem__("postgres_repository",
                                                                         "pass"))
    mapping = R.control_check_ids()
    db_check = mapping["production-database-adapter"]
    q_check = mapping["production-queue-adapter"]
    # Asserts the PROPERTY, not a mechanism. Two independent defences now hold this control down:
    # the evaluator itself refuses it without production adapter evidence, and this runner demotes a
    # PASS it cannot evaluate. Requiring the demotion specifically would fail the moment the root
    # cause was fixed upstream -- which is exactly what happened -- so the check records which
    # defence applied instead of mandating one.
    demoted_here = db_check in {d["check_id"] for d in pg_promote.get("demoted_controls", [])}
    rec("MC04b postgres-context-promotes-database-adapter",
        pg_promote.get("result") == "evaluated"
        and pg_promote["control_dispositions"].get(db_check) != "PASS",
        "a PostgreSQL context observing an ACTIVE PostgreSQL repository -- which the accepted "
        "restricted runtime really does report -- still does not promote "
        "production-database-adapter: the restricted runtime is not a production adapter",
        level="execution integration",
        extra={"disposition": pg_promote["control_dispositions"].get(db_check),
               "held_by": ("evaluator refusal (production adapter evidence required)"
                           if not demoted_here else "runner applicability/never-promotable demotion"),
               "runner_demotion_also_applied": demoted_here})
    q_eval = evaluated("client-postgres")
    q_demoted = q_check in {d["check_id"] for d in q_eval.get("demoted_controls", [])}
    rec("MC05b inline-context-promotes-queue-adapter",
        q_eval["control_dispositions"].get(q_check) != "PASS",
        "production-queue-adapter never PASSes in any context. Mechanism-agnostic on purpose (as "
        "MC04b is): it is now held by the EVALUATOR requiring production queue-adapter evidence, and "
        "also by this runner's never-promotable list. The earlier rationale -- 'every context runs "
        "the inline worker' -- became stale when the evaluator consumer was isolated",
        extra={"disposition": q_eval["control_dispositions"].get(q_check),
               "held_by": ("evaluator refusal (production queue evidence required)"
                           if not q_demoted else "runner never-promotable demotion"),
               "runner_demotion_also_applied": q_demoted})
    rec("MC07 client-mode-claimed-in-demo-context",
        refuses("demo-local",
                lambda b, r: b["readiness_by_id"].__setitem__("client_mode", "pass")),
        "a DEMO context whose observation claims client mode is refused, so a demo run cannot "
        "promote the production-configuration control through a self-contradictory observation")

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
        never = {mapping[c] for c in R.NEVER_PROMOTABLE_CONTROL_IDS if c in mapping}
        still_blocked = all(
            all(r["control_dispositions"].get(cid) == "BLOCKED" for cid in never)
            for r in everything.get("results", []))
        rec("MD02 blocked-treated-as-pass",
            everything.get("ga_ready") is False and everything.get("client_data_ready") is False
            and everything.get("release_candidate_ready") is False and still_blocked,
            "even when the evaluator reports EVERY control PASS, the run never claims readiness and "
            "the never-promotable production-adapter controls remain BLOCKED -- an evaluator that "
            "treats blocked controls as passing cannot produce a ready result",
            level="execution integration",
            extra={"aggregate_ga_ready": everything.get("ga_ready"),
                   "never_promotable_still_blocked": still_blocked})
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
    # A forge_report is not a disposition, but ga_readiness._forge_probe turns a self-consistent one
    # into a PASS for parser-coverage -- so it is an artifact-shaped input that MINTS a disposition.
    forged = {"status": "pass", "generated_at": "2026-01-01T00:00:00Z",
              "documents": 1, "passed": 1, "failed": 0}
    rec("MD06 forged-forge-report",
        refuses("client-postgres", lambda b, r: b.__setitem__("forge_report", forged)),
        "a caller-supplied forge_report is refused: it is an artifact-shaped observation that would "
        "mint a parser-coverage PASS with no real evidence")

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

    # Cover BOTH assignment forms -- the runner's own style is annotated assignment, so matching only
    # ast.Assign made the exact restatement this guard exists to catch invisible. Also compare tuple
    # literals BY VALUE, so restating the four contexts under a different name is caught too.
    protected_names = ("CANONICAL_CONTEXT_ORDER", "SUPPORTED_CLIENT_DATA_MODES",
                       "SUPPORTED_REPOSITORY_BACKENDS", "CONTROL_IDS",
                       "CLIENT_IDENTITY_CONTROLS", "POSTGRES_EVIDENCE_CONTROLS",
                       "ACCEPTED_CONTEXT_EVIDENCE")
    redefined: list[str] = []
    restated: list[str] = []
    contract_values = {
        tuple(RC.CANONICAL_CONTEXT_ORDER), tuple(RC.SUPPORTED_CLIENT_DATA_MODES),
        tuple(RC.SUPPORTED_REPOSITORY_BACKENDS), tuple(RC.CONTROL_IDS),
    }
    for node in runner_ast.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        if not targets:
            continue
        if any(t in protected_names for t in targets):
            redefined.extend(t for t in targets if t in protected_names)
        value = getattr(node, "value", None)
        if isinstance(value, (ast.Tuple, ast.List)):
            try:
                literal = tuple(ast.literal_eval(value))
            except Exception:  # noqa: BLE001 - non-literal tuples are not restatements
                continue
            if literal in contract_values:
                restated.extend(targets)
    rec("FS01 runner-imports-canonical-inventory",
        imports_rc and not redefined and not restated,
        "the runner imports the accepted canonical inventory at module level and does NOT restate "
        "the contexts, the axes or the control ids -- checked for plain AND annotated assignment, "
        "and by VALUE so an aliased restatement is caught",
        level="structural source check",
        extra={"redefined_names": sorted(set(redefined)), "restated_values": sorted(set(restated))})

    # An import-graph/AST check, not a substring scan: `Popen(...)`, `os.popen`, `os.spawnv` and a
    # dynamically assembled module name all defeat substring matching.
    launcher_modules = {"subprocess", "multiprocessing", "docker", "uvicorn", "playwright",
                        "selenium", "webdriver", "fastapi.testclient", "starlette.testclient"}
    imported: list[str] = []
    for node in ast.walk(runner_ast):
        if isinstance(node, ast.Import):
            imported += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
            if node.module in ("os",):
                imported += [f"os.{a.name}" for a in node.names]
    dangerous_calls = [
        n.func.attr for n in ast.walk(runner_ast)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in ("popen", "spawnv", "spawnl", "system", "execv", "fork", "Popen",
                            "check_output", "call")
    ]
    dynamic_import = [
        n.func.attr for n in ast.walk(runner_ast)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in ("import_module", "__import__")
    ]
    found_launchers = sorted({m for m in imported if m.split(".")[0] in launcher_modules}
                             | set(dangerous_calls) | set(dynamic_import))
    rec("FS02 runner-launches-nothing", found_launchers == [],
        "the runner imports no process/container/browser module and makes no process-spawning or "
        "dynamic-import call, so a capacity-blocked invocation cannot start the runtime under test "
        "(the evaluator it calls may still read git -- see the module docstring)",
        level="structural source check", extra={"launchers_found": found_launchers})

    rec("FS06 accepted-hash-pinned-literally",
        R.ACCEPTED_INVENTORY_HASH == RC.canonical_hash()
        and f'"{R.ACCEPTED_INVENTORY_HASH}"' in runner_src,
        "the accepted canonical inventory hash is pinned as a LITERAL in the runner source and "
        "currently equals the contract's computed hash, so a contract mutation cannot certify itself",
        level="structural source check",
        extra={"pinned": R.ACCEPTED_INVENTORY_HASH[:16] + "..."})

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
    # A dead `evaluated` satisfying the AST predicate is not enough: require that the battery's own
    # verdicts actually FLOW THROUGH it, by proving the live helper reaches the real runner.
    live_reaches_runner = evaluated("demo-local").get("dispositions_source") == \
        "backend.app.ga_readiness.evaluate_blockers"
    rec("FS04 battery-drives-real-harness",
        imports_runner and calls_real and live_reaches_runner,
        "this battery imports the real runner at module level, drives the real evaluate_context, and "
        "the LIVE helper demonstrably reaches it -- a dead function matching the shape is not "
        "sufficient",
        level="structural source check")

    # Behavioural, not a self-reported literal. Two properties a hardcoded disposition table could
    # not reproduce together: the evaluator emits a genuinely VARIED range of dispositions from real
    # artifacts, and one specific control tracks the presence of one specific artifact.
    #
    # Deliberately NOT asserting "nothing passes without v3": three controls really do PASS from
    # other on-disk evidence (migration-runner, rbac-role-separation, verified-reviewer-identity).
    # Claiming otherwise would be false, and would have made this check fail for the right reason.
    varied = len({d for d in disp_a.values()}) >= 3
    tracks_artifact = disp_a.get(tenant_check) == "PASS" and disp_b.get(tenant_check) != "PASS"
    rec("FS05 no-simulated-dispositions",
        base.get("dispositions_source") == "backend.app.ga_readiness.evaluate_blockers"
        and varied and tracks_artifact,
        "dispositions come from the real evaluator, shown behaviourally: the emitted range spans "
        "several distinct dispositions driven by real artifacts, and one control tracks the presence "
        "of one artifact -- a hardcoded table could not do both",
        level="structural source check",
        extra={"distinct_dispositions": sorted({d for d in disp_a.values()})})

    # ---------------------------------------------------------------- completeness
    # Pin the SIZE as well as the membership, and record it BEFORE the membership gate so the gate
    # sees it. Without a size pin, deleting a mutation together with its expected-list entry leaves
    # completeness satisfied and the battery silently shrinks.
    mutations_so_far = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]
    rec("FZ01 battery-size-pinned",
        len(EXPECTED_CHECK_IDS) == EXPECTED_TOTAL_CHECKS
        and len(mutations_so_far) == EXPECTED_MUTATION_COUNT,
        f"the battery is pinned at {EXPECTED_TOTAL_CHECKS} declared checks / "
        f"{EXPECTED_MUTATION_COUNT} mutations, so a mutation cannot be removed together with its "
        "expected-list entry",
        level="structural source check",
        extra={"declared_ids": len(EXPECTED_CHECK_IDS), "mutations": len(mutations_so_far)})

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
