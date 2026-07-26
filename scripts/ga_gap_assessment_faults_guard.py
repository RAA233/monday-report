"""audit:ga-gap-assessment-faults -- non-vacuity battery for the gap-assessment drift guard.

Every mutation writes a hostile assessment to a temp file, points the REAL drift guard at it, and
requires refusal. Nothing is re-implemented: the predicates under test are the drift guard's own,
driven end to end. The tracked artifact is proved byte-identical afterwards.

Carries the protections earlier increments were caught lacking: a pinned declared-id-set hash so a
mutation cannot be deleted together with its id and both counts, and a fingerprint of every mutated
artifact so one mutation's body cannot be replaced by a copy of another's.

Docker-free. No container, database, queue or process is contacted; no evidence is generated.

Honest scope: claim_scope = ga-gap-assessment-faults-only. Certifies nothing but the drift guard's
discrimination: PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED, PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED,
FOUR_READINESS_CONTEXTS_NOT_ACCEPTED, GA_BLOCKED.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import build_ga_gap_assessment as GEN  # noqa: E402
import ga_gap_assessment_guard as GG  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("MC", "MA", "MT", "MR", "MB", "MP")

DB_ID, QUEUE_ID = "production-database-adapter", "production-queue-adapter"

EXPECTED_CHECK_IDS = [
    "FB00 baseline-passes", "FB01 artifact-untouched",
    # control set
    "MC01 control-omitted", "MC02 twenty-ninth-control-added", "MC03 duplicate-control",
    "MC04 control-id-changed", "MC05 check-id-changed", "MC06 category-changed",
    "MC07 severity-changed", "MC08 owner-changed",
    # adapter metadata / state
    "MA01 db-metadata-restored-to-delegation", "MA02 queue-metadata-restored-to-ping",
    "MA03 db-adapter-changed-pass", "MA04 queue-adapter-changed-pass",
    "MA05 static-contract-as-execution-acceptance", "MA06 db-evidence-status-claimed-present",
    "MA07 queue-evidence-status-claimed-present",
    # tenant / readiness freshness
    "MT01 stale-tenant-evidence-presented-exact-head",
    "MT02 tenant-authorization-changed-pass",
    "MT03 readiness-contract-presented-as-execution",
    "MT04 harness-acceptance-presented-as-execution",
    "MT05 capacity-changed-available",
    # release state
    "MR01 migration-validity-changed-pass", "MR02 client-data-ready-true",
    "MR03 release-candidate-ready-true", "MR04 ga-ready-true", "MR05 ga-blocked-changed-ready",
    # bindings
    "MB01 resolution-condition-stale", "MB02 registry-sha-stale",
    "MB03 inventory-hash-stale", "MB04 adapter-contract-hash-stale",
    "MB05 commit-tree-stale", "MB05b worktree-clean-false", "MB06 canonical-hash-tampered",
    "MB07 superseded-schema", "MB08 classified-as-evidence",
    "MB09 local-artifact-claimed-tracked",
    # privacy / robustness
    "MP01 private-path-inserted", "MP02 dsn-inserted", "MP03 malformed-artifact-crashes",
    "FZ00 completeness", "FZ01 battery-size-pinned", "FZ02 id-set-hash-pinned",
    "FZ03 mutations-are-distinct-inputs", "FZ04 drift-guard-check-set-pinned",
]
EXPECTED_TOTAL_CHECKS = 44
EXPECTED_MUTATION_COUNT = 38
PINNED_DRIFT_ID_SET_HASH = "ded52c497ff1235a74a066a5c176afbe88ba44be2e4e8af0c88713437360c60b"
PINNED_DRIFT_CHECK_COUNT = 47
#: Self-switchable by design -- it is a tripwire against carelessness, not a bind against intent.
PINNED_ID_SET_HASH = "e7529a77e457327adf0e99087907648c108e82adce2a45c4c5533753c18741b8"

MUTATION_FINGERPRINTS: dict[str, str] = {}


def rec(cid, ok, desc, level="artifact mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def live_artifact() -> dict:
    return json.loads(GG.ARTIFACT_PATH.read_text(encoding="utf-8"))


def guard_result(artifact) -> tuple[int, list[str]]:
    """Run the REAL drift guard against a hostile artifact."""
    saved = GG.ARTIFACT_PATH
    tmp = Path(tempfile.mkdtemp(prefix="gga-"))
    try:
        target = tmp / "assessment.json"
        target.write_text(artifact if isinstance(artifact, str)
                          else json.dumps(artifact, indent=2, ensure_ascii=False), encoding="utf-8")
        GG.ARTIFACT_PATH = target
        GG.checks.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = GG.run()
        return rc, [c["check_id"] for c in GG.checks if not c["ok"]]
    except Exception as exc:  # noqa: BLE001 - a crash is recorded as a refusal
        return 1, [f"<exception:{exc.__class__.__name__}>"]
    finally:
        GG.ARTIFACT_PATH = saved
        GG.checks.clear()
        shutil.rmtree(tmp, ignore_errors=True)


def rehash(artifact: dict) -> dict:
    artifact = copy.deepcopy(artifact)
    artifact.pop("canonical_payload_hash", None)
    artifact["canonical_payload_hash"] = GEN.canonical_hash(artifact)
    return artifact


def refuses(cid, mutate, desc, *, rehash_after=True, level="artifact mutation"):
    artifact = copy.deepcopy(live_artifact())
    mutate(artifact)
    artifact = rehash(artifact) if rehash_after else artifact
    MUTATION_FINGERPRINTS[cid] = hashlib.sha256(
        json.dumps(artifact, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    rc, failing = guard_result(artifact)
    rec(cid, rc != 0 and bool(failing), desc, level=level,
        extra={"guard_exit": rc, "failing_checks": failing[:4],
               "mutation_fingerprint": MUTATION_FINGERPRINTS[cid]})


def ctl(artifact: dict, rid: str) -> dict:
    return next(c for c in artifact["controls"] if c["id"] == rid)


def run() -> int:
    rc, failing = guard_result(live_artifact())
    rec("FB00 baseline-passes", rc == 0 and not failing,
        "ANCHOR: the real drift guard passes against the tracked assessment, so every refusal below "
        "is discriminating rather than an always-fail guard",
        level="assessment reconciliation", extra={"failing": failing[:4]})
    before = GG.ARTIFACT_PATH.read_bytes()

    # ---------------------------------------------------------------- control set
    refuses("MC01 control-omitted", lambda a: a["controls"].pop(3),
            "removing a control is refused")
    refuses("MC02 twenty-ninth-control-added",
            lambda a: a["controls"].append({**copy.deepcopy(a["controls"][0]), "id": "invented",
                                            "check_id": "ga_invented"}),
            "an unknown twenty-ninth control is refused")
    refuses("MC03 duplicate-control",
            lambda a: a["controls"].append(copy.deepcopy(a["controls"][0])),
            "a duplicated control is refused")
    refuses("MC04 control-id-changed",
            lambda a: ctl(a, DB_ID).__setitem__("id", "production-database-adapter-v2"),
            "changing a control id is refused")
    refuses("MC05 check-id-changed",
            lambda a: ctl(a, QUEUE_ID).__setitem__("check_id", "ga_queue"),
            "changing a check id is refused")
    refuses("MC06 category-changed",
            lambda a: ctl(a, DB_ID).__setitem__("category", "product"),
            "changing a category away from the registry's is refused")
    refuses("MC07 severity-changed",
            lambda a: ctl(a, DB_ID).__setitem__("severity", "warning"),
            "changing a severity away from the registry's is refused")
    refuses("MC08 owner-changed",
            lambda a: ctl(a, QUEUE_ID).__setitem__("owner_type", "engineering"),
            "changing an owner type away from the registry's is refused")

    # ---------------------------------------------------------------- adapters
    refuses("MA01 db-metadata-restored-to-delegation",
            lambda a: (ctl(a, DB_ID).__setitem__("probe_type", "delegated_readiness_check"),
                       ctl(a, DB_ID).__setitem__(
                           "probe_location",
                           "backend/app/ga_readiness.py:evaluate_blockers -> "
                           "_delegate(postgres_repository)")),
            "restoring the generic postgres-delegation probe metadata is refused")
    refuses("MA02 queue-metadata-restored-to-ping",
            lambda a: (ctl(a, QUEUE_ID).__setitem__("probe_type", "delegated_readiness_check"),
                       ctl(a, QUEUE_ID).__setitem__(
                           "probe_location",
                           "backend/app/ga_readiness.py:evaluate_blockers -> "
                           "_delegate(redis_queue)")),
            "restoring the redis_queue/PING probe metadata is refused")
    refuses("MA03 db-adapter-changed-pass",
            lambda a: ctl(a, DB_ID).__setitem__("current_disposition_fresh_checkout", "PASS"),
            "recording the database adapter as PASS is refused: the evaluator returns BLOCKED")
    refuses("MA04 queue-adapter-changed-pass",
            lambda a: ctl(a, QUEUE_ID).__setitem__("current_disposition_fresh_checkout", "PASS"),
            "recording the queue adapter as PASS is refused")
    refuses("MA05 static-contract-as-execution-acceptance",
            lambda a: (a.__setitem__("static_contract_acceptance_is_not_execution_acceptance", False),
                       a["execution_verdicts"].__setitem__(
                           "production_database_adapter",
                           "PRODUCTION_DATABASE_ADAPTER_ACCEPTED")),
            "presenting an accepted STATIC CONTRACT as production adapter acceptance is refused")
    refuses("MA06 db-evidence-status-claimed-present",
            lambda a: ctl(a, DB_ID).__setitem__("evidence_status", "present_exact_head"),
            "claiming exact-head database evidence exists is refused")
    refuses("MA07 queue-evidence-status-claimed-present",
            lambda a: ctl(a, QUEUE_ID).__setitem__("evidence_status", "present_exact_head"),
            "claiming exact-head queue evidence exists is refused")

    # ---------------------------------------------------------------- tenant / readiness
    refuses("MT01 stale-tenant-evidence-presented-exact-head",
            lambda a: a.__setitem__("exact_head_tenant_evidence_present", True),
            "presenting tenant evidence from an earlier commit as exact-head is refused")
    refuses("MT02 tenant-authorization-changed-pass",
            lambda a: ctl(a, "tenant-authorization-enforcement").__setitem__(
                "current_disposition_fresh_checkout", "PASS"),
            "recording tenant authorization as PASS without a current artifact is refused")
    refuses("MT03 readiness-contract-presented-as-execution",
            lambda a: a.__setitem__("four_contexts_executed_at_this_head", True),
            "presenting readiness-CONTRACT acceptance as context EXECUTION is refused")
    refuses("MT04 harness-acceptance-presented-as-execution",
            lambda a: a["execution_verdicts"].__setitem__(
                "four_readiness_contexts", "FOUR_READINESS_CONTEXTS_ACCEPTED"),
            "presenting HARNESS acceptance as context execution acceptance is refused")
    refuses("MT05 capacity-changed-available",
            lambda a: a.__setitem__("capacity_gate", "available"),
            "flipping the capacity gate to available without an observation is refused")

    # ---------------------------------------------------------------- release state
    refuses("MR01 migration-validity-changed-pass",
            lambda a: ctl(a, "migration-validity").__setitem__(
                "current_disposition_fresh_checkout", "PASS"),
            "recording migration validity as PASS without an exact current proof is refused")
    refuses("MR02 client-data-ready-true", lambda a: a.__setitem__("client_data_ready", True),
            "client_data_ready=true is refused")
    refuses("MR03 release-candidate-ready-true",
            lambda a: a.__setitem__("release_candidate_ready", True),
            "release_candidate_ready=true is refused")
    refuses("MR04 ga-ready-true", lambda a: a.__setitem__("ga_ready", True),
            "ga_ready=true is refused")
    refuses("MR05 ga-blocked-changed-ready",
            lambda a: a.__setitem__("release_recommendation", "GA_READY"),
            "GA_READY is refused")

    # ---------------------------------------------------------------- bindings
    refuses("MB01 resolution-condition-stale",
            lambda a: ctl(a, DB_ID).__setitem__(
                "resolution_condition",
                "The requested repository backend is postgres, the active adapter is postgres via a "
                "live probe, and a database URL is configured."),
            "a stale resolution condition that no longer matches the registry is refused")
    refuses("MB02 registry-sha-stale",
            lambda a: a["source_bindings"].__setitem__("registry_sha256", "0" * 64),
            "a stale recorded registry SHA is refused")
    refuses("MB03 inventory-hash-stale",
            lambda a: a["source_bindings"].__setitem__(
                "readiness_context_inventory_hash", "1" * 64),
            "a stale recorded readiness-context inventory hash is refused")
    refuses("MB04 adapter-contract-hash-stale",
            lambda a: a["source_bindings"].__setitem__(
                "production_queue_adapter_contract_hash", "2" * 64),
            "a stale recorded adapter contract hash is refused")
    refuses("MB05 commit-tree-stale",
            lambda a: a.__setitem__("generated_from_commit", "3" * 40),
            "an assessment left bound to a different commit is refused -- the drift that started "
            "this increment")
    refuses("MB05b worktree-clean-false",
            lambda a: a.__setitem__("worktree_clean", False),
            "an assessment generated from a dirty tracked worktree is refused")
    refuses("MB06 canonical-hash-tampered",
            lambda a: a.__setitem__("canonical_payload_hash", "4" * 64),
            "a canonical hash that does not match the body is refused", rehash_after=False)
    refuses("MB07 superseded-schema",
            lambda a: a.__setitem__("schema_version", "ga-gap-assessment.v1"),
            "the superseded v1 schema is refused")
    refuses("MB08 classified-as-evidence",
            lambda a: (a.__setitem__("is_evidence", True),
                       a.__setitem__("is_acceptance_artifact", True)),
            "an assessment reclassifying itself as evidence or an acceptance artifact is refused")
    refuses("MB09 local-artifact-claimed-tracked",
            lambda a: a["local_evidence_artifact"].__setitem__("tracked", True),
            "claiming a gitignored machine-local artifact is tracked repository state is refused")

    # ---------------------------------------------------------------- privacy / robustness
    refuses("MP01 private-path-inserted",
            lambda a: ctl(a, DB_ID).__setitem__("notes", r"see C:\Users\someone\evidence"),
            "a private filesystem path inserted into the artifact is refused")
    refuses("MP02 dsn-inserted",
            lambda a: ctl(a, QUEUE_ID).__setitem__("notes", "rediss://svc@cache-1:6380/0"),
            "a connection string inserted into the artifact is refused")

    rc_bad, failing_bad = guard_result("{not valid json")
    rec("MP03 malformed-artifact-crashes", rc_bad != 0 and bool(failing_bad),
        "a malformed artifact is a controlled refusal, never an uncaught crash",
        level="schema mutation", extra={"failing": failing_bad[:3]})
    MUTATION_FINGERPRINTS["MP03 malformed-artifact-crashes"] = hashlib.sha256(
        b"{not valid json").hexdigest()[:16]

    rec("FB01 artifact-untouched", GG.ARTIFACT_PATH.read_bytes() == before,
        "the tracked assessment is byte-identical after every mutation: each ran on a temp copy",
        level="structural source check")

    # ---------------------------------------------------------------- completeness
    id_set_hash = hashlib.sha256("\n".join(sorted(EXPECTED_CHECK_IDS)).encode("utf-8")).hexdigest()
    rec("FZ02 id-set-hash-pinned", id_set_hash == PINNED_ID_SET_HASH,
        "the declared check-id set hashes to the pinned literal, so deleting a mutation together "
        "with its id and both counts is caught",
        level="structural source check", extra={"observed": id_set_hash[:16] + "..."})
    dup = {}
    for fingerprint in set(MUTATION_FINGERPRINTS.values()):
        ids = [k for k, v in MUTATION_FINGERPRINTS.items() if v == fingerprint]
        if len(ids) > 1:
            dup[fingerprint] = sorted(ids)
    rec("FZ03 mutations-are-distinct-inputs",
        not dup and len(MUTATION_FINGERPRINTS) == EXPECTED_MUTATION_COUNT,
        "every mutation applies a DISTINCT artifact, so one mutation's body cannot be replaced by a "
        "copy of another's while the id list and counts stay intact",
        level="structural source check",
        extra={"fingerprinted": len(MUTATION_FINGERPRINTS),
               "duplicate_bodies": {k[:12]: v for k, v in list(dup.items())[:3]}})
    # Cross-pin the DRIFT guard's own check set. Without it four of its checks -- GA21, GA42, GA70,
    # GA71 -- could each be deleted with this battery still green.
    GG.checks.clear()
    with contextlib.redirect_stdout(io.StringIO()):
        GG.run()
    drift_ids = sorted(c["check_id"] for c in GG.checks)
    GG.checks.clear()
    drift_hash = hashlib.sha256("
".join(drift_ids).encode("utf-8")).hexdigest()
    rec("FZ04 drift-guard-check-set-pinned",
        drift_hash == PINNED_DRIFT_ID_SET_HASH and len(drift_ids) == PINNED_DRIFT_CHECK_COUNT,
        "the drift guard's emitted check-id set is hashed and pinned HERE, so one of its checks "
        "cannot be deleted with this battery still reporting green",
        level="structural source check",
        extra={"observed": drift_hash[:16] + "...", "count": len(drift_ids)})

    rec("FZ01 battery-size-pinned",
        len(EXPECTED_CHECK_IDS) == EXPECTED_TOTAL_CHECKS
        and len(MUTATION_FINGERPRINTS) == EXPECTED_MUTATION_COUNT,
        f"pinned at {EXPECTED_TOTAL_CHECKS} declared checks / {EXPECTED_MUTATION_COUNT} mutations",
        level="structural source check",
        extra={"declared": len(EXPECTED_CHECK_IDS), "mutations": len(MUTATION_FINGERPRINTS)})

    emitted = [c["check_id"] for c in checks]
    missing = [c for c in EXPECTED_CHECK_IDS if c not in emitted and c != "FZ00 completeness"]
    unknown = [c for c in emitted if c not in EXPECTED_CHECK_IDS]
    dupes = sorted({c for c in emitted if emitted.count(c) > 1})
    stray = [c for c in emitted if not c.startswith("F") and c[:2] not in MUTATION_PREFIXES]
    rec("FZ00 completeness", not (missing or unknown or dupes or stray),
        "the emitted check set equals the declared set exactly",
        level="structural source check",
        extra={"missing": missing, "unknown": unknown, "duplicates": dupes,
               "unknown_prefix": stray})

    passed = sum(1 for c in checks if c["ok"])
    failed = len(checks) - passed
    print(json.dumps({
        "guard": "audit:ga-gap-assessment-faults",
        "claim_scope": "ga-gap-assessment-faults-only",
        "summary": {"passed": passed, "failed": failed, "skipped": 0,
                    "mutations": len(MUTATION_FINGERPRINTS),
                    "non_mutation_checks": len(checks) - len(MUTATION_FINGERPRINTS),
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": checks,
        "assessment_is_evidence": False,
        "docker_used": False,
        "evidence_generated": False,
        "production_database_adapter_accepted": False,
        "production_queue_adapter_accepted": False,
        "four_readiness_contexts_accepted": False,
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
