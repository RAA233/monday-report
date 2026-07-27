"""audit:ga-gap-assessment-faults -- non-vacuity battery for the gap-assessment drift guard.

Every mutation writes a hostile assessment to a temp file, points the REAL drift guard at it, and
requires refusal. Nothing is re-implemented: the predicates under test are the drift guard's own,
driven end to end. The tracked artifact is proved byte-identical afterwards.

Completeness is carried by gates whose removal is a large, obvious, reviewable edit rather than a one-word change: FZ00
(emitted == declared), FZ01 (size), FZ03 (every mutation applies a DISTINCT artifact), FZ04 (a
cross-FILE pin of the drift guard's own check set) and FZ05 (the expected CONTROL inventory is loaded
from the real registry). A self-pinned id-set hash was removed as an acceptance authority: it is
editable alongside the very list it protects, so it proves nothing against intent.

Docker-free. No container, database, queue or process is contacted; no evidence is generated.

Honest scope: claim_scope = ga-gap-assessment-faults-only. Certifies nothing but the drift guard's
discrimination: PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED, PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED,
FOUR_READINESS_CONTEXTS_NOT_ACCEPTED, GA_BLOCKED.
"""
from __future__ import annotations

import ast as _ast
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

from backend.app import ga_readiness as GA_MOD  # noqa: E402
import build_ga_gap_assessment as GEN  # noqa: E402
import ga_gap_assessment_guard as GG  # noqa: E402
import ga_gap_assessment_coupling as COUPLING  # noqa: E402
import ga_gap_assessment_positive_paths as PP  # noqa: E402
import synthetic_ga_evidence as SYN  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("MC", "MA", "MT", "MR", "MB", "MP", "MV", "MI", "MG", "MX", "PM")

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
    # v2 identity
    "MV02 legacy-v1-file-present",
    "MV03 generator-path-reverted-to-v1", "MV04 legacy-constant-collapsed-onto-current",
    # registry-derived inventory
    "MI01 registry-control-removed", "MI02 registry-control-added",
    "MI03 registry-check-id-changed", "MI04 artifact-supplies-expected-inventory",
    "MI05 artifact-check-id-mapping-changed",
    # binding
    "MG01 arbitrary-old-ancestor", "MG02 source-file-hash-stale",
    "MG03 generation-model-removed",
    # forgeries an independent review executed successfully against the previous cut
    "MX01 verdict-subject-injected", "MX02 legend-class-invented",
    "MX03 verified-dispositions-forged", "MX04 local-evidence-note-forged",
    "MX05 unknown-top-level-key", "MX06 prose-claims-executed-drill",
    "MX07 prose-effort-none", "MX08 tree-binding-forged",
    "MX10 source-hash-crlf-bound", "MX14 nested-context-key-injected",
    "MX15 source-binding-key-injected", "MX16 control-key-injected",
    "MX17 legend-value-rewritten", "MX18 curated-prose-rewritten",
    "MX19 authoritative-note-forged", "MX20 evidence-status-claimed",
    "MX21 verified-flip-below-threshold", "MX23 presence-flag-forged",
    "MX24 verified-context-key-injected", "MX25 controls-reordered", "MX26 context-authority-flipped",
    "MX27 bound-commit-is-prose", "MX28 matches-head-truthy-string",
    "MX29 evidence-path-count-forged", "MX30 verified-disposition-is-prose",
    "MX31 promoter-names-wrong-artifact",
    "MX32 conjunction-one-component-named",
    "MX33 promoter-named-but-absent", "MX34 detail-reports-a-missing-component",
    "MX22 prose-disclosure-removed", "MX11 blocking-reason-rewritten",
    "MX12 extra-context-injected", "MX13 static-contract-invented",
    # (there is deliberately no MX09: ga_ready=true is already MR04, and FZ03 rejected the duplicate)
    # positive paths -- a RIGHT promotion must be ACCEPTED, not merely a wrong one refused
    "PP01 migration-runner-own-artifact-accepted",
    "PP02 migration-validity-scope-recognized-blocker-retained",
    "PP03 tenant-conjunction-accepted",
    "PP04 database-adapter-own-synthetic-artifact-accepted",
    "PP05 queue-adapter-own-synthetic-artifact-accepted",
    "PP06 persistence-locking-own-artifact-accepted",
    "PP07 correction-atomicity-own-artifact-accepted",
    "PP08 unrelated-artifacts-rejected",
    "PP09 stale-artifacts-rejected",
    "PP10 overall-ga-remains-blocked",
    "PP11 graph-exactness-derived-from-evaluator",
    "PP12 honest-payload-accepted-by-the-unmutated-guard",
    # scope mutations -- each must break a POSITIVE path, not merely fail closed
    "PM01 empty-evidence-scope-mapping",
    "PM02 remove-migration-runner-arm", "PP13 migration-validity-arm-pinned",
    "PM04 remove-tenant-conjunction-arm", "PM05 remove-database-adapter-arm",
    "PM06 remove-queue-adapter-arm", "PM07 remove-persistence-locking-arm",
    "PM08 remove-correction-atomicity-arm",
    "PM09 tenant-all-of-weakened-to-any-of", "PM10 tenant-conjunction-member-removed",
    "PM11 own-artifact-replaced-with-unrelated", "PM12 artifact-path-changed",
    "PM13 promoter-attribution-disabled", "PM14 promoter-basename-collision-restored",
    "FZ00 completeness", "FZ01 battery-size-pinned",
    "FZ03 mutations-are-distinct-inputs", "FZ04 drift-guard-check-set-pinned",
    "FZ05 inventory-authority-is-the-registry", "FZ06 mutations-trip-the-gate-they-protect",
    "FZ07 protected-gates-are-structurally-load-bearing",
    "FZ08 gate-hollowing-is-behaviorally-detected",
    "FZ09 protected-gates-are-actually-emitted",
    "FZ10-GA50b rejects-what-it-exists-to-reject",
    "FZ10-GA04k rejects-what-it-exists-to-reject",
    "FZ10-GA47f rejects-what-it-exists-to-reject",
    "FZ11 protected-gate-set-is-pinned",
]
EXPECTED_TOTAL_CHECKS = 123
EXPECTED_MUTATION_COUNT = 95
PINNED_DRIFT_ID_SET_HASH = "f95936ca392966b9efa0e5dacb5a4378ac45af509658752a3a9e5541188571a4"
PINNED_DRIFT_CHECK_COUNT = 92
#: NOTE: this battery no longer pins its own id-set hash as an ACCEPTANCE AUTHORITY. Such a pin is
#: editable alongside the very list it protects, so it proves nothing against intent. Completeness is
#: carried by FZ00 (emitted == declared), FZ01 (size), FZ03 (distinct mutation inputs) and FZ04
#: (cross-file pin of the DRIFT guard's set), and the expected CONTROL inventory now comes from the
#: real registry (FZ05).

#: The gates whose behaviour FZ10 probes and whose shape FZ07/FZ08 inspect, and how many coupling
#: mutations that set produces. Pinned because the set was otherwise editable alongside the checks
#: that consume it.
PINNED_PROTECTED_GATES = "GA04k,GA47f,GA50b"
PINNED_COUPLING_MUTATIONS = 18

MUTATION_FINGERPRINTS: dict[str, str] = {}

#: What each mutation actually TRIPPED, so coverage can be reconciled (see FZ06).
MUTATION_TRIPPED: dict[str, list] = {}

#: The drift check every listed mutation exists to protect. Nothing previously bound a mutation to
#: a gate: FZ03 proves mutations are distinct INPUTS, FZ04/GA80 hash only id SETS, FZ00/FZ01 only
#: count. An exact-head review neutered GA47f (1 edit) and then re-bodied MX21 to attack a
#: different field (1 more edit, no pin changes) -- both guards stayed fully green while GA47f had
#: ZERO coverage. A mutation that no longer trips its own gate is now a failure.
EXPECTED_TRIP = {
    "MX01 verdict-subject-injected": "GA24b",
    "MX02 legend-class-invented": "GA04h",
    "MX03 verified-dispositions-forged": "GA47c",
    "MX04 local-evidence-note-forged": "GA47d",
    "MX05 unknown-top-level-key": "GA51b",
    "MX06 prose-claims-executed-drill": "GA04i",
    "MX07 prose-effort-none": "GA04i",
    "MX08 tree-binding-forged": "GA50h",
    "MX10 source-hash-crlf-bound": "GA50g",
    "MX11 blocking-reason-rewritten": "GA47e",
    "MX12 extra-context-injected": "GA45b",
    "MX13 static-contract-invented": "GA04j",
    "MX14 nested-context-key-injected": "GA56",
    "MX15 source-binding-key-injected": "GA56",
    "MX16 control-key-injected": "GA56",
    "MX17 legend-value-rewritten": "GA56",
    "MX18 curated-prose-rewritten": "GA56",
    "MX19 authoritative-note-forged": "GA56",
    "MX20 evidence-status-claimed": "GA56",
    "MX21 verified-flip-below-threshold": "GA47f",
    "MX22 prose-disclosure-removed": "GA04k",
    "MX26 context-authority-flipped": "GA45c",
    "MX27 bound-commit-is-prose": "GA47i",
    "MX28 matches-head-truthy-string": "GA47i",
    "MX29 evidence-path-count-forged": "GA47f",
    "MX30 verified-disposition-is-prose": "GA47m",
    "MX31 promoter-names-wrong-artifact": "GA47f",
    "MX32 conjunction-one-component-named": "GA47f",
    "MX33 promoter-named-but-absent": "GA47f",
    "MX34 detail-reports-a-missing-component": "GA47f",
    "MX23 presence-flag-forged": "GA47g",
    "MX24 verified-context-key-injected": "GA47h",
    "MX25 controls-reordered": "GA56",
    "MV02 legacy-v1-file-present": "GA00e",
    "MV03 generator-path-reverted-to-v1": "GA00d",
    "MV04 legacy-constant-collapsed-onto-current": "GA00e",
    "MR02 client-data-ready-true": "GA43a",
    "MR03 release-candidate-ready-true": "GA43b",
    "MR04 ga-ready-true": "GA43c",
    "MB05b worktree-clean-false": "GA50b",
    "MB06 canonical-hash-tampered": "GA54",
    "MB07 superseded-schema": "GA02",
    "MB08 classified-as-evidence": "GA55",
}

#: Whether the FB00 anchor held; gates the reported coverage number.
BASELINE_OK: list = []


def rec(cid, ok, desc, level="artifact mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def live_artifact() -> dict:
    return json.loads(GG.ARTIFACT_PATH.read_text(encoding="utf-8"))


def _emitted_drift_checks() -> list:
    """The drift guard's REAL emitted inventory, from an actual run against the tracked artifact."""
    saved = list(GG.checks)
    GG.checks.clear()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            GG.run()
        return list(GG.checks)
    except Exception:  # noqa: BLE001 - reported by the caller as a missing-gate failure
        return []
    finally:
        GG.checks.clear()
        GG.checks.extend(saved)


def _retally(a: dict) -> None:
    """Recompute the machine-local tally so a promotion probe stays self-consistent."""
    tally: dict = {}
    for control in a["controls"]:
        value = control["current_disposition_verified_environment"]
        tally[value] = tally.get(value, 0) + 1
    a["contexts"]["verified_environment_with_evidence"]["tally"] = dict(sorted(tally.items()))


def real_refusal(rc: int, failing: list) -> bool:
    """A refusal is a NAMED check deciding against the artifact -- never a crash.

    ``guard_result`` records an exception as a synthetic ``<exception:...>`` entry so the battery
    survives, but ``rc != 0 and bool(failing)`` scores that as a refusal. That is precisely how
    MV03/MV04 became dead code. ``refuses()`` filters it; six call sites that build their refusals
    by hand did not, so the filter lives here and every site uses it.
    """
    return rc != 0 and bool(failing) and not any(str(f).startswith("<exception") for f in failing)


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
    # A CRASH IS NOT A REFUSAL. guard_result records an exception as a synthetic failing entry so
    # the battery does not die, but counting that as a refusal is how MV03/MV04 became dead code:
    # they raised FileNotFoundError before the guard ever ran and were scored as passes. A refusal
    # must be a named check deciding against the artifact.
    crashed = [f for f in failing if str(f).startswith("<exception")]
    MUTATION_TRIPPED[cid] = list(failing)
    rec(cid, real_refusal(rc, failing), desc, level=level,
        extra={"guard_exit": rc, "failing_checks": failing[:4], "crashed": crashed,
               "mutation_fingerprint": MUTATION_FINGERPRINTS[cid]})


def ctl(artifact: dict, rid: str) -> dict:
    return next(c for c in artifact["controls"] if c["id"] == rid)


def run() -> int:
    rc, failing = guard_result(live_artifact())
    BASELINE_OK.append(rc == 0 and not failing)
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
            "the superseded v1 schema is refused. This also covers 'schema changed to v1' -- a "
            "separate MV01 doing the same thing was removed after FZ03 flagged the duplicate body")
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
    rec("MP03 malformed-artifact-crashes", real_refusal(rc_bad, failing_bad),
        "a malformed artifact is a controlled refusal, never an uncaught crash",
        level="schema mutation", extra={"failing": failing_bad[:3]})
    MUTATION_FINGERPRINTS["MP03 malformed-artifact-crashes"] = hashlib.sha256(
        b"{not valid json").hexdigest()[:16]

    # ---------------------------------------------------------------- v2 identity
    def _with_legacy_present():
        """Redirect the LEGACY path to a temp file rather than writing the tracked location.

        The first cut wrote "{}" over docs/GA_GAP_ASSESSMENT.v1.json and unlinked it -- a read-only
        audit command silently overwriting and deleting a user file at a tracked path. It is latent
        only because that file is currently absent.
        """
        saved_gen, saved_gg = GEN.LEGACY_ARTIFACT_PATH, GG.LEGACY_ARTIFACT_PATH
        tmp = Path(tempfile.mkdtemp(prefix="gga-legacy-"))
        try:
            legacy = tmp / "GA_GAP_ASSESSMENT.v1.json"
            legacy.write_text("{}", encoding="utf-8")
            GEN.LEGACY_ARTIFACT_PATH = legacy
            GG.LEGACY_ARTIFACT_PATH = legacy
            return guard_result(live_artifact())
        finally:
            GEN.LEGACY_ARTIFACT_PATH, GG.LEGACY_ARTIFACT_PATH = saved_gen, saved_gg
            shutil.rmtree(tmp, ignore_errors=True)

    rc_legacy, failing_legacy = _with_legacy_present()
    MUTATION_TRIPPED["MV02 legacy-v1-file-present"] = list(failing_legacy)
    rec("MV02 legacy-v1-file-present", real_refusal(rc_legacy, failing_legacy),
        "a legacy v1 artifact existing alongside the current v2 one is refused: two files either of "
        "which could be read as current is not an acceptable state",
        level="structural source check", extra={"failing": failing_legacy[:3]})
    # Fingerprint the ACTUAL redirected path, not a hand-written label: a constant asserts
    # distinctness of the name rather than of the input.
    MUTATION_FINGERPRINTS["MV02 legacy-v1-file-present"] = hashlib.sha256(
        f"legacy-present:{GEN.LEGACY_ARTIFACT_PATH.name}:{{}}".encode("utf-8")).hexdigest()[:16]

    def _with_v1_path(redirect_generator, cid, desc):
        """Point the canonical path at a v1-named file and require refusal.

        The first cut read the artifact AFTER reassigning the guard's path, so it raised
        FileNotFoundError before the guard was ever invoked and the broad except recorded that as a
        "refusal" -- leaving GA00d with no protection at all. The payload is captured FIRST.
        """
        payload = json.loads(GG.ARTIFACT_PATH.read_text(encoding="utf-8"))
        saved_gen, saved_gg = GEN.OUTPUT_PATH, GG.ARTIFACT_PATH
        tmp = Path(tempfile.mkdtemp(prefix="gga-v1path-"))
        try:
            v1_path = tmp / "GA_GAP_ASSESSMENT.v1.json"
            v1_path.write_text(json.dumps(payload), encoding="utf-8")
            GG.ARTIFACT_PATH = v1_path
            if redirect_generator:
                GEN.OUTPUT_PATH = v1_path
            GG.checks.clear()
            with contextlib.redirect_stdout(io.StringIO()):
                rc = GG.run()
            failing = [c["check_id"] for c in GG.checks if not c["ok"]]
        except Exception as exc:  # noqa: BLE001
            rc, failing = 1, [f"<exception:{exc.__class__.__name__}>"]
        finally:
            GEN.OUTPUT_PATH, GG.ARTIFACT_PATH = saved_gen, saved_gg
            GG.checks.clear()
            shutil.rmtree(tmp, ignore_errors=True)
        MUTATION_TRIPPED[cid] = list(failing)
        rec(cid, real_refusal(rc, failing),
            desc, level="structural source check", extra={"failing": failing[:3]})
        MUTATION_FINGERPRINTS[cid] = hashlib.sha256(
            f"v1path:{redirect_generator}".encode("utf-8")).hexdigest()[:16]

    _with_v1_path(True, "MV03 generator-path-reverted-to-v1",
                  "reverting the CANONICAL generator OUTPUT path to a v1 filename is refused by "
                  "GA00d: filename and schema must agree. An exception does not count as a refusal")
    def _with_collapsed_legacy():
        """Point the LEGACY constant at the CURRENT artifact and require refusal.

        Replaces an earlier MV04 that redirected only the guard's INPUT path. That asserted a
        property the design deliberately does not have -- ``ARTIFACT_PATH = GEN.OUTPUT_PATH``, so the
        guard consumes the canonical constant and a harness-only redirection proves nothing. This
        mutation instead attacks GA00e: if the legacy constant can be collapsed onto the current
        filename, "no legacy artifact exists" becomes trivially satisfiable in reverse.
        """
        saved_gen, saved_gg = GEN.LEGACY_ARTIFACT_PATH, GG.LEGACY_ARTIFACT_PATH
        try:
            GEN.LEGACY_ARTIFACT_PATH = GEN.OUTPUT_PATH
            GG.LEGACY_ARTIFACT_PATH = GG.ARTIFACT_PATH
            return guard_result(live_artifact())
        finally:
            GEN.LEGACY_ARTIFACT_PATH, GG.LEGACY_ARTIFACT_PATH = saved_gen, saved_gg

    rc_collapse, failing_collapse = _with_collapsed_legacy()
    MUTATION_TRIPPED["MV04 legacy-constant-collapsed-onto-current"] = list(failing_collapse)
    rec("MV04 legacy-constant-collapsed-onto-current",
        real_refusal(rc_collapse, failing_collapse),
        "collapsing the LEGACY path constant onto the current artifact's filename is refused: the "
        "legacy-absence check cannot be neutered by aiming it at a file that must exist",
        level="structural source check", extra={"failing": failing_collapse[:3]})
    MUTATION_FINGERPRINTS["MV04 legacy-constant-collapsed-onto-current"] = hashlib.sha256(
        f"legacy-collapsed:{GEN.OUTPUT_PATH.name}".encode("utf-8")).hexdigest()[:16]

    # ---------------------------------------------------------------- registry-derived inventory
    def _with_registry(mutate_registry, cid, desc):
        """Mutate a TEMP COPY of the registry and point the modules at it.

        The first cut wrote the tracked registry three times per run, restored only by a finally --
        verbatim the anti-pattern this increment's own GA70 docstring condemns, and unsafe to
        interrupt or run concurrently. Nothing here touches the tracked file.
        """
        saved_gen, saved_gg, saved_ga = GEN.REGISTRY_PATH, GG.REGISTRY_PATH, GA_MOD.REGISTRY_PATH
        tmp = Path(tempfile.mkdtemp(prefix="gga-reg-"))
        try:
            data = json.loads(GEN.REGISTRY_PATH.read_text(encoding="utf-8"))
            mutate_registry(data)
            target = tmp / "blocker_registry.v1.json"
            target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
            GEN.REGISTRY_PATH = target
            GG.REGISTRY_PATH = target
            GA_MOD.REGISTRY_PATH = target
            payload = json.loads(GG.ARTIFACT_PATH.read_text(encoding="utf-8"))
            fingerprint = hashlib.sha256(
                json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
            rc, failing = guard_result(payload)
        except Exception as exc:  # noqa: BLE001
            rc, failing, fingerprint = 1, [f"<exception:{exc.__class__.__name__}>"], cid
        finally:
            GEN.REGISTRY_PATH, GG.REGISTRY_PATH = saved_gen, saved_gg
            GA_MOD.REGISTRY_PATH = saved_ga
            shutil.rmtree(tmp, ignore_errors=True)
        MUTATION_FINGERPRINTS[cid] = fingerprint
        MUTATION_TRIPPED[cid] = list(failing)
        rec(cid, real_refusal(rc, failing), desc, level="registry mutation",
            extra={"failing": failing[:3], "mutation_fingerprint": fingerprint})

    _with_registry(lambda d: d["blockers"].pop(5), "MI01 registry-control-removed",
                   "removing a control from the REGISTRY makes the artifact stale: the expected "
                   "inventory is the registry, so the artifact no longer reconciles")
    _with_registry(lambda d: d["blockers"].append({**copy.deepcopy(d["blockers"][0]),
                                                   "id": "invented-control",
                                                   "check_id": "ga_invented_control"}),
                   "MI02 registry-control-added",
                   "adding a control to the REGISTRY makes the artifact stale")
    _with_registry(lambda d: d["blockers"][7].__setitem__("check_id", "ga_renamed_check"),
                   "MI03 registry-check-id-changed",
                   "changing a registry check-id makes the artifact stale: the id->check-id mapping "
                   "is reconciled, not just the id set")
    refuses("MI04 artifact-supplies-expected-inventory",
            lambda a: a.__setitem__("expected_control_ids",
                                    [c["id"] for c in a["controls"]][:5]),
            "an artifact that declares its own expected inventory is refused -- an artifact stating "
            "what it should contain proves nothing")
    refuses("MI05 artifact-check-id-mapping-changed",
            lambda a: ctl(a, DB_ID).__setitem__("check_id", "ga_redis_adapter"),
            "cross-wiring a control to another control's check id is refused")

    # ---------------------------------------------------------------- binding
    refuses("MG01 arbitrary-old-ancestor",
            lambda a: a.__setitem__("generated_from_commit",
                                    "df9c90da2f5a29c88183292a9ce4825d95fd5e7e"),
            "an arbitrary OLD ancestor is refused even though it is genuinely an ancestor: the model "
            "is the immediate parent of the artifact commit")
    refuses("MG02 source-file-hash-stale",
            lambda a: a["source_file_hashes"].__setitem__(
                "backend/app/ga_readiness.py", "0" * 64),
            "a stale per-file source hash is refused: ancestry alone is not relied upon")
    refuses("MG03 generation-model-removed",
            lambda a: a.pop("artifact_generation_model"),
            "an artifact that does not declare its generation model is refused")

    # ------------------------------------------------ forgeries a review executed successfully
    # Every mutation below reproduces an attack that certified GREEN against the previous cut. They
    # are recorded here so the fix cannot silently regress.
    refuses("MX01 verdict-subject-injected",
            lambda a: a["execution_verdicts"].__setitem__("ga", "GA_ACCEPTED"),
            "an extra execution_verdicts subject is refused: pinning the three known values while "
            "ignoring unknown keys let ga=GA_ACCEPTED through the most load-bearing field")
    refuses("MX02 legend-class-invented",
            lambda a: (a["measurement_class_legend"].__setitem__(
                "PRODUCTION_VERIFIED", "Verified end to end against a real production deployment."),
                [c.__setitem__("measurement_class", "PRODUCTION_VERIFIED") for c in a["controls"]]),
            "inventing a measurement class and applying it to all 28 controls is refused: the "
            "legend is not a self-supplied authority")

    def _forge_verified(a):
        for c in a["controls"]:
            c["current_disposition_verified_environment"] = "PASS"
        a["contexts"]["verified_environment_with_evidence"]["tally"] = {"PASS": 28}

    refuses("MX03 verified-dispositions-forged", _forge_verified,
            "forging all 28 verified dispositions to PASS with a matching tally is refused. Both "
            "fields sit outside the canonical hash, so the forgery collided byte-for-byte with the "
            "honest artifact and only recomputation catches it")
    refuses("MX04 local-evidence-note-forged",
            lambda a: a["local_evidence_artifact"].__setitem__(
                "note", "Production adapter evidence collected and accepted at this head."),
            "free text inside the non-canonical local_evidence_artifact block is refused: it was a "
            "second hash-collision channel")
    refuses("MX05 unknown-top-level-key",
            lambda a: a.__setitem__("executive_summary",
                                    "All production adapters have been executed and accepted."),
            "an unknown top-level key is refused: unknown keys were previously ignored entirely")

    def _forge_prose(a):
        target = next(c for c in a["controls"]
                      if c["current_disposition_fresh_checkout"] != "PASS")
        target["implemented_capability"] = (
            "A full restore drill was executed against the production cluster with approved "
            "RPO=15m / RTO=4h. Evidence signed off by the release manager.")
        target["missing_capability"] = "Nothing. This control is operationally satisfied."

    refuses("MX06 prose-claims-executed-drill", _forge_prose,
            "curated prose claiming an EXECUTED, signed-off drill on a control the evaluator "
            "reports as not-PASS is refused, even though the prose is hand-written free text")

    def _forge_effort(a):
        target = next(c for c in a["controls"]
                      if c["current_disposition_fresh_checkout"] != "PASS")
        target["estimated_effort"] = "NONE"
        target["missing_capability"] = ""

    refuses("MX07 prose-effort-none", _forge_effort,
            "a not-PASS control with NONE effort and an empty missing_capability is refused")
    refuses("MX08 tree-binding-forged",
            lambda a: a.__setitem__("generated_from_tree", "f" * 40),
            "a forged tree binding is refused: the field was emitted but never checked")
    def _crlf_hash(a):
        path = "scripts/build_ga_gap_assessment.py"
        raw = (ROOT / path).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        a["source_file_hashes"][path] = hashlib.sha256(raw).hexdigest()

    # Every mutation in this block certified GREEN against the previous cut. They are the reason
    # the per-field approach was replaced by a whole-payload comparison (GA52).
    refuses("MX14 nested-context-key-injected",
            lambda a: a["contexts"]["fresh_checkout_no_local_evidence"].__setitem__(
                "production_status", "PRODUCTION ADAPTERS ACCEPTED"),
            "an extra key INSIDE a known context is refused; closing the context NAME set left "
            "every context body open")
    refuses("MX15 source-binding-key-injected",
            lambda a: a["source_bindings"].__setitem__(
                "production_execution_accepted", "PRODUCTION_ADAPTERS_ACCEPTED"),
            "an extra key inside source_bindings is refused")
    refuses("MX16 control-key-injected",
            lambda a: a["controls"][0].__setitem__("production_acceptance",
                                                   "ACCEPTED at this head"),
            "an extra key inside a control entry is refused")
    refuses("MX17 legend-value-rewritten",
            lambda a: a["measurement_class_legend"].__setitem__(
                "ABSENT", "Verified end to end against a real production deployment."),
            "rewriting a legend VALUE is refused; pinning the legend's key set left its prose free")
    refuses("MX18 curated-prose-rewritten",
            lambda a: [c.__setitem__(
                "implemented_capability",
                "Delivered and exercised against a real production deployment; approved by the "
                "client release board. The control's condition holds today.")
                for c in a["controls"]
                if c["current_disposition_fresh_checkout"] != "PASS"],
            "wholesale rewriting of the curated prose is refused WITHOUT relying on a phrase "
            "blacklist: a review defeated the blacklist by rewording the lie")
    refuses("MX19 authoritative-note-forged",
            lambda a: a.__setitem__(
                "authoritative_context_note",
                "Both production adapters have been run and accepted in production."),
            "forging the authoritative-context note is refused")

    def _claim_evidence(a):
        t = next(c for c in a["controls"] if c["id"] == "backup-restore-drill")
        t["probe_type"] = "evidence_driven_probe"
        t["evidence_status"] = "present_exact_head"
        t["behaviorally_measured"] = True

    refuses("MX20 evidence-status-claimed", _claim_evidence,
            "a non-adapter control claiming exact-head evidence is refused; the earlier check "
            "pinned evidence_status for the two adapters only")

    def _flip_below_threshold(a):
        flipped = 0
        for c in a["controls"]:
            if c["current_disposition_verified_environment"] == "BLOCKED" and flipped < 17:
                c["current_disposition_verified_environment"] = "PASS"
                flipped += 1
        tally: dict = {}
        for c in a["controls"]:
            v = c["current_disposition_verified_environment"]
            tally[v] = tally.get(v, 0) + 1
        a["contexts"]["verified_environment_with_evidence"]["tally"] = dict(sorted(tally.items()))

    refuses("MX21 verified-flip-below-threshold", _flip_below_threshold,
            "flipping MOST verified dispositions to PASS while leaving one BLOCKED is refused. The "
            "decision recomputation only fires when EVERY disposition is non-blocking, so a review "
            "flipped both production adapters to PASS with the canonical hash unchanged")

    refuses("MX22 prose-disclosure-removed",
            lambda a: a.pop("curated_prose_disclosure"),
            "removing the disclosure that the curated prose is author-supplied and unverifiable is "
            "refused: the disclosure is the only honest control over content no guard can check")
    refuses("MX26 context-authority-flipped",
            lambda a: (a["contexts"]["verified_environment_with_evidence"].__setitem__(
                "authoritative_for_release", True),
                a["contexts"]["verified_environment_with_evidence"].__setitem__(
                    "informational_only", False)),
            "promoting the machine-local context to authoritative is refused: the classification is "
            "machine-readable precisely so it cannot be quietly inverted")
    refuses("MX27 bound-commit-is-prose",
            lambda a: a["local_evidence_artifact"].__setitem__(
                "bound_to_commit",
                "Production database and queue adapters were exercised and ACCEPTED at this head."),
            "prose in bound_to_commit is refused: the block's key set and note were closed while "
            "its VALUES stayed open, and it sits outside both the hash and the deep comparison")
    refuses("MX28 matches-head-truthy-string",
            lambda a: a["local_evidence_artifact"].__setitem__(
                "matches_current_head", "yes - exact-head production evidence present"),
            "a truthy STRING in matches_current_head is refused; the old check only rejected the "
            "literal True, so any sentence passed")

    def _forge_paths(a):
        a["local_evidence_paths_present"] = 0
        for c in a["controls"]:
            if c["id"] in ("production-database-adapter", "production-queue-adapter"):
                c["current_disposition_verified_environment"] = "PASS"
        t = {}
        for c in a["controls"]:
            v = c["current_disposition_verified_environment"]; t[v] = t.get(v, 0) + 1
        a["contexts"]["verified_environment_with_evidence"]["tally"] = dict(sorted(t.items()))

    refuses("MX29 evidence-path-count-forged", _forge_paths,
            "recording both production adapters PASS in the verified half with NO evidence artifact "
            "present anywhere is refused; dropping the presence requirement had widened this")
    def _prose_dispo(a):
        tgt = a["controls"][0]
        sentence = ("PASS - production database and queue adapters were exercised and ACCEPTED at "
                    "this head by the release engineer.")
        tgt["current_disposition_verified_environment"] = sentence
        t = {}
        for c in a["controls"]:
            v = c["current_disposition_verified_environment"]; t[v] = t.get(v, 0) + 1
        a["contexts"]["verified_environment_with_evidence"]["tally"] = dict(sorted(t.items()))

    refuses("MX30 verified-disposition-is-prose", _prose_dispo,
            "an arbitrary sentence in a verified disposition (and mirrored into the tally key) is "
            "refused; it previously certified with a byte-identical canonical hash")
    # One probe per substantive GA47f arm. Each was previously unreachable because the only
    # GA47f-bound mutations either used a string promoter or set none at all.
    # Each probe must differ from a VALID promotion in exactly ONE arm. The first cut tripped two
    # or three arms at once, and because the arms are OR'd a probe that trips several pins none of
    # them: `present != required`, `missing` and the conjunction equality could each be deleted with
    # both batteries fully green.
    def _wrong_artifact(a):
        # ONLY `named != required`: the named artifact is known but gates a different control.
        t = next(c for c in a["controls"] if c["check_id"] == "ga_postgres_adapter")
        t["current_disposition_verified_environment"] = "PASS"
        t["verified_promoted_by"] = ["migration-evidence.v1.json"]
        t["verified_promotion_detail"] = {
            "required": ["production-database-adapter-evidence.v1.json"],
            "present": ["production-database-adapter-evidence.v1.json"],
            "missing": [], "conjunction": False}
        _retally(a)

    def _one_component(a):
        # ONLY the conjunction equality: both components named and present, flag says False.
        t = next(c for c in a["controls"] if c["check_id"] == "ga_tenant_authorization")
        both = ["tenant-authorization-evidence.v3.json",
                "tenant-rls-enforcement-evidence.v2.json"]
        t["current_disposition_verified_environment"] = "PASS"
        t["verified_promoted_by"] = list(both)
        t["verified_promotion_detail"] = {"required": list(both), "present": list(both),
                                          "missing": [], "conjunction": False}
        _retally(a)

    def _named_but_absent(a):
        # ONLY `present != required`: correct artifact named, detail reports none present,
        # and `missing` left EMPTY so that arm cannot also fire.
        t = next(c for c in a["controls"] if c["check_id"] == "ga_redis_adapter")
        t["current_disposition_verified_environment"] = "PASS"
        t["verified_promoted_by"] = ["production-queue-adapter-evidence.v1.json"]
        t["verified_promotion_detail"] = {
            "required": ["production-queue-adapter-evidence.v1.json"],
            "present": [], "missing": [], "conjunction": False}
        _retally(a)

    def _missing_component(a):
        # ONLY `missing`: named and present agree with required, but missing is non-empty.
        t = next(c for c in a["controls"] if c["check_id"] == "ga_migration_runner")
        t["current_disposition_verified_environment"] = "PASS"
        t["verified_promoted_by"] = ["migration-evidence.v1.json"]
        t["verified_promotion_detail"] = {
            "required": ["migration-evidence.v1.json"],
            "present": ["migration-evidence.v1.json"],
            "missing": ["migration-evidence.v1.json"], "conjunction": False}
        _retally(a)

    refuses("MX34 detail-reports-a-missing-component", _missing_component,
            "a non-empty missing list is refused even when named and present agree with required: "
            "this pins the `missing` arm alone")

    refuses("MX31 promoter-names-wrong-artifact", _wrong_artifact,
            "a promoter naming a KNOWN artifact that does not gate THIS control is refused: the "
            "per-control arm, not merely `some promoter was named`")
    refuses("MX32 conjunction-one-component-named", _one_component,
            "naming one component of a conjunction is refused; the requirement comes from the "
            "evaluator graph, so a control cannot redefine its own conjunction as a single artifact")
    refuses("MX33 promoter-named-but-absent", _named_but_absent,
            "naming the correct artifact while the detail block reports it MISSING is refused: "
            "naming is not having")
    refuses("MX23 presence-flag-forged",
            lambda a: a.__setitem__("local_evidence_artifact_present",
                                    {"ga": "GA_READY", "note": "adapters accepted"}),
            "an arbitrary value in the top-level presence flag is refused; it was read by NO check, "
            "so false / prose / null / an object all certified green with an identical hash")
    refuses("MX24 verified-context-key-injected",
            lambda a: a["contexts"]["verified_environment_with_evidence"].__setitem__(
                "executive_summary", "Both production adapters were exercised and accepted."),
            "an injected key inside the machine-local context is refused; the whole subtree was "
            "popped from the deep comparison and accepted anything")
    refuses("MX25 controls-reordered",
            lambda a: a.__setitem__("controls", list(reversed(a["controls"]))),
            "a reordered controls array is refused: the generator emits them sorted by check_id, so "
            "a different order is not a regeneration even though every entry matches")
    refuses("MX11 blocking-reason-rewritten",
            lambda a: [c.__setitem__("blocking_reason", "Resolved: verified in production.")
                       for c in a["controls"]],
            "rewriting every derived blocking_reason to claim resolution is refused: the reasons "
            "come from the evaluator, not from an author")
    refuses("MX12 extra-context-injected",
            lambda a: a["contexts"].__setitem__(
                "production_verified", {"ga": "GA_READY", "tally": {"PASS": 28}}),
            "an injected third context reporting GA_READY is refused; closing only the top-level "
            "key set left every nested block open")
    refuses("MX13 static-contract-invented",
            lambda a: a["static_contracts_accepted"].__setitem__(
                "ga_production_readiness_contract", True),
            "an invented static contract is refused even though its name satisfies the _contract "
            "suffix rule -- a naming convention is not an inventory")
    refuses("MX10 source-hash-crlf-bound", _crlf_hash,
            "a source hash bound to CRLF working-tree bytes is refused: .gitattributes pins eol=lf, "
            "so such a hash is reproducible on exactly one machine and the artifact validates "
            "nowhere else")

    rec("FB01 artifact-untouched", GG.ARTIFACT_PATH.read_bytes() == before,
        "the tracked assessment is byte-identical after every mutation: each ran on a temp copy",
        level="structural source check")

    # ---------------------------------------------------------------- positive paths
    # Until now the battery proved only that a WRONG promotion is refused. A guard that silently
    # stops accepting the generator's own honest output looks identical to a working one -- which
    # is exactly how an inert resolver survived two independent reviews. These checks require a
    # RIGHT promotion to be ACCEPTED, and the mutations below require each of them to break.
    fx = PP.fixture(SYN, GEN, GA_MOD)
    matrix, payload, promoted = fx["matrix"], fx["payload"], fx["promoted"]

    def _scoped(cid, label, artifacts):
        entry = matrix.get(cid, {})
        control = fx["controls"].get(cid, {})
        rec(label,
            entry.get("disposition") == "PASS"
            and set(entry.get("movers") or []) == PP.EXPECTED_MOVERS[cid]
            and set(control.get("verified_promoted_by") or []) == set(artifacts)
            and payload["release_recommendation"] == "GA_BLOCKED",
            f"{cid} reaches PASS from its OWN exact-head artifact, moves exactly the intended "
            f"control, and is attributed to exactly {sorted(artifacts)}",
            level="positive path",
            extra={"disposition": entry.get("disposition"), "movers": entry.get("movers"),
                   "promoted_by": control.get("verified_promoted_by"),
                   "synthetic_artifact": True, "parser_evaluator_coverage_only": True,
                   "real_production_execution": False})

    _scoped("ga_migration_runner", "PP01 migration-runner-own-artifact-accepted",
            ["migration-evidence.v1.json"])

    mv = matrix.get("ga_migration_validity", {})
    marker, sibling = PP.STATIC_BLOCKER_CONTROLS["ga_migration_validity"]
    rec("PP02 migration-validity-scope-recognized-blocker-retained",
        mv.get("disposition") == "BLOCKED"
        and marker in mv.get("detail", "")
        and matrix.get(sibling, {}).get("disposition") == "PASS"
        and "not proven" not in mv.get("detail", ""),
        "the migration artifact is RECOGNISED as in scope -- proved by the sibling reaching PASS "
        "off the same artifact -- while the control stays BLOCKED on the independent legacy FK "
        "blocker. A fail-closed BLOCKED is NOT accepted as success: scope-resolution failure "
        "reads 'Migration validity not proven' and leaves the sibling BLOCKED too",
        level="positive path",
        extra={"disposition": mv.get("disposition"), "sibling": sibling,
               "sibling_disposition": matrix.get(sibling, {}).get("disposition"),
               "blocker_marker_present": marker in mv.get("detail", ""),
               "detail": mv.get("detail", "")[:140]})

    tenant = fx["controls"].get("ga_tenant_authorization", {})
    tdetail = tenant.get("verified_promotion_detail") or {}
    both = {"tenant-rls-enforcement-evidence.v2.json", "tenant-authorization-evidence.v3.json"}
    conj = PP.conjunction_members_matrix(SYN, GEN, GA_MOD)
    alone_blocked = all(v == "BLOCKED" for v in conj["alone"].values())
    rec("PP03 tenant-conjunction-accepted",
        matrix.get("ga_tenant_authorization", {}).get("disposition") == "PASS"
        and set(matrix.get("ga_tenant_authorization", {}).get("movers") or [])
        == {"ga_tenant_authorization"}
        and set(tdetail.get("required") or []) == both
        and set(tdetail.get("present") or []) == both
        and not tdetail.get("missing")
        and tdetail.get("conjunction") is True
        and len(conj["alone"]) == 2 and alone_blocked and conj["both"] == "PASS",
        "the tenant conjunction is measured BEHAVIOURALLY: each member installed ALONE leaves the "
        "control BLOCKED and only both together reach PASS. The graph derives `conjunction` from "
        "artifact CARDINALITY, not from the evaluator's operator, so weakening the real all-of to "
        "an any-of was invisible until the single-member cases were actually evaluated",
        level="positive path",
        extra={"detail": tdetail, "each_member_alone": conj["alone"], "both": conj["both"]})

    _scoped("ga_postgres_adapter", "PP04 database-adapter-own-synthetic-artifact-accepted",
            ["production-database-adapter-evidence.v1.json"])
    _scoped("ga_redis_adapter", "PP05 queue-adapter-own-synthetic-artifact-accepted",
            ["production-queue-adapter-evidence.v1.json"])
    _scoped("ga_persistence_locking", "PP06 persistence-locking-own-artifact-accepted",
            ["persistence-atomicity-evidence.v4.json"])
    _scoped("ga_correction_cross_process_atomicity",
            "PP07 correction-atomicity-own-artifact-accepted",
            ["normalized-correction-persistence-evidence.v4.json"])

    bc = PP.unrelated_and_stale_matrix(SYN, GEN, GA_MOD)
    rec("PP08 unrelated-artifacts-rejected",
        isinstance(bc.get("unrelated"), list)
        and "measured" in bc and bc["measured"]
        and set(bc["unrelated"]) <= {"ga_redis_adapter"},
        "with only ONE control's artifact present, no OTHER control moves: an unrelated artifact "
        "never promotes a control",
        level="positive path", extra={"movers": bc["unrelated"]})
    rec("PP09 stale-artifacts-rejected",
        isinstance(bc.get("stale"), list) and bc.get("measured")
        and not bc["stale"],
        "artifacts corrupted so their own validators refuse them promote nothing at all",
        level="positive path", extra={"movers": bc["stale"]})
    rec("PP10 overall-ga-remains-blocked",
        payload["release_recommendation"] == "GA_BLOCKED"
        and payload["ga_ready"] is False
        and payload["execution_verdicts"]["production_database_adapter"].endswith("NOT_ACCEPTED")
        and payload["execution_verdicts"]["production_queue_adapter"].endswith("NOT_ACCEPTED"),
        "even with every synthetic artifact present and six controls promoted, GA stays blocked "
        "and both production adapters stay NOT_ACCEPTED. Synthetic evidence is parser/evaluator "
        "coverage and can never be production acceptance",
        level="positive path",
        extra={"release_recommendation": payload["release_recommendation"],
               "production_adapter_accepted": False,
               "synthetic_artifact": True, "parser_evaluator_coverage_only": True,
               "real_production_execution": False})

    derived = PP.graph_fingerprint(COUPLING, ROOT)
    rec("PP11 graph-exactness-derived-from-evaluator",
        set(derived) == set(PP.EXPECTED_MOVERS)
        and derived.get("ga_tenant_authorization", {}).get("conjunction") is True
        and all(spec["artifacts"] for spec in derived.values())
        and all(spec["validators"] for spec in derived.values()),
        "artifacts, operator and validators are re-derived from the evaluator's own AST every run "
        "and cover exactly the seven artifact-gated controls -- not one editable copy of a mapping "
        "compared against another",
        level="structural source check",
        extra={"controls": len(derived),
               "conjunction_controls": sorted(k for k, v in derived.items() if v["conjunction"])})

    anchor_rc, anchor_failing = PP.guard_verdict(GG, payload)
    rec("PP12 honest-payload-accepted-by-the-unmutated-guard",
        anchor_rc == 0 and not anchor_failing,
        "ANCHOR for the whole scope-mutation family: the UNMUTATED guard ACCEPTS the honest "
        "evidence-present payload. Without it every PM below only proves that a mutated guard "
        "refuses -- which an always-refusing guard satisfies too. A review set EVIDENCE_SCOPE={} "
        "permanently and the entire battery still certified green, because the tracked artifact "
        "promotes nothing and GA47f/GA47n are vacuous against it",
        level="positive path",
        extra={"guard_exit": anchor_rc, "failing": anchor_failing[:4]})

    # ---------------------------------------------------------------- scope mutations
    def _scope_mutation(cid, label, removed, expect_control):
        """Remove mapping arms and require the corresponding POSITIVE path to break."""
        with PP.scope_without(GG, removed):
            rc, failing = PP.guard_verdict(GG, payload)
        crashed = [f for f in failing if str(f).startswith("<exception")]
        tripped = [f for f in failing if f.split(" ", 1)[0] == "GA47f"]
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            ("scope:" + ",".join(sorted(removed))).encode("utf-8")).hexdigest()[:16]
        MUTATION_TRIPPED[label] = list(failing)
        rec(label, rc != 0 and bool(tripped) and not crashed,
            f"removing {sorted(removed) or 'the whole mapping'} breaks the accepted promotion of "
            f"{expect_control}: the positive path stops working, which a fail-closed guard hides",
            level="scope mutation",
            extra={"removed": sorted(removed), "failing": failing[:3],
                   "mutation_fingerprint": MUTATION_FINGERPRINTS[label]})

    _scope_mutation(None, "PM01 empty-evidence-scope-mapping",
                    set(GG.EVIDENCE_SCOPE), "every promoted control")
    for cid, label in (
            ("ga_migration_runner", "PM02 remove-migration-runner-arm"),
            ("ga_tenant_authorization", "PM04 remove-tenant-conjunction-arm"),
            ("ga_postgres_adapter", "PM05 remove-database-adapter-arm"),
            ("ga_redis_adapter", "PM06 remove-queue-adapter-arm"),
            ("ga_persistence_locking", "PM07 remove-persistence-locking-arm"),
            ("ga_correction_cross_process_atomicity", "PM08 remove-correction-atomicity-arm")):
        _scope_mutation(cid, label, {cid}, cid)

    # ga_migration_validity is the one mapped control that never promotes -- its independent
    # static blocker outlives the evidence gate -- so removing its arm cannot break a promotion.
    # Its mapping is load-bearing structurally instead: it must be present in the graph derived
    # from the evaluator, with the same artifact its promoting sibling uses.
    derived_mv = PP.graph_fingerprint(COUPLING, ROOT).get("ga_migration_validity", {})
    rec("PP13 migration-validity-arm-pinned",
        derived_mv.get("artifacts") == ("migration-evidence.v1.json",)
        and derived_mv.get("conjunction") is False
        and bool(derived_mv.get("extra_predicates")),
        "the migration-validity arm is present in the graph DERIVED from the evaluator, bound to "
        "the same artifact its sibling promotes from, and carries extra static predicates. It is "
        "pinned structurally rather than by a broken promotion: this control never promotes, so "
        "claiming a promotion-break mutation for it would be vacuous",
        level="structural source check",
        extra={"derived": {k: list(v) if isinstance(v, tuple) else v
                           for k, v in derived_mv.items()},
               "applies_a_mutation": False})

    def _scope_rewrite(label, rewrite, why):
        original = GG.EVIDENCE_SCOPE
        mutated_scope = rewrite(dict(original))
        try:
            GG.EVIDENCE_SCOPE = mutated_scope
            rc, failing = PP.guard_verdict(GG, payload)
        finally:
            GG.EVIDENCE_SCOPE = original
        crashed = [f for f in failing if str(f).startswith("<exception")]
        tripped = [f for f in failing if f.split(" ", 1)[0] == "GA47f"]
        # Fingerprint the mutated MAPPING, not the check's own name: hashing the label makes two
        # mutations with identical bodies indistinguishable and hollows out FZ03.
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            json.dumps({k: sorted(v) for k, v in sorted(mutated_scope.items())},
                       sort_keys=True).encode("utf-8")).hexdigest()[:16]
        MUTATION_TRIPPED[label] = list(failing)
        rec(label, rc != 0 and bool(tripped) and not crashed, why,
            level="scope mutation",
            extra={"failing": failing[:3], "mutation_fingerprint": MUTATION_FINGERPRINTS[label]})

    _scope_rewrite("PM09 tenant-all-of-weakened-to-any-of",
                   lambda m: {**m, "ga_tenant_authorization":
                              {"tenant-rls-enforcement-evidence.v2.json"}},
                   "weakening the tenant ALL-OF to a single sufficient member is refused: the "
                   "artifact names both, so a one-member requirement no longer matches")
    _scope_rewrite("PM10 tenant-conjunction-member-removed",
                   lambda m: {**m, "ga_tenant_authorization":
                              {"tenant-authorization-evidence.v3.json"}},
                   "dropping the other conjunction member is refused for the same reason")
    _scope_rewrite("PM11 own-artifact-replaced-with-unrelated",
                   lambda m: {**m, "ga_postgres_adapter": {"migration-evidence.v1.json"}},
                   "pointing a control's requirement at an unrelated artifact is refused")
    _scope_rewrite("PM12 artifact-path-changed",
                   lambda m: {**m, "ga_redis_adapter": {"production-queue-adapter-evidence.v9.json"}},
                   "a changed artifact filename is refused: the promoter no longer matches")

    def _generator_mutation(label, patch, restore, why):
        _mutated_promoters, _mutation_shape = {}, [label]
        try:
            patch()
            mutated, _mutated_promoters = PP.legitimate_promotion_payload(SYN, GEN)
            _mutation_shape = [[c.get("check_id"), c.get("verified_promoted_by"),
                                c.get("verified_promotion_detail")]
                               for c in mutated.get("controls", [])]
            rc, failing = PP.guard_verdict(GG, mutated)
        except Exception as exc:  # noqa: BLE001
            rc, failing = 1, [f"<exception:{exc.__class__.__name__}>"]
        finally:
            restore()
        crashed = [f for f in failing if str(f).startswith("<exception")]
        # Hash the full per-control promotion DETAIL, not just the promoter map: two different
        # generator mutations can both yield an empty promoter map while differing in what the
        # detail block reports, and hashing only the map made them indistinguishable to FZ03.
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            json.dumps(_mutation_shape, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        MUTATION_TRIPPED[label] = list(failing)
        rec(label, rc != 0 and bool(failing) and not crashed, why,
            level="generator mutation",
            extra={"failing": failing[:3], "mutation_fingerprint": MUTATION_FINGERPRINTS[label]})

    _original_promotion_map = GEN._promotion_map
    _generator_mutation(
        "PM13 promoter-attribution-disabled",
        lambda: setattr(GEN, "_promotion_map", lambda fresh: {}),
        lambda: setattr(GEN, "_promotion_map", _original_promotion_map),
        "a generator that stops attributing promotions is refused: a promoted control with no "
        "promoter is exactly the state GA47n exists to catch")

    def _collide():
        def broken(fresh):
            result = _original_promotion_map(fresh)
            # the pre-fix behaviour: last path with a given basename wins, so a control whose
            # artifact basename appears twice loses its `present` entry
            for spec in result.values():
                spec["present"] = []
                spec["missing"] = list(spec["required"])
            return result
        GEN._promotion_map = broken

    _generator_mutation(
        "PM14 promoter-basename-collision-restored",
        _collide,
        lambda: setattr(GEN, "_promotion_map", _original_promotion_map),
        "restoring the basename-collision behaviour -- present empty, everything reported missing "
        "for a control that WAS promoted -- is refused. This regression made the guard reject the "
        "generator's own honest output and was found by the first positive-path run")

    # ---------------------------------------------------------------- completeness
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
    # Protected exactly like _emitted_drift_checks(). Unprotected, a hollowing that the coupling
    # verifier DOES detect (an input rebound to a constant) raised AttributeError here and the whole
    # battery died with ZERO stdout, no JSON and no named failure -- the precise outcome this file
    # calls unacceptable elsewhere. A crash is not a refusal, and it is not a pin either.
    drift_ids = sorted(c["check_id"] for c in _emitted_drift_checks())
    crashed_enumerating = not drift_ids
    drift_hash = hashlib.sha256("\n".join(drift_ids).encode("utf-8")).hexdigest()
    rec("FZ04 drift-guard-check-set-pinned",
        not crashed_enumerating
        and drift_hash == PINNED_DRIFT_ID_SET_HASH and len(drift_ids) == PINNED_DRIFT_CHECK_COUNT,
        "the drift guard's emitted check-id set is hashed and pinned HERE, so one of its checks "
        "cannot be deleted with this battery still reporting green",
        level="structural source check",
        extra={"observed": drift_hash[:16] + "...", "count": len(drift_ids),
               "crashed_enumerating": crashed_enumerating})

    # The expected control inventory must come from the registry, and no editable constant may
    # redefine it. Proved on the parsed guard source, not by string search.
    import ast as _ast
    # ---------------------------------------------------------------- behavioral discrimination
    # THE load-bearing proof. FZ07/FZ08 inspect the SHAPE of each gate's predicate, and an
    # exact-head review showed that is an arms race that cannot be won: of twenty hollowings it
    # tried, nineteen evaded the shape rules (`len(x) >= 0`, `x == x`, `x or True`, `str(x) != "z"`,
    # `list()`, `x.clear()`, ...), each leaving both batteries at a full green while the gate no
    # longer did anything. Enumerating bad syntax is the same mistake as the raw-text scan it
    # replaced, one level up.
    #
    # These probes ask the only question that matters: does the gate still REJECT the thing it
    # exists to reject? A hollowed gate stops rejecting it, whatever syntax was used, so no
    # enumeration is needed and there is nothing to evade.
    def _fails_on(scenario_name, gate, prepare, restore=None):
        artifact_copy, patch = prepare()
        try:
            rc, failing = guard_result(artifact_copy)
        finally:
            if restore is not None:
                restore(patch)
        tripped = [f for f in failing if str(f).split(" ", 1)[0] == gate]
        rec(f"FZ10-{gate} rejects-what-it-exists-to-reject",
            bool(tripped) and not any(str(f).startswith("<exception") for f in failing),
            f"the REAL {gate} rejects {scenario_name}. This is behavioural, not syntactic: a gate "
            f"hollowed by any means -- constant, trivial read, rebound input, deleted conjunct -- "
            f"stops rejecting it and this fails, so no catalogue of bad syntax has to be maintained",
            level="behavioural gate probe",
            extra={"scenario": scenario_name, "tripped": tripped[:2], "all_failing": failing[:4]})

    # GA50b must reject a DIRTY tracked tree. The tree here is clean, so the measurement the gate
    # performs is intercepted rather than the tree being touched.
    def _dirty_tree():
        import subprocess as _sp

        class _Result:
            returncode = 0
            stdout = " M backend/app/permissions.py\n M backend/app/store.py\n"

        original = GG.subprocess.run

        def fake(cmd, *a, **k):
            if list(cmd[:3]) == ["git", "status", "--porcelain"]:
                return _Result()
            return original(cmd, *a, **k)

        GG.subprocess.run = fake
        return copy.deepcopy(live_artifact()), original

    _fails_on("a dirty tracked worktree", "GA50b", _dirty_tree,
              restore=lambda original: setattr(GG.subprocess, "run", original))

    # GA04k must reject a disclosure that claims the curated prose was verified.
    def _forbidden_disclosure():
        a = copy.deepcopy(live_artifact())
        a["curated_prose_disclosure"] = (
            "This commentary has been independently verified and reviewed by a senior engineer "
            "and may be relied upon as the fuller and more accurate description of the system. "
            "current_disposition_fresh_checkout and blocking_reason are author-supplied and no "
            "guard can verify them; where they disagree the commentary governs.")
        return rehash(a), None

    _fails_on("a disclosure claiming the prose was independently verified", "GA04k",
              _forbidden_disclosure)

    # GA47f must reject a machine-local promotion that no artifact scopes to that control.
    def _unscoped_promotion():
        a = copy.deepcopy(live_artifact())
        target = next(c for c in a["controls"] if c["check_id"] == "ga_postgres_adapter")
        target["current_disposition_verified_environment"] = "PASS"
        # A LIST, matching the shipped shape. As a string this tripped only the `not named` arm and
        # every substantive arm -- named != required, present != required, missing, conjunction --
        # had ZERO coverage: all four could be deleted with both batteries fully green.
        target["verified_promoted_by"] = ["migration-evidence.v1.json"]
        target["verified_promotion_detail"] = {
            "required": ["production-database-adapter-evidence.v1.json"],
            "present": ["production-database-adapter-evidence.v1.json"],
            "missing": [], "conjunction": False}
        tally: dict = {}
        for control in a["controls"]:
            value = control["current_disposition_verified_environment"]
            tally[value] = tally.get(value, 0) + 1
        a["contexts"]["verified_environment_with_evidence"]["tally"] = dict(sorted(tally.items()))
        return rehash(a), None

    _fails_on("the production database adapter promoted on an unrelated artifact's authority",
              "GA47f", _unscoped_promotion)

    # ---------------------------------------------------------------- gate coupling
    # The previous FZ07 asked only ``needle not in guard_src`` -- a substring search over the whole
    # file, so a comment, a docstring, a dead branch or an unused variable satisfied it while the
    # predicate it claimed to pin was ``True``. An exact-head review hollowed GA50b, GA04k and
    # GA47f exactly that way with every needle intact and both batteries stayed green.
    guard_source = (ROOT / "scripts" / "ga_gap_assessment_guard.py").read_text(encoding="utf-8")
    structural = COUPLING.verify_coupling(guard_source)
    rec("FZ07 protected-gates-are-structurally-load-bearing",
        not structural,
        "each protected gate's PREDICATE is parsed from the AST and must be non-constant, must read "
        "the names that make it load-bearing, must be reachable, and must own its check id "
        "uniquely. Only the predicate subtree is inspected, so comments, docstrings and unused "
        "strings are invisible to this check",
        level="structural source check",
        extra={"gates": sorted(COUPLING.PROTECTED_GATES), "problems": structural[:4]})

    # Behavioral half: actually perform each hollowing on an isolated copy of the guard source and
    # require the verifier to catch it. A mutation that fails to PARSE is not counted as detected --
    # that would only prove the mutation was malformed.
    undetected, unparsed, absent = [], [], []
    for name, mutated in sorted(COUPLING.mutations(guard_source).items()):
        if mutated is None:
            absent.append(name)
            continue
        try:
            _ast.parse(mutated)
        except SyntaxError:
            unparsed.append(name)
            continue
        problems = COUPLING.verify_coupling(mutated)
        # Own-gate attribution is REQUIRED, not merely observed: accepting "some problem" is the
        # masking bug that made a mutation look covered because a different gate tripped.
        gate = next((g for g in COUPLING.PROTECTED_GATES if g in name), None)
        if (not problems or any("does not parse" in p for p in problems)
                or (gate and not any(p.startswith(gate) for p in problems))):
            undetected.append(name)
    mutation_total = len(COUPLING.mutations(guard_source))
    gate_set = ",".join(sorted(COUPLING.PROTECTED_GATES))
    rec("FZ08 gate-hollowing-is-behaviorally-detected",
        mutation_total >= 8 and not undetected and not unparsed and not absent,
        "every hollowing of a protected gate -- constant predicate, same-named no-op, unreachable "
        "placement, removal from the emitted inventory, and a duplicated id replacing the real "
        "gate -- is performed for real and detected. Mutations that do not parse, or whose anchor "
        "is missing, are failures rather than silent passes",
        level="structural source check",
        extra={"mutations": mutation_total, "undetected": undetected,
               "did_not_parse": unparsed, "anchor_missing": absent, "gates": gate_set})
    rec("FZ11 protected-gate-set-is-pinned",
        gate_set == PINNED_PROTECTED_GATES and mutation_total == PINNED_COUPLING_MUTATIONS,
        "the protected-gate SET and the mutation count are pinned. Dropping a gate from "
        "PROTECTED_GATES silently removed six mutations while every counter stayed green",
        level="structural source check",
        extra={"gates": gate_set, "mutations": mutation_total})

    # Runtime link: a gate that is structurally sound but never emitted proves nothing.
    emitted_ids = {c["check_id"].split(" ", 1)[0] for c in _emitted_drift_checks()}
    missing_runtime = sorted(set(COUPLING.PROTECTED_GATES) - emitted_ids)
    rec("FZ09 protected-gates-are-actually-emitted",
        not missing_runtime,
        "every protected gate appears in the drift guard's REAL emitted check inventory, closing "
        "the gap between a gate that parses and a gate that runs",
        level="structural source check",
        extra={"missing": missing_runtime, "emitted": len(emitted_ids)})

    guard_src = guard_source
    guard_tree = _ast.parse(guard_src)
    calls_registry_inventory = any(
        isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
        and n.func.attr == "registry_inventory"
        for n in _ast.walk(guard_tree))
    # no module-level literal collection large enough to be a hand-authored control list
    gen_tree = _ast.parse((ROOT / "scripts" / "build_ga_gap_assessment.py")
                          .read_text(encoding="utf-8"))
    gen_reads_registry = any(
        isinstance(n, _ast.FunctionDef) and n.name == "registry_inventory" for n in gen_tree.body)
    # Dicts and comprehensions count too, and the GENERATOR is scanned as well -- the first cut
    # matched only >=20-element List/Tuple/Set in the guard, so a 28-key dict evaded it entirely.
    literal_lists = []
    registry_names = set()
    for entry in json.loads(GEN.REGISTRY_PATH.read_text(encoding="utf-8"))["blockers"]:
        registry_names.add(entry["id"])
        registry_names.add(entry["check_id"])

    def _scan(tree, label):
        """Flag a literal only when its CONTENTS enumerate real control identifiers.

        Size alone is the wrong signal: walking the whole AST correctly found build()'s ~40-key
        payload dict, which is a document template, not an inventory. What matters is whether a
        literal hard-codes the control set, so the strings inside are matched against the real
        registry.
        """
        for node in _ast.walk(tree):
            value = getattr(node, "value", None)
            if isinstance(value, (_ast.List, _ast.Tuple, _ast.Set)):
                items = value.elts
            elif isinstance(value, _ast.Dict):
                items = list(value.keys)
            else:
                continue
            names = {e.value for e in items
                     if isinstance(e, _ast.Constant) and isinstance(e.value, str)}
            overlap = names & registry_names
            if len(overlap) >= 20:
                target = (getattr(node, "targets", [None]) or [None])[0]
                name = (getattr(target, "id", None)
                        or getattr(getattr(node, "target", None), "id", None) or "<anonymous>")
                # _ASSESSMENT is a KNOWN hand-authored 28-key block. It is not an expected-id
                # authority -- GA04e reconciles its keys against the registry -- so it is named
                # here rather than silently tolerated.
                if name != "_ASSESSMENT":
                    literal_lists.append(f"{label}:{name}({len(overlap)} control ids)")

    _scan(guard_tree, "guard")
    _scan(gen_tree, "generator")
    # A textual split was defeatable by re-adding the constant ABOVE the note. Assert instead that
    # no module-level assignment binds such a name at all.
    own_tree = _ast.parse((ROOT / "scripts" / "ga_gap_assessment_faults_guard.py")
                          .read_text(encoding="utf-8"))
    pin_names = set()
    for node in own_tree.body:
        for target in (getattr(node, "targets", []) or
                       ([node.target] if getattr(node, "target", None) else [])):
            name = getattr(target, "id", "")
            if name == "PINNED_ID_SET_HASH":
                pin_names.add(name)
    no_pin_authority = not pin_names
    missing_trip = []
    for mid, expected in sorted(EXPECTED_TRIP.items()):
        tripped = MUTATION_TRIPPED.get(mid)
        if tripped is None:
            missing_trip.append(f"{mid}:NOT-RUN")
        elif not any(str(t).split(" ", 1)[0] == expected for t in tripped):
            missing_trip.append(f"{mid}:expected {expected}, tripped {tripped[:2]}")
    rec("FZ06 mutations-trip-the-gate-they-protect",
        not missing_trip,
        "every mutation with a declared target trips THAT drift check, not merely some check. "
        "Without this a gate could be neutered and its mutation re-bodied to attack a different "
        "field, leaving the gate with zero coverage and every completeness counter green",
        level="structural source check",
        extra={"declared": len(EXPECTED_TRIP), "broken": missing_trip[:5]})

    guard_src = (ROOT / "scripts" / "ga_gap_assessment_guard.py").read_text(encoding="utf-8")
    rec("FZ05 inventory-authority-is-the-registry",
        calls_registry_inventory and gen_reads_registry and not literal_lists and no_pin_authority,
        "the drift guard loads its expected inventory by calling the generator's registry_inventory() "
        "and the generator derives it from the real registry file. The literal scan below is a "
        "tripwire against a single large hand-authored collection, NOT a proof that none can exist: "
        "a review defeated it by splitting one into halves, and the curated _ASSESSMENT block is an "
        "acknowledged 28-key dict reconciled by GA04e instead",
        level="structural source check",
        extra={"guard_calls_registry_inventory": calls_registry_inventory,
               "generator_derives": gen_reads_registry,
               "large_literal_collections": literal_lists})

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
    # "PP" is a legitimate non-mutation prefix: a positive path asserts an ACCEPTANCE, so it is
    # neither an F-gate nor a mutation, and must not be reported as a stray id.
    stray = [c for c in emitted
             if not c.startswith(("F", "PP")) and c[:2] not in MUTATION_PREFIXES]
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
                    # Reported only when the baseline anchor holds: on a broken baseline every
                    # mutation "refuses" vacuously, and the previous cut printed 49 mutations
                    # beside a RED anchor as though that were coverage.
                    "mutations": len(MUTATION_FINGERPRINTS) if all(BASELINE_OK) else 0,
                    "baseline_anchor_holds": bool(BASELINE_OK) and all(BASELINE_OK),
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
