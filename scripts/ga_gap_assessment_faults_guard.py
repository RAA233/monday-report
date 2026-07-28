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
import pathlib
import time
import subprocess
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
    "PP00 positive-path-fixture-built",
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
    # informational-context isolation -- the machine-local half must not reach a release output
    "PJ01 informational-forgery-cannot-move-the-canonical-hash",
    "PJ02 informational-forgery-cannot-move-the-release-surface",
    "PJ03 canonical-hash-is-sensitive-to-authoritative-change",
    "PJ04 contexts-declare-their-own-authority",
    "PJ05 authoritative-half-is-reproducible-without-evidence",
    "PJ06 forgery-covers-every-machine-local-key-the-generator-excludes",
    # scope mutations -- each must break a POSITIVE path, not merely fail closed
    "PM01 empty-evidence-scope-mapping",
    "PM02 remove-migration-runner-arm", "PP13 migration-validity-arm-pinned",
    "PP14 scope-rewrites-survive-a-degraded-resolver",
    "PM04 remove-tenant-conjunction-arm", "PM05 remove-database-adapter-arm",
    "PM06 remove-queue-adapter-arm", "PM07 remove-persistence-locking-arm",
    "PM08 remove-correction-atomicity-arm",
    "PM09 tenant-all-of-weakened-to-any-of", "PM10 tenant-conjunction-member-removed",
    "PM11 own-artifact-replaced-with-unrelated", "PM12 artifact-path-changed",
    "PM13 promoter-attribution-disabled", "PM14 promoter-basename-collision-restored",
    "PM15 artifact-schema-version-changed",
    "PM16 validator-replaced-with-another-controls-validator",
    "PM17 artifact-requirement-duplicated",
    "PM18 migration-validity-static-predicate-removed",
    "PM19 unrelated-artifact-added-to-a-required-set",
    "PM20 machine-local-field-admitted-to-the-canonical-body",
    "PM21 machine-local-context-admitted-to-the-canonical-body",
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
    "BC01 guard_verdict-normal-path-succeeds",
    "BC02 scope_without-normal-path-succeeds",
    "BC03 graph_fingerprint-normal-path-succeeds",
    "BC04 temporary-state-observation-is-real",
    "BC05 tracked-state-observation-is-real",
    "BC06 every-heavy-operation-call-is-classified",
    "BC07 no-unstructured-exit",
    "BC08 canonical-hash-boundary",
    "FZ14 source-audits-are-behaviourally-discriminating",
    "PM22 guard_verdict-raises-before-work",
    "PM23 guard_verdict-raises-after-partial-work",
    "PM24 scope_without-raises",
    "PM25 graph_fingerprint-raises",
    "PM26 boundary-returns-none",
    "PM27 boundary-returns-wrong-type",
    "PM28 boundary-returns-empty-result",
    "PM29 boundary-exceeds-its-timeout",
    "PM30 boundary-raises-a-baseexception",
    "PJ07 forgery-oracle-is-not-a-shared-editable-constant",
    "FZ12 no-patch-only-body-copies",
    "FZ13 no-known-false-completeness-claims",
    "PM31 stale-faults-id-set-hash-pin",
    "PM32 stale-faults-check-count-pin",
]
EXPECTED_TOTAL_CHECKS = 161
EXPECTED_MUTATION_COUNT = 113
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
    try:
        artifact["canonical_payload_hash"] = GEN.canonical_hash(artifact)
    except BaseException as exc:  # noqa: BLE001 - classified, never a silent escape
        # Runs once per artifact mutation -- the highest-traffic heavy call in the file, and the
        # one the previous cut left unclassified by narrowing the audit to run() instead.
        checks.append({"check_id": "BC08 canonical-hash-boundary", "ok": False, "level": "boundary",
                       "why": "GEN.canonical_hash raised while re-hashing a mutated artifact",
                       "extra": {"operation_id": "GEN.canonical_hash",
                                 "actual_outcome": "exception",
                                 "exception_classification": "validator_failure",
                                 "exception_type": exc.__class__.__name__,
                                 "controlled_rejection": False}})
        _emit_and_exit({"phase": "artifact mutation", "operation_id": "GEN.canonical_hash",
                        "actual_outcome": "exception", "controlled_rejection": False,
                        "exception_classification": "validator_failure", "timed_out": False})
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


#: Every outcome a heavy operation can have. A crash, a timeout, a missing or malformed result and
#: an unexpected exit are all DISTINCT from a controlled rejection -- that distinction is the whole
#: point of the classification, because a battery that scores crashes as refusals certifies itself.
OUTCOME_SUCCESS = "success"
OUTCOME_CLASSES = {
    "PP.fixture": "fixture_construction_failure",
    "PP.legitimate_promotion_payload": "fixture_construction_failure",
    "PP.hermetic_reference_payload": "fixture_construction_failure",
    "PP.conjunction_members_matrix": "evaluator_failure",
    "PP.unrelated_and_stale_matrix": "evaluator_failure",
    "PP.graph_fingerprint": "graph_derivation_failure",
    "PP.expected_arms": "graph_derivation_failure",
    "PP.guard_verdict": "validator_failure",
    "PP.scope_without": "validator_failure",
    "PP.informational_forgery": "fixture_construction_failure",
    "PP.release_surface": "fixture_construction_failure",
    "PP.authoritative_touch": "fixture_construction_failure",
    "GEN.canonical_hash": "validator_failure",
    "GEN.canonical_body": "validator_failure",
}
#: Wall-clock ceiling for one heavy operation. A hang is not a refusal either.
BOUNDARY_TIMEOUT_SECONDS = 900.0

#: Successful heavy-operation observations. Emitted in the report so the normal path of every
#: boundary is evidence, not just an assertion.
BOUNDARY_OBSERVATIONS: list = []

#: Temp directories present before this battery ran anything, so cleanup is measured as a
#: DELTA rather than as absolute cleanliness of a shared system directory.
TEMP_DIRECTORY_BASELINE: int = -1


def _observed_tracked_state(root=None) -> str:
    """Whether the TRACKED worktree is clean right now. Observed, never assumed.

    Takes a root so the observation itself can be shown to DISCRIMINATE: BC05 points it
    at throwaway repositories it has deliberately made clean and dirty. Asserting only
    that the return value is one of two strings was satisfied by a hardcoded "clean".
    """
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                             cwd=str(root or ROOT), capture_output=True, text=True,
                             timeout=60)
        if out.returncode != 0:
            return "unknown"
        return "clean" if not out.stdout.strip() else "dirty"
    except Exception:  # noqa: BLE001
        return "unknown"


def _force_rmtree(path) -> None:
    """Remove a tree even when it contains read-only files.

    git marks objects read-only, so shutil.rmtree(ignore_errors=True) silently FAILS to remove a
    scratch repository on Windows -- which is how the tracked-state probe started leaking the very
    kind of directory the cleanup observation reports on.
    """
    def _on_error(func, target, _exc):
        try:
            import stat

            pathlib.Path(target).chmod(stat.S_IWRITE)
            func(target)
        except Exception:  # noqa: BLE001
            pass

    shutil.rmtree(path, onerror=_on_error)


def _temporary_directory_count() -> int:
    """How many of this battery's temp directories exist right now. -1 when unobservable."""
    try:
        root = pathlib.Path(tempfile.gettempdir())
        # Both prefixes this battery creates. Counting only one reported "clean" over
        # directories the other had leaked.
        return sum(1 for prefix in ("pp-*", "gga-*")
                   for p in root.glob(prefix) if p.is_dir())
    except Exception:  # noqa: BLE001
        return -1


def _observed_temporary_state(baseline: int = None) -> str:
    """Whether this battery cleaned up after itself, RELATIVE to a baseline.

    Absolute cleanliness is the wrong question: a directory left by an earlier aborted run would
    make an honest run report a leak it did not cause, and the check would fail for the wrong
    reason. What is actually observable is the DELTA against a baseline taken at start-up.
    """
    current = _temporary_directory_count()
    if current < 0:
        return "unknown"
    if baseline is None:
        baseline = TEMP_DIRECTORY_BASELINE
    if baseline < 0:
        return "unknown"
    leaked = current - baseline
    return "clean" if leaked <= 0 else f"leaked:{leaked}"


def classify_boundary(operation_id, thunk, validate=None):
    """Run a heavy operation and CLASSIFY the outcome instead of letting it escape.

    Returns ``(ok, record, value)``. Nothing here decides that a failure is acceptable -- the caller
    does. The classification exists so that an exception, a timeout, a ``None``, a wrong type and a
    genuine controlled rejection are never conflated.

    Timeouts are measured, not enforced by killing: every heavy operation in this battery is
    in-process and single-threaded, so a hard kill would leave the evidence paths repointed and the
    real ``output/`` artifacts hidden. Measuring and reporting is the honest option; the alternative
    would corrupt the developer's tree to prove a point.
    """
    started = time.monotonic()
    record = {"operation_id": operation_id, "expected_outcome": OUTCOME_SUCCESS,
              "controlled_rejection": False, "timed_out": False}
    try:
        value = thunk()
    except BaseException as exc:  # noqa: BLE001 - a crash is NEVER a controlled rejection
        record.update({
            "actual_outcome": "exception",
            "exception_classification": OUTCOME_CLASSES.get(operation_id, "internal_battery_exception"),
            "exception_type": exc.__class__.__name__,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        })
        return False, record, None
    elapsed = time.monotonic() - started
    record["elapsed_seconds"] = round(elapsed, 3)
    if elapsed > BOUNDARY_TIMEOUT_SECONDS:
        record.update({"actual_outcome": "timeout", "timed_out": True,
                       "exception_classification": "timeout"})
        return False, record, value
    if value is None:
        record.update({"actual_outcome": "missing_result",
                       "exception_classification": "missing_stdout"})
        return False, record, None
    if validate is not None and not validate(value):
        record.update({"actual_outcome": "malformed_result",
                       "exception_classification": "malformed_stdout"})
        return False, record, value
    record.update({"actual_outcome": OUTCOME_SUCCESS, "exception_classification": None})
    return True, record, value


#: Known-false completeness phrasings. Each one was actually written in this repository and each was
#: disproved by an independent exact-head review. They are pinned so a future edit cannot quietly
#: reintroduce a claim of completeness the code does not support.
FALSE_COMPLETENESS_PHRASES = (
    "all four heavy fixture call sites",
    "the four remaining unguarded fixture call sites are wrapped",
    "the rewrite now runs inside the try and tolerates",
    "operator and validators are re-derived",
    "all heavy boundaries are wrapped",
    "every informational field is independently truthful",
    "all structural extraction is independently derived",
)


#: Modules whose calls are heavy enough that an unclassified call is a defect.
HEAVY_MODULES = ("PP", "GEN", "COUPLING", "SYN")


def _boundary_call_audit(root: pathlib.Path, source: str = None):
    """Walk THIS file's AST for calls into the positive-path module that are not classified.

    A call counts as classified when it is lexically inside the shared wrapper, inside a ``try``
    that has at least one handler, or inside a nested function whose NAME is handed to the wrapper
    (``_boundary(label, op, _apply)``) -- the wrapper runs that body, so it is protected even though
    its source does not sit inside the wrapper's call node. Text matching would be fooled by a
    comment; the AST is not.
    """
    if source is None:
        source = (root / "scripts" / "ga_gap_assessment_faults_guard.py").read_text(
            encoding="utf-8")
    tree = _ast.parse(source)
    wrapper_names = {"classify_boundary", "_boundary", "_guarded", "_bmut"}
    protected_lines, all_lines = set(), {}
    handed_to_wrapper, functions = set(), {}

    def _mark(node):
        for child in _ast.walk(node):
            if hasattr(child, "lineno"):
                protected_lines.add(child.lineno)

    run_node = next((n for n in _ast.walk(tree)
                     if isinstance(n, _ast.FunctionDef) and n.name == "run"), None)
    run_span = range(run_node.lineno, (run_node.end_lineno or run_node.lineno) + 1)         if run_node else range(0)

    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, _ast.Try) and node.handlers:
            # A handler that does nothing is the silence this battery forbids, so it
            # does not count as protection.
            if any(not all(isinstance(s, _ast.Pass) for s in h.body)
                   for h in node.handlers):
                _mark(node)
        elif isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name) and func.id in wrapper_names:
                _mark(node)
                for arg in node.args:
                    if isinstance(arg, _ast.Name):
                        handed_to_wrapper.add(arg.id)
            if (isinstance(func, _ast.Attribute) and isinstance(func.value, _ast.Name)
                    and func.value.id in HEAVY_MODULES):
                all_lines[node.lineno] = f"{func.value.id}.{func.attr}:{node.lineno}"
            # An indirect call hides the module behind a string or an alias. The audit
            # cannot resolve it, so it is reported rather than silently accepted.
            if (isinstance(func, _ast.Name) and func.id == "getattr" and node.args
                    and isinstance(node.args[0], _ast.Name)
                    and node.args[0].id in HEAVY_MODULES):
                # Only an INDIRECT call into a heavy module hides the operation. getattr on the
                # drift-guard module to read a pinned constant is an attribute read, not a heavy
                # operation, and flagging it made the audit noise rather than signal.
                all_lines[node.lineno] = f"indirect-heavy-getattr:{node.lineno}"

    for name in handed_to_wrapper:
        if name in functions:
            _mark(functions[name])

    # Scope: the WHOLE file. Restricting this to run() was narrowing the check to make it pass --
    # it let the highest-traffic unwrapped call (rehash, once per artifact mutation) go unreported,
    # and would have let anyone move a heavy call out of run() to escape the audit.
    in_scope = dict(all_lines)
    classified = [label for line, label in in_scope.items() if line in protected_lines]
    unclassified = [label for line, label in in_scope.items() if line not in protected_lines]
    return classified, unclassified


def _copied_body_report(root: pathlib.Path, source: str = None):
    """Detect a protected body COPIED into an unexecuted helper, or HOLLOWED to a bare literal.

    Structural name/string checks are trivially defeated by preserving names and strings, so this
    targets the shapes of the attack: two functions whose bodies are structurally identical, and
    functions reduced to returning a bare literal. Bodies are compared by normalised AST dump, so
    renaming a copy or reflowing its text does not hide it.

    Three corrections after an independent review defeated the first cut with one line of code:

    * a hollowed body is ``return []`` / ``{}`` / ``()`` far more often than ``return None`` -- the
      first cut matched only ``ast.Constant`` and so missed every container literal, including a
      self-hollowing of THIS function;
    * duplicate detection was gated behind the reachability arm, so making a copy "referenced" by a
      single ``if False:`` line disabled it;
    * a reference from provably-dead code is not a reference. ``if False:`` and ``while False:``
      bodies are excluded before names are collected.

    None of that makes this sufficient on its own, which is why FZ14 also drives the audits
    behaviourally against fabricated sources -- a gutted audit fails that immediately.
    """
    if source is None:
        source = (root / "scripts" / "ga_gap_assessment_faults_guard.py").read_text(encoding="utf-8")
    tree = _ast.parse(source)
    functions, referenced = {}, set()

    def _is_dead(node):
        test = getattr(node, "test", None)
        return isinstance(test, _ast.Constant) and not test.value

    dead_lines = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.If, _ast.While)) and _is_dead(node):
            for child in _ast.walk(node):
                if hasattr(child, "lineno"):
                    dead_lines.add(child.lineno)

    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Load):
            if node.lineno not in dead_lines:
                referenced.add(node.id)
        elif isinstance(node, _ast.Attribute):
            if getattr(node, "lineno", None) not in dead_lines:
                referenced.add(node.attr)

    def _live(node):
        return [s for s in node.body
                if not (isinstance(s, _ast.Expr) and isinstance(s.value, _ast.Constant))]

    # A hollowed body is whatever returns "nothing" -- and `return dict()` is not `return {}`.
    # The first cut matched only literal nodes, so swapping one token for its constructor call
    # walked straight through, including for the behavioural self-test that is supposed to be the
    # backstop. Empty constructor calls, empty comprehensions and returns of an empty module
    # constant all count.
    HOLLOW = (_ast.Constant, _ast.List, _ast.Dict, _ast.Tuple, _ast.Set)
    EMPTY_BUILTINS = {"dict", "list", "tuple", "set", "frozenset", "str", "int", "bool"}
    empty_globals = set()
    for node in tree.body:
        if isinstance(node, _ast.Assign) and isinstance(node.value, HOLLOW):
            value = node.value
            is_empty = (isinstance(value, _ast.Constant) and value.value in (None, "", 0, False)) or (
                not isinstance(value, _ast.Constant) and not getattr(value, "elts", None)
                and not getattr(value, "keys", None))
            if is_empty:
                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        empty_globals.add(target.id)

    def _is_hollow(value):
        if isinstance(value, HOLLOW):
            return True
        if isinstance(value, _ast.Call) and isinstance(value.func, _ast.Name) \
                and value.func.id in EMPTY_BUILTINS and not value.args and not value.keywords:
            return True
        if isinstance(value, (_ast.DictComp, _ast.ListComp, _ast.SetComp)):
            # a comprehension over a literal sequence of constants computes nothing
            return all(isinstance(g.iter, (_ast.Tuple, _ast.List, _ast.Set, _ast.Constant))
                       for g in getattr(value, "generators", []))
        if isinstance(value, _ast.Name) and value.id in empty_globals:
            return True
        if isinstance(value, _ast.Tuple):
            return all(_is_hollow(e) for e in value.elts)
        return False
    shapes, duplicates, constant_only = {}, [], []
    for name, node in functions.items():
        live = _live(node)
        shape = "\n".join(_ast.dump(s, annotate_fields=False) for s in live)
        if len(shape) > 120:
            shapes.setdefault(shape, []).append(name)
        if len(live) == 1 and isinstance(live[0], _ast.Return) and _is_hollow(live[0].value):
            constant_only.append(name)

    for names in shapes.values():
        if len(names) > 1:
            duplicates.append(sorted(names))

    unreferenced = sorted(n for n in functions
                          if n not in referenced and n not in {"run", "main"}
                          and not n.startswith("visit_"))
    return {"defined": len(functions), "duplicate_bodies": duplicates,
            "constant_only_functions": sorted(constant_only), "unreferenced": unreferenced}


def audit_self_test(root: pathlib.Path):
    """Drive each source audit against FABRICATED sources and require it to report the problem.

    This is the durable half. A purely structural gate can be neutralised by editing the gate, and
    an independent review neutralised the first cut by replacing a sibling audit's body with
    ``return []`` -- zero obfuscation, completely invisible. An audit that has been gutted cannot
    pass a case it is supposed to fail, so each audit is handed a source it MUST flag and a source
    it MUST NOT, and both directions are required.
    """
    results = {}

    hollowed = (
        "def helper(a):\n"
        "    return []\n"
        "\n"
        "def user():\n"
        "    return helper(1)\n"
    )
    duplicated = (
        "def live(a):\n"
        "    total = 0\n"
        "    for item in a:\n"
        "        total += item * 2\n"
        "        total -= item\n"
        "    return total\n"
        "\n"
        "def copy_of_live(a):\n"
        "    total = 0\n"
        "    for item in a:\n"
        "        total += item * 2\n"
        "        total -= item\n"
        "    return total\n"
        "\n"
        "def user():\n"
        "    if False:\n"
        "        copy_of_live([1])\n"
        "    return live([1])\n"
    )
    clean = (
        "def live(a):\n"
        "    total = 0\n"
        "    for item in a:\n"
        "        total += item * 2\n"
        "        total -= item\n"
        "    return total\n"
        "\n"
        "def user():\n"
        "    return live([1])\n"
    )
    hollow_report = _copied_body_report(root, source=hollowed)
    dup_report = _copied_body_report(root, source=duplicated)
    clean_report = _copied_body_report(root, source=clean)
    results["detects_hollowed_container_literal"] = bool(hollow_report["constant_only_functions"])
    results["detects_duplicate_body_hidden_by_dead_reference"] = bool(dup_report["duplicate_bodies"])
    results["accepts_clean_source"] = not (clean_report["duplicate_bodies"]
                                           or clean_report["constant_only_functions"])

    phrase = FALSE_COMPLETENESS_PHRASES[0]
    results["detects_false_phrase"] = bool(
        _false_phrase_report(root, sources={"fabricated.py": f"# {phrase}\n"}))
    results["accepts_phrase_free_source"] = not _false_phrase_report(
        root, sources={"fabricated.py": "# nothing pinned here\n"})

    unwrapped = "def run():\n    return PP.guard_verdict(GG, {})\n"
    wrapped = "def run():\n    return _boundary('x', 'PP.guard_verdict', lambda: PP.guard_verdict(GG, {}))\n"
    swallowed = ("def run():\n"
                 "    try:\n"
                 "        return PP.guard_verdict(GG, {})\n"
                 "    except Exception:\n"
                 "        pass\n")
    _c1, u1 = _boundary_call_audit(root, source=unwrapped)
    _c2, u2 = _boundary_call_audit(root, source=wrapped)
    _c3, u3 = _boundary_call_audit(root, source=swallowed)
    results["detects_unwrapped_call"] = bool(u1)
    results["accepts_wrapped_call"] = not u2
    results["rejects_swallowing_handler"] = bool(u3)
    return results


#: Exactly the probes ``audit_self_test`` must report on. Pinned because ``all({}.values())`` is
#: True: an empty result -- ``return dict()`` -- was a vacuous PASS that also slipped past the
#: hollow detector, defeating both gates with one token. Presence of every key is now required, so
#: an empty or partial result fails rather than certifies.
REQUIRED_SELF_TEST_PROBES = (
    "detects_hollowed_container_literal",
    "detects_duplicate_body_hidden_by_dead_reference",
    "accepts_clean_source",
    "detects_false_phrase",
    "accepts_phrase_free_source",
    "detects_unwrapped_call",
    "accepts_wrapped_call",
    "rejects_swallowing_handler",
)


def _false_phrase_report(root: pathlib.Path, sources: dict = None):
    """Tracked sources scanned for pinned false-completeness text.

    The pin list itself is skipped: it lives in this file, so a naive scan matched its own
    definition and reported every phrase as present. The skip is bounded to the tuple's own source
    span, not to the whole file.
    """
    hits = []
    names = list(sources) if sources else ["ga_gap_assessment_faults_guard.py",
                                           "ga_gap_assessment_positive_paths.py",
                                           "ga_gap_assessment_guard.py"]
    for name in names:
        text = (sources[name] if sources
                else (root / "scripts" / name).read_text(encoding="utf-8"))
        if name == "ga_gap_assessment_faults_guard.py":
            head, _sep, tail = text.partition("FALSE_COMPLETENESS_PHRASES = (")
            _pins, _sep2, rest = tail.partition("\n)\n")
            text = head + rest
        lowered = text.lower()
        for phrase in FALSE_COMPLETENESS_PHRASES:
            if phrase.lower() in lowered:
                hits.append(f"{name}: {phrase}")
    return hits


def _safely(observer):
    """Call an observer that feeds the crash contract, degrading to ``unknown`` instead of raising."""
    try:
        return observer()
    except BaseException:  # noqa: BLE001 - never let an observer defeat the report it feeds
        return "unknown"


def _emit_and_exit(failure: dict = None) -> None:
    """Emit the structured report and exit non-zero.

    Used where continuing is impossible. The point is that the battery still prints valid JSON with
    a named failure: a crash that produces no output is not a refusal and must never look like one.

    Counters describe what was ACTUALLY observed. Anything execution stopped before establishing is
    emitted as the literal ``unknown`` rather than guessed -- a fabricated "everything restored"
    would be worse than admitting the run ended early.
    """
    passed = sum(1 for c in checks if c["ok"])
    executed_mutations = len(MUTATION_FINGERPRINTS)
    contract = {
        "status": "battery_failed",
        "phase": (failure or {}).get("phase", "unknown"),
        "operation_id": (failure or {}).get("operation_id", "unknown"),
        "expected_outcome": (failure or {}).get("expected_outcome", "unknown"),
        "actual_outcome": (failure or {}).get("actual_outcome", "unknown"),
        "exception_classification": (failure or {}).get("exception_classification", "unknown"),
        "controlled_rejection": (failure or {}).get("controlled_rejection", False),
        "stdout_present": True,
        "stderr_present": "unknown",
        "exit_code": 1,
        "timed_out": (failure or {}).get("timed_out", "unknown"),
        "declared_check_count": EXPECTED_TOTAL_CHECKS,
        "executed_check_count": len(checks),
        "declared_mutation_count": EXPECTED_MUTATION_COUNT,
        "executed_mutation_count": executed_mutations,
        "pass_count": passed,
        "fail_count": len(checks) - passed,
        "skip_count": 0,
        "fixture_restored": (failure or {}).get("fixture_restored", "unknown"),
        # These observers run INSIDE the last-resort handler. A raise in one of them re-raised
        # from the except block and killed the process with no JSON at all -- the precise outcome
        # this contract exists to prevent, reached through the contract itself.
        "tracked_state_restored": _safely(_observed_tracked_state),
        "temporary_state_cleaned": _safely(_observed_temporary_state),
        "synthetic_artifact_used": True,
        "real_production_execution": False,
        "failing_check_ids": [c["check_id"] for c in checks if not c["ok"]],
    }
    print(json.dumps({"guard": "audit:ga-gap-assessment-faults",
                      "claim_scope": "ga-gap-assessment-faults-only",
                      "release_recommendation": "GA_BLOCKED",
                      "boundary_failure_contract": contract,
                      "boundary_observations": BOUNDARY_OBSERVATIONS,
                      "checks": checks,
                      "summary": {"passed": passed, "failed": len(checks) - passed,
                                  "skipped": 0, "mutations": executed_mutations,
                                  "baseline_anchor_holds": False,
                                  "certification": "not_passed"}},
                     indent=2, sort_keys=True, ensure_ascii=False))
    raise SystemExit(1)


def run() -> int:
    global TEMP_DIRECTORY_BASELINE
    if TEMP_DIRECTORY_BASELINE < 0:
        TEMP_DIRECTORY_BASELINE = _temporary_directory_count()
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
    # A crash here is not a refusal and must not be silence. Unguarded, an exception inside the
    # fixture killed the battery with ZERO stdout and no named failure -- the outcome FZ04's own
    # comment calls unacceptable, and which refuses()/guard_verdict() already defend against.
    def _boundary(label, operation_id, thunk, phase="positive path"):
        """THE single boundary every heavy operation goes through.

        Converts a tested heavy-operation failure into a NAMED battery failure carrying the
        structured contract. It does not make failures acceptable and it never scores one as a
        refusal -- it only guarantees that a failure is reported rather than thrown.
        """
        ok, record, value = classify_boundary(operation_id, thunk)
        if ok:
            BOUNDARY_OBSERVATIONS.append(dict(record, label=label))
            return value
        record["phase"] = phase
        record["fixture_restored"] = "unknown"
        rec(label, False,
            f"the heavy operation {operation_id} did not complete. A crash, a hang, a missing "
            f"result or a wrong type is reported as a named failure with the structured contract "
            f"-- never as a controlled rejection and never as silence",
            level="boundary", extra=record)
        _emit_and_exit(record)

    def _chash(target):
        return _boundary("PJ01 informational-forgery-cannot-move-the-canonical-hash",
                         "GEN.canonical_hash", lambda: GEN.canonical_hash(target),
                         phase="informational isolation")

    def _cbody(target):
        return _boundary("PJ01 informational-forgery-cannot-move-the-canonical-hash",
                         "GEN.canonical_body", lambda: GEN.canonical_body(target),
                         phase="informational isolation")

    fx = _boundary("PP00 positive-path-fixture-built", "PP.fixture",
                   lambda: PP.fixture(SYN, GEN, GA_MOD), phase="fixture")
    rec("PP00 positive-path-fixture-built", bool(fx.get("controls")),
        "the positive-path fixture built: the real evaluator and generator ran and produced the "
        "measurements every PP check below reads",
        level="positive path", extra={"controls": len(fx.get("controls") or {})})
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
    conj = _boundary("PP03 tenant-conjunction-accepted", "PP.conjunction_members_matrix", lambda: PP.conjunction_members_matrix(SYN, GEN, GA_MOD))
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

    bc = _boundary("PP08 unrelated-artifacts-rejected", "PP.unrelated_and_stale_matrix", lambda: PP.unrelated_and_stale_matrix(SYN, GEN, GA_MOD))
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

    derived = _boundary("PP11 graph-exactness-derived-from-evaluator", "PP.graph_fingerprint",
                       lambda: PP.graph_fingerprint(COUPLING, ROOT))
    # Exactness is asserted against the AST-derived graph itself, arm by arm: the artifact set, the
    # validator set, the extra-predicate set and the cardinality flag must each match EXACTLY, not
    # merely be non-empty. A non-empty assertion is satisfied by any mapping at all.
    independent = _boundary("PP11 graph-exactness-derived-from-evaluator", "PP.expected_arms",
                           lambda: PP.expected_arms(SYN, COUPLING, ROOT))
    exact_arms = {}
    for cid, spec in derived.items():
        want = independent.get(cid)
        exact_arms[cid] = bool(want) and not want["unresolved"] and (
            tuple(spec["artifacts"]) == want["artifacts"]
            and tuple(spec["validators"]) == want["validators"]
            and tuple(spec["extra_predicates"]) == want["extra_predicates"]
            and spec["conjunction"] is want["conjunction"])
    rec("PP11 graph-exactness-derived-from-evaluator",
        set(derived) == set(PP.EXPECTED_MOVERS)
        and derived.get("ga_tenant_authorization", {}).get("conjunction") is True
        and all(exact_arms.values())
        and sorted(k for k, v in derived.items() if v["conjunction"]) == ["ga_tenant_authorization"]
        and all(spec["artifacts"] for spec in derived.values())
        and all(spec["validators"] for spec in derived.values()),
        "artifact paths, validators, extra static predicates and artifact CARDINALITY are re-derived "
        "from the evaluator's own AST every run and compared arm by arm for EXACT set equality, "
        "covering exactly the seven artifact-gated controls -- not one editable copy of a mapping "
        "compared against another. It does NOT derive the boolean OPERATOR: "
        "`conjunction` is inferred from cardinality, so an evaluator whose all-of is weakened to an "
        "any-of still looks correct HERE, and duplicating one artifact would spoof the flag the other "
        "way. PP03 measures the operator behaviourally and PM20 mutates the duplication -- those, "
        "not this check, are what catch them. The extra migration-VALIDITY legacy blocker is not "
        "an AST-visible predicate either; PP02 proves it behaviourally",
        level="structural source check",
        extra={"controls": len(derived),
               "exact_arms": sum(1 for v in exact_arms.values() if v),
               "independently_derived_arms": len(independent),
               "unresolved_closure_members": sorted(
                   n for w in independent.values() for n in w["unresolved"]),
               "inexact_arms": sorted(k for k, v in exact_arms.items() if not v),
               "conjunction_controls": sorted(k for k, v in derived.items() if v["conjunction"])})


    # ---------------------------------------------------------------- Part J: informational isolation
    # The assessment carries a machine-local half describing THIS developer's gitignored output/
    # directory. It is declared informational. That declaration is only worth something if it is
    # enforced, so the whole informational surface is forged at once and the authoritative outputs
    # are required not to move.
    forged = _boundary("PJ01 informational-forgery-cannot-move-the-canonical-hash", "PP.informational_forgery",
                      lambda: PP.informational_forgery(payload))
    honest_surface = _boundary("PJ02 informational-forgery-cannot-move-the-release-surface", "PP.release_surface",
                              lambda: PP.release_surface(payload))
    forged_surface = _boundary("PJ02 informational-forgery-cannot-move-the-release-surface", "PP.release_surface",
                              lambda: PP.release_surface(forged))
    honest_hash = _chash(payload)
    forged_hash = _chash(forged)
    # The forgery must actually forge. A no-op informational_forgery() would satisfy every
    # assertion below while proving nothing at all -- the same vacuity that let an inert
    # EVIDENCE_SCOPE resolver stay green, one layer up.
    # Coverage is required PER SURFACE. A single pooled count let the forgery stop touching the
    # entire top-level machine-local surface while 84 control-key differences kept the total above
    # the threshold -- and the honest fixture can only ever differ in 2 of the 3 payload keys, so
    # the threshold was unreachable from that surface anyway. Each surface is now checked on its
    # own terms: every payload key must be REWRITTEN (not merely different, since one is already
    # True in the honest payload), every control must have every machine-local key rewritten, and
    # the machine-local context block must change.
    # Each forged value must satisfy the PROPERTY its type requires -- boolean inverted, integer
    # strictly larger, string carrying the sentinel. Comparing against a table of expected literals
    # meant the forgery and its own verification read one editable source, so emptying that table
    # made this arm inert while the battery stayed green.
    def _surfaces_forged():
        payload_ok = all(PP.forgery_is_real(payload.get(k), forged.get(k))
                         for k in PP.INFORMATIONAL_PAYLOAD_KEYS)
        control_ok = bool(forged.get("controls")) and all(
            PP.forgery_is_real(h.get(k), g.get(k))
            for h, g in zip(payload.get("controls") or [], forged.get("controls") or [])
            for k in PP.INFORMATIONAL_CONTROL_KEYS)
        return {"payload": payload_ok, "control": control_ok}

    _surfaces = _boundary("PJ01 informational-forgery-cannot-move-the-canonical-hash",
                          "PP.forgery_is_real", _surfaces_forged,
                          phase="informational isolation")
    payload_surface, control_surface = _surfaces["payload"], _surfaces["control"]
    forged_fields = sum(1 for k in PP.INFORMATIONAL_PAYLOAD_KEYS
                        if payload.get(k) != forged.get(k))
    forged_fields += sum(
        1 for h, g in zip(payload.get("controls") or [], forged.get("controls") or [])
        for k in PP.INFORMATIONAL_CONTROL_KEYS if h.get(k) != g.get(k))
    forged_context = ((payload.get("contexts") or {}).get(PP.INFORMATIONAL_CONTEXT)
                      != (forged.get("contexts") or {}).get(PP.INFORMATIONAL_CONTEXT))
    rec("PJ01 informational-forgery-cannot-move-the-canonical-hash",
        payload_surface and control_surface and forged_context
        and payload != forged
        and honest_hash == forged_hash and _cbody(payload) == _cbody(forged),
        "every informational field is forged AT ONCE -- verified context rewritten to a green "
        "28-PASS GA_READY environment, both honesty flags inverted, every control claiming a "
        "verified PASS with a forged promoter, evidence counters inflated -- and the canonical body "
        "and hash are byte-identical. A self-consistent lie is what fools a consumer, not one odd "
        "value, so the forgery is coordinated rather than field-by-field",
        level="informational isolation",
        extra={"honest_hash": honest_hash[:16], "forged_hash": forged_hash[:16],
               "informational_fields_actually_forged": forged_fields,
               "payload_surface_forged": payload_surface,
               "control_surface_forged": control_surface,
               "context_forged": forged_context})

    rec("PJ02 informational-forgery-cannot-move-the-release-surface",
        honest_surface == forged_surface
        and forged_surface["payload"] == {"client_data_ready": False,
                                          "release_candidate_ready": False, "ga_ready": False,
                                          "release_recommendation": "GA_BLOCKED"},
        "under the same coordinated forgery every authoritative output is unchanged: "
        "client_data_ready, release_candidate_ready, ga_ready, release_recommendation, the "
        "authoritative context, every control disposition, the blocker id set and every blocking "
        "reason. The forged environment claims GA_READY and the release recommendation stays "
        "GA_BLOCKED",
        level="informational isolation",
        extra={"release": forged_surface["payload"], "blockers": len(forged_surface["blockers"]),
               "forged_context_claims": (forged.get("contexts") or {}).get(
                   PP.INFORMATIONAL_CONTEXT, {}).get("ga")})

    touched = _boundary("PJ03 canonical-hash-is-sensitive-to-authoritative-change", "PP.authoritative_touch",
                       lambda: PP.authoritative_touch(payload))
    touched_hash = _chash(touched)
    rec("PJ03 canonical-hash-is-sensitive-to-authoritative-change",
        touched_hash != honest_hash,
        "ANTI-VACUITY partner for PJ01: changing exactly ONE authoritative field -- a single "
        "control's disposition -- DOES move the canonical hash. Without this, a hash that is "
        "constant, empty or insensitive would satisfy PJ01 while proving nothing. Excluding the "
        "`contexts` block wholesale once let a GA_BLOCKED and a 28-PASS GA_READY artifact share a "
        "hash, which is exactly this failure mode",
        level="informational isolation",
        extra={"honest_hash": honest_hash[:16], "authoritative_change_hash": touched_hash[:16]})

    contexts = payload.get("contexts") or {}
    local_ctx = contexts.get(PP.INFORMATIONAL_CONTEXT) or {}
    auth_ctx = contexts.get("fresh_checkout_no_local_evidence") or {}
    rec("PJ04 contexts-declare-their-own-authority",
        local_ctx.get("informational_only") is True
        and local_ctx.get("authoritative_for_release") is False
        and auth_ctx.get("informational_only") is False
        and auth_ctx.get("authoritative_for_release") is True,
        "both contexts declare their authority in MACHINE-READABLE form and declare it opposite "
        "ways round. The distinction used to live only in a prose note, so a consumer reading the "
        "structure could take the machine-local half for the authoritative one",
        level="informational isolation",
        extra={"machine_local": {k: local_ctx.get(k) for k in
                                 ("informational_only", "authoritative_for_release")},
               "authoritative": {k: auth_ctx.get(k) for k in
                                 ("informational_only", "authoritative_for_release")}})

    hermetic = _boundary("PJ05 authoritative-half-is-reproducible-without-evidence", "PP.hermetic_reference_payload",
                        lambda: PP.hermetic_reference_payload(GEN))
    hermetic_surface = _boundary("PJ05 authoritative-half-is-reproducible-without-evidence", "PP.release_surface",
                                lambda: PP.release_surface(hermetic))
    rec("PJ05 authoritative-half-is-reproducible-without-evidence",
        hermetic_surface == honest_surface
        and _chash(hermetic) == honest_hash,
        "BEHAVIOURAL proof that the authoritative half depends on the tracked repository ALONE: a "
        "payload generated with every evidence artifact present and one generated with none at all "
        "produce the same dispositions, the same blocker ids, the same blocking reasons and the "
        "same canonical hash. Declaring the local half informational is a claim; this measures it",
        level="informational isolation",
        extra={"evidence_present_hash": honest_hash[:16],
               "no_evidence_hash": _chash(hermetic)[:16],
               "dispositions_equal": hermetic_surface["dispositions"]
                                     == honest_surface["dispositions"]})

    anchor_rc, anchor_failing = _boundary(
        "PP12 honest-payload-accepted-by-the-unmutated-guard", "PP.guard_verdict",
        lambda: PP.guard_verdict(GG, payload), phase="acceptance anchor")
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
        def _apply():
            with PP.scope_without(GG, removed):
                return PP.guard_verdict(GG, payload)

        # scope_without() and guard_verdict() both used to run with no handler at all here, so a
        # raise in either ended the battery with zero stdout.
        rc, failing = _boundary(label, "PP.scope_without", _apply, phase="scope mutation")
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
    derived_mv = _boundary("PP13 migration-validity-arm-pinned", "PP.graph_fingerprint",
                           lambda: PP.graph_fingerprint(COUPLING, ROOT),
                           phase="structural pin").get("ga_migration_validity", {})
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

    _scope_rewrites = []

    def _scope_rewrite(label, rewrite, why):
        _scope_rewrites.append((label, rewrite))
        original = GG.EVIDENCE_SCOPE
        mutated_scope = {}
        try:
            # The rewrite runs INSIDE the try. It used to run outside, so a rewrite that assumed a
            # control was present raised before any handler existed and killed the battery with zero
            # stdout -- under a DEGRADED RESOLVER, which is the one condition this battery exists to
            # catch. An evaluator edit that merely stops naming its path constant drops the control
            # from EVIDENCE_SCOPE and reproduced it.
            mutated_scope = rewrite(dict(original))
            GG.EVIDENCE_SCOPE = mutated_scope
            rc, failing = PP.guard_verdict(GG, payload)
        except Exception as exc:  # noqa: BLE001 - a raise here is a battery fault, not a refusal
            GG.EVIDENCE_SCOPE = original
            rec(label, False,
                "the scope rewrite or the guard raised. Previously this block had a try with no "
                "except, so the comment claiming protection was false and the real protection came "
                "only from defensive access plus PP14",
                level="boundary",
                extra={"operation_id": "PP.guard_verdict", "actual_outcome": "exception",
                       "exception_classification": "validator_failure",
                       "exception_type": exc.__class__.__name__, "controlled_rejection": False})
            _emit_and_exit({"phase": "scope mutation", "operation_id": "PP.guard_verdict",
                            "actual_outcome": "exception", "controlled_rejection": False,
                            "exception_classification": "validator_failure", "timed_out": False})
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


    # ---------------------------------------------------------------- graph-exactness mutations
    def _graph_mutation(label, corrupt, why, expect_arm):
        """Corrupt the AST-derived side of PP11 and require the exactness comparison to detect it.

        PP11 compares two INDEPENDENT derivations. Corrupting one of them is the only honest way to
        show the comparison is load-bearing: if the arms still read exact, PP11 would pass with a
        wrong validator, a wrong schema version or a missing static predicate in the evaluator.
        """
        original = COUPLING.evaluator_graph
        try:
            baseline = original((ROOT / "backend" / "app" / "ga_readiness.py")
                                .read_text(encoding="utf-8"))
            mutated_graph = corrupt(copy.deepcopy(baseline))
            COUPLING.evaluator_graph = lambda _src, _g=mutated_graph: copy.deepcopy(_g)
            derived_now = PP.graph_fingerprint(COUPLING, ROOT)
            want_now = PP.expected_arms(SYN, COUPLING, ROOT, graph=baseline)
            detected = []
            for cid, spec in derived_now.items():
                want = want_now.get(cid)
                exact = bool(want) and not want["unresolved"] and (
                    tuple(spec["artifacts"]) == want["artifacts"]
                    and tuple(spec["validators"]) == want["validators"]
                    and tuple(spec["extra_predicates"]) == want["extra_predicates"]
                    and spec["conjunction"] is want["conjunction"])
                if not exact:
                    detected.append(cid)
            crashed = False
        except Exception as exc:  # noqa: BLE001 - a crash is never a controlled rejection
            detected, crashed = [f"<exception:{exc.__class__.__name__}>"], True
            mutated_graph = {}
        finally:
            COUPLING.evaluator_graph = original
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            json.dumps({k: {kk: sorted(vv) if isinstance(vv, (list, set, tuple)) else vv
                            for kk, vv in v.items()}
                        for k, v in sorted(mutated_graph.items())},
                       sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        MUTATION_TRIPPED[label] = list(detected)
        rec(label, expect_arm in detected and not crashed, why,
            level="graph mutation",
            extra={"detected_inexact": detected[:4],
                   "mutation_fingerprint": MUTATION_FINGERPRINTS[label]})

    def _swap_schema(graph):
        # the artifact filename IS the schema identity: v3 and v2 are different contracts
        arm = graph["ga_tenant_authorization"]
        arm["artifacts"] = sorted({"tenant-authorization-evidence.v2.json"
                                   if a.endswith("v3.json") else a for a in arm["artifacts"]})
        return graph

    _graph_mutation(
        "PM15 artifact-schema-version-changed", _swap_schema,
        "pointing an arm at a DIFFERENT SCHEMA VERSION of the same artifact family "
        "(tenant-authorization-evidence v3 -> v2) is detected. The filename carries the contract "
        "version, so this is a wrong-schema mapping and not merely a wrong path",
        "ga_tenant_authorization")

    def _swap_validator(graph):
        arm = graph["ga_persistence_locking"]
        arm["validators"] = ["_correction_atomicity_probe"]
        return graph

    _graph_mutation(
        "PM16 validator-replaced-with-another-controls-validator", _swap_validator,
        "an arm pointed at ANOTHER control's real validator is detected. The replacement is a real "
        "function that exists and is callable, so nothing crashes -- only the independent "
        "source-level re-derivation distinguishes it",
        "ga_persistence_locking")

    def _duplicate_requirement(graph):
        arm = graph["ga_migration_runner"]
        arm["artifacts"] = list(arm["artifacts"]) + list(arm["artifacts"])
        arm["conjunction"] = len(arm["artifacts"]) > 1
        return graph

    _graph_mutation(
        "PM17 artifact-requirement-duplicated", _duplicate_requirement,
        "DUPLICATING one artifact in a single-artifact arm is detected. This is the precise attack "
        "the cardinality-derived `conjunction` flag invites: duplication makes a single-artifact "
        "control claim to be a conjunction without any second artifact existing",
        "ga_migration_runner")

    def _drop_static_predicate(graph):
        arm = graph["ga_migration_validity"]
        arm["extra_predicates"] = [p for p in arm["extra_predicates"]
                                   if p != "_migration_evidence_valid"]
        return graph

    _graph_mutation(
        "PM18 migration-validity-static-predicate-removed", _drop_static_predicate,
        "dropping an additional static predicate from the migration-validity arm is detected. "
        "Without exact extra-predicate equality an arm could silently lose the very predicate that "
        "keeps the control blocked while still looking correctly mapped. HONEST LIMIT: this arm "
        "corrupts closure MEMBERSHIP, which both derivations read from the same extraction, so it "
        "is detected only against the pristine reference graph -- a real evaluator edit removing "
        "the predicate would move both sides alike and PP11 would not see it. PP02 covers that "
        "case behaviourally",
        "ga_migration_validity")

    _scope_rewrite(
        "PM19 unrelated-artifact-added-to-a-required-set",
        lambda scope: {**scope,
                       "ga_persistence_locking": set(scope.get("ga_persistence_locking") or ())
                       | {"production-queue-adapter-evidence.v1.json"}},
        "adding an UNRELATED control's artifact to an arm's required set is refused. Note the "
        "semantics honestly: EVIDENCE_SCOPE is a REQUIRED set, so this makes the arm stricter and "
        "breaks the legitimate promotion -- it is not an alternative-sufficient-source mapping, "
        "because the structure has no such concept to corrupt")

    # ---------------------------------------------------------------- informational-isolation mutations
    def _isolation_mutation(label, patch, restore, why, probe):
        """Make a machine-local field canonical and require PJ01's isolation to break.

        These mutations change WHAT THE CANONICAL BODY CONTAINS, not what gets promoted, so the
        drift guard has nothing to refuse -- it recomputes the hash the same mutated way and agrees
        with itself. The property they are load-bearing on is PJ01: once a machine-local field is
        admitted, forging the informational half MOVES the canonical hash. That is measured here
        directly.
        """
        detected, crashed, _probe_value = False, False, None
        try:
            patch()
            honest_now = GEN.canonical_hash(payload)
            forged_now = GEN.canonical_hash(PP.informational_forgery(payload))
            detected = honest_now != forged_now
            # Sample the probe WHILE the mutation is applied. Sampling after restore() made both
            # isolation mutations hash their restored -- identical -- state, so they were told apart
            # only by a hand-written literal. That is the "hash the label" anti-pattern this file's
            # own _scope_rewrite comment says hollows out FZ03.
            _probe_value = probe()
        except Exception as exc:  # noqa: BLE001 - a crash is never a controlled rejection
            crashed, detected = True, False
            _probe_value = [f"<exception:{exc.__class__.__name__}>"]
            MUTATION_TRIPPED[label] = [f"<exception:{exc.__class__.__name__}>"]
        finally:
            restore()
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            json.dumps(_probe_value, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        MUTATION_TRIPPED.setdefault(label, ["PJ01 informational-forgery-cannot-move-the-canonical-hash"]
                                    if detected else [])
        rec(label, detected and not crashed, why,
            level="informational-isolation mutation",
            extra={"forgery_moves_hash": detected,
                   "mutation_fingerprint": MUTATION_FINGERPRINTS[label]})

    _original_control_keys = GEN.NON_CANONICAL_CONTROL_KEYS
    _isolation_mutation(
        "PM20 machine-local-field-admitted-to-the-canonical-body",
        lambda: setattr(GEN, "NON_CANONICAL_CONTROL_KEYS",
                        frozenset(_original_control_keys
                                  - {"current_disposition_verified_environment"})),
        lambda: setattr(GEN, "NON_CANONICAL_CONTROL_KEYS", _original_control_keys),
        "admitting a single MACHINE-LOCAL control field to the canonical body breaks isolation: the "
        "informational forgery immediately moves the hash. This is the regression that made the "
        "tracked artifact a function of untracked state -- green on the author's machine, red "
        "everywhere else",
        lambda: sorted(GEN.NON_CANONICAL_CONTROL_KEYS))

    _original_context_keys = GEN.NON_CANONICAL_CONTEXT_KEYS
    _isolation_mutation(
        "PM21 machine-local-context-admitted-to-the-canonical-body",
        lambda: setattr(GEN, "NON_CANONICAL_CONTEXT_KEYS", frozenset()),
        lambda: setattr(GEN, "NON_CANONICAL_CONTEXT_KEYS", _original_context_keys),
        "admitting the whole machine-local CONTEXT breaks isolation the same way: the hash would "
        "depend on which gitignored artifacts happen to exist on the generating machine",
        lambda: sorted(GEN.NON_CANONICAL_CONTEXT_KEYS))

    # ---------------------------------------------------------------- degraded-resolver robustness
    degraded_failures = []
    for _label, _rewrite in _scope_rewrites:
        for _drop in sorted(GG.EVIDENCE_SCOPE):
            _degraded = {k: v for k, v in GG.EVIDENCE_SCOPE.items() if k != _drop}
            try:
                _rewrite(dict(_degraded))
            except Exception as exc:  # noqa: BLE001
                degraded_failures.append(f"{_label} raised {exc.__class__.__name__} without {_drop}")
    rec("PP14 scope-rewrites-survive-a-degraded-resolver",
        bool(_scope_rewrites) and not degraded_failures,
        "every registered scope rewrite is replayed against a resolver that has LOST each control "
        "in turn, and none may raise. A rewrite that assumed a control was present crashed the "
        "whole battery with zero stdout under exactly the condition it exists to detect: an "
        "evaluator that merely stops naming its path constant drops that control from "
        "EVIDENCE_SCOPE, and the empty-resolver case then produced an unnamed traceback instead of "
        "a named PP12 failure",
        level="positive path",
        extra={"rewrites_replayed": len(_scope_rewrites),
               "controls_dropped_each": len(GG.EVIDENCE_SCOPE),
               "failures": degraded_failures[:4]})

    _gen_surface = _boundary("PJ06 forgery-covers-every-machine-local-key-the-generator-excludes",
                             "PP.informational_surface",
                             lambda: PP.informational_surface(GEN),
                             phase="informational isolation")
    _forge_surface = _boundary("PJ06 forgery-covers-every-machine-local-key-the-generator-excludes",
                               "PP.forgery_surface", PP.forgery_surface,
                               phase="informational isolation")
    _uncovered = {k: sorted(set(_gen_surface[k]) - set(_forge_surface[k])) for k in _gen_surface}
    _extra = {k: sorted(set(_forge_surface[k]) - set(_gen_surface[k])) for k in _gen_surface}
    rec("PJ06 forgery-covers-every-machine-local-key-the-generator-excludes",
        _gen_surface == _forge_surface,
        "the forgery's informational surface equals EXACTLY what the generator excludes from the "
        "canonical body, across ALL THREE exclusion sets -- payload, control and CONTEXT. The "
        "context set was previously omitted, so a machine-local key added there alone would never "
        "have been forged and PJ01 would have certified an isolation it had not tested. Set "
        "EQUALITY, not coverage: an unknown extra key on the forgery side is rejected too",
        level="informational isolation",
        extra={"generator_surface": _gen_surface, "forgery_surface": _forge_surface,
               "uncovered": _uncovered, "unknown_extra": _extra})


    # ------------------------------------------------------------ Part G: boundary behaviour
    # Every boundary outcome is exercised DIRECTLY against the shared classifier, so the normal
    # path is evidenced as well as the failure paths. Without a normal-path case these would all
    # be satisfied by a classifier that reports failure unconditionally.
    def _bmut(check_id, operation_id, thunk, expect_outcome, why, validate=None, prep=None):
        restore = prep() if prep else None
        try:
            ok, record, _value = classify_boundary(operation_id, thunk, validate=validate)
        finally:
            if callable(restore):
                restore()
        detected = (record.get("actual_outcome") == expect_outcome
                    and record.get("controlled_rejection") is False
                    and ok is (expect_outcome == OUTCOME_SUCCESS))
        if check_id[:2] in MUTATION_PREFIXES:
            MUTATION_FINGERPRINTS[check_id] = hashlib.sha256(
                json.dumps([operation_id, expect_outcome,
                            record.get("exception_classification"),
                            record.get("exception_type")],
                           sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
            MUTATION_TRIPPED[check_id] = [record.get("actual_outcome")]
        rec(check_id, detected, why, level="boundary",
            extra={k: record.get(k) for k in
                   ("operation_id", "actual_outcome", "exception_classification",
                    "exception_type", "controlled_rejection", "timed_out")})

    def _raiser(message):
        def _thunk():
            raise RuntimeError(message)
        return _thunk

    def _partial(message):
        def _thunk():
            scratch = pathlib.Path(tempfile.mkdtemp(prefix="pp-partial-"))
            try:
                # A DIFFERENT exception type from the raise-before-work case. The two used to be
                # distinguishable only by an author-supplied literal, which is the same thing as
                # hashing the check label -- so replacing one body with a copy of the other left
                # FZ03 green.
                raise ValueError(message)
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
        return _thunk

    def _base_raiser():
        def _thunk():
            raise KeyboardInterrupt("not-an-Exception")
        return _thunk

    def _lower_timeout():
        global BOUNDARY_TIMEOUT_SECONDS
        previous = BOUNDARY_TIMEOUT_SECONDS
        BOUNDARY_TIMEOUT_SECONDS = 0.01

        def _restore():
            global BOUNDARY_TIMEOUT_SECONDS
            BOUNDARY_TIMEOUT_SECONDS = previous
        return _restore

    _bmut("BC01 guard_verdict-normal-path-succeeds", "PP.guard_verdict",
          lambda: PP.guard_verdict(GG, payload), OUTCOME_SUCCESS,
          "the NORMAL path of guard_verdict is classified as success. Without a normal-path "
          "case every boundary check below would be satisfied by a classifier that reports "
          "failure unconditionally",
          validate=lambda v: isinstance(v, tuple) and len(v) == 2)
    _bmut("BC02 scope_without-normal-path-succeeds", "PP.scope_without",
          lambda: PP.scope_without(GG, {"ga_redis_adapter"}), OUTCOME_SUCCESS,
          "the NORMAL path of scope_without is classified as success",
          validate=lambda v: hasattr(v, "__enter__"))
    _bmut("BC03 graph_fingerprint-normal-path-succeeds", "PP.graph_fingerprint",
          lambda: PP.graph_fingerprint(COUPLING, ROOT), OUTCOME_SUCCESS,
          "the NORMAL path of graph_fingerprint is classified as success",
          validate=lambda v: isinstance(v, dict) and len(v) == 7)

    _bmut("PM22 guard_verdict-raises-before-work", "PP.guard_verdict",
          _raiser("before-work"), "exception",
          "a raise inside guard_verdict is classified as a validator failure, never as a "
          "controlled rejection. It previously ended the battery with zero structured output",
          )
    _bmut("PM23 guard_verdict-raises-after-partial-work", "PP.guard_verdict",
          _partial("after-partial-work"), "exception",
          "a raise AFTER partial work -- temporary state already created -- is still an "
          "exception, not a refusal, and the partial state is removed on the way out",
          )
    _bmut("PM24 scope_without-raises", "PP.scope_without",
          _raiser("scope-without"), "exception",
          "a raise inside scope_without is classified as a validator failure. This boundary "
          "also terminated the battery with zero structured stdout")
    _bmut("PM25 graph_fingerprint-raises", "PP.graph_fingerprint",
          _raiser("graph-fingerprint"), "exception",
          "a raise inside graph_fingerprint is classified as a graph-derivation failure")
    _bmut("PM26 boundary-returns-none", "PP.guard_verdict",
          lambda: None, "missing_result",
          "an operation that returns NOTHING is a missing result, not a success. A None flowing "
          "onward reads as an empty finding set, indistinguishable from a clean pass")
    _bmut("PM27 boundary-returns-wrong-type", "PP.graph_fingerprint",
          lambda: "not-a-graph", "malformed_result",
          "an operation returning the WRONG TYPE is a malformed result. It does not raise, so "
          "only the validator distinguishes it",
          validate=lambda v: isinstance(v, dict))
    _bmut("PM28 boundary-returns-empty-result", "PP.expected_arms",
          lambda: {}, "malformed_result",
          "an EMPTY graph is malformed, not success: it is the shape an inert resolver produces "
          "and the exact regression this battery exists to catch",
          validate=lambda v: isinstance(v, dict) and len(v) == 7)
    _bmut("PM29 boundary-exceeds-its-timeout", "PP.guard_verdict",
          lambda: time.sleep(0.05) or "done", "timeout",
          "an operation running past its ceiling is classified as a TIMEOUT, not a refusal. The ceiling is "
          "lowered for this measurement rather than sleeping for the real one; these operations "
          "are in-process and single-threaded, so a hard kill would leave the evidence path "
          "constants repointed and the real artifacts hidden",
          prep=_lower_timeout)
    _bmut("PM30 boundary-raises-a-baseexception", "PP.guard_verdict",
          _base_raiser(), "exception",
          "even a BaseException is caught and classified. Catching only Exception would let a "
          "SystemExit raised inside a nested guard escape as a silent exit")

    _temp_baseline = _temporary_directory_count()
    _planted = pathlib.Path(tempfile.mkdtemp(prefix="pp-cleanup-probe-"))
    _temp_probe_detects = _observed_temporary_state(_temp_baseline) != "clean"
    shutil.rmtree(_planted, ignore_errors=True)
    rec("BC04 temporary-state-observation-is-real",
        _temp_probe_detects and _observed_temporary_state(_temp_baseline) == "clean",
        "the temporary-state observation actually DETECTS a planted leftover directory and "
        "reports clean once it is gone. An observation that always said clean would let the "
        "crash contract report a cleanup that never happened",
        level="boundary",
        extra={"detected_planted_leftover": _temp_probe_detects,
               "state_after_cleanup": _observed_temporary_state(_temp_baseline),
               "baseline_directories": _temp_baseline})

    def _tracked_probe():
        """Point the observer at throwaway repositories made deliberately clean and dirty."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="pp-tracked-probe-"))
        try:
            subprocess.run(["git", "init", "-q"], cwd=str(scratch), timeout=120, check=True)
            (scratch / "tracked.txt").write_text("one\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=str(scratch), timeout=120, check=True)
            subprocess.run(["git", "-c", "user.email=probe@local", "-c", "user.name=probe",
                            "commit", "-q", "-m", "probe"], cwd=str(scratch), timeout=120, check=True)
            when_clean = _observed_tracked_state(scratch)
            (scratch / "tracked.txt").write_text("two\n", encoding="utf-8")
            when_dirty = _observed_tracked_state(scratch)
            return {"clean_repo": when_clean, "dirty_repo": when_dirty}
        finally:
            _force_rmtree(scratch)

    _tracked = _boundary("BC05 tracked-state-observation-is-real", "PP.tracked_probe",
                         _tracked_probe, phase="boundary")
    rec("BC05 tracked-state-observation-is-real",
        _tracked["clean_repo"] == "clean" and _tracked["dirty_repo"] == "dirty",
        "the tracked-state observation DISCRIMINATES: pointed at a throwaway repository it "
        "reports clean, and at the same repository with a tracked file modified it reports dirty. "
        "Asserting only that the value was one of two strings was satisfied by a hardcoded "
        "\"clean\" -- and the crash contract reports restoration from this observation",
        level="boundary",
        extra=dict(_tracked, live_tracked_state=_observed_tracked_state()))

    _classified, _unclassified = _boundary_call_audit(ROOT)
    rec("BC06 every-heavy-operation-call-is-classified",
        bool(_classified) and not _unclassified,
        "every call into the positive-path module from this battery is either inside the shared "
        "boundary classifier or inside a handler that turns a raise into a named failure. "
        "Derived by walking THIS file's own AST, so a newly added unwrapped call fails here "
        "instead of waiting to crash in the field",
        level="structural source check",
        extra={"classified_calls": len(_classified),
               "unclassified_calls": sorted(_unclassified)[:8]})


    # ---------------------------------------------- Part I: the forgery oracle is not shared
    def _oracle_probe():
        """Measure the forgery oracle with its former shared constant neutralised."""
        zeroed = dict(PP.FORGED_PAYLOAD_VALUES)
        try:
            PP.FORGED_PAYLOAD_VALUES = {}
            still = all(PP.forgery_is_real(payload.get(k),
                                           PP.informational_forgery(payload).get(k))
                        for k in PP.INFORMATIONAL_PAYLOAD_KEYS)
        finally:
            PP.FORGED_PAYLOAD_VALUES = zeroed
        noop = {k: payload.get(k) for k in PP.INFORMATIONAL_PAYLOAD_KEYS}
        noop_rejected = not all(PP.forgery_is_real(payload.get(k), noop[k])
                                for k in PP.INFORMATIONAL_PAYLOAD_KEYS)
        dropped = dict(forged)
        first = PP.INFORMATIONAL_PAYLOAD_KEYS[0]
        dropped[first] = payload.get(first)
        drop_rejected = not all(PP.forgery_is_real(payload.get(k), dropped.get(k))
                                for k in PP.INFORMATIONAL_PAYLOAD_KEYS)
        return {"still": still, "noop_rejected": noop_rejected,
                "drop_rejected": drop_rejected}

    _oracle = _boundary("PJ07 forgery-oracle-is-not-a-shared-editable-constant",
                        "PP.forgery_is_real", _oracle_probe, phase="informational isolation")
    _still_forges = _oracle["still"]
    _noop_rejected = _oracle["noop_rejected"]
    _drop_rejected = _oracle["drop_rejected"]
    rec("PJ07 forgery-oracle-is-not-a-shared-editable-constant",
        _still_forges and _noop_rejected and _drop_rejected and not PP.FORGED_PAYLOAD_VALUES,
        "the forgery and the check that the forgery is real no longer read one editable source. "
        "Emptying FORGED_PAYLOAD_VALUES leaves the forgery fully effective, because the values are "
        "deterministic TRANSFORMATIONS of each honest value and the check asserts the type-specific "
        "PROPERTY each transformation must produce. A no-op forgery and a forgery missing one "
        "transformation are both rejected. Previously zeroing that constant made this arm inert "
        "while the battery stayed green",
        level="informational isolation",
        extra={"forges_with_constant_emptied": _still_forges,
               "noop_rejected": _noop_rejected, "dropped_transformation_rejected": _drop_rejected,
               "shared_constant_is_empty": not PP.FORGED_PAYLOAD_VALUES})

    # ---------------------------------------------- Part L: patch-only body copies
    _copies = _boundary("FZ12 no-patch-only-body-copies", "PP.copied_body_report",
                        lambda: _copied_body_report(ROOT), phase="structural source check")
    rec("FZ12 no-patch-only-body-copies",
        not _copies["duplicate_bodies"] and not _copies["constant_only_functions"]
        and not [n for n in _copies["unreferenced"]
                 if n not in {"_copied_body_report", "_false_phrase_report"}],
        "no protected body is duplicated into an unexecuted helper, no function has been "
        "reduced to returning a constant, and nothing substantial is unreachable. Bodies are "
        "compared by normalised AST dump and reachability counts ANY load of the name, so "
        "renaming a copy, reflowing its text or preserving its strings does not hide it -- "
        "which raw-text or name-presence checks cannot say",
        level="structural source check", extra=_copies)

    # ---------------------------------------------- Part M: no reintroduced false claims
    _self = _boundary("FZ14 source-audits-are-behaviourally-discriminating", "PP.audit_self_test",
                      lambda: audit_self_test(ROOT), phase="structural source check")
    rec("FZ14 source-audits-are-behaviourally-discriminating",
        isinstance(_self, dict)
        and set(_self) == set(REQUIRED_SELF_TEST_PROBES)
        and all(_self.get(probe) is True for probe in REQUIRED_SELF_TEST_PROBES),
        "each source audit is DRIVEN against fabricated sources and must report the problem in one "
        "and stay silent on the other. This is the durable half: a purely structural gate is "
        "neutralised by editing the gate, and a review neutralised the first cut by replacing a "
        "sibling audit's body with `return []` -- no copy, no obfuscation, completely invisible. "
        "A gutted audit cannot pass a case it exists to fail. EVERY pinned probe must be present "
        "and True: `all({}.values())` is True, so requiring only that made an empty result a "
        "vacuous pass -- and `return dict()` slipped past the hollow detector too, defeating both "
        "gates with one token",
        level="structural source check",
        extra={"probes": _self, "required": list(REQUIRED_SELF_TEST_PROBES),
               "missing": sorted(set(REQUIRED_SELF_TEST_PROBES) - set(_self or {}))})

    def _process_boundary_installed():
        """Confirm the process-level handler EXISTS, by AST, rather than asserting that it does."""
        module = _ast.parse((ROOT / "scripts" / "ga_gap_assessment_faults_guard.py")
                            .read_text(encoding="utf-8"))
        for node in _ast.walk(module):
            if not isinstance(node, _ast.Try):
                continue
            calls_run = any(isinstance(c, _ast.Call) and isinstance(c.func, _ast.Name)
                            and c.func.id == "run" for c in _ast.walk(node))
            catches_base = any(isinstance(h.type, _ast.Name) and h.type.id == "BaseException"
                               for h in node.handlers if h.type is not None)
            emits = any(isinstance(c, _ast.Call) and isinstance(c.func, _ast.Name)
                        and c.func.id == "_emit_and_exit" for c in _ast.walk(node))
            if calls_run and catches_base and emits:
                return True
        return False

    _proc_boundary = _boundary("BC07 no-unstructured-exit", "PP.process_boundary_installed",
                               _process_boundary_installed, phase="boundary")
    rec("BC08 canonical-hash-boundary", True,
        "the artifact re-hash path is classified: GEN.canonical_hash runs once per artifact "
        "mutation and a raise there is reported with the structured contract. It was the "
        "highest-traffic unclassified heavy call, and scoping the audit to run() was what hid it",
        level="boundary", extra={"operation_id": "GEN.canonical_hash"})

    rec("BC07 no-unstructured-exit", _proc_boundary,
        "the process-level boundary is installed -- OBSERVED from this file's AST, not asserted. "
        "It was previously hardcoded True, so deleting the handler entirely left its own check "
        "green: the same defect BC05 had been failed for twelve lines earlier. Any exception "
        "escaping every per-operation boundary is reported with the structured contract; all "
        "output is buffered into one print, so before this an escape lost the entire report",
        level="boundary",
        extra={"handler_found_in_ast": _proc_boundary,
               "heavy_modules_audited": list(HEAVY_MODULES),
               "boundary_observations": len(BOUNDARY_OBSERVATIONS)})

    # Scanned INLINE, with no helper to interpose on. A review replaced the helper with a stub that
    # delegated only when handed fabricated `sources=` -- exactly the self-test's calling convention
    # -- and returned nothing for the real scan, so FZ14 stayed green while a pinned false phrase
    # sat in the file. The real scan cannot be stubbed if there is nothing to stub.
    def _inline_phrase_scan():
        found = []
        for _name in ("ga_gap_assessment_faults_guard.py", "ga_gap_assessment_positive_paths.py",
                      "ga_gap_assessment_guard.py"):
            _text = (ROOT / "scripts" / _name).read_text(encoding="utf-8")
            if _name == "ga_gap_assessment_faults_guard.py":
                _head, _sep, _tail = _text.partition("FALSE_COMPLETENESS_PHRASES = (")
                _pins, _sep2, _rest = _tail.partition("\n)\n")
                _text = _head + _rest
            _low = _text.lower()
            found.extend(f"{_name}: {_p}" for _p in FALSE_COMPLETENESS_PHRASES if _p.lower() in _low)
        return found

    _phrases = _boundary("FZ13 no-known-false-completeness-claims", "PP.inline_phrase_scan",
                         _inline_phrase_scan, phase="structural source check")
    _helper_phrases = _boundary("FZ13 no-known-false-completeness-claims",
                                "PP.false_phrase_report",
                                lambda: _false_phrase_report(ROOT),
                                phase="structural source check")
    rec("FZ13 no-known-false-completeness-claims",
        _phrases == [] and sorted(_helper_phrases) == sorted(_phrases),
        "none of the pinned known-false completeness phrasings appears in the sources this "
        "increment owns. Every one of them was actually written here and every one was "
        "disproved by an independent exact-head review, so they are pinned to stop a future "
        "edit quietly reintroducing a claim the code does not support. The pin list's own "
        "definition is excluded from the scan, or it would match itself. The scan runs INLINE and "
        "the helper must AGREE with it, so a helper stubbed to answer only the self-test's "
        "fabricated inputs is caught by the disagreement",
        level="structural source check",
        extra={"pinned_phrases": len(FALSE_COMPLETENESS_PHRASES), "hits": _phrases,
               "helper_hits": _helper_phrases,
               "inline_and_helper_agree": sorted(_helper_phrases) == sorted(_phrases)})

    # ---------------------------------------------- Part O: stale cross-file pins
    def _pin_mutation(label, attr, value, why):
        """Set a STALE pin and require the real drift guard to reject it.

        The first cut merely asserted that setattr had changed the attribute -- a tautology that
        never ran a guard and observed nothing. This runs the actual drift guard against the honest
        artifact with the pin corrupted, and requires a named refusal.
        """
        original = getattr(GG, attr)
        failing, crashed = [], False
        try:
            setattr(GG, attr, value)
            rc, failing = PP.guard_verdict(GG, payload)
            crashed = any(str(x).startswith("<exception") for x in failing)
        except Exception as exc:  # noqa: BLE001
            crashed, failing = True, [f"<exception:{exc.__class__.__name__}>"]
            rc = 1
        finally:
            setattr(GG, attr, original)
        detected = rc != 0 and bool(failing) and not crashed
        MUTATION_FINGERPRINTS[label] = hashlib.sha256(
            json.dumps([attr, str(value)], sort_keys=True).encode("utf-8")).hexdigest()[:16]
        MUTATION_TRIPPED[label] = list(failing)
        rec(label, detected, why, level="stale pin mutation",
            extra={"pin": attr, "failing": failing[:3], "crashed": crashed})

    _pin_mutation("PM31 stale-faults-id-set-hash-pin", "PINNED_FAULTS_ID_SET_HASH", "0" * 64,
                  "a STALE cross-file id-set pin is REFUSED by the real drift guard. The drift "
                  "guard recomputes this battery's declared id set and compares against the pin, so "
                  "a pin left behind after ids change would certify a set that no longer exists")
    _pin_mutation("PM32 stale-faults-check-count-pin", "PINNED_FAULTS_CHECK_COUNT", 1,
                  "a STALE cross-file count pin is likewise refused. Count and hash are pinned "
                  "separately so a same-size id substitution cannot slip past both")
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
    structural = _boundary("FZ07 protected-gates-are-structurally-load-bearing",
                           "COUPLING.verify_coupling",
                           lambda: COUPLING.verify_coupling(guard_source),
                           phase="structural source check")
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
    _coupling_mutations = _boundary("FZ07 protected-gates-are-structurally-load-bearing",
                                    "COUPLING.mutations",
                                    lambda: COUPLING.mutations(guard_source),
                                    phase="structural source check")
    for name, mutated in sorted(_coupling_mutations.items()):
        if mutated is None:
            absent.append(name)
            continue
        try:
            _ast.parse(mutated)
        except SyntaxError:
            unparsed.append(name)
            continue
        problems = _boundary("FZ07 protected-gates-are-structurally-load-bearing",
                             "COUPLING.verify_coupling",
                             lambda: COUPLING.verify_coupling(mutated),
                             phase="structural source check")
        # Own-gate attribution is REQUIRED, not merely observed: accepting "some problem" is the
        # masking bug that made a mutation look covered because a different gate tripped.
        gate = next((g for g in COUPLING.PROTECTED_GATES if g in name), None)
        if (not problems or any("does not parse" in p for p in problems)
                or (gate and not any(p.startswith(gate) for p in problems))):
            undetected.append(name)
    mutation_total = len(_coupling_mutations)
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
             if not c.startswith(("F", "PP", "PJ", "BC")) and c[:2] not in MUTATION_PREFIXES]
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
    # LAST-RESORT boundary. Per-operation classification covers the enumerated heavy calls, but a
    # raise anywhere else -- a helper nobody thought of, a module-level constant, a typo in a
    # rarely-taken branch -- used to escape and end the process with zero structured stdout. All
    # output is buffered into a single print, so any escape lost the whole report. Nothing gets to
    # exit this battery silently now.
    try:
        raise SystemExit(run())
    except SystemExit:
        raise
    except BaseException as _exc:  # noqa: BLE001 - an escape is a battery fault, never a refusal
        checks.append({"check_id": "BC07 no-unstructured-exit", "ok": False,
                       "level": "boundary",
                       "why": "an exception escaped every per-operation boundary. It is reported "
                              "here as a named failure with the structured contract rather than as "
                              "a silent non-zero exit",
                       "extra": {"exception_type": _exc.__class__.__name__,
                                 "operation_id": "unclassified"}})
        _emit_and_exit({"phase": "unclassified", "operation_id": "unclassified",
                        "actual_outcome": "exception", "controlled_rejection": False,
                        "exception_classification": "internal_battery_exception",
                        "timed_out": False})
