"""audit:production-adapter-registry-metadata-faults -- non-vacuity battery for the metadata guard.

Every mutation writes a hostile registry to a temp file, points the REAL metadata guard and the REAL
evaluator at it, and requires the guard to refuse. Nothing is re-implemented here: the predicates
under test are the metadata guard's own, driven end to end.

Docker-free. No queue, database, container or process is contacted; the live registry is never
modified (each mutation works on a temp copy and the original path is restored in a ``finally``).

Honest scope: claim_scope = production-adapter-registry-metadata-faults-only. Certifies NO adapter:
PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED / PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED, GA_BLOCKED.
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

from backend.app import ga_readiness as GA  # noqa: E402
import production_adapter_registry_metadata_guard as MG  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("MD", "MQ", "MX", "MS", "MC")

DB = "ga_postgres_adapter"
QUEUE = "ga_redis_adapter"

EXPECTED_CHECK_IDS = [
    "FB00 baseline-passes", "FB01 registry-file-untouched",
    # database metadata regressions
    "MD01 db-description-restored-to-delegation", "MD02 db-resolution-restored-to-backend-pass",
    "MD03 db-policy-reference-missing-file", "MD04 db-cites-wrong-contract-schema",
    "MD05 db-policy-reference-points-at-queue-contract",
    # queue metadata regressions
    "MQ01 queue-description-restored-to-ping", "MQ02 queue-resolution-restored-to-reachability",
    "MQ03 queue-policy-reference-missing-file", "MQ04 queue-cites-wrong-contract-schema",
    "MQ05 queue-described-as-durable",
    # cross-evidence / overclaim
    "MX01 test-runtime-presented-as-production", "MX02 tenant-evidence-as-database-evidence",
    "MX03 worker-evidence-as-queue-evidence", "MX04 parity-claimed-without-artifact",
    "MX05 evidence-claimed-to-exist",
    # registry-shape violations
    "MS01 target-control-omitted", "MS02 third-control-modified", "MS03 control-id-changed",
    "MS04 check-id-changed", "MS05 severity-changed", "MS06 policy-source-changed",
    "MS07 manual-review-flag-changed", "MS08 registry-count-changed",
    "MS09 control-order-changed", "MS10 non-target-control-changed",
    # consumer / disposition consistency
    "MC01 consumer-and-metadata-disagree", "MC02 dispositions-must-not-change",
    "MC03 inventory-hash-must-not-move",
    "FZ02 id-set-hash-pinned", "FZ03 mutations-are-distinct-inputs",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]
EXPECTED_TOTAL_CHECKS = 34
#: Mutations counted by what ACTUALLY mutates a registry -- i.e. entries in MUTATION_FINGERPRINTS --
#: not by id prefix. The first cut keyed on the prefix and counted two plain assertions (MC02, MC03)
#: as mutations, overstating the total by two.
EXPECTED_MUTATION_COUNT = 26

#: Hash of this battery's own declared id set, pinned as a literal. Without it a mutation can be
#: deleted together with its declared id AND both pins, leaving the battery green at a smaller size.
PINNED_ID_SET_HASH = "50c684f7053ad3511caaff8aef1305baf1f46beec58e72d78b8028b5e8023cc3"


def rec(cid, ok, desc, level="registry mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def live_registry() -> dict:
    return json.loads(MG.REGISTRY_PATH.read_text(encoding="utf-8"))


def guard_result(registry: dict) -> tuple[int, list[str]]:
    """Run the REAL metadata guard against a hostile registry. Returns (rc, failing check ids)."""
    saved_mg, saved_ga = MG.REGISTRY_PATH, GA.REGISTRY_PATH
    tmp = Path(tempfile.mkdtemp(prefix="pram-"))
    try:
        target = tmp / "blocker_registry.v1.json"
        target.write_text(json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        MG.REGISTRY_PATH = target
        GA.REGISTRY_PATH = target
        MG.checks.clear()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = MG.run()
        failing = [c["check_id"] for c in MG.checks if not c["ok"]]
        return rc, failing
    except Exception as exc:  # noqa: BLE001 - a crash is a refusal, recorded as such
        return 1, [f"<exception:{exc.__class__.__name__}>"]
    finally:
        MG.REGISTRY_PATH, GA.REGISTRY_PATH = saved_mg, saved_ga
        MG.checks.clear()
        shutil.rmtree(tmp, ignore_errors=True)


#: Fingerprints of every mutated registry, so a mutation body replaced by a copy of another's is
#: detectable. Ported from the accepted queue battery (FC03), which this file lacked.
MUTATION_FINGERPRINTS: dict[str, str] = {}


def refuses(cid, mutate, desc, *, level="registry mutation"):
    registry = copy.deepcopy(live_registry())
    mutate(registry)
    fingerprint = hashlib.sha256(
        json.dumps(registry, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    MUTATION_FINGERPRINTS[cid] = fingerprint
    rc, failing = guard_result(registry)
    rec(cid, rc != 0 and bool(failing), desc, level=level,
        extra={"guard_exit": rc, "failing_checks": failing[:4],
               "mutation_fingerprint": fingerprint})


def entry(registry: dict, check_id: str) -> dict:
    return next(b for b in registry["blockers"] if b["check_id"] == check_id)


def run() -> int:
    # ---------------------------------------------------------------- baseline
    rc, failing = guard_result(live_registry())
    rec("FB00 baseline-passes", rc == 0 and not failing,
        "ANCHOR: the real metadata guard passes against the live registry, so every refusal below is "
        "discriminating rather than an always-fail guard",
        level="metadata integration", extra={"failing": failing[:4]})

    before = MG.REGISTRY_PATH.read_bytes()

    # ---------------------------------------------------------------- database metadata
    refuses("MD01 db-description-restored-to-delegation",
            lambda r: entry(r, DB).__setitem__(
                "description",
                "Delegates to the postgres_repository readiness check: env vars alone cannot certify "
                "readiness; a reachable Postgres must be the active adapter."),
            "restoring the generic postgres-delegation description is refused")
    refuses("MD02 db-resolution-restored-to-backend-pass",
            lambda r: entry(r, DB).__setitem__(
                "resolution_condition",
                "The requested repository backend is postgres, the active adapter is postgres via a "
                "live probe, and a database URL is configured."),
            "restoring the repository-backend resolution condition is refused: a disposable "
            "PostgreSQL satisfies it")
    refuses("MD03 db-policy-reference-missing-file",
            lambda r: entry(r, DB).__setitem__(
                "policy_reference", "docs/production_database_adapter_that_does_not_exist.md"),
            "a policy reference naming a file that is not committed is refused")
    refuses("MD04 db-cites-wrong-contract-schema",
            lambda r: entry(r, DB).__setitem__(
                "resolution_condition",
                entry(r, DB)["resolution_condition"].replace(
                    "production-database-adapter-evidence.v1", "some-other-evidence.v9")),
            "citing a schema id the contract module does not declare is refused")
    refuses("MD05 db-policy-reference-points-at-queue-contract",
            lambda r: entry(r, DB).__setitem__(
                "policy_reference",
                "backend/app/production_queue_adapter_evidence.py (queue contract); consumer "
                "backend/app/ga_readiness.py::_postgres_adapter_probe"),
            "cross-wiring the database control to the QUEUE contract module is refused")

    # ---------------------------------------------------------------- queue metadata
    refuses("MQ01 queue-description-restored-to-ping",
            lambda r: entry(r, QUEUE).__setitem__(
                "description",
                "Delegates to the redis_queue readiness check: a reachable Redis must be the active "
                "queue backend."),
            "restoring the redis_queue/PING description is refused")
    refuses("MQ02 queue-resolution-restored-to-reachability",
            lambda r: entry(r, QUEUE).__setitem__(
                "resolution_condition",
                "The requested queue backend is redis, the active worker is redis via a live probe, "
                "and a Redis URL is configured."),
            "restoring the reachability resolution condition is refused: a Redis answering PING "
            "satisfies it")
    refuses("MQ03 queue-policy-reference-missing-file",
            lambda r: entry(r, QUEUE).__setitem__(
                "policy_reference", "backend/app/queue_contract_that_does_not_exist.py"),
            "a queue policy reference naming a file that is not committed is refused")
    refuses("MQ04 queue-cites-wrong-contract-schema",
            lambda r: entry(r, QUEUE).__setitem__(
                "resolution_condition",
                entry(r, QUEUE)["resolution_condition"].replace(
                    "production-queue-adapter-evidence.v1",
                    "production-database-adapter-evidence.v1")),
            "citing the DATABASE schema id in the queue control is refused")
    refuses("MQ05 queue-described-as-durable",
            lambda r: entry(r, QUEUE).__setitem__(
                "description",
                entry(r, QUEUE)["description"]
                .replace("is not durable or recoverable", "is durable and recoverable")
                .replace("at-most-once", "at-least-once with acknowledgement")),
            "describing the present queue as durable or recoverable is refused -- it is neither")

    # ---------------------------------------------------------------- cross-evidence / overclaim
    refuses("MX01 test-runtime-presented-as-production",
            lambda r: entry(r, DB).__setitem__(
                "resolution_condition",
                "The accepted restricted PostgreSQL runtime functional matrix passes, which "
                "establishes the production database adapter."),
            "presenting the restricted test runtime as the production proof is refused")
    refuses("MX02 tenant-evidence-as-database-evidence",
            lambda r: entry(r, DB).__setitem__(
                "resolution_condition",
                "Valid tenant-authorization evidence v3 is present at the evaluated head."),
            "presenting tenant-authorization evidence as database-adapter evidence is refused")
    refuses("MX03 worker-evidence-as-queue-evidence",
            lambda r: entry(r, QUEUE).__setitem__(
                "resolution_condition",
                "The restricted worker/import functional matrix passes with zero worker process "
                "failures."),
            "presenting worker functional evidence as queue-adapter evidence is refused")
    refuses("MX04 parity-claimed-without-artifact",
            lambda r: [entry(r, c).__setitem__(
                "description",
                entry(r, c)["description"] + " Production parity has been achieved for this adapter.")
                for c in (DB, QUEUE)],
            "claiming production parity in the metadata is refused")
    refuses("MX05 evidence-claimed-to-exist",
            lambda r: entry(r, DB).__setitem__(
                "description",
                entry(r, DB)["description"] + " A valid production evidence artifact is present."),
            "asserting that the production evidence currently exists is refused")

    # ---------------------------------------------------------------- registry shape
    refuses("MS01 target-control-omitted",
            lambda r: r["blockers"].remove(entry(r, QUEUE)),
            "removing a target control is refused")
    refuses("MS02 third-control-modified",
            lambda r: entry(r, "ga_migration_validity").__setitem__(
                "description", "MUTATED third control"),
            "modifying a control outside the two targets is refused")
    refuses("MS03 control-id-changed",
            lambda r: entry(r, DB).__setitem__("id", "production-database-adapter-v2"),
            "changing a target's registry identifier is refused")
    refuses("MS04 check-id-changed",
            lambda r: entry(r, QUEUE).__setitem__("check_id", "ga_queue_adapter"),
            "changing a target's check identifier is refused")
    refuses("MS05 severity-changed",
            lambda r: entry(r, DB).__setitem__("severity", "warning"),
            "changing a target's severity is refused")
    refuses("MS06 policy-source-changed",
            lambda r: entry(r, QUEUE).__setitem__("policy_source", "mutated_source"),
            "changing a target's policy_source is refused. (This registry schema has no "
            "'dependencies' field; policy_source is the nearest immutable provenance field and is "
            "covered in its place)")
    refuses("MS07 manual-review-flag-changed",
            lambda r: entry(r, DB).__setitem__("manual_review_required", True),
            "changing a target's manual-review flag is refused")
    refuses("MS08 registry-count-changed",
            lambda r: r["blockers"].append(copy.deepcopy(entry(r, DB))),
            "changing the control count away from 28 is refused")
    refuses("MS09 control-order-changed",
            lambda r: r["blockers"].insert(0, r["blockers"].pop()),
            "reordering the controls is refused")
    refuses("MS10 non-target-control-changed",
            lambda r: entry(r, "ga_client_organizational_approval").__setitem__(
                "resolution_condition", "MUTATED"),
            "changing any non-target control is refused")

    # ---------------------------------------------------------------- consumer / dispositions
    refuses("MC01 consumer-and-metadata-disagree",
            lambda r: [entry(r, DB).__setitem__("policy_reference",
                                                "backend/app/readiness.py postgres_repository"),
                       entry(r, DB).__setitem__(
                           "resolution_condition",
                           "The postgres_repository readiness check passes.")],
            "metadata that disagrees with the real consumer -- pointing at the readiness check the "
            "consumer no longer uses -- is refused")

    readiness = {"redis_queue": "pass", "postgres_repository": "pass",
                 "local_llm_runtime": "pass", "demo_seed_removed": "pass", "client_mode": "pass"}
    live = {c["id"]: c["disposition"]
            for c in GA.evaluate_blockers(dict(readiness), forge_report=None)}
    rec("MC02 dispositions-must-not-change",
        live.get(DB) == "BLOCKED" and live.get(QUEUE) == "BLOCKED" and len(live) == 28,
        "with every readiness check passing, both adapter controls remain BLOCKED and the control "
        "count is 28: a metadata correction changes no disposition",
        level="evaluator integration",
        extra={DB: live.get(DB), QUEUE: live.get(QUEUE), "controls": len(live)})

    from backend.app import readiness_contexts as RC
    rec("MC03 inventory-hash-must-not-move",
        RC.canonical_hash() == MG.ACCEPTED_INVENTORY_HASH,
        "the canonical readiness-context inventory hash is unchanged by the metadata correction, so "
        "no rebind is warranted -- the canonical body carries control ids and dispositions, never "
        "registry prose",
        level="structural source check", extra={"inventory_hash": RC.canonical_hash()})

    rec("FB01 registry-file-untouched", MG.REGISTRY_PATH.read_bytes() == before,
        "the live registry file is byte-identical after every mutation: each ran against a temp copy",
        level="structural source check")

    # ---------------------------------------------------------------- cross-file / distinctness
    id_set_hash = hashlib.sha256(
        "\n".join(sorted(EXPECTED_CHECK_IDS)).encode("utf-8")).hexdigest()
    rec("FZ02 id-set-hash-pinned", id_set_hash == PINNED_ID_SET_HASH,
        "the declared check-id set hashes to the pinned literal, so deleting a mutation together "
        "with its declared id and both counts is caught",
        level="structural source check", extra={"observed_id_set_hash": id_set_hash[:16] + "..."})

    duplicated = {}
    for fingerprint, ids in {
        f: [k for k, v in MUTATION_FINGERPRINTS.items() if v == f]
        for f in set(MUTATION_FINGERPRINTS.values())
    }.items():
        if len(ids) > 1:
            duplicated[fingerprint] = sorted(ids)
    rec("FZ03 mutations-are-distinct-inputs",
        not duplicated and len(MUTATION_FINGERPRINTS) == EXPECTED_MUTATION_COUNT,
        "every mutation applies a DISTINCT mutated registry, so replacing one mutation's body with "
        "a copy of another's -- which leaves the id list and both counts untouched -- is caught",
        level="structural source check",
        extra={"fingerprinted": len(MUTATION_FINGERPRINTS),
               "duplicate_bodies": {k[:12]: v for k, v in list(duplicated.items())[:3]}})

    # ---------------------------------------------------------------- completeness
    mutations_so_far = list(MUTATION_FINGERPRINTS)
    rec("FZ01 battery-size-pinned",
        len(EXPECTED_CHECK_IDS) == EXPECTED_TOTAL_CHECKS
        and len(mutations_so_far) == EXPECTED_MUTATION_COUNT,
        f"pinned at {EXPECTED_TOTAL_CHECKS} declared checks / {EXPECTED_MUTATION_COUNT} mutations",
        level="structural source check",
        extra={"declared": len(EXPECTED_CHECK_IDS), "mutations": len(mutations_so_far)})

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

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    mutation_ids = list(MUTATION_FINGERPRINTS)

    print(json.dumps({
        "guard": "audit:production-adapter-registry-metadata-faults",
        "claim_scope": "production-adapter-registry-metadata-faults-only",
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "mutations": len(mutation_ids),
                    "non_mutation_checks": len(checks) - len(mutation_ids),
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        "control_dispositions_changed": False,
        "production_database_adapter_accepted": False,
        "production_queue_adapter_accepted": False,
        "production_parity": False,
        "docker_used": False,
        "database_execution_verdict": "PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED",
        "queue_execution_verdict": "PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
