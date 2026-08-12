"""audit:production-queue-adapter-contract-faults -- integrity battery for the queue contract.

The evidence guard proves the validator rejects bad *artifacts*. This battery proves the *contract*
cannot be quietly weakened, which is the other half: a requirement deleted from the contract would
leave every artifact-level test passing while the bar dropped.

Two kinds of check, stated separately rather than blurred:

* **Constant mutations** weaken one contract constant and assert BOTH that the weakening is
  *detectable* (the pinned contract hash changes) and that the constant is *load-bearing* -- that
  weakening it ELIMINATES a specific rejection reason. Comparing "was there any reason" would be
  masked by environment-level reasons such as a dirty worktree appearing in both runs; that mistake
  made all 15 equivalent checks vacuous in the database increment's first cut.
* **Artifact and evaluator mutations** assert only that the real validator or the real readiness
  dispatch refuses. Several deliberately overlap the evidence battery: the same rule is worth pinning
  from both sides.

Every predicate comes from the real modules -- ``Q.validate`` and the real ``ga_readiness``
dispatch -- never from a local copy of the rules. No queue, Redis, container or process is contacted.

Honest scope: claim_scope = production-queue-adapter-contract-integrity-only;
real_production_queue_executed = false; production_queue_adapter_accepted = false;
release_recommendation = GA_BLOCKED.
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
from backend.app import production_queue_adapter_evidence as Q  # noqa: E402
import production_queue_adapter_evidence_guard as EG  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("CD", "CT", "CI", "CV", "CB", "CP", "CE")

PINNED_CONTRACT_HASH = "45bc335f8066576ee1694ba07d47e2c6d97ad74ac4fab69374e9202ad16e7afb"

#: Cross-file pins of the EVIDENCE battery, so its coverage cannot be reduced by editing only that
#: file (see FC02/FC03).
PINNED_EVIDENCE_ID_SET_HASH = "4ab1c76ee947a29dd3ff45226aebd97dcb9d540ccdec8e4ee06d86520bc38893"
PINNED_EVIDENCE_CHECK_COUNT = 104
#: Floor on how many mutations carry an input fingerprint, so the distinctness check
#: cannot be defeated by simply stopping to record them.
PINNED_EVIDENCE_MIN_FINGERPRINTED = 60

EXPECTED_CHECK_IDS = [
    "FC00 contract-hash-pinned", "FC01 baseline-accepts-valid",
    # required domains
    "CD01 required-domain-removed", "CD02 failover-domain-removed",
    "CD03 recovery-domain-removed", "CD04 monitoring-domain-removed",
    "CD05 capacity-domain-removed", "CD06 incident-rollback-removed",
    "CD07 dead-letter-domain-removed", "CD08 poison-message-domain-removed",
    "CD09 domain-field-requirement-removed", "CD10 executed-drill-requirement-relaxed",
    "CD11 ping-promoted-to-proving",
    # target / environment
    "CT01 test-evidence-promoted", "CT02 development-accepted",
    "CT03 loopback-accepted", "CT04 docker-bridge-accepted",
    "CT05 provider-unknown-accepted", "CT06 unsafe-eviction-accepted",
    # identities
    "CI01 admin-runtime-identity-accepted", "CI02 default-user-accepted",
    "CI03 admin-separation-removed", "CI04 tenant-namespace-requirement-removed",
    "CI05 payload-override-accepted", "CI06 local-fallback-accepted",
    # delivery
    "CV01 delivery-model-omitted", "CV02 exactly-once-accepted",
    "CV03 retry-limit-removed", "CV04 duplicate-handling-removed",
    "CV05 idempotency-compatibility-removed", "CV06 poison-isolation-removed",
    "CV07 dead-letter-requirement-removed", "CV08 durability-without-observation",
    # bindings / hashing
    "CB01 canonical-hash-ignored", "CB02 commit-tree-binding-ignored",
    "CB03 dirty-worktree-accepted", "CB04 staleness-check-removed",
    "CB05 git-unavailability-accepted", "CB06 non-canonical-keys-widened",
    # parity / disclosure / privacy
    "CP01 parity-omitted", "CP02 parity-true-without-observations",
    "CP03 disclosure-requirement-removed", "CP04 non-qualifying-list-emptied",
    "CP05 secret-scan-ignored",
    # evaluator isolation
    "CE01 evaluator-exception-is-pass", "CE02 redis-queue-cannot-promote",
    "CE03 tenant-evidence-cannot-promote", "CE04 ui-evidence-cannot-promote",
    "CE05 worker-evidence-cannot-promote", "CE06 database-evidence-cannot-promote",
    "CE07 delegation-defect-reintroduced-fails", "CE08 registry-untouched",
    "FC02 evidence-battery-id-set-pinned", "FC03 evidence-mutations-are-distinct-inputs",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]
EXPECTED_TOTAL_CHECKS = 56
EXPECTED_MUTATION_COUNT = 50


def rec(cid, ok, desc, level="contract mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def valid() -> dict:
    return EG.build_valid_artifact()


def validate(payload) -> list[str]:
    return Q.validate(payload, current_commit=EG.COMMIT, current_tree=EG.TREE, now=EG._now())


def weaken(attr: str, value):
    class _Patch:
        def __enter__(self):
            self.saved = getattr(Q, attr)
            setattr(Q, attr, value)
            return self

        def __exit__(self, *exc):
            setattr(Q, attr, self.saved)
            return False
    return _Patch()


def detectable_and_load_bearing(cid, attr, weakened_value, artifact_mutation, desc):
    """Assert the weakening changes the pinned hash AND eliminates a specific rejection reason."""
    payload = valid()
    artifact_mutation(payload)
    payload = EG.rehash(payload)
    before = set(validate(payload))
    with weaken(attr, weakened_value):
        hash_changed = Q.contract_hash() != PINNED_CONTRACT_HASH
        after = set(validate(payload))
    eliminated = sorted(before - after)
    rec(cid, hash_changed and bool(eliminated), desc,
        extra={"detectable_by_hash": hash_changed,
               "constant_is_load_bearing": bool(eliminated),
               "reasons_eliminated": eliminated[:2]})


def refuses_artifact(cid, mutation, desc, *, rehash_after=True):
    payload = valid()
    mutation(payload)
    payload = EG.rehash(payload) if rehash_after else payload
    reasons = validate(payload)
    rec(cid, bool(reasons), desc, level="predicate/unit mutation",
        extra={"first_reason": reasons[0] if reasons else None})


def run() -> int:
    rec("FC00 contract-hash-pinned", Q.contract_hash() == PINNED_CONTRACT_HASH,
        "the contract hash equals the pinned literal, so any change to required domains, rejection "
        "sets, ALLOWED enums, provenance requirements, delivery models or disclosures is detectable",
        level="structural source check", extra={"contract_hash": Q.contract_hash()})
    rec("FC01 baseline-accepts-valid", validate(valid()) == [],
        "ANCHOR: the unmutated contract accepts the complete synthetic artifact, so every mutation "
        "below is discriminating",
        level="structural source check", extra={"reasons": validate(valid())[:3]})

    # ------------------------------------------------------------------ required domains
    def drop(name):
        return tuple(d for d in Q.REQUIRED_PROOF_DOMAINS if d != name)

    for cid, name, desc in (
        ("CD01 required-domain-removed", "ordering_guarantees",
         "removing a required proof domain is detectable and changes behaviour"),
        ("CD02 failover-domain-removed", "failover_drill",
         "removing the failover domain is detectable and changes behaviour"),
        ("CD03 recovery-domain-removed", "recovery_behavior",
         "removing the recovery domain is detectable and changes behaviour -- durability without "
         "proven recovery is not recovery evidence"),
        ("CD04 monitoring-domain-removed", "monitoring_and_alerting",
         "removing the monitoring domain is detectable and changes behaviour"),
        ("CD05 capacity-domain-removed", "capacity_and_throughput_thresholds",
         "removing the capacity-threshold domain is detectable and changes behaviour"),
        ("CD06 incident-rollback-removed", "incident_and_rollback_process",
         "removing the incident/rollback domain is detectable and changes behaviour"),
        ("CD07 dead-letter-domain-removed", "dead_letter_behavior",
         "removing the dead-letter domain is detectable and changes behaviour"),
        ("CD08 poison-message-domain-removed", "poison_message_isolation",
         "removing the poison-message domain is detectable and changes behaviour"),
    ):
        detectable_and_load_bearing(cid, "REQUIRED_PROOF_DOMAINS", drop(name),
                                    lambda p, n=name: p["proof_domains"].pop(n), desc)

    detectable_and_load_bearing(
        "CD09 domain-field-requirement-removed", "REQUIRED_DOMAIN_FIELDS", ("status",),
        lambda p: p["proof_domains"]["replication"].pop("binding_fingerprint"),
        "dropping the per-domain provenance field requirement is detectable and lets a domain "
        "without a binding fingerprint through")

    relaxed = dict(Q.DOMAIN_OBSERVATION_REQUIREMENTS)
    relaxed["failover_drill"] = ("signed_operator_attestation",)
    detectable_and_load_bearing(
        "CD10 executed-drill-requirement-relaxed", "DOMAIN_OBSERVATION_REQUIREMENTS", relaxed,
        lambda p: p["proof_domains"].__setitem__(
            "failover_drill",
            EG.domain("failover", observation_class="signed_operator_attestation")),
        "relaxing an executed-drill domain to accept a generic attestation is detectable and would "
        "let 'an operator says failover works' count as a failover drill")

    detectable_and_load_bearing(
        "CD11 ping-promoted-to-proving", "PROVING_OBSERVATION_CLASSES",
        Q.PROVING_OBSERVATION_CLASSES + ("queue_reachability_ping",),
        lambda p: p["proof_domains"].__setitem__(
            "ordering_guarantees",
            EG.domain("ordering", observation_class="queue_reachability_ping")),
        "promoting a queue reachability PING to a proving observation class is detectable -- this is "
        "the exact defect the contract exists to close")

    # ------------------------------------------------------------------ target / environment
    for cid, attr, weakened, mutation, desc in (
        ("CT01 test-evidence-promoted", "REJECTED_ENVIRONMENTS", (),
         lambda p: p["target"].__setitem__("environment_classification", "test"),
         "allowing a test environment is detectable and would promote disposable infrastructure"),
        ("CT02 development-accepted", "REJECTED_ENVIRONMENTS", ("test",),
         lambda p: p["target"].__setitem__("environment_classification", "development"),
         "allowing a development environment is detectable and changes behaviour"),
        ("CT03 loopback-accepted", "REJECTED_ENDPOINT_CLASSIFICATIONS", ("docker-bridge", "unknown"),
         lambda p: p["target"].__setitem__("endpoint_classification", "loopback"),
         "allowing a loopback endpoint is detectable and changes behaviour"),
        ("CT04 docker-bridge-accepted", "REJECTED_ENDPOINT_CLASSIFICATIONS",
         ("loopback", "unknown"),
         lambda p: p["target"].__setitem__("endpoint_classification", "docker-bridge"),
         "allowing a Docker-bridge endpoint is detectable and changes behaviour"),
        ("CT05 provider-unknown-accepted", "REJECTED_PROVIDER_CLASSIFICATIONS", (),
         lambda p: p["target"].__setitem__("provider_classification", "unknown"),
         "allowing an unknown provider is detectable and would let an unidentifiable target certify"),
        ("CT06 unsafe-eviction-accepted", "UNSAFE_EVICTION_POLICIES", (),
         lambda p: p["target"].__setitem__("eviction_policy", "allkeys-lru"),
         "allowing a job-discarding eviction policy is detectable and changes behaviour"),
    ):
        detectable_and_load_bearing(cid, attr, weakened, mutation, desc)

    detectable_and_load_bearing(
        "CI01 admin-runtime-identity-accepted", "REJECTED_RUNTIME_IDENTITIES", ("default-user",),
        lambda p: p["identities"].__setitem__("consumer_worker_identity_classification",
                                              "administrative"),
        "allowing an administrative runtime identity is detectable and changes behaviour")
    # Targets the ADMINISTRATIVE role deliberately. 'default-user' is caught by two independent
    # gates for a runtime role, so weakening one leaves the other rejecting and the constant looks
    # non-load-bearing. The admin role is exempt from REJECTED_RUNTIME_IDENTITIES, so only
    # NEVER_ACCEPTABLE_IDENTITIES holds it -- which is exactly the constant under test.
    detectable_and_load_bearing(
        "CI02 default-user-accepted", "NEVER_ACCEPTABLE_IDENTITIES", (),
        lambda p: p["identities"].__setitem__("administrative_identity_classification",
                                              "default-user"),
        "allowing a default-user identity for ANY role -- including the administrative one -- is "
        "detectable and changes behaviour")

    # ------------------------------------------------------------------ artifact-level rules
    for cid, mutation, desc in (
        ("CI03 admin-separation-removed",
         lambda p: p["identities"].__setitem__("administrative_distinct_from_runtime", False),
         "an administrative identity not separated from the runtime identity is refused"),
        ("CI04 tenant-namespace-requirement-removed",
         lambda p: p["identities"].__setitem__("tenant_namespace_bound", False),
         "a shared namespace without per-tenant/job binding is refused"),
        ("CI05 payload-override-accepted",
         lambda p: p["identities"].__setitem__("payload_tenant_override_rejected", False),
         "trusting a payload-supplied tenant is refused"),
        ("CI06 local-fallback-accepted",
         lambda p: p["identities"].__setitem__("local_fallback_prevented", False),
         "permitting silent fallback to a local/in-memory queue is refused"),
        ("CV01 delivery-model-omitted", lambda p: p["delivery"].pop("model"),
         "omitting the delivery model is refused, not defaulted"),
        ("CV02 exactly-once-accepted", lambda p: p["delivery"].__setitem__("model", "exactly-once"),
         "claiming exactly-once delivery is refused"),
        ("CV03 retry-limit-removed", lambda p: p["delivery"].pop("retry_limit"),
         "removing the retry limit is refused"),
        ("CV04 duplicate-handling-removed",
         lambda p: p["delivery"].__setitem__("duplicate_delivery_behavior", None),
         "removing duplicate-delivery handling is refused"),
        ("CV05 idempotency-compatibility-removed",
         lambda p: p["delivery"].__setitem__(
             "idempotency_contract_compatibility_observed", False),
         "at-least-once delivery without observed idempotency compatibility is refused"),
        ("CV06 poison-isolation-removed",
         lambda p: p["delivery"].__setitem__("poison_message_isolated", False),
         "removing poison-message isolation is refused"),
        ("CV07 dead-letter-requirement-removed",
         lambda p: p["delivery"].__setitem__("dead_letter_disposition", "none"),
         "a required dead-letter disposition declared as none is refused"),
        ("CV08 durability-without-observation",
         lambda p: (p["target"].__setitem__("storage_classification", "ephemeral-only"),
                    p["target"].__setitem__("durability_claimed", True)),
         "claiming durability on ephemeral-only storage is refused"),
        ("CB02 commit-tree-binding-ignored", lambda p: p.__setitem__("git_tree", "e" * 40),
         "an artifact bound to a different tree is refused"),
        ("CB03 dirty-worktree-accepted", lambda p: p.__setitem__("worktree_clean", False),
         "an artifact not attesting a clean worktree is refused"),
        ("CP01 parity-omitted", lambda p: p.pop("production_parity"),
         "omitting production_parity is refused, not defaulted to true"),
        ("CP02 parity-true-without-observations",
         lambda p: p.__setitem__("proof_domains", {}),
         "production_parity=true with no proof domains at all is refused: parity cannot come from a "
         "literal"),
        ("CP03 disclosure-requirement-removed",
         lambda p: p["non_qualifying_evidence_disclosure"].pop("worker_test_disclosure"),
         "removing the worker/disposable-queue disclosure is refused"),
        ("CP04 non-qualifying-list-emptied",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "non_qualifying_sources", []),
         "emptying the non-qualifying evidence list is refused"),
        ("CP05 secret-scan-ignored", lambda p: p.__setitem__("secret_scan_clean", False),
         "a non-clean secret scan is refused"),
    ):
        refuses_artifact(cid, mutation, desc)

    refuses_artifact("CB01 canonical-hash-ignored",
                     lambda p: p.__setitem__("canonical_payload_hash", "c" * 64),
                     "a canonical hash not matching the body is refused", rehash_after=False)

    stale = EG.rehash(valid())
    rec("CB04 staleness-check-removed",
        bool(Q.validate(stale, current_commit=EG.COMMIT, current_tree=EG.TREE,
                        now=EG._now().replace(year=2030))),
        "an artifact old in absolute time is refused, so removing/ignoring the staleness bound "
        "changes behaviour",
        level="predicate/unit mutation")

    real_git = Q._git
    try:
        Q._git = lambda args: Q.GIT_UNAVAILABLE
        unverifiable = bool(Q.validate(valid(), now=EG._now()))
    finally:
        Q._git = real_git
    rec("CB05 git-unavailability-accepted", unverifiable,
        "git unavailability is refused rather than failing open into 'clean worktree, binding "
        "skipped'", level="predicate/unit mutation")

    base_a = valid()
    base_b = copy.deepcopy(base_a)
    base_b["delivery"]["retry_limit"] = 99
    real_differs = Q.canonical_hash(base_a) != Q.canonical_hash(base_b)
    with weaken("NON_CANONICAL_KEYS", frozenset(Q.NON_CANONICAL_KEYS | {"delivery"})):
        collides = Q.canonical_hash(base_a) == Q.canonical_hash(base_b)
        widened_detectable = Q.contract_hash() != PINNED_CONTRACT_HASH
    rec("CB06 non-canonical-keys-widened", real_differs and collides and widened_detectable,
        "widening the non-canonical key set makes two substantively different artifacts collide on "
        "the canonical hash, and the widening is itself detectable by the pinned contract hash",
        extra={"differs_under_real_contract": real_differs, "collides_when_widened": collides})

    # ------------------------------------------------------------------ evaluator isolation
    real_validate = Q.validate
    try:
        def boom(*a, **k):
            raise RuntimeError("validator exploded")
        Q.validate = boom
        disposition = EG.probe_with(valid())
    finally:
        Q.validate = real_validate
    rec("CE01 evaluator-exception-is-pass", disposition == "BLOCKED",
        "an exception inside the contract validator leaves the control BLOCKED; never a PASS, and it "
        "never crashes the readiness evaluator",
        level="predicate/unit mutation", extra={"disposition": disposition})

    import tenant_authorization_evidence_guard as TAEG
    import production_database_adapter_evidence_guard as PDAEG

    rec("CE02 redis-queue-cannot-promote",
        EG.dispatch_with(EG.ALL_PASS_READINESS, None).get(EG.QUEUE_CONTROL) == "BLOCKED",
        "redis_queue=pass cannot promote the queue-adapter control through the real dispatch",
        level="evaluator integration")
    rec("CE03 tenant-evidence-cannot-promote",
        EG.dispatch_with(EG.BASE_READINESS, None,
                         TENANT_AUTHORIZATION_EVIDENCE_PATH=TAEG.build_valid_v3(),
                         TENANT_RLS_EVIDENCE_PATH=TAEG.build_valid_v2_rls()
                         ).get(EG.QUEUE_CONTROL) == "BLOCKED",
        "valid tenant-authorization evidence v3 cannot promote the queue-adapter control",
        level="evaluator integration")
    rec("CE04 ui-evidence-cannot-promote",
        EG.probe_with({"schema_version": "dual-backend-ui-certification.v1",
                       "certification": "passed"}) == "BLOCKED",
        "UI evidence cannot promote the queue-adapter control", level="evaluator integration")
    rec("CE05 worker-evidence-cannot-promote",
        EG.probe_with({"schema_version": "restricted-postgres-runtime-worker-import.v1",
                       "certification": "passed"}) == "BLOCKED",
        "worker functional evidence cannot promote the queue-adapter control",
        level="evaluator integration")
    rec("CE06 database-evidence-cannot-promote",
        EG.dispatch_with(EG.BASE_READINESS, None,
                         PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH=PDAEG.build_valid_artifact()
                         ).get(EG.QUEUE_CONTROL) == "BLOCKED",
        "a valid production DATABASE artifact cannot promote the QUEUE-adapter control",
        level="evaluator integration")

    # The lesson from the database increment: prove the ORIGINAL defect would fail this battery.
    consumer_src = (ROOT / "backend" / "app" / "ga_readiness.py").read_text(encoding="utf-8")
    consumer_ast = ast.parse(consumer_src)
    delegates = [
        call for call in ast.walk(consumer_ast)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        and call.func.id == "_delegate"
        and any(isinstance(a, ast.Tuple)
                and any(getattr(e, "value", None) == "redis_queue" for e in a.elts)
                for a in call.args)
    ]
    rec("CE07 delegation-defect-reintroduced-fails", not delegates,
        "the consumer contains no _delegate call passing 'redis_queue'. Reintroducing the delegation "
        "fails this check structurally AND fails CE02/MH01 behaviourally through the real dispatch",
        level="structural source check", extra={"redis_queue_delegations": len(delegates)})

    registry = GA.load_registry()
    entry = next((e for e in registry["blockers"] if e["check_id"] == "ga_redis_adapter"), None)
    rec("CE08 registry-untouched",
        len(registry["blockers"]) == 28 and entry is not None
        and entry["id"] == "production-queue-adapter"
        and not entry.get("allow_not_applicable"),
        "the registry still declares 28 controls and the queue-adapter entry is unchanged: this "
        "increment altered the CONSUMER, not the registry. Its metadata is now stale -- recorded as "
        "a deferred correction, deliberately not edited here",
        level="structural source check")

    # ------------------------------------------------------------------ cross-battery pins
    # An independent review silently removed coverage from the evidence battery two ways that its own
    # self-referential FZ00/FZ01 could not see: (C) delete a mutation, its declared id AND decrement
    # both pins -> green; (D) keep the id but replace the body with a duplicate of an already-covered
    # rejection -> green. Neither battery cross-pinned the other. These two do.
    import contextlib
    import hashlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        EG.checks.clear()
        EG.run()
    ev_checks = list(EG.checks)
    ev_ids = [c["check_id"] for c in ev_checks]
    id_set_hash = hashlib.sha256("\n".join(sorted(ev_ids)).encode("utf-8")).hexdigest()
    rec("FC02 evidence-battery-id-set-pinned",
        id_set_hash == PINNED_EVIDENCE_ID_SET_HASH and len(ev_ids) == PINNED_EVIDENCE_CHECK_COUNT,
        "the evidence battery's emitted check-id set is hashed and pinned HERE, in a different file, "
        "so deleting a mutation together with its declared id and both of its own pins is caught",
        level="structural source check",
        extra={"observed_id_set_hash": id_set_hash[:16] + "...", "observed_count": len(ev_ids)})

    ev_mutations = [c for c in ev_checks if c["check_id"][:2] in EG.MUTATION_PREFIXES]
    # Distinct mutation INPUTS, not distinct reasons. Two mutations may legitimately exercise the
    # same rule through different shapes -- retry_limit=0 and retry_limit=True defeat different
    # guards -- so requiring distinct reasons was over-strict and flagged real coverage as
    # redundant. What must never happen is a mutation whose BODY is a copy of another's, which is
    # exactly what an identical mutated artifact means.
    fps: dict[str, list[str]] = {}
    for c in ev_mutations:
        f = c.get("mutation_fingerprint")
        if isinstance(f, str):
            fps.setdefault(f, []).append(c["check_id"])
    duplicated = {f: ids for f, ids in fps.items() if len(ids) > 1}
    covered = sum(len(ids) for ids in fps.values())
    rec("FC03 evidence-mutations-are-distinct-inputs",
        not duplicated and covered >= PINNED_EVIDENCE_MIN_FINGERPRINTED,
        "every evidence-battery mutation applies a DISTINCT mutated artifact, so substituting an "
        "already-covered rejection for a mutation's body -- which leaves the id list and both counts "
        "untouched -- is caught. Distinct inputs rather than distinct reasons: two mutations may "
        "legitimately exercise one rule through different shapes",
        level="structural source check",
        extra={"fingerprinted_mutations": covered,
               "duplicate_bodies": {f[:12]: ids for f, ids in list(duplicated.items())[:3]}})

    # ------------------------------------------------------------------ completeness
    mutations_so_far = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]
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
    mutation_ids = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]

    print(json.dumps({
        "guard": "audit:production-queue-adapter-contract-faults",
        "claim_scope": "production-queue-adapter-contract-integrity-only",
        "contract_hash": Q.contract_hash(),
        "pinned_contract_hash": PINNED_CONTRACT_HASH,
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "mutations": len(mutation_ids),
                    "non_mutation_checks": len(checks) - len(mutation_ids),
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        "real_production_queue_executed": False,
        "synthetic_artifact_used_for_parser_coverage": True,
        "production_queue_adapter_accepted": False,
        "production_parity": False,
        "docker_used": False,
        "redis_launched": False,
        "eligible_for_readiness": False,
        "queue_execution_verdict": "PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
