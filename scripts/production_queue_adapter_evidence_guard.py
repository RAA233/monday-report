"""audit:production-queue-adapter-evidence -- fail-closed guard for the production queue contract.

Drives the REAL validator (``backend.app.production_queue_adapter_evidence.validate``) and the REAL
readiness dispatch (``ga_readiness.evaluate_blockers``) once per rejection category, and proves the
queue-adapter control is isolated: nothing but a valid production queue artifact moves it.

**No queue, Redis, container, network target or process is contacted.** A fully valid artifact is
*synthesised* so the accept path can be exercised at all -- without it every rejection test would
compare two identical BLOCKED results and prove nothing. It is NOT evidence about any real queue.

Carried forward from the database-adapter increment, where an independent review showed both
batteries could stay green while the original defect was reintroduced: the decisive checks here go
through the real ``evaluate_blockers`` DISPATCH with ``redis_queue="pass"``, not through the probe
helper, because the dispatch is what decides the control.

Honest scope: claim_scope = production-queue-adapter-contract-only;
real_production_queue_executed = false; production_queue_adapter_accepted = false;
production_parity = false; release_recommendation = GA_BLOCKED.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from backend.app import ga_readiness as GA  # noqa: E402
from backend.app import production_queue_adapter_evidence as Q  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("MS", "MT", "MI", "MV", "MD", "MP", "MO", "MH")

COMMIT = Q.git_rev("HEAD")
TREE = Q.git_rev("HEAD^{tree}")
QUEUE_CONTROL = "ga_redis_adapter"
DB_CONTROL = "ga_postgres_adapter"

EXPECTED_CHECK_IDS = [
    # anchors (Part N)
    "FA00 synthetic-valid-artifact-passes", "FA01 no-artifact-blocks",
    "FA02 only-queue-control-moves", "FA03 disposable-redis-artifact-blocks",
    "FA04 redis-queue-pass-blocks", "FA05 tenant-evidence-alone-blocks",
    "FA06 ui-evidence-alone-blocks", "FA07 worker-evidence-alone-blocks",
    "FA08 database-artifact-alone-blocks", "FA09 parity-false-blocks",
    # schema / binding
    "MS01 unknown-schema", "MS02 foreign-database-schema", "MS03 wrong-evidence-type",
    "MS04 wrong-commit", "MS05 wrong-tree", "MS06 abbreviated-commit",
    "MS07 dirty-binding", "MS08 wrong-canonical-hash", "MS09 missing-canonical-hash",
    "MS10 implementation-version-drift", "MS11 artifact-stale-absolute",
    "MS12 git-unavailable-not-accepted",
    # target
    "MT01 provider-unknown", "MT02 environment-test", "MT03 environment-development",
    "MT04 endpoint-loopback", "MT05 endpoint-docker-bridge", "MT06 tls-not-verified",
    "MT07 credential-rotation-absent", "MT08 unsafe-eviction",
    "MT09 durability-on-ephemeral", "MT10 service-fingerprint-absent",
    # identities
    "MI01 runtime-administrative-identity", "MI02 runtime-default-user",
    "MI03 runtime-unauthenticated", "MI04 admin-not-separated",
    "MI05 tenant-namespace-unbound", "MI06 payload-tenant-override-trusted",
    "MI07 local-fallback-permitted",
    # delivery semantics
    "MV01 delivery-model-missing", "MV02 exactly-once-claimed",
    "MV03 retry-limit-absent", "MV04 retry-limit-non-positive",
    "MV05 duplicate-behavior-absent", "MV06 poison-message-not-isolated",
    "MV07 dead-letter-required-but-absent",
    "MV08 at-least-once-without-idempotency-observation",
    "MV09 at-most-once-without-loss-window", "MV10 conditional-domain-without-model",
    # proof domains
    "MD01 missing-proof-domain", "MD02 bare-literal-domain",
    "MD03 non-proving-observation-class", "MD04 queue-ping-as-proof",
    "MD05 failover-by-attestation", "MD06 recovery-by-attestation",
    "MD07 retry-by-attestation", "MD08 dead-letter-by-attestation",
    "MD09 duplicate-by-attestation", "MD10 tls-by-attestation",
    "MD11 acl-by-attestation", "MD12 monitoring-by-attestation",
    "MD13 capacity-by-attestation", "MD14 stale-observation",
    "MD15 future-dated-observation", "MD16 domain-not-pass",
    "MD17 fingerprint-not-sha256", "MD18 unknown-proof-domain",
    # disclosure / parity / privacy
    "MP01 disclosure-missing", "MP02 worker-disclosure-altered",
    "MP03 static-scope-disclosure-altered", "MP04 non-qualifying-list-incomplete",
    "MP05 non-qualifying-source-promoted", "MP06 secret-scan-not-clean",
    "MP07 production-parity-false", "MP08 raw-connection-string-leaked",
    "MP09 raw-queue-key-leaked", "MP10 raw-provider-host-leaked",
    # robustness / isolation
    "MO01 malformed-never-crashes", "MO02 not-an-object", "MO03 unreadable-artifact",
    "MO04 absent-artifact", "MO05 canonical-hash-deterministic",
    "MO06 canonical-hash-covers-substance", "MO07 runner-never-simulates",
    "MO08 runner-refuses-without-target",
    # regression pins (the lesson from the database increment)
    "MH01 readiness-pass-without-artifact", "MH02 delegation-reintroduced-is-caught",
    "MH03 database-consumer-unchanged",
    # structural
    "FS01 consumer-requires-artifact", "FS02 consumer-no-longer-delegates",
    "FS03 guard-drives-real-validator", "FS04 contract-touches-no-queue",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]
EXPECTED_TOTAL_CHECKS = 94
EXPECTED_MUTATION_COUNT = 78


def rec(cid, ok, desc, level="predicate/unit mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def fp(label: str) -> str:
    return hashlib.sha256(f"synthetic-queue-binding:{label}".encode("utf-8")).hexdigest()


def _now() -> datetime:
    """Fixed epoch: the canonical hash must be stable across runs."""
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def domain(label: str, observation_class: str | None = None, observed_days_ago: int = 1,
           status: str = "PASS") -> dict:
    if observation_class is None:
        observation_class = Q.DOMAIN_OBSERVATION_REQUIREMENTS.get(
            label, ("live_target_observation",))[0]
    return {
        "status": status,
        "proven_by": f"observed on the configured production queue target: {label}",
        "observation_class": observation_class,
        "observed_at": (_now() - timedelta(days=observed_days_ago)).isoformat(),
        "binding_fingerprint": fp(label),
    }


def build_valid_artifact() -> dict:
    """A complete, contract-VALID artifact. SYNTHETIC -- describes no real queue.

    Declares ``at-least-once`` so the conditional idempotency domain is exercised.
    """
    payload = {
        "schema_version": Q.SCHEMA_VERSION,
        "implementation_version": Q.IMPLEMENTATION_VERSION,
        "evidence_type": Q.EVIDENCE_TYPE,
        "git_commit": COMMIT,
        "git_tree": TREE,
        "worktree_clean": True,
        "generated_at": _now().isoformat(),
        "target": {
            "provider_classification": "managed-redis-compatible",
            "service_identity_fingerprint": fp("service-identity"),
            "environment_classification": "production",
            "endpoint_classification": "private-network",
            "tls_verified": True,
            "credential_rotation_configured": True,
            "eviction_policy": "noeviction",
            "storage_classification": "durable-replicated",
            "durability_claimed": True,
        },
        "identities": {
            "producer_identity_classification": "dedicated-least-privilege",
            "consumer_worker_identity_classification": "dedicated-least-privilege",
            "administrative_identity_classification": "administrative",
            "administrative_distinct_from_runtime": True,
            "tenant_namespace_bound": True,
            "payload_tenant_override_rejected": True,
            "local_fallback_prevented": True,
        },
        "delivery": {
            "model": "at-least-once",
            "retry_limit": 5,
            "duplicate_delivery_behavior": "deduplicated by job identity at the consumer",
            "poison_message_isolated": True,
            "dead_letter_required": True,
            "dead_letter_disposition": "quarantined to a dead-letter stream after the retry limit",
            "idempotency_contract_compatibility_observed": True,
            "loss_window_disclosed": False,
        },
        "non_qualifying_evidence_disclosure": {
            "worker_test_disclosure": Q.WORKER_TEST_DISCLOSURE,
            "static_validation_disclosure": Q.STATIC_VALIDATION_DISCLOSURE,
            "non_qualifying_sources": list(Q.NON_QUALIFYING_EVIDENCE),
            "promoted_sources": [],
        },
        "proof_domains": {name: domain(name) for name in Q.REQUIRED_PROOF_DOMAINS},
        "secret_scan_clean": True,
        "production_parity": True,
    }
    # at-least-once => the conditional idempotency domain is required
    payload["proof_domains"]["idempotency_interaction"] = domain("idempotency_interaction")
    payload["canonical_payload_hash"] = Q.canonical_hash(payload)
    return payload


def rehash(payload: dict) -> dict:
    payload = copy.deepcopy(payload)
    payload.pop("canonical_payload_hash", None)
    payload["canonical_payload_hash"] = Q.canonical_hash(payload)
    return payload


def mutated(mutate, *, rehash_after=True) -> dict:
    payload = build_valid_artifact()
    mutate(payload)
    return rehash(payload) if rehash_after else payload


def validate(payload) -> list[str]:
    return Q.validate(payload, current_commit=COMMIT, current_tree=TREE, now=_now())


def rejects(mutate, *, rehash_after=True) -> tuple[bool, list[str]]:
    reasons = validate(mutated(mutate, rehash_after=rehash_after))
    return bool(reasons), reasons


def probe_with(artifact) -> str:
    original = GA.PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH
    tmp = Path(tempfile.mkdtemp(prefix="pqae-probe-"))
    try:
        target = tmp / "artifact.json"
        if artifact is not None:
            target.write_text(json.dumps(artifact) if not isinstance(artifact, str) else artifact,
                              encoding="utf-8")
        GA.PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH = target
        return GA._queue_adapter_probe()[0]
    finally:
        GA.PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH = original
        shutil.rmtree(tmp, ignore_errors=True)


def dispatch_with(readiness: dict, queue_artifact=None, **other_paths) -> dict[str, str]:
    """Full 28-control map through the REAL evaluate_blockers dispatch."""
    saved = {"PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH":
             GA.PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH}
    for name in other_paths:
        saved[name] = getattr(GA, name)
    tmp = Path(tempfile.mkdtemp(prefix="pqae-dispatch-"))
    try:
        qpath = tmp / "queue.json"
        if queue_artifact is not None:
            qpath.write_text(json.dumps(queue_artifact), encoding="utf-8")
        GA.PRODUCTION_QUEUE_ADAPTER_EVIDENCE_PATH = qpath
        for name, payload in other_paths.items():
            p = tmp / f"{name}.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            setattr(GA, name, p)
        return {c["id"]: c["disposition"]
                for c in GA.evaluate_blockers(dict(readiness), forge_report=None)}
    finally:
        for name, original in saved.items():
            setattr(GA, name, original)
        shutil.rmtree(tmp, ignore_errors=True)


BASE_READINESS = {"redis_queue": "fail", "postgres_repository": "fail",
                  "local_llm_runtime": "fail", "demo_seed_removed": "fail"}
ALL_PASS_READINESS = {"redis_queue": "pass", "postgres_repository": "pass",
                      "local_llm_runtime": "pass", "demo_seed_removed": "pass",
                      "client_mode": "pass"}


def run() -> int:
    valid = build_valid_artifact()

    # ------------------------------------------------------------------ anchors
    baseline = validate(valid)
    rec("FA00 synthetic-valid-artifact-passes", baseline == [],
        "ANCHOR: a complete synthetic artifact validates, so every rejection below is "
        "discriminating. Scope: the contract validates DECLARATIONS -- structure, provenance class, "
        "binding, freshness -- and cannot verify that a declared observation occurred, so this "
        "fixture proves parser/accept-path coverage only",
        level="evaluator integration", extra={"reasons": baseline[:4]})

    disp_none = dispatch_with(BASE_READINESS, None)
    disp_valid = dispatch_with(BASE_READINESS, valid)
    rec("FA01 no-artifact-blocks", disp_none.get(QUEUE_CONTROL) == "BLOCKED",
        "case A: with no production queue artifact the control is BLOCKED",
        level="evaluator integration")
    changed = sorted(k for k in disp_valid if disp_valid[k] != disp_none.get(k))
    rec("FA02 only-queue-control-moves", changed == [QUEUE_CONTROL],
        "case D differential: a valid production queue artifact changes EXACTLY the queue-adapter "
        "control; every other control is canonically identical",
        level="evaluator integration", extra={"changed_controls": changed})

    disposable = rehash({**copy.deepcopy(valid), "target": {
        **copy.deepcopy(valid["target"]),
        "environment_classification": "test",
        "endpoint_classification": "docker-bridge",
        "storage_classification": "ephemeral-only",
        "tls_verified": False,
        "eviction_policy": "allkeys-lru",
    }})
    rec("FA03 disposable-redis-artifact-blocks", probe_with(disposable) == "BLOCKED",
        "case B: an artifact describing a disposable Docker Redis as it really is (test environment, "
        "Docker-bridge endpoint, ephemeral-only storage, unverified TLS, evicting policy) is BLOCKED",
        level="evaluator integration")

    rec("FA04 redis-queue-pass-blocks",
        dispatch_with(ALL_PASS_READINESS, None).get(QUEUE_CONTROL) == "BLOCKED",
        "redis_queue=pass -- which a Docker Redis answering PING produces -- does NOT promote the "
        "queue-adapter control",
        level="evaluator integration")

    import tenant_authorization_evidence_guard as TAEG
    import production_database_adapter_evidence_guard as PDAEG

    rec("FA05 tenant-evidence-alone-blocks",
        dispatch_with(BASE_READINESS, None,
                      TENANT_AUTHORIZATION_EVIDENCE_PATH=TAEG.build_valid_v3(),
                      TENANT_RLS_EVIDENCE_PATH=TAEG.build_valid_v2_rls()
                      ).get(QUEUE_CONTROL) == "BLOCKED",
        "a VALID tenant-authorization evidence v3 plus RLS sub-proof at their own real paths leaves "
        "the queue-adapter control BLOCKED",
        level="evaluator integration")
    rec("FA06 ui-evidence-alone-blocks",
        probe_with({"schema_version": "dual-backend-ui-certification.v1", "certification": "passed",
                    "local_backend_certified": True,
                    "restricted_postgres_backend_certified": True}) == "BLOCKED",
        "a passing dual-backend UI certification cannot satisfy the queue-adapter control "
        "(stub payload, so a weaker form of the test than FA05)",
        level="evaluator integration")
    rec("FA07 worker-evidence-alone-blocks",
        probe_with({"schema_version": "restricted-postgres-runtime-worker-import.v1",
                    "certification": "passed", "passed": 29, "failed": 0,
                    "normal_worker_process_failures": 0}) == "BLOCKED",
        "a passing restricted worker/import functional matrix cannot satisfy the queue-adapter "
        "control -- worker behaviour in test infrastructure is not queue production evidence",
        level="evaluator integration")
    rec("FA08 database-artifact-alone-blocks",
        dispatch_with(BASE_READINESS, None,
                      PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH=PDAEG.build_valid_artifact()
                      ).get(QUEUE_CONTROL) == "BLOCKED",
        "a VALID production DATABASE-adapter artifact leaves the QUEUE-adapter control BLOCKED: the "
        "two adapters are independently evidenced",
        level="evaluator integration")
    rec("FA09 parity-false-blocks",
        probe_with(rehash({**copy.deepcopy(valid), "production_parity": False})) == "BLOCKED",
        "case C: a structurally valid artifact with production_parity=false remains BLOCKED",
        level="evaluator integration")

    # ------------------------------------------------------------------ schema / binding
    for cid, mutate, desc in (
        ("MS01 unknown-schema", lambda p: p.__setitem__("schema_version", "queue.v9"),
         "an unknown schema id is rejected"),
        ("MS02 foreign-database-schema",
         lambda p: p.__setitem__("schema_version", "production-database-adapter-evidence.v1"),
         "the production DATABASE schema presented at the queue path is rejected"),
        ("MS03 wrong-evidence-type",
         lambda p: p.__setitem__("evidence_type", "production-database-adapter"),
         "a wrong evidence_type is rejected"),
        ("MS04 wrong-commit", lambda p: p.__setitem__("git_commit", "0" * 40),
         "an artifact bound to a different commit is rejected as stale"),
        ("MS05 wrong-tree", lambda p: p.__setitem__("git_tree", "1" * 40),
         "an artifact bound to a different tree is rejected as stale"),
        ("MS06 abbreviated-commit", lambda p: p.__setitem__("git_commit", COMMIT[:12]),
         "an abbreviated commit binding is rejected"),
        ("MS07 dirty-binding", lambda p: p.__setitem__("worktree_clean", False),
         "an artifact not attesting a clean worktree is rejected"),
        ("MS10 implementation-version-drift",
         lambda p: p.__setitem__("implementation_version", "0.0.1"),
         "an implementation_version drifting from the contract module is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    ok, _ = rejects(lambda p: p.__setitem__("canonical_payload_hash", "a" * 64), rehash_after=False)
    rec("MS08 wrong-canonical-hash", ok, "a canonical hash not matching the body is rejected")
    ok, _ = rejects(lambda p: p.pop("canonical_payload_hash"), rehash_after=False)
    rec("MS09 missing-canonical-hash", ok, "a missing canonical hash is rejected")
    rec("MS11 artifact-stale-absolute",
        bool(Q.validate(build_valid_artifact(), current_commit=COMMIT, current_tree=TREE,
                        now=_now() + timedelta(days=400))),
        "an artifact old in ABSOLUTE time is rejected -- the staleness limit is not measured only "
        "against the artifact's own self-declared generation date")

    real_git = Q._git
    try:
        Q._git = lambda args: Q.GIT_UNAVAILABLE
        unverifiable = Q.validate(build_valid_artifact(), now=_now())
    finally:
        Q._git = real_git
    rec("MS12 git-unavailable-not-accepted", bool(unverifiable),
        "when git cannot be consulted the binding is UNVERIFIABLE and the artifact is rejected -- it "
        "does not fail open into 'clean worktree, binding skipped'",
        extra={"first_reason": unverifiable[0] if unverifiable else None})

    # ------------------------------------------------------------------ target
    def tgt(field, value):
        return lambda p: p["target"].__setitem__(field, value)

    for cid, mutate, desc in (
        ("MT01 provider-unknown", tgt("provider_classification", "unknown"),
         "an unknown provider is rejected: an unidentified target is not auditable"),
        ("MT02 environment-test", tgt("environment_classification", "test"),
         "a test environment is rejected"),
        ("MT03 environment-development", tgt("environment_classification", "development"),
         "a development environment is rejected"),
        ("MT04 endpoint-loopback", tgt("endpoint_classification", "loopback"),
         "a loopback endpoint is rejected"),
        ("MT05 endpoint-docker-bridge", tgt("endpoint_classification", "docker-bridge"),
         "a Docker-bridge endpoint is rejected"),
        ("MT06 tls-not-verified", tgt("tls_verified", False),
         "an unverified TLS session is rejected"),
        ("MT07 credential-rotation-absent", tgt("credential_rotation_configured", False),
         "absent credential rotation is rejected"),
        ("MT08 unsafe-eviction", tgt("eviction_policy", "allkeys-lru"),
         "an eviction policy that can silently discard a queued job is rejected"),
        ("MT09 durability-on-ephemeral", tgt("storage_classification", "ephemeral-only"),
         "claiming durability on ephemeral-only storage is rejected"),
        ("MT10 service-fingerprint-absent",
         lambda p: p["target"].pop("service_identity_fingerprint"),
         "a missing service identity fingerprint is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ identities
    def ident(field, value):
        return lambda p: p["identities"].__setitem__(field, value)

    for cid, mutate, desc in (
        ("MI01 runtime-administrative-identity",
         ident("consumer_worker_identity_classification", "administrative"),
         "an administrative runtime consumer identity is rejected"),
        ("MI02 runtime-default-user", ident("producer_identity_classification", "default-user"),
         "a default-user runtime producer identity is rejected"),
        ("MI03 runtime-unauthenticated",
         ident("producer_identity_classification", "unauthenticated"),
         "an unauthenticated runtime identity is rejected"),
        ("MI04 admin-not-separated", ident("administrative_distinct_from_runtime", False),
         "an administrative identity not separated from the runtime identity is rejected"),
        ("MI05 tenant-namespace-unbound", ident("tenant_namespace_bound", False),
         "a shared namespace without per-tenant/job binding is rejected"),
        ("MI06 payload-tenant-override-trusted", ident("payload_tenant_override_rejected", False),
         "trusting a tenant supplied in the job payload is rejected"),
        ("MI07 local-fallback-permitted", ident("local_fallback_prevented", False),
         "permitting silent fallback to a local/in-memory queue is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ delivery semantics
    def dlv(field, value):
        return lambda p: p["delivery"].__setitem__(field, value)

    for cid, mutate, desc in (
        ("MV01 delivery-model-missing", lambda p: p["delivery"].pop("model"),
         "an artifact that does not state its delivery model is rejected"),
        ("MV02 exactly-once-claimed", dlv("model", "exactly-once"),
         "claiming exactly-once delivery is rejected: nothing in this repository implements it"),
        ("MV03 retry-limit-absent", dlv("retry_limit", None),
         "an absent retry limit is rejected"),
        ("MV04 retry-limit-non-positive", dlv("retry_limit", 0),
         "a non-positive retry limit is rejected"),
        ("MV05 duplicate-behavior-absent", dlv("duplicate_delivery_behavior", "unspecified"),
         "undeclared duplicate-delivery behavior is rejected"),
        ("MV06 poison-message-not-isolated", dlv("poison_message_isolated", False),
         "a queue where one poison message can block processing is rejected"),
        ("MV07 dead-letter-required-but-absent", dlv("dead_letter_disposition", None),
         "a required dead-letter disposition that is not declared is rejected"),
        ("MV08 at-least-once-without-idempotency-observation",
         dlv("idempotency_contract_compatibility_observed", False),
         "at-least-once delivery without OBSERVED compatibility with the application idempotency "
         "contract is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    def to_at_most_once(p, loss_window: bool):
        p["delivery"]["model"] = "at-most-once"
        p["delivery"]["loss_window_disclosed"] = loss_window
        p["proof_domains"].pop("idempotency_interaction", None)

    ok, reasons = rejects(lambda p: to_at_most_once(p, False))
    rec("MV09 at-most-once-without-loss-window", ok,
        "at-most-once delivery without disclosing the loss window and its compensating "
        "re-derivation mechanism is rejected -- which is what the current LPOP-before-processing "
        "implementation actually is",
        extra={"first_reason": reasons[0] if reasons else None})
    ok, reasons = rejects(lambda p: to_at_most_once(p, True) or p["proof_domains"].__setitem__(
        "idempotency_interaction", domain("idempotency_interaction")))
    rec("MV10 conditional-domain-without-model", ok,
        "the conditional idempotency domain present WITHOUT declaring at-least-once is rejected",
        extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ proof domains
    attestation = "signed_operator_attestation"
    for cid, mutate, desc in (
        ("MD01 missing-proof-domain", lambda p: p["proof_domains"].pop("failover_drill"),
         "a missing required proof domain is rejected -- never treated as NOT_APPLICABLE"),
        ("MD02 bare-literal-domain",
         lambda p: p["proof_domains"].__setitem__("replication", True),
         "a bare boolean in place of a proof domain is rejected"),
        ("MD03 non-proving-observation-class",
         lambda p: p["proof_domains"].__setitem__(
             "queue_engine_and_version", domain("engine", observation_class="repository_setting")),
         "a PASS from a repository setting is rejected"),
        ("MD04 queue-ping-as-proof",
         lambda p: p["proof_domains"].__setitem__(
             "network_boundary", domain("net", observation_class="queue_reachability_ping")),
         "a PASS from a queue reachability PING is rejected -- the defect this contract closes"),
        ("MD05 failover-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "failover_drill", domain("failover", observation_class=attestation)),
         "failover claimed by attestation rather than an EXECUTED drill is rejected"),
        ("MD06 recovery-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "recovery_behavior", domain("recovery", observation_class=attestation)),
         "recovery claimed by attestation rather than an executed drill is rejected"),
        ("MD07 retry-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "retry_and_backoff_policy", domain("retry", observation_class=attestation)),
         "retry behaviour claimed by attestation rather than an executed delivery/retry test is "
         "rejected"),
        ("MD08 dead-letter-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "dead_letter_behavior", domain("dlq", observation_class=attestation)),
         "dead-letter behaviour claimed by attestation rather than an executed poison-message test "
         "is rejected"),
        ("MD09 duplicate-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "duplicate_delivery_handling", domain("dup", observation_class=attestation)),
         "duplicate handling claimed by attestation rather than an executed duplicate-delivery test "
         "is rejected"),
        ("MD10 tls-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "tls_and_certificate_verification", domain("tls", observation_class=attestation)),
         "TLS claimed by attestation rather than an observed verified session is rejected"),
        ("MD11 acl-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "acl_or_authorization_model", domain("acl", observation_class=attestation)),
         "the authorization model claimed by attestation rather than an observed authenticated "
         "server identity is rejected"),
        ("MD12 monitoring-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "monitoring_and_alerting", domain("mon", observation_class=attestation)),
         "monitoring claimed by attestation rather than an observed alert-delivery test is rejected"),
        ("MD13 capacity-by-attestation",
         lambda p: p["proof_domains"].__setitem__(
             "capacity_and_throughput_thresholds",
             domain("cap", observation_class=attestation)),
         "capacity thresholds claimed by attestation rather than an observed threshold plus load "
         "result are rejected"),
        ("MD14 stale-observation",
         lambda p: p["proof_domains"].__setitem__(
             "replication", domain("replication", observed_days_ago=400)),
         "an observation older than the staleness limit is rejected"),
        ("MD15 future-dated-observation",
         lambda p: p["proof_domains"].__setitem__(
             "replication", domain("replication", observed_days_ago=-30)),
         "an observation dated after generation is rejected"),
        ("MD16 domain-not-pass",
         lambda p: p["proof_domains"].__setitem__(
             "ordering_guarantees", domain("ordering", status="NOT_PROVEN")),
         "a domain that is not PASS is rejected"),
        ("MD17 fingerprint-not-sha256",
         lambda p: p["proof_domains"]["replication"].__setitem__("binding_fingerprint", "xyz"),
         "a PASS without a full SHA-256 binding fingerprint is rejected"),
        ("MD18 unknown-proof-domain",
         lambda p: p["proof_domains"].__setitem__("invented_domain", domain("nope")),
         "an unknown proof domain is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ disclosure / parity / privacy
    for cid, mutate, desc in (
        ("MP01 disclosure-missing",
         lambda p: p.pop("non_qualifying_evidence_disclosure"),
         "a missing non-qualifying-evidence disclosure block is rejected"),
        ("MP02 worker-disclosure-altered",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "worker_test_disclosure", "the worker tests prove production readiness"),
         "an altered worker/disposable-queue disclosure is rejected"),
        ("MP03 static-scope-disclosure-altered",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "static_validation_disclosure", "static validation proves the observation occurred"),
         "an altered static-validation scope disclosure is rejected"),
        ("MP04 non-qualifying-list-incomplete",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "non_qualifying_sources", ["unit tests"]),
         "an incomplete non-qualifying-source list is rejected"),
        ("MP05 non-qualifying-source-promoted",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "promoted_sources", ["disposable Docker Redis"]),
         "promoting a non-qualifying source as production proof is rejected"),
        ("MP06 secret-scan-not-clean", lambda p: p.__setitem__("secret_scan_clean", False),
         "a non-clean secret scan is rejected"),
        ("MP07 production-parity-false", lambda p: p.__setitem__("production_parity", False),
         "production_parity=false is rejected, keeping the evidence non-accepting"),
        ("MP08 raw-connection-string-leaked",
         lambda p: p["target"].__setitem__("note", "rediss://user@cache-1:6380/0"),
         "a raw queue connection string in the artifact is rejected"),
        ("MP09 raw-queue-key-leaked",
         lambda p: p["target"].__setitem__("note", "key monday-report:processing-jobs"),
         "a raw queue key in the artifact is rejected"),
        ("MP10 raw-provider-host-leaked",
         lambda p: p["target"].__setitem__("note", "q1.cache.amazonaws.com"),
         "a raw provider hostname in the artifact is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ robustness
    hostile = [None, 7, "s", [], {}, {"schema_version": Q.SCHEMA_VERSION},
               {"proof_domains": "x"}, {"target": 1}, {"identities": []}, {"delivery": "no"}]
    bad = []
    for item in hostile:
        try:
            result = Q.validate(item, current_commit=COMMIT, current_tree=TREE, now=_now())
            if not isinstance(result, list) or not result:
                bad.append(repr(item)[:24])
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{type(item).__name__}:{exc.__class__.__name__}")
    rec("MO01 malformed-never-crashes", bad == [],
        "every hostile payload shape returns a non-empty reason list; the validator never raises and "
        "never accepts", level="schema mutation", extra={"crashed_or_accepted": bad})
    rec("MO02 not-an-object", bool(Q.validate([1, 2])), "a non-object artifact is rejected",
        level="schema mutation")
    rec("MO03 unreadable-artifact", probe_with("{bad json") == "BLOCKED",
        "an unreadable artifact leaves the control BLOCKED rather than crashing the evaluator",
        level="evaluator integration")
    rec("MO04 absent-artifact", probe_with(None) == "BLOCKED",
        "an absent artifact leaves the control BLOCKED", level="evaluator integration")
    rec("MO05 canonical-hash-deterministic",
        len({Q.canonical_hash(build_valid_artifact()) for _ in range(3)}) == 1,
        "the canonical hash is deterministic across repeated computation",
        level="schema mutation", extra={"canonical_hash": Q.canonical_hash(valid)})
    moved = copy.deepcopy(valid)
    moved["delivery"]["retry_limit"] = 9
    meta = copy.deepcopy(valid)
    meta["generated_at"] = "2000-01-01T00:00:00+00:00"
    rec("MO06 canonical-hash-covers-substance",
        Q.canonical_hash(moved) != Q.canonical_hash(valid)
        and Q.canonical_hash(meta) == Q.canonical_hash(valid),
        "the canonical hash changes on substance and is stable across excluded generation metadata",
        level="schema mutation")
    for cid, result, desc in (
        ("MO07 runner-never-simulates", Q.generate(None),
         "generate() never returns a simulated artifact"),
        ("MO08 runner-refuses-without-target", Q.collect(None),
         "collect() refuses without an explicit production target and never auto-discovers "
         "developer/Docker Redis, loopback services or unrelated containers"),
    ):
        rec(cid, result.get("artifact") is None
            and result.get("certification") == "unavailable"
            and result.get("production_queue_executed") is False
            and result.get("production_queue_adapter_accepted") is False,
            desc, level="schema mutation")

    # ------------------------------------------------------------------ regression pins
    rec("MH01 readiness-pass-without-artifact",
        dispatch_with(ALL_PASS_READINESS, None).get(QUEUE_CONTROL) == "BLOCKED",
        "REGRESSION PIN: with EVERY readiness check passing -- including redis_queue, which a "
        "disposable Redis answering PING satisfies -- and NO production artifact, the control is "
        "BLOCKED through the real evaluate_blockers dispatch",
        level="evaluator integration")

    consumer_src = (ROOT / "backend" / "app" / "ga_readiness.py").read_text(encoding="utf-8")
    consumer_ast = ast.parse(consumer_src)
    delegates_to_redis = any(
        any(isinstance(a, ast.Tuple)
            and any(getattr(e, "value", None) == "redis_queue" for e in a.elts)
            for a in call.args)
        for call in ast.walk(consumer_ast)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        and call.func.id == "_delegate")
    rec("MH02 delegation-reintroduced-is-caught", not delegates_to_redis,
        "no _delegate call in the consumer passes 'redis_queue': reintroducing the delegation is "
        "caught structurally as well as behaviourally (MH01)",
        level="structural source check")
    rec("MH03 database-consumer-unchanged",
        dispatch_with(ALL_PASS_READINESS, valid).get(DB_CONTROL) == "BLOCKED",
        "a valid QUEUE artifact does not move the DATABASE-adapter control: the two consumers stay "
        "isolated",
        level="evaluator integration")

    # ------------------------------------------------------------------ structural
    probe_fn = next((n for n in consumer_ast.body
                     if isinstance(n, ast.FunctionDef) and n.name == "_queue_adapter_probe"), None)
    rec("FS01 consumer-requires-artifact",
        probe_fn is not None and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_production_queue_adapter_reasons" for n in ast.walk(probe_fn)),
        "the readiness consumer resolves the queue-adapter control through the production queue "
        "contract, verified on the parsed source", level="structural source check")
    rec("FS02 consumer-no-longer-delegates", not delegates_to_redis,
        "the queue-adapter control no longer delegates to the readiness check 'redis_queue'",
        level="structural source check")

    own_ast = ast.parse((ROOT / "scripts" / "production_queue_adapter_evidence_guard.py")
                        .read_text(encoding="utf-8"))
    rejects_fn = next((n for n in own_ast.body
                       if isinstance(n, ast.FunctionDef) and n.name == "validate"), None)
    rec("FS03 guard-drives-real-validator",
        any(isinstance(n, ast.ImportFrom) and n.module == "backend.app"
            and any(a.name == "production_queue_adapter_evidence" for a in n.names)
            for n in own_ast.body)
        and rejects_fn is not None and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "validate" and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "Q" for n in ast.walk(rejects_fn)),
        "this guard imports the real contract module and drives the real validate(); it does not "
        "re-implement the rules it tests", level="structural source check")

    contract_ast = ast.parse((ROOT / "backend" / "app" / "production_queue_adapter_evidence.py")
                             .read_text(encoding="utf-8"))
    queue_modules = {"redis", "rediscluster", "kombu", "celery", "pika", "boto3", "requests",
                     "httpx", "socket", "psycopg"}
    imported: list[str] = []
    for node in ast.walk(contract_ast):
        if isinstance(node, ast.Import):
            imported += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".")[0])
    touched = sorted(set(imported) & queue_modules)
    rec("FS04 contract-touches-no-queue", touched == [],
        "the contract module imports no queue client, broker library, cloud SDK, HTTP client or "
        "socket library, so validating an artifact cannot reach a queue. It DOES use git via "
        "subprocess to verify the commit/tree binding -- disclosed, not denied",
        level="structural source check", extra={"queue_imports": touched})

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
        "guard": "audit:production-queue-adapter-evidence",
        "claim_scope": "production-queue-adapter-contract-only",
        "contract_hash": Q.contract_hash(),
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
