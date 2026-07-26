"""Production queue-adapter evidence contract (``production-queue-adapter-evidence.v1``).

Sibling of ``production_database_adapter_evidence`` and built for the same reason: the
``production-queue-adapter`` control was satisfied by a Redis that answers ``PING``.

What the repository's queue layer actually is
--------------------------------------------
Read ``backend/app/queue_backend.py`` before believing anything about durability. The queue is a
**best-effort index over authoritative store state**, not a broker:

* enqueue is ``SADD`` (dedupe set) followed by ``RPUSH`` (list) as **two separate commands** -- no
  MULTI, no Lua -- so a crash between them marks the job queued while nothing is listed;
* dequeue is ``LPOP`` then ``SREM``. There is **no claim, no lease, no visibility timeout and no
  acknowledgement**: the id leaves Redis *before* the job is processed, so a worker that dies mid-job
  loses that delivery. Recovery is not a queue property here -- it is ``sync_processing_queue()``
  re-deriving the list from the store;
* the queue holds a bare job UUID and **one globally shared key**. There is no per-tenant namespace,
  and the tenant is never read from the payload (it comes from the worker process environment), so
  payload-driven tenant override is structurally impossible -- which is a genuine strength;
* there is no retry counter, no dead-letter list, no backoff, no pooling and no TLS configuration in
  the client (``redis.Redis.from_url`` with timeouts, created fresh per call);
* when the backend is not Redis every queue function is a no-op: the ``inline_worker`` path has no
  queue at all.

So the honest delivery model of the current implementation is **at-most-once from the queue**, with
store re-derivation as the compensating mechanism. This contract therefore does not assume a broker:
it makes the artifact *declare* its delivery model and then demands the evidence that model implies.
Claiming exactly-once is rejected outright -- nothing here implements it.

Design rules
------------
* **Declared delivery model drives the requirements.** ``at-least-once`` requires observed
  compatibility with the application's idempotency contract; ``at-most-once`` requires the loss
  window to be disclosed and a compensating re-derivation proof.
* **Domain-specific provenance.** A failover claim needs an *executed failover drill*; dead-letter
  behaviour needs an *executed poison-message test*; duplicate handling needs an *executed
  duplicate-delivery test*. A generic attestation cannot satisfy an executed-drill domain.
* **Privacy by construction.** No host, port, account, project, resource name, username, credential,
  connection string, queue key, tenant value or container identifier is carried -- classifications
  and non-reversible fingerprints only.
* **``production_parity=false`` keeps the evidence non-accepting.** That is the honest state today.

Scope limit, stated because it is easy to overread:

    Static validation proves evidence structure, binding, provenance class,
    freshness, and internal consistency. It does not independently prove that
    a declared production observation actually occurred.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

SCHEMA_VERSION = "production-queue-adapter-evidence.v1"
IMPLEMENTATION_VERSION = "1.0.0"
EVIDENCE_TYPE = "production-queue-adapter"

REJECTED_SCHEMA_VERSIONS: tuple[str, ...] = (
    "production-queue-adapter-evidence.v0",
    "production-database-adapter-evidence.v1",
    "tenant-authorization-evidence.v3",
    "tenant-rls-enforcement-evidence.v2",
)

EVIDENCE_PATH = ROOT / "output" / "production-queue-adapter" / f"{SCHEMA_VERSION}.json"

STATIC_VALIDATION_DISCLOSURE = (
    "Static validation proves evidence structure, binding, provenance class, "
    "freshness, and internal consistency. It does not independently prove that "
    "a declared production observation actually occurred."
)

# --------------------------------------------------------------------------------------------
# Proof domains. All required; a missing domain is a rejection, never NOT_APPLICABLE.
# --------------------------------------------------------------------------------------------
REQUIRED_PROOF_DOMAINS: tuple[str, ...] = (
    "platform_and_service_identity",
    "provider_and_environment_classification",
    "queue_engine_and_version",
    "network_boundary",
    "tls_and_certificate_verification",
    "credential_source",
    "credential_rotation",
    "acl_or_authorization_model",
    "producer_identity",
    "consumer_worker_identity",
    "administrative_identity_separation",
    "tenant_and_job_namespace_isolation",
    "payload_trust_boundary",
    "local_fallback_prevention",
    "enqueue_semantics",
    "claim_or_lease_semantics",
    "acknowledgement_semantics",
    "delivery_guarantee",
    "retry_and_backoff_policy",
    "duplicate_delivery_handling",
    "poison_message_isolation",
    "dead_letter_behavior",
    "ordering_guarantees",
    "concurrency_behavior",
    "durability_or_persistence_model",
    "replication",
    "failover_drill",
    "recovery_behavior",
    "eviction_and_memory_policy",
    "connection_limits_and_timeouts",
    "capacity_and_throughput_thresholds",
    "latency_objectives",
    "monitoring_and_alerting",
    "maintenance_and_upgrade_process",
    "incident_and_rollback_process",
    "retention_and_deletion_policy",
    "secret_scan",
)

#: Required only when the declared delivery model is ``at-least-once``: a redelivery is only safe if
#: the application's idempotency contract absorbs it, and that has to be observed, not assumed.
CONDITIONAL_PROOF_DOMAINS: tuple[str, ...] = ("idempotency_interaction",)

# --------------------------------------------------------------------------------------------
# Observation classes. Deliberately more specific than the database contract: a queue's
# availability properties are events, and an event is proven by having run it.
# --------------------------------------------------------------------------------------------
PROVING_OBSERVATION_CLASSES: tuple[str, ...] = (
    "live_target_observation",
    "provider_control_plane_response",
    "observed_verified_session",
    "observed_authenticated_server_identity",
    "executed_failover_drill",
    "executed_recovery_drill",
    "executed_delivery_retry_test",
    "executed_poison_message_test",
    "executed_duplicate_delivery_test",
    "executed_idempotency_test",
    "observed_alert_delivery_test",
    "observed_threshold_plus_load_result",
    "signed_operator_attestation",
)

NON_PROVING_OBSERVATION_CLASSES: tuple[str, ...] = (
    "repository_setting",
    "literal_assertion",
    "documentation_only",
    "test_fixture",
    "assumed_default",
    "queue_reachability_ping",   # named explicitly: this is the defect being closed
    "unspecified",
)

#: Per-domain provenance. A generic ``signed_operator_attestation`` deliberately does NOT appear in
#: any executed-drill entry: an operator asserting that failover works is not a failover drill.
DOMAIN_OBSERVATION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "failover_drill": ("executed_failover_drill",),
    "recovery_behavior": ("executed_recovery_drill",),
    "retry_and_backoff_policy": ("executed_delivery_retry_test",),
    "duplicate_delivery_handling": ("executed_duplicate_delivery_test",),
    "poison_message_isolation": ("executed_poison_message_test",),
    "dead_letter_behavior": ("executed_poison_message_test",),
    "idempotency_interaction": ("executed_idempotency_test",),
    "tls_and_certificate_verification": ("observed_verified_session",),
    "acl_or_authorization_model": ("observed_authenticated_server_identity",),
    "monitoring_and_alerting": ("observed_alert_delivery_test",),
    "capacity_and_throughput_thresholds": ("observed_threshold_plus_load_result",),
    "latency_objectives": ("observed_threshold_plus_load_result",
                           "live_target_observation"),
    "durability_or_persistence_model": ("live_target_observation",
                                        "provider_control_plane_response"),
    "replication": ("live_target_observation", "provider_control_plane_response"),
    "eviction_and_memory_policy": ("live_target_observation",
                                   "provider_control_plane_response"),
    "network_boundary": ("live_target_observation", "provider_control_plane_response"),
    "queue_engine_and_version": ("live_target_observation",),
    "connection_limits_and_timeouts": ("live_target_observation",),
    "producer_identity": ("live_target_observation",),
    "consumer_worker_identity": ("live_target_observation",),
    "administrative_identity_separation": ("live_target_observation",),
    "tenant_and_job_namespace_isolation": ("live_target_observation",),
    "local_fallback_prevention": ("live_target_observation",),
    "enqueue_semantics": ("live_target_observation",),
    "claim_or_lease_semantics": ("live_target_observation",),
    "acknowledgement_semantics": ("live_target_observation",),
    "delivery_guarantee": ("live_target_observation", "executed_delivery_retry_test"),
    "secret_scan": ("executed_delivery_retry_test", "live_target_observation"),
}

REQUIRED_DOMAIN_FIELDS: tuple[str, ...] = (
    "status", "proven_by", "observation_class", "observed_at", "binding_fingerprint",
)
DOMAIN_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "BLOCKED", "NOT_PROVEN")
MAX_OBSERVATION_AGE_DAYS = 90

# --------------------------------------------------------------------------------------------
# Delivery model. The artifact states what it really is; the contract then demands what that implies.
# --------------------------------------------------------------------------------------------
DELIVERY_MODELS: tuple[str, ...] = (
    "at-most-once", "at-least-once", "exactly-once-not-claimed",
)
#: Claiming exactly-once is rejected: nothing in this repository implements it, and an unprovable
#: guarantee in an evidence artifact is worse than no claim at all.
REJECTED_DELIVERY_MODELS: tuple[str, ...] = ("exactly-once",)

# --------------------------------------------------------------------------------------------
# Provider / target classification -- provider-neutral, as the repository selects none.
# --------------------------------------------------------------------------------------------
PROVIDER_CLASSIFICATIONS: tuple[str, ...] = (
    "managed-redis-compatible", "self-managed-redis-compatible", "managed-queue-service", "unknown",
)
REJECTED_PROVIDER_CLASSIFICATIONS: tuple[str, ...] = ("unknown",)

ENVIRONMENT_CLASSIFICATIONS: tuple[str, ...] = ("production", "staging", "test", "development")
REJECTED_ENVIRONMENTS: tuple[str, ...] = ("staging", "test", "development")

ENDPOINT_CLASSIFICATIONS: tuple[str, ...] = (
    "private-network", "public-with-allowlist", "loopback", "docker-bridge", "unknown",
)
REJECTED_ENDPOINT_CLASSIFICATIONS: tuple[str, ...] = ("loopback", "docker-bridge", "unknown")

STORAGE_CLASSIFICATIONS: tuple[str, ...] = (
    "durable-replicated", "durable-single", "ephemeral-only",
)

EVICTION_POLICY_CLASSIFICATIONS: tuple[str, ...] = (
    "noeviction", "volatile-ttl", "allkeys-lru", "allkeys-random", "volatile-lru", "unknown",
)
#: An eviction policy that can silently drop a *queued job* is unsafe for a work queue.
UNSAFE_EVICTION_POLICIES: tuple[str, ...] = (
    "allkeys-lru", "allkeys-random", "volatile-lru", "volatile-ttl", "unknown",
)

QUEUE_IDENTITY_CLASSIFICATIONS: tuple[str, ...] = (
    "dedicated-least-privilege", "shared-application", "administrative", "default-user",
    "unauthenticated",
)
REJECTED_RUNTIME_IDENTITIES: tuple[str, ...] = ("administrative", "default-user", "unauthenticated")

# --------------------------------------------------------------------------------------------
NON_QUALIFYING_EVIDENCE: tuple[str, ...] = (
    "disposable Docker Redis",
    "local or in-memory queue",
    "restricted worker functional matrix",
    "worker process-boundary tenant-isolation proof",
    "tenant-authorization evidence v3",
    "dual-backend UI evidence",
    "queue reachability or PING",
    "repository configuration defaults",
    "environment-variable presence",
    "unit tests",
    "mocked provider metadata",
    "synthetic parser-coverage artifact",
)

WORKER_TEST_DISCLOSURE = (
    "The accepted worker and disposable-queue tests prove software behavior, "
    "tenant boundaries, retry handling, and fail-closed operation in controlled "
    "test infrastructure. They do not prove the availability, durability, "
    "identity provisioning, network, TLS, capacity, monitoring, failover, or "
    "recovery properties of a production queue adapter."
)

NON_CANONICAL_KEYS: frozenset[str] = frozenset({
    "canonical_payload_hash", "generated_at", "generation_metadata",
})

_LEAK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"redis(?:s)?://", "a Redis connection string"),
    (r"postgres(?:ql)?://", "a database URL"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"(?i)\bpassword\b\s*[:=]", "a password field"),
    (r"(?i)\b(secret|api[_-]?key|token|requirepass)\b\s*[:=]", "a secret field"),
    (r"monday-report:[a-z-]+", "a raw queue key"),
    (r"(?i)\b[a-z0-9.-]+\.(?:cache\.amazonaws\.com|redis\.cache\.windows\.net|"
     r"upstash\.io|redislabs\.com)\b", "a provider hostname"),
)

GIT_UNAVAILABLE = "\x00git-unavailable"


class ProductionQueueEvidenceUnavailable(RuntimeError):
    """Raised by the runner interface, which never fabricates an artifact."""


# --------------------------------------------------------------------------------- canonical hash

def _normalize(obj: Any) -> Any:
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    return obj


def canonical_body(payload: dict) -> dict:
    return {k: _normalize(v) for k, v in payload.items() if k not in NON_CANONICAL_KEYS}


def canonical_json(payload: dict) -> str:
    return json.dumps(canonical_body(payload), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def canonical_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def contract_hash() -> str:
    """Deterministic hash of the CONTRACT. Covers the allowed sets as well as the rejected ones --
    the database contract's first cut covered only the rejections, and widening an allowed enum then
    produced an accepted artifact with a byte-identical pin."""
    return hashlib.sha256(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "evidence_type": EVIDENCE_TYPE,
        "required_proof_domains": list(REQUIRED_PROOF_DOMAINS),
        "conditional_proof_domains": list(CONDITIONAL_PROOF_DOMAINS),
        "required_domain_fields": list(REQUIRED_DOMAIN_FIELDS),
        "domain_statuses": list(DOMAIN_STATUSES),
        "proving_observation_classes": list(PROVING_OBSERVATION_CLASSES),
        "non_proving_observation_classes": list(NON_PROVING_OBSERVATION_CLASSES),
        "domain_observation_requirements": {k: list(v) for k, v in
                                           sorted(DOMAIN_OBSERVATION_REQUIREMENTS.items())},
        "delivery_models": list(DELIVERY_MODELS),
        "rejected_delivery_models": list(REJECTED_DELIVERY_MODELS),
        "rejected_schema_versions": list(REJECTED_SCHEMA_VERSIONS),
        "allowed_provider_classifications": list(PROVIDER_CLASSIFICATIONS),
        "rejected_provider_classifications": list(REJECTED_PROVIDER_CLASSIFICATIONS),
        "allowed_environment_classifications": list(ENVIRONMENT_CLASSIFICATIONS),
        "rejected_environments": list(REJECTED_ENVIRONMENTS),
        "allowed_endpoint_classifications": list(ENDPOINT_CLASSIFICATIONS),
        "rejected_endpoint_classifications": list(REJECTED_ENDPOINT_CLASSIFICATIONS),
        "storage_classifications": list(STORAGE_CLASSIFICATIONS),
        "eviction_policies": list(EVICTION_POLICY_CLASSIFICATIONS),
        "unsafe_eviction_policies": list(UNSAFE_EVICTION_POLICIES),
        "queue_identity_classifications": list(QUEUE_IDENTITY_CLASSIFICATIONS),
        "rejected_runtime_identities": list(REJECTED_RUNTIME_IDENTITIES),
        "non_qualifying_evidence": list(NON_QUALIFYING_EVIDENCE),
        "worker_test_disclosure": WORKER_TEST_DISCLOSURE,
        "static_validation_disclosure": STATIC_VALIDATION_DISCLOSURE,
        "non_canonical_keys": sorted(NON_CANONICAL_KEYS),
        "leak_patterns": [p for p, _ in _LEAK_PATTERNS],
        "max_observation_age_days": MAX_OBSERVATION_AGE_DAYS,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------- git helpers

def _git(args: list[str]) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True,
                             timeout=30)
        return out.stdout.strip() if out.returncode == 0 else GIT_UNAVAILABLE
    except Exception:  # noqa: BLE001
        return GIT_UNAVAILABLE


def git_rev(ref: str) -> str:
    return _git(["rev-parse", ref])


def worktree_is_clean() -> bool:
    """Tracked-only cleanliness. An unavailable git is not clean -- it is unknown, and unknown fails
    closed."""
    return _git(["status", "--porcelain", "--untracked-files=no"]) == ""


def _is_full_sha(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{40}", value))


def _is_full_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------------- domain gate

def _check_domain(name: str, domain: Any, reasons: list[str], generated: datetime | None) -> None:
    if isinstance(domain, (bool, str, int, float)) or domain is None:
        reasons.append(f"proof domain {name!r} is a bare literal assertion, not an observation "
                       "object carrying status/proven_by/observation_class/observed_at/"
                       "binding_fingerprint")
        return
    if not isinstance(domain, dict):
        reasons.append(f"proof domain {name!r} is not an object")
        return
    missing = [f for f in REQUIRED_DOMAIN_FIELDS if f not in domain]
    if missing:
        reasons.append(f"proof domain {name!r} omits required field(s): {', '.join(missing)}")
        return
    status = domain.get("status")
    if status not in DOMAIN_STATUSES:
        reasons.append(f"proof domain {name!r} has unknown status {status!r}")
        return
    observation_class = domain.get("observation_class")
    if observation_class not in PROVING_OBSERVATION_CLASSES + NON_PROVING_OBSERVATION_CLASSES:
        reasons.append(f"proof domain {name!r} has unknown observation_class {observation_class!r}")
        return
    if status != "PASS":
        reasons.append(f"proof domain {name!r} is not proven (status {status})")
        return
    if observation_class not in PROVING_OBSERVATION_CLASSES:
        reasons.append(f"proof domain {name!r} claims PASS from a non-proving observation_class "
                       f"{observation_class!r}: a setting, a document, a fixture or a queue PING is "
                       "not evidence about a production queue")
        return
    required_classes = DOMAIN_OBSERVATION_REQUIREMENTS.get(name)
    if required_classes and observation_class not in required_classes:
        reasons.append(f"proof domain {name!r} claims PASS from observation_class "
                       f"{observation_class!r}, but this domain requires one of "
                       f"{', '.join(required_classes)} -- an availability property is proven by "
                       "executing it, not by attesting to it")
        return
    proven_by = domain.get("proven_by")
    if not isinstance(proven_by, str) or len(proven_by.strip()) < 12:
        reasons.append(f"proof domain {name!r} claims PASS without a substantive proven_by")
    if not _is_full_sha256(domain.get("binding_fingerprint")):
        reasons.append(f"proof domain {name!r} claims PASS without a full SHA-256 "
                       "binding_fingerprint")
    observed = _parse_ts(domain.get("observed_at"))
    if observed is None:
        reasons.append(f"proof domain {name!r} claims PASS with an unparseable observed_at")
    elif generated is not None:
        age_days = (generated - observed).total_seconds() / 86400.0
        if age_days > MAX_OBSERVATION_AGE_DAYS:
            reasons.append(f"proof domain {name!r} observation is stale: {age_days:.0f} days old "
                           f"(limit {MAX_OBSERVATION_AGE_DAYS})")
        elif age_days < -1:
            reasons.append(f"proof domain {name!r} observation is dated after generation")


# --------------------------------------------------------------------------------- validator

def validate(payload: Any, *, current_commit: str | None = None,
             current_tree: str | None = None, now: datetime | None = None) -> list[str]:
    """Return rejection reasons. Empty list == valid. NEVER raises."""
    reasons: list[str] = []
    try:
        if not isinstance(payload, dict):
            return ["production queue-adapter evidence is not a JSON object"]
        if now is None:
            now = datetime.now(timezone.utc)

        schema = payload.get("schema_version")
        if schema in REJECTED_SCHEMA_VERSIONS:
            reasons.append(f"superseded or foreign schema {schema!r} presented as {SCHEMA_VERSION}")
        elif schema != SCHEMA_VERSION:
            reasons.append(f"unknown schema_version {schema!r} (expected {SCHEMA_VERSION})")
        if payload.get("evidence_type") != EVIDENCE_TYPE:
            reasons.append(f"wrong evidence_type {payload.get('evidence_type')!r} "
                           f"(expected {EVIDENCE_TYPE})")
        if payload.get("implementation_version") != IMPLEMENTATION_VERSION:
            reasons.append("implementation_version does not match the contract module")

        commit, tree = payload.get("git_commit"), payload.get("git_tree")
        if not _is_full_sha(commit):
            reasons.append("git_commit is missing or not a full 40-character SHA")
        if not _is_full_sha(tree):
            reasons.append("git_tree is missing or not a full 40-character SHA")
        expected_commit = current_commit if current_commit is not None else git_rev("HEAD")
        expected_tree = current_tree if current_tree is not None else git_rev("HEAD^{tree}")
        if not _is_full_sha(expected_commit):
            reasons.append("the current commit could not be determined, so the evidence binding "
                           "cannot be verified")
        elif commit != expected_commit:
            reasons.append("evidence is stale: git_commit does not match the current commit")
        if not _is_full_sha(expected_tree):
            reasons.append("the current tree could not be determined, so the evidence binding "
                           "cannot be verified")
        elif tree != expected_tree:
            reasons.append("evidence is stale: git_tree does not match the current tree")
        if payload.get("worktree_clean") is not True:
            reasons.append("evidence does not attest a clean worktree")
        elif not worktree_is_clean():
            reasons.append("the tracked worktree is dirty now: evidence no longer describes "
                           "this tree")

        declared = payload.get("canonical_payload_hash")
        if not _is_full_sha256(declared):
            reasons.append("canonical_payload_hash is missing or not a full lowercase SHA-256")
        elif declared != canonical_hash(payload):
            reasons.append("canonical_payload_hash does not match the canonical body")

        generated = _parse_ts(payload.get("generated_at"))
        if generated is None:
            reasons.append("generated_at is missing or unparseable")
        else:
            age = (now - generated).total_seconds() / 86400.0
            if age > MAX_OBSERVATION_AGE_DAYS:
                reasons.append(f"the artifact itself is stale: generated {age:.0f} days ago "
                               f"(limit {MAX_OBSERVATION_AGE_DAYS})")
            elif age < -1:
                reasons.append("the artifact is dated in the future")

        # ---- target ----
        target = payload.get("target")
        if not isinstance(target, dict):
            reasons.append("target classification block is missing")
        else:
            provider = target.get("provider_classification")
            if provider not in PROVIDER_CLASSIFICATIONS:
                reasons.append(f"unknown provider_classification {provider!r}")
            elif provider in REJECTED_PROVIDER_CLASSIFICATIONS:
                reasons.append(f"provider_classification {provider!r} is not auditable")
            if not _is_full_sha256(target.get("service_identity_fingerprint")):
                reasons.append("target omits a full SHA-256 service_identity_fingerprint")
            environment = target.get("environment_classification")
            if environment not in ENVIRONMENT_CLASSIFICATIONS:
                reasons.append(f"unknown environment_classification {environment!r}")
            elif environment in REJECTED_ENVIRONMENTS:
                reasons.append(f"environment_classification {environment!r} is not production")
            endpoint = target.get("endpoint_classification")
            if endpoint not in ENDPOINT_CLASSIFICATIONS:
                reasons.append(f"unknown endpoint_classification {endpoint!r}")
            elif endpoint in REJECTED_ENDPOINT_CLASSIFICATIONS:
                reasons.append(f"endpoint_classification {endpoint!r} is not a production network "
                               "boundary")
            if target.get("tls_verified") is not True:
                reasons.append("target does not attest a verified TLS session")
            if target.get("credential_rotation_configured") is not True:
                reasons.append("target does not attest configured credential rotation")

            eviction = target.get("eviction_policy")
            if eviction not in EVICTION_POLICY_CLASSIFICATIONS:
                reasons.append(f"unknown eviction_policy {eviction!r}")
            elif eviction in UNSAFE_EVICTION_POLICIES:
                reasons.append(f"eviction_policy {eviction!r} can silently discard a queued job")

            storage = target.get("storage_classification")
            if storage not in STORAGE_CLASSIFICATIONS:
                reasons.append(f"unknown storage_classification {storage!r}")
            elif storage == "ephemeral-only" and target.get("durability_claimed") is True:
                reasons.append("durability is claimed on ephemeral-only storage")

        # ---- identities ----
        identities = payload.get("identities")
        if not isinstance(identities, dict):
            reasons.append("identities block is missing")
        else:
            for role in ("producer", "consumer_worker", "administrative"):
                value = identities.get(f"{role}_identity_classification")
                if value not in QUEUE_IDENTITY_CLASSIFICATIONS:
                    reasons.append(f"unknown {role} identity classification {value!r}")
                elif role != "administrative" and value in REJECTED_RUNTIME_IDENTITIES:
                    reasons.append(f"the {role} runtime identity is {value!r}: a runtime principal "
                                   "must not be administrative, default or unauthenticated")
            if identities.get("administrative_distinct_from_runtime") is not True:
                reasons.append("the administrative queue identity is not separated from the runtime "
                               "identity")
            if identities.get("tenant_namespace_bound") is not True:
                reasons.append("the queue namespace is not bound per tenant/job: a shared namespace "
                               "without tenant binding is rejected")
            if identities.get("payload_tenant_override_rejected") is not True:
                reasons.append("the payload trust boundary is not established: a tenant supplied in "
                               "the job payload must never be trusted")
            if identities.get("local_fallback_prevented") is not True:
                reasons.append("silent fallback to a local/in-memory queue is not prevented")

        # ---- delivery semantics ----
        delivery = payload.get("delivery")
        if not isinstance(delivery, dict):
            reasons.append("delivery block is missing")
        else:
            model = delivery.get("model")
            if model in REJECTED_DELIVERY_MODELS:
                reasons.append(f"delivery model {model!r} is claimed but nothing in this repository "
                               "implements it")
            elif model not in DELIVERY_MODELS:
                reasons.append(f"delivery model is missing or unknown ({model!r})")
            if delivery.get("retry_limit") is None:
                reasons.append("no retry limit is declared")
            elif not isinstance(delivery.get("retry_limit"), int) or delivery["retry_limit"] < 1:
                reasons.append("the declared retry limit is not a positive integer")
            if delivery.get("duplicate_delivery_behavior") in (None, "", "unspecified"):
                reasons.append("duplicate-delivery behavior is not declared")
            if delivery.get("poison_message_isolated") is not True:
                reasons.append("poison-message isolation is not declared: one bad job must not block "
                               "the queue")
            if delivery.get("dead_letter_required") is True and \
                    delivery.get("dead_letter_disposition") in (None, "", "none"):
                reasons.append("a dead-letter disposition is required but not declared")
            if model == "at-least-once" and \
                    delivery.get("idempotency_contract_compatibility_observed") is not True:
                reasons.append("at-least-once delivery is declared without observed compatibility "
                               "with the application idempotency contract")
            if model == "at-most-once" and delivery.get("loss_window_disclosed") is not True:
                reasons.append("at-most-once delivery is declared without disclosing the loss "
                               "window and its compensating re-derivation mechanism")

        # ---- non-qualifying disclosure ----
        disclosure = payload.get("non_qualifying_evidence_disclosure")
        if not isinstance(disclosure, dict):
            reasons.append("non_qualifying_evidence_disclosure block is missing")
        else:
            if disclosure.get("worker_test_disclosure") != WORKER_TEST_DISCLOSURE:
                reasons.append("the required worker/disposable-queue disclosure is missing or "
                               "altered")
            if disclosure.get("static_validation_disclosure") != STATIC_VALIDATION_DISCLOSURE:
                reasons.append("the required static-validation scope disclosure is missing or "
                               "altered")
            listed = disclosure.get("non_qualifying_sources")
            if not isinstance(listed, list) or set(NON_QUALIFYING_EVIDENCE) - set(map(str, listed)):
                reasons.append("non_qualifying_sources does not enumerate every non-qualifying "
                               "evidence source")
            if disclosure.get("promoted_sources"):
                reasons.append("a non-qualifying evidence source is promoted as production proof: "
                               f"{sorted(map(str, disclosure['promoted_sources']))}")

        # ---- proof domains ----
        domains = payload.get("proof_domains")
        if not isinstance(domains, dict):
            reasons.append("proof_domains block is missing")
        else:
            for name in REQUIRED_PROOF_DOMAINS:
                if name not in domains:
                    reasons.append(f"required proof domain {name!r} is missing")
                else:
                    _check_domain(name, domains[name], reasons, generated)
            at_least_once = isinstance(delivery, dict) and delivery.get("model") == "at-least-once"
            for name in CONDITIONAL_PROOF_DOMAINS:
                if at_least_once:
                    if name not in domains:
                        reasons.append(f"at-least-once delivery is declared but proof domain "
                                       f"{name!r} is missing")
                    else:
                        _check_domain(name, domains[name], reasons, generated)
                elif name in domains:
                    reasons.append(f"proof domain {name!r} is present without declaring "
                                   "at-least-once delivery")
            unknown = sorted(set(domains) - set(REQUIRED_PROOF_DOMAINS)
                             - set(CONDITIONAL_PROOF_DOMAINS))
            if unknown:
                reasons.append(f"unknown proof domain(s): {', '.join(unknown)}")

        if payload.get("secret_scan_clean") is not True:
            reasons.append("the artifact does not attest a clean secret scan")
        if payload.get("production_parity") is not True:
            reasons.append("production_parity is not true: the queue adapter is not at production "
                           "parity, which is the expected safe state today and keeps this evidence "
                           "non-accepting")

        try:
            blob = json.dumps(payload, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001
            blob = ""
        for pattern, described in _LEAK_PATTERNS:
            if re.search(pattern, blob):
                reasons.append(f"the artifact appears to contain {described}; production evidence "
                               "must carry classifications and non-reversible fingerprints only")
    except Exception as exc:  # noqa: BLE001 - fail closed
        reasons.append(f"production queue-adapter evidence could not be evaluated: "
                       f"{exc.__class__.__name__}")
    return reasons


def load_and_validate(path: Any = None, **kwargs: Any) -> list[str]:
    target = Path(path) if path is not None else EVIDENCE_PATH
    try:
        if not target.exists():
            return ["no production queue-adapter evidence artifact"]
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"production queue-adapter evidence unreadable: {exc.__class__.__name__}"]
    return validate(payload, **kwargs)


# --------------------------------------------------------------------------------- runner interface
RUNNER_UNAVAILABLE_REASON = (
    "production queue-adapter certification is not implemented. It additionally requires an "
    "explicit production target configuration -- this interface never auto-discovers or probes "
    "developer Redis, Docker Redis, loopback services or unrelated running containers -- and the "
    "environment-capacity gate to pass."
)


def _unavailable(stage: str, target_config: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "stage": stage,
        "contract_hash": contract_hash(),
        "certification": "unavailable",
        "production_queue_executed": False,
        "production_queue_adapter_accepted": False,
        "explicit_target_configuration_supplied": target_config is not None,
        "artifact": None,
        "reason": RUNNER_UNAVAILABLE_REASON,
        "release_recommendation": "GA_BLOCKED",
    }


def assess(target_config: Any = None) -> dict[str, Any]:
    result = _unavailable("assess", target_config)
    result["required_proof_domains"] = list(REQUIRED_PROOF_DOMAINS)
    result["conditional_proof_domains"] = list(CONDITIONAL_PROOF_DOMAINS)
    result["delivery_models"] = list(DELIVERY_MODELS)
    result["non_qualifying_evidence"] = list(NON_QUALIFYING_EVIDENCE)
    return result


def collect(target_config: Any = None) -> dict[str, Any]:
    return _unavailable("collect", target_config)


def verify(artifact: Any = None, target_config: Any = None) -> dict[str, Any]:
    result = _unavailable("verify", target_config)
    if artifact is not None:
        result["validation_reasons"] = validate(artifact)
        result["artifact_valid"] = not result["validation_reasons"]
    return result


def generate(target_config: Any = None) -> dict[str, Any]:
    return _unavailable("generate", target_config)
