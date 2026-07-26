"""Production database-adapter evidence contract (``production-database-adapter-evidence.v1``).

The repository already has an *accepted* restricted-PostgreSQL runtime proof. It is easy -- and
wrong -- to read that as "the PostgreSQL adapter is production-ready". It is not, and this contract
exists to make the difference impossible to blur:

    The accepted restricted PostgreSQL runtime proves functional behavior and
    tenant isolation in disposable test infrastructure. It does not prove the
    availability, operations, identity provisioning, backup, restore, network,
    TLS, capacity, monitoring, or recovery properties of a production database
    adapter.

Everything the restricted runtime proves happens inside a runner-owned, throwaway Docker container,
reached over loopback, provisioned by a test bootstrap superuser, with ephemeral storage, no TLS
verification, no backup, no restore drill, no monitoring and no failover. Those are precisely the
properties a production adapter has to have, so the accepted proof is *evidence of a different
thing*. This module therefore treats every existing repository proof as **non-qualifying** on its
own (see :data:`NON_QUALIFYING_EVIDENCE`).

What this module is
-------------------
A versioned schema plus a never-raising validator. It defines what a production database-adapter
artifact must contain, and refuses anything short of it with a list of reasons. It does NOT execute,
probe, provision or discover anything: :func:`assess`, :func:`collect`, :func:`verify` and
:func:`generate` are declared and return a controlled ``certification="unavailable"``.

Design rules that matter
------------------------
* **No bare assertions.** A proof domain cannot be satisfied by ``true`` or by a string. Every
  domain is an object carrying ``status`` / ``proven_by`` / ``observation_class`` / ``observed_at`` /
  ``binding_fingerprint``, and a PASS whose ``observation_class`` is not one of
  :data:`PROVING_OBSERVATION_CLASSES` is rejected. "A repository setting exists" is not a proof.
* **Provider-neutral.** The repository selects no cloud provider, so neither does this contract. A
  provider *classification* is required, but ``unknown`` is rejected -- an unnamed target cannot be
  audited.
* **Privacy by construction.** Endpoints, hosts, accounts, projects, resource names, role names and
  credentials are never carried. The schema accepts classifications and non-reversible fingerprints,
  and the validator rejects a payload that looks like it contains a raw endpoint or DSN.
* **``production_parity=false`` is the expected safe state today** and keeps the evidence
  non-accepting. That is not a bug to be worked around; it is the honest current answer.
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

SCHEMA_VERSION = "production-database-adapter-evidence.v1"
IMPLEMENTATION_VERSION = "1.0.0"
EVIDENCE_TYPE = "production-database-adapter"

#: Superseded/unknown schema ids that must never be accepted at the v1 path.
REJECTED_SCHEMA_VERSIONS: tuple[str, ...] = (
    "production-database-adapter-evidence.v0",
    "tenant-authorization-evidence.v3",
    "tenant-rls-enforcement-evidence.v2",
)

EVIDENCE_PATH = ROOT / "output" / "production-database-adapter" / f"{SCHEMA_VERSION}.json"

# --------------------------------------------------------------------------------------------
# Proof domains. Every one is REQUIRED; a missing domain is a rejection, never NOT_APPLICABLE.
# Marking a missing domain N/A would read as "this deployment does not need backups", which is the
# exact overclaim this contract exists to prevent.
# --------------------------------------------------------------------------------------------
REQUIRED_PROOF_DOMAINS: tuple[str, ...] = (
    "platform_and_service_identity",
    "postgresql_version_and_extensions",
    "network_boundary",
    "tls_configuration",
    "credential_source_and_rotation",
    "migration_identity_and_least_privilege",
    "runtime_api_identity",
    "runtime_worker_identity",
    "runtime_import_identity",
    "rls_and_force_policy_inventory",
    "connection_limits_and_timeouts",
    "transaction_and_isolation_policy",
    "pooling_configuration",
    "failover_behavior",
    "backup_policy",
    "restore_test",
    "monitoring_and_alerting",
    "capacity_and_disk_thresholds",
    "maintenance_and_upgrade_process",
    "incident_and_rollback_process",
    "data_retention_policy",
    "secret_scan",
)

#: Required only when the artifact CLAIMS point-in-time recovery. Claiming it without proving it is
#: a rejection; not claiming it is permitted (and recorded).
CONDITIONAL_PROOF_DOMAINS: tuple[str, ...] = ("point_in_time_recovery",)

#: Observation classes that can support a PASS: something was really observed, executed or signed.
PROVING_OBSERVATION_CLASSES: tuple[str, ...] = (
    "live_target_observation",        # queried the actual production target
    "provider_control_plane_response",  # the managing service reported it
    "executed_drill",                # a real restore/failover drill was run
    "signed_operator_attestation",   # a named, verifiable human attestation
)

#: Observation classes that can NEVER support a PASS. Present in the schema so a generator has to
#: state which of the two kinds it has, rather than omitting the question.
NON_PROVING_OBSERVATION_CLASSES: tuple[str, ...] = (
    "repository_setting",
    "literal_assertion",
    "documentation_only",
    "test_fixture",
    "assumed_default",
    "unspecified",
)

#: Per-domain provenance requirements. Without these, one uniform rule applied to all domains, so a
#: restore test, a failover test and point-in-time recovery could all be satisfied by a signed
#: attestation that nobody ever ran anything -- which an independent review demonstrated. Recovery
#: and availability properties are only established by ACTUALLY DOING THEM; a live/control-plane
#: observation is required where the property is a current configuration rather than an event.
DOMAIN_OBSERVATION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "restore_test": ("executed_drill",),
    "failover_behavior": ("executed_drill",),
    "point_in_time_recovery": ("executed_drill",),
    "backup_policy": ("live_target_observation", "provider_control_plane_response"),
    "monitoring_and_alerting": ("live_target_observation", "provider_control_plane_response"),
    "capacity_and_disk_thresholds": ("live_target_observation", "provider_control_plane_response"),
    "tls_configuration": ("live_target_observation",),
    "network_boundary": ("live_target_observation", "provider_control_plane_response"),
    "postgresql_version_and_extensions": ("live_target_observation",),
    "rls_and_force_policy_inventory": ("live_target_observation",),
    "connection_limits_and_timeouts": ("live_target_observation",),
    "runtime_api_identity": ("live_target_observation",),
    "runtime_worker_identity": ("live_target_observation",),
    "runtime_import_identity": ("live_target_observation",),
    "migration_identity_and_least_privilege": ("live_target_observation",),
    "secret_scan": ("executed_drill", "live_target_observation"),
}

#: Fields every proof domain must carry. A domain that is a bare bool/str/number is rejected.
REQUIRED_DOMAIN_FIELDS: tuple[str, ...] = (
    "status", "proven_by", "observation_class", "observed_at", "binding_fingerprint",
)

DOMAIN_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "BLOCKED", "NOT_PROVEN")

#: An observation older than this (relative to ``generated_at``) is stale: operational properties
#: decay, so a year-old restore drill is not evidence about today's adapter.
MAX_OBSERVATION_AGE_DAYS = 90

# --------------------------------------------------------------------------------------------
# Provider / target classification. Provider-neutral: the repository selects no provider.
# --------------------------------------------------------------------------------------------
PROVIDER_CLASSIFICATIONS: tuple[str, ...] = (
    "managed-postgresql", "self-managed-postgresql", "unknown",
)
#: ``unknown`` is a valid *classification* but never an acceptable one: an unidentified target
#: cannot be audited, and "we do not know what this is" is not production evidence.
REJECTED_PROVIDER_CLASSIFICATIONS: tuple[str, ...] = ("unknown",)

ENVIRONMENT_CLASSIFICATIONS: tuple[str, ...] = ("production", "staging", "test", "development")
#: ``staging`` is rejected too: this control certifies the PRODUCTION adapter, and a staging target
#: is by definition not the one serving client data. An independent review found a staging artifact
#: certifying the production control, which is exactly the class of overclaim this contract exists
#: to prevent.
REJECTED_ENVIRONMENTS: tuple[str, ...] = ("staging", "test", "development")

ENDPOINT_CLASSIFICATIONS: tuple[str, ...] = (
    "private-network", "public-with-allowlist", "loopback", "docker-bridge", "unknown",
)
REJECTED_ENDPOINT_CLASSIFICATIONS: tuple[str, ...] = ("loopback", "docker-bridge", "unknown")

STORAGE_CLASSIFICATIONS: tuple[str, ...] = ("durable-replicated", "durable-single", "ephemeral")
REJECTED_STORAGE_CLASSIFICATIONS: tuple[str, ...] = ("ephemeral",)

# --------------------------------------------------------------------------------------------
# Non-qualifying evidence. Each of these is real and, for its own scope, accepted -- and none of
# them, alone or together, establishes a production database adapter.
# --------------------------------------------------------------------------------------------
NON_QUALIFYING_EVIDENCE: tuple[str, ...] = (
    "runner-owned disposable Docker PostgreSQL",
    "test-only bootstrap migration administrator",
    "restricted runtime functional matrix",
    "dual-backend demo-mode UI certification",
    "tenant-authorization evidence v3",
    "local development DSN",
    "repository configuration defaults",
    "unit tests",
    "mocked provider metadata",
)

RESTRICTED_RUNTIME_DISCLOSURE = (
    "The accepted restricted PostgreSQL runtime proves functional behavior and "
    "tenant isolation in disposable test infrastructure. It does not prove the "
    "availability, operations, identity provisioning, backup, restore, network, "
    "TLS, capacity, monitoring, or recovery properties of a production database "
    "adapter."
)

#: Keys excluded from the canonical body: the hash itself, plus explicitly allowed generation
#: metadata. Everything else is covered, so no substantive field can be changed without changing
#: the hash.
NON_CANONICAL_KEYS: frozenset[str] = frozenset({
    "canonical_payload_hash", "generated_at", "generation_metadata",
})

#: Shapes that indicate a raw endpoint/credential leaked into the artifact.
_LEAK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"postgres(?:ql)?://", "a database URL"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"(?i)\bpassword\b\s*[:=]", "a password field"),
    (r"(?i)\b(secret|api[_-]?key|token)\b\s*[:=]", "a secret field"),
    (r"(?i)\b[a-z0-9.-]+\.(?:rds\.amazonaws\.com|postgres\.database\.azure\.com|"
     r"cloudsql\.google\.com|neon\.tech|supabase\.co)\b", "a provider hostname"),
)


class ProductionAdapterEvidenceUnavailable(RuntimeError):
    """Raised by the runner interface, which never fabricates an artifact."""


# --------------------------------------------------------------------------------- canonical hash

def _normalize(obj: Any) -> Any:
    """Normalize for hashing: booleans stay booleans, integral floats collapse to int, lists keep
    order (order is meaningful), mappings are key-sorted by ``json.dumps(sort_keys=True)``."""
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
    """The exact object the canonical hash covers."""
    return {k: _normalize(v) for k, v in payload.items() if k not in NON_CANONICAL_KEYS}


def canonical_json(payload: dict) -> str:
    return json.dumps(canonical_body(payload), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def canonical_hash(payload: dict) -> str:
    """Full lowercase 64-character SHA-256 over :func:`canonical_json`."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def contract_hash() -> str:
    """Deterministic hash of the CONTRACT itself (not of an artifact).

    Lets a reviewer detect that the requirements changed without reading the diff.
    """
    return hashlib.sha256(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "evidence_type": EVIDENCE_TYPE,
        "required_proof_domains": list(REQUIRED_PROOF_DOMAINS),
        "conditional_proof_domains": list(CONDITIONAL_PROOF_DOMAINS),
        "required_domain_fields": list(REQUIRED_DOMAIN_FIELDS),
        "proving_observation_classes": list(PROVING_OBSERVATION_CLASSES),
        "non_proving_observation_classes": list(NON_PROVING_OBSERVATION_CLASSES),
        "rejected_schema_versions": list(REJECTED_SCHEMA_VERSIONS),
        "rejected_provider_classifications": list(REJECTED_PROVIDER_CLASSIFICATIONS),
        "rejected_environments": list(REJECTED_ENVIRONMENTS),
        "rejected_endpoint_classifications": list(REJECTED_ENDPOINT_CLASSIFICATIONS),
        "rejected_storage_classifications": list(REJECTED_STORAGE_CLASSIFICATIONS),
        "non_qualifying_evidence": list(NON_QUALIFYING_EVIDENCE),
        "restricted_runtime_disclosure": RESTRICTED_RUNTIME_DISCLOSURE,
        "max_observation_age_days": MAX_OBSERVATION_AGE_DAYS,
        # Covered so that WIDENING the excluded-key set -- which would move substantive fields
        # outside the canonical hash -- is itself detectable.
        "non_canonical_keys": sorted(NON_CANONICAL_KEYS),
        "required_target_rejections": {
            "environments": list(REJECTED_ENVIRONMENTS),
            "endpoints": list(REJECTED_ENDPOINT_CLASSIFICATIONS),
            "storage": list(REJECTED_STORAGE_CLASSIFICATIONS),
        },
        # The ALLOWED enums must be covered too, not only the rejected ones. An independent review
        # widened the allowed sets with "sandbox" / "container-network", which produced an accepted
        # artifact and a PASS control while this hash stayed byte-identical.
        "allowed_provider_classifications": list(PROVIDER_CLASSIFICATIONS),
        "allowed_environment_classifications": list(ENVIRONMENT_CLASSIFICATIONS),
        "allowed_endpoint_classifications": list(ENDPOINT_CLASSIFICATIONS),
        "allowed_storage_classifications": list(STORAGE_CLASSIFICATIONS),
        "domain_statuses": list(DOMAIN_STATUSES),
        "domain_observation_requirements": {k: list(v) for k, v in
                                            sorted(DOMAIN_OBSERVATION_REQUIREMENTS.items())},
        "leak_patterns": [pattern for pattern, _ in _LEAK_PATTERNS],
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------- git helpers

#: Sentinel returned when git cannot be consulted. Distinguished from a real empty result so the
#: validator can FAIL CLOSED: an independent review showed that returning "" for both made an
#: unavailable git report a clean worktree and skip the commit/tree comparison entirely, so a forged
#: binding was accepted.
GIT_UNAVAILABLE = "\x00git-unavailable"


def _git(args: list[str]) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True,
                             timeout=30)
        return out.stdout.strip() if out.returncode == 0 else GIT_UNAVAILABLE
    except Exception:  # noqa: BLE001 - absence of git is a rejection, never a crash
        return GIT_UNAVAILABLE


def git_rev(ref: str) -> str:
    return _git(["rev-parse", ref])


def worktree_is_clean() -> bool:
    """Tracked-only cleanliness: untracked files (e.g. partner documents that must not be touched)
    do not make the evidence wrong about the tree it describes.

    An unavailable git is NOT clean -- it is unknown, and unknown fails closed.
    """
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
    """Validate ONE proof domain. Appends a reason per problem; never raises."""
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

    # From here on the domain claims PASS, so the provenance has to hold up.
    if observation_class not in PROVING_OBSERVATION_CLASSES:
        reasons.append(f"proof domain {name!r} claims PASS from a non-proving observation_class "
                       f"{observation_class!r}: the existence of a setting, a document or a test "
                       "fixture is not evidence about a production target")
        return

    # Per-domain requirement: a recovery/availability property is proven by executing it, not by
    # attesting that it would work.
    required_classes = DOMAIN_OBSERVATION_REQUIREMENTS.get(name)
    if required_classes and observation_class not in required_classes:
        reasons.append(f"proof domain {name!r} claims PASS from observation_class "
                       f"{observation_class!r}, but this domain requires one of "
                       f"{', '.join(required_classes)}")
        return

    proven_by = domain.get("proven_by")
    if not isinstance(proven_by, str) or len(proven_by.strip()) < 12:
        reasons.append(f"proof domain {name!r} claims PASS without a substantive proven_by")

    fingerprint = domain.get("binding_fingerprint")
    if not _is_full_sha256(fingerprint):
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
    """Return a list of rejection reasons. Empty list == valid. NEVER raises.

    A malformed artifact must degrade the control to BLOCKED, not crash the readiness evaluator.
    """
    reasons: list[str] = []
    try:
        if not isinstance(payload, dict):
            return ["production database-adapter evidence is not a JSON object"]
        # Wall clock by default; injectable so a guard can pin a deterministic epoch.
        if now is None:
            now = datetime.now(timezone.utc)

        # ---- schema identity ----
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

        # ---- commit / tree binding ----
        commit, tree = payload.get("git_commit"), payload.get("git_tree")
        if not _is_full_sha(commit):
            reasons.append("git_commit is missing or not a full 40-character SHA")
        if not _is_full_sha(tree):
            reasons.append("git_tree is missing or not a full 40-character SHA")
        expected_commit = current_commit if current_commit is not None else git_rev("HEAD")
        expected_tree = current_tree if current_tree is not None else git_rev("HEAD^{tree}")
        # Fail closed on an unverifiable binding: no git, no verdict.
        if not expected_commit or expected_commit == GIT_UNAVAILABLE or not _is_full_sha(
                expected_commit):
            reasons.append("the current commit could not be determined, so the evidence binding "
                           "cannot be verified")
        elif commit != expected_commit:
            reasons.append("evidence is stale: git_commit does not match the current commit")
        if not expected_tree or expected_tree == GIT_UNAVAILABLE or not _is_full_sha(expected_tree):
            reasons.append("the current tree could not be determined, so the evidence binding "
                           "cannot be verified")
        elif tree != expected_tree:
            reasons.append("evidence is stale: git_tree does not match the current tree")
        if payload.get("worktree_clean") is not True:
            reasons.append("evidence does not attest a clean worktree")
        elif not worktree_is_clean():
            reasons.append("the tracked worktree is dirty now: evidence no longer describes "
                           "this tree")

        # ---- canonical hash ----
        declared = payload.get("canonical_payload_hash")
        if not _is_full_sha256(declared):
            reasons.append("canonical_payload_hash is missing or not a full lowercase SHA-256")
        else:
            recomputed = canonical_hash(payload)
            if declared != recomputed:
                reasons.append("canonical_payload_hash does not match the canonical body")

        generated = _parse_ts(payload.get("generated_at"))
        if generated is None:
            reasons.append("generated_at is missing or unparseable")
        elif now is not None:
            # An ABSOLUTE recency bound. Without it the staleness limit was measured only against the
            # artifact's own self-declared generated_at, so an artifact claiming generation in 2021
            # with 2020 observations validated -- the limit was self-referential.
            artifact_age_days = (now - generated).total_seconds() / 86400.0
            if artifact_age_days > MAX_OBSERVATION_AGE_DAYS:
                reasons.append(f"the artifact itself is stale: generated {artifact_age_days:.0f} "
                               f"days ago (limit {MAX_OBSERVATION_AGE_DAYS})")
            elif artifact_age_days < -1:
                reasons.append("the artifact is dated in the future")

        # ---- target classification ----
        target = payload.get("target")
        if not isinstance(target, dict):
            reasons.append("target classification block is missing")
        else:
            provider = target.get("provider_classification")
            if provider not in PROVIDER_CLASSIFICATIONS:
                reasons.append(f"unknown provider_classification {provider!r}")
            elif provider in REJECTED_PROVIDER_CLASSIFICATIONS:
                reasons.append(f"provider_classification {provider!r} is not auditable: an "
                               "unidentified target cannot be production evidence")
            if not isinstance(target.get("service_identity_fingerprint"), str) or \
                    not _is_full_sha256(target.get("service_identity_fingerprint")):
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

            storage = target.get("storage_classification")
            if storage not in STORAGE_CLASSIFICATIONS:
                reasons.append(f"unknown storage_classification {storage!r}")
            elif storage in REJECTED_STORAGE_CLASSIFICATIONS:
                reasons.append(f"storage_classification {storage!r} cannot hold production data")

            if target.get("tls_verified") is not True:
                reasons.append("target does not attest verified TLS")
            if target.get("credential_rotation_configured") is not True:
                reasons.append("target does not attest configured credential rotation")

        # ---- runtime role safety (mirrors the accepted tenant-RLS posture) ----
        runtime = payload.get("runtime_roles")
        if not isinstance(runtime, dict):
            reasons.append("runtime_roles block is missing")
        else:
            for field, message in (
                ("runtime_not_superuser", "the runtime role is a superuser"),
                ("runtime_not_bypassrls", "the runtime role has BYPASSRLS"),
                ("runtime_not_table_owner", "the runtime role owns protected tables"),
                ("rls_enabled_and_forced", "RLS is not enabled and forced on protected tables"),
                ("migration_principal_distinct_from_runtime",
                 "the migration administrator is reused as the runtime principal"),
            ):
                if runtime.get(field) is not True:
                    reasons.append(message)
            policies = runtime.get("policy_inventory")
            if not isinstance(policies, list) or not policies:
                reasons.append("runtime_roles omits a non-empty policy_inventory")
            else:
                # Non-emptiness alone carried no information: [0], [None], [{}] all passed.
                malformed = [i for i, entry in enumerate(policies)
                             if not isinstance(entry, dict)
                             or not isinstance(entry.get("table_classification"), str)
                             or not isinstance(entry.get("policy_count"), int)
                             or entry.get("policy_count", 0) < 1
                             or entry.get("forced") is not True]
                if malformed:
                    reasons.append(f"policy_inventory has {len(malformed)} entry/entries without a "
                                   "table classification, a positive policy count and forced=true")

        # ---- non-qualifying evidence disclosure ----
        disclosure = payload.get("non_qualifying_evidence_disclosure")
        if not isinstance(disclosure, dict):
            reasons.append("non_qualifying_evidence_disclosure block is missing")
        else:
            if disclosure.get("restricted_runtime_disclosure") != RESTRICTED_RUNTIME_DISCLOSURE:
                reasons.append("the required restricted-runtime disclosure is missing or altered")
            listed = disclosure.get("non_qualifying_sources")
            if not isinstance(listed, list) or set(NON_QUALIFYING_EVIDENCE) - set(map(str, listed)):
                reasons.append("non_qualifying_sources does not enumerate every non-qualifying "
                               "evidence source")
            promoted = disclosure.get("promoted_sources")
            if promoted:
                reasons.append("a non-qualifying evidence source is promoted as production proof: "
                               f"{sorted(map(str, promoted))}")

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
            claims_pitr = bool(payload.get("claims_point_in_time_recovery"))
            for name in CONDITIONAL_PROOF_DOMAINS:
                if claims_pitr:
                    if name not in domains:
                        reasons.append(f"point-in-time recovery is claimed but proof domain "
                                       f"{name!r} is missing")
                    else:
                        _check_domain(name, domains[name], reasons, generated)
                elif name in domains:
                    reasons.append(f"proof domain {name!r} is present without claiming "
                                   "point-in-time recovery")
            unknown_domains = sorted(set(domains) - set(REQUIRED_PROOF_DOMAINS)
                                     - set(CONDITIONAL_PROOF_DOMAINS))
            if unknown_domains:
                reasons.append(f"unknown proof domain(s): {', '.join(unknown_domains)}")

        # ---- secret scan + parity ----
        if payload.get("secret_scan_clean") is not True:
            reasons.append("the artifact does not attest a clean secret scan")
        if payload.get("production_parity") is not True:
            reasons.append("production_parity is not true: the adapter is not at production parity, "
                           "which is the expected safe state today and keeps this evidence "
                           "non-accepting")

        # ---- privacy: the artifact itself must not carry raw endpoints or credentials ----
        try:
            blob = json.dumps(payload, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001
            blob = ""
        for pattern, described in _LEAK_PATTERNS:
            if re.search(pattern, blob):
                reasons.append(f"the artifact appears to contain {described}; production evidence "
                               "must carry classifications and non-reversible fingerprints only")
    except Exception as exc:  # noqa: BLE001 - fail closed; a validator crash is a rejection
        reasons.append(f"production database-adapter evidence could not be evaluated: "
                       f"{exc.__class__.__name__}")
    return reasons


def load_and_validate(path: Any = None, **kwargs: Any) -> list[str]:
    """Read and validate. Absence and unreadability are reasons, never exceptions."""
    target = Path(path) if path is not None else EVIDENCE_PATH
    try:
        if not target.exists():
            return ["no production database-adapter evidence artifact"]
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"production database-adapter evidence unreadable: {exc.__class__.__name__}"]
    return validate(payload, **kwargs)


# --------------------------------------------------------------------------------- runner interface
# DECLARED, NOT IMPLEMENTED. Nothing here probes, provisions or auto-discovers anything, and none of
# it ever returns a simulated passing artifact.

RUNNER_UNAVAILABLE_REASON = (
    "production database-adapter certification is not implemented. It additionally requires an "
    "explicit production target configuration -- this interface never auto-discovers or probes "
    "local/developer infrastructure -- and the environment-capacity gate to pass."
)


def _unavailable(stage: str, target_config: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "stage": stage,
        "contract_hash": contract_hash(),
        "certification": "unavailable",
        "production_adapter_executed": False,
        "production_adapter_accepted": False,
        "explicit_target_configuration_supplied": target_config is not None,
        "artifact": None,
        "reason": RUNNER_UNAVAILABLE_REASON,
        "release_recommendation": "GA_BLOCKED",
    }


def assess(target_config: Any = None) -> dict[str, Any]:
    """Report what would have to be proven. Probes nothing."""
    result = _unavailable("assess", target_config)
    result["required_proof_domains"] = list(REQUIRED_PROOF_DOMAINS)
    result["conditional_proof_domains"] = list(CONDITIONAL_PROOF_DOMAINS)
    result["non_qualifying_evidence"] = list(NON_QUALIFYING_EVIDENCE)
    return result


def collect(target_config: Any = None) -> dict[str, Any]:
    """Collect observations from an EXPLICITLY configured production target. Not implemented."""
    return _unavailable("collect", target_config)


def verify(artifact: Any = None, target_config: Any = None) -> dict[str, Any]:
    """Verify a supplied artifact against this contract. Validation itself is available."""
    result = _unavailable("verify", target_config)
    if artifact is not None:
        result["validation_reasons"] = validate(artifact)
        result["artifact_valid"] = not result["validation_reasons"]
    return result


def generate(target_config: Any = None) -> dict[str, Any]:
    """Generate an artifact. Refuses without an explicit production target; never simulates one."""
    return _unavailable("generate", target_config)
