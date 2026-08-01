"""Production-queue-PROFILE BEHAVIORAL evidence tier.

A distinct, disposable-provable acceptance tier, SEPARATE from the accepted production-
TARGET queue contract in ``production_queue_adapter_evidence.py`` (schema
``production-queue-adapter-evidence.v1`` / control ``ga_redis_adapter``). That contract is
NOT modified, NOT reinterpreted, and REMAINS BLOCKED: it requires live production-target
observations and executed failover/recovery/retry/poison/duplicate drills against a real
managed broker, which disposable infrastructure cannot honestly provide.

This tier certifies only the adapter's BEHAVIOR against a DISPOSABLE, TLS-enabled Redis
Streams broker coupled to disposable TLS PostgreSQL: fail-closed selection with no
inline/in-memory fallback, verified TLS, bounded resources, tenant/idempotency-bound
messages, at-least-once delivery + lease + ack-after-durable-commit, DB-durable
tenant-scoped idempotency (duplicate => no duplicate business/audit effect), bounded
classified retry, poison => dead-letter with authorized idempotent replay, bounded
concurrency + a stress matrix, and bounded startup/shutdown. Its PASS verdict is
``PRODUCTION_QUEUE_ADAPTER_BEHAVIORAL_ACCEPTED`` and it MUST NEVER be read to imply a real
broker endpoint/credentials, managed durability/replication/failover, real DLQ
inspection, monitoring, ``PRODUCTION_QUEUE_ADAPTER_ACCEPTED``, or GA acceptance.
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

SCHEMA_VERSION = "production-queue-profile-evidence.v1"
EVIDENCE_TYPE = "production-queue-profile-behavioral"
IMPLEMENTATION_VERSION = "1.0.0"
BEHAVIORAL_VERDICT = "PRODUCTION_QUEUE_ADAPTER_BEHAVIORAL_ACCEPTED"
EVIDENCE_PATH = ROOT / "output" / "production-queue-profile" / f"{SCHEMA_VERSION}.json"

REJECTED_SCHEMA_VERSIONS: tuple[str, ...] = ("production-queue-adapter-evidence.v1",)

REQUIRED_BEHAVIORAL_DOMAINS: tuple[str, ...] = (
    "explicit_selection_and_no_fallback",
    "verified_tls_enforcement",
    "bounded_resources_and_backpressure",
    "tenant_and_idempotency_bound_messages",
    "message_schema_and_size_validation",
    "at_least_once_delivery_with_lease",
    "ack_after_durable_business_and_audit_commit",
    "durable_tenant_scoped_idempotency",
    "duplicate_delivery_no_duplicate_effect",
    "cross_tenant_isolation",
    "bounded_classified_retry",
    "poison_dead_letter_isolation",
    "authorized_idempotent_replay",
    "bounded_concurrency_stress",
    "bounded_startup_and_shutdown",
    "redacted_observability",
    "secret_scan",
)

PROVING_CLASSES = ("executed_disposable_test", "disposable_target_observation")
NON_PROVING_CLASSES = ("literal_assertion", "documentation_only", "assumed_default", "queue_reachability_ping")

REQUIRED_DOMAIN_FIELDS = ("status", "observation_class", "checks_total", "checks_passed")
DOMAIN_STATUSES = ("PASS", "FAIL", "NOT_PROVEN")

REQUIRED_TARGET = {
    "provider_classification": "disposable-docker-redis",
    "environment_classification": "test",
    "endpoint_classification": "docker-loopback",
    "durability_classification": "ephemeral",
    "delivery_model": "at-least-once",
}
FORBIDDEN_TARGET_VALUES: frozenset[str] = frozenset({
    "managed-redis-compatible", "self-managed-redis-compatible", "managed-queue-service",
    "production", "staging", "private-network", "public-with-allowlist",
    "durable-replicated", "durable-single", "exactly-once",
})

REQUIRED_DISCLOSURES = (
    "not_production_target_acceptance",
    "ga_redis_adapter_remains_blocked",
    "no_real_broker_endpoint_or_credentials",
    "no_managed_durability_replication_failover_or_monitoring_certified",
    "not_ga_acceptance",
)

MAX_AGE_DAYS = 90
NON_CANONICAL_KEYS = frozenset({"canonical_payload_hash", "generated_at", "generation_metadata"})
_LEAK_PATTERNS = (r"redis(?:s)?://", r"password\s*[:=]", r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                  r"requirepass", r"\bmrq:[0-9a-f]{6,}")
GIT_UNAVAILABLE = "<git-unavailable>"


def _normalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in sorted(obj.items()) if k not in NON_CANONICAL_KEYS}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def canonical_hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def contract_hash() -> str:
    body = {"schema_version": SCHEMA_VERSION, "evidence_type": EVIDENCE_TYPE,
            "implementation_version": IMPLEMENTATION_VERSION, "verdict": BEHAVIORAL_VERDICT,
            "required_domains": list(REQUIRED_BEHAVIORAL_DOMAINS), "proving_classes": list(PROVING_CLASSES),
            "required_target": REQUIRED_TARGET, "forbidden_target_values": sorted(FORBIDDEN_TARGET_VALUES),
            "required_disclosures": list(REQUIRED_DISCLOSURES), "rejected_schema_versions": list(REJECTED_SCHEMA_VERSIONS)}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _git(args):
    try:
        out = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, timeout=15)
        return GIT_UNAVAILABLE if out.returncode != 0 else out.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return GIT_UNAVAILABLE


def git_rev(ref): return _git(["rev-parse", ref])
def worktree_is_clean(): return _git(["status", "--porcelain", "--untracked-files=no"]) == ""
def _sha(v, n): return isinstance(v, str) and bool(re.fullmatch(rf"[0-9a-f]{{{n}}}", v))


def _ts(v):
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate(payload, *, current_commit=None, current_tree=None, now=None):
    r: list[str] = []
    try:
        if not isinstance(payload, dict):
            return ["profile evidence is not a JSON object"]
        now = now or datetime.now(timezone.utc)
        if payload.get("schema_version") in REJECTED_SCHEMA_VERSIONS:
            r.append("a foreign (production-target) schema is presented at the behavioral path")
        elif payload.get("schema_version") != SCHEMA_VERSION:
            r.append(f"unknown schema_version {payload.get('schema_version')!r}")
        if payload.get("evidence_type") != EVIDENCE_TYPE:
            r.append("wrong evidence_type")
        if payload.get("implementation_version") != IMPLEMENTATION_VERSION:
            r.append("implementation_version mismatch")
        if payload.get("verdict") != BEHAVIORAL_VERDICT:
            r.append("verdict is not the behavioral verdict")
        commit, tree = payload.get("git_commit"), payload.get("git_tree")
        if not _sha(commit, 40):
            r.append("git_commit missing/not 40-char SHA")
        if not _sha(tree, 40):
            r.append("git_tree missing/not 40-char SHA")
        exp_c = current_commit if current_commit is not None else git_rev("HEAD")
        exp_t = current_tree if current_tree is not None else git_rev("HEAD^{tree}")
        if not _sha(exp_c, 40):
            r.append("current commit unverifiable")
        elif commit != exp_c:
            r.append("evidence is stale: git_commit != current commit (wrong head)")
        if not _sha(exp_t, 40):
            r.append("current tree unverifiable")
        elif tree != exp_t:
            r.append("evidence is stale: git_tree != current tree")
        if payload.get("worktree_clean") is not True:
            r.append("evidence does not attest a clean worktree")
        elif not worktree_is_clean():
            r.append("tracked worktree is dirty now")
        declared = payload.get("canonical_payload_hash")
        if not _sha(declared, 64):
            r.append("canonical_payload_hash missing/not 64-char SHA-256")
        elif declared != canonical_hash(payload):
            r.append("canonical_payload_hash does not match the body")
        gen = _ts(payload.get("generated_at"))
        if gen is None:
            r.append("generated_at missing/unparseable")
        elif (now - gen).total_seconds() / 86400.0 > MAX_AGE_DAYS:
            r.append("artifact is stale (>90 days)")
        elif (now - gen).total_seconds() / 86400.0 < -1:
            r.append("artifact dated in the future")
        target = payload.get("target")
        if not isinstance(target, dict):
            r.append("target classification missing")
        else:
            for k, want in REQUIRED_TARGET.items():
                if target.get(k) != want:
                    r.append(f"target.{k} must be {want!r} for the disposable behavioral tier (got {target.get(k)!r})")
            blob = json.dumps(target).lower()
            for f in FORBIDDEN_TARGET_VALUES:
                if f in blob:
                    r.append(f"target dishonestly claims a production property: {f!r}")
        disc = payload.get("disclosures")
        if not isinstance(disc, dict):
            r.append("disclosures block missing")
        else:
            for k in REQUIRED_DISCLOSURES:
                if disc.get(k) is not True:
                    r.append(f"required disclosure {k!r} not affirmed")
            if disc.get("production_target_control") not in ("BLOCKED", "NOT_ACCEPTED"):
                r.append("disclosures must record the production-target control as BLOCKED/NOT_ACCEPTED")
        domains = payload.get("behavioral_domains")
        if not isinstance(domains, dict):
            r.append("behavioral_domains missing")
        else:
            for name in REQUIRED_BEHAVIORAL_DOMAINS:
                d = domains.get(name)
                if not isinstance(d, dict):
                    r.append(f"behavioral domain {name!r} missing")
                    continue
                for f in REQUIRED_DOMAIN_FIELDS:
                    if f not in d:
                        r.append(f"domain {name!r} omits {f!r}")
                if d.get("status") != "PASS":
                    r.append(f"domain {name!r} is not PASS")
                if d.get("observation_class") not in PROVING_CLASSES:
                    r.append(f"domain {name!r} PASS not from a proving class")
                if not (isinstance(d.get("checks_total"), int) and d.get("checks_total", 0) > 0
                        and d.get("checks_passed") == d.get("checks_total")):
                    r.append(f"domain {name!r} has no fully-passing executed checks")
        totals = payload.get("totals")
        if not isinstance(totals, dict) or totals.get("all_passed") is not True:
            r.append("totals.all_passed is not true")
        if payload.get("secret_scan_clean") is not True:
            r.append("secret_scan_clean is not true")
        text = json.dumps(payload)
        for pat in _LEAK_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                r.append("artifact contains a leaked URL/credential/namespace shape")
                break
    except Exception as exc:  # noqa: BLE001
        r.append(f"validator error (fail-closed): {type(exc).__name__}")
    return r


def load_and_validate(path=None, **kw):
    p = path or EVIDENCE_PATH
    if not p.exists():
        return None, ["no behavioral-profile queue evidence artifact present"]
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, [f"artifact is not valid JSON: {type(exc).__name__}"]
    return payload, validate(payload, **kw)


def behavioral_control(path=None, **kw):
    _p, reasons = load_and_validate(path, **kw)
    return "PASS" if not reasons else "BLOCKED"
