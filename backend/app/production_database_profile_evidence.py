"""Production-database-PROFILE BEHAVIORAL evidence tier.

A distinct, disposable-provable acceptance tier that is deliberately SEPARATE from the
accepted production-TARGET contract in ``production_database_adapter_evidence.py``. That
contract (``production-database-adapter-evidence.v1`` / ``ga_postgres_adapter``) is NOT
modified, NOT reinterpreted, and REMAINS BLOCKED: it requires live production-target
observations (managed/self-managed identity, private-network endpoint, durable-replicated
storage, executed backup/restore/failover drills) that disposable infrastructure cannot
and must not provide.

This tier certifies only the adapter's BEHAVIOR against DISPOSABLE, TLS-enabled test
PostgreSQL: fail-closed selection/config, enforced verify-full TLS, migration/runtime
least-privilege, forced RLS, transaction-local tenant context with pool hygiene, bounded
pooling, business/audit atomicity, a bounded pre-mutation / no post-mutation retry
boundary, and bounded startup/shutdown. Its PASS verdict is
``PRODUCTION_DATABASE_ADAPTER_BEHAVIORAL_ACCEPTED`` and it MUST NEVER be read to imply a
real endpoint, real credentials, production networking/IAM, backups, failover,
observability, operational ownership, the production-target ``PRODUCTION_DATABASE_ADAPTER_ACCEPTED``,
or any GA acceptance.

Like the production-target module, this is a never-raising validator that executes,
probes, provisions, and discovers NOTHING; a separate guard/generator runs the disposable
proofs and this validates the resulting artifact's structure, binding, and honesty.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]  # repository root (backend/app/x.py -> repo)

SCHEMA_VERSION = "production-database-profile-evidence.v1"
EVIDENCE_TYPE = "production-database-profile-behavioral"
IMPLEMENTATION_VERSION = "1.0.0"
BEHAVIORAL_VERDICT = "PRODUCTION_DATABASE_ADAPTER_BEHAVIORAL_ACCEPTED"
EVIDENCE_PATH = ROOT / "output" / "production-database-profile" / f"{SCHEMA_VERSION}.json"

REJECTED_SCHEMA_VERSIONS: tuple[str, ...] = (
    "production-database-adapter-evidence.v1",   # the production-TARGET schema — never at this path
)

#: Behavioral proof domains. Each is REQUIRED and each is proven by EXECUTING a test
#: against disposable infrastructure — the only proving classes this tier accepts.
REQUIRED_BEHAVIORAL_DOMAINS: tuple[str, ...] = (
    "explicit_selection_and_fail_closed_config",
    "verified_tls_enforcement",
    "migration_runtime_role_separation",
    "runtime_least_privilege",
    "forced_rls",
    "schema_and_migration_verification",
    "bounded_connection_pool",
    "transaction_local_tenant_context",
    "pool_hygiene_no_tenant_leak",
    "cross_tenant_isolation",
    "business_audit_atomicity",
    "pre_mutation_retry_bounded",
    "no_post_mutation_retry",
    "bounded_startup_and_shutdown",
    "redacted_observability",
    "secret_scan",
)

#: Observation classes that support a PASS in THIS tier — an executed disposable test or
#: a direct observation of the disposable target. (Not the production-target proving
#: classes.) A literal assertion or documentation never supports a PASS.
PROVING_CLASSES: tuple[str, ...] = ("executed_disposable_test", "disposable_target_observation")
NON_PROVING_CLASSES: tuple[str, ...] = ("literal_assertion", "documentation_only", "assumed_default")

REQUIRED_DOMAIN_FIELDS: tuple[str, ...] = ("status", "observation_class", "checks_total", "checks_passed")
DOMAIN_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "NOT_PROVEN")

#: The target MUST be honestly classified as disposable. Any production-target
#: classification at this path is a rejection — this tier must never masquerade as the
#: production-target acceptance.
REQUIRED_TARGET = {
    "provider_classification": "disposable-docker-postgresql",
    "environment_classification": "test",
    "endpoint_classification": "docker-loopback",
    "storage_classification": "ephemeral",
}
#: Values that would dishonestly claim production. Their presence is a hard rejection.
FORBIDDEN_TARGET_VALUES: frozenset[str] = frozenset({
    "managed-postgresql", "self-managed-postgresql", "production", "staging",
    "private-network", "public-with-allowlist", "durable-replicated", "durable-single",
})

REQUIRED_DISCLOSURES: tuple[str, ...] = (
    "not_production_target_acceptance",
    "ga_postgres_adapter_remains_blocked",
    "no_real_endpoint_or_credentials",
    "no_backup_restore_failover_or_monitoring_certified",
    "not_ga_acceptance",
)

MAX_AGE_DAYS = 90
NON_CANONICAL_KEYS: frozenset[str] = frozenset({"canonical_payload_hash", "generated_at", "generation_metadata"})

_LEAK_PATTERNS: tuple[str, ...] = (
    r"postgres(?:ql)?://", r"password\s*[:=]", r"sslkey\s*[:=]",
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b", r"\bmr_p(?:rt|mig)_[0-9a-f]{6,}\b",
)

GIT_UNAVAILABLE = "<git-unavailable>"


class ProfileEvidenceUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------- canonical hash
def _normalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in sorted(obj.items()) if k not in NON_CANONICAL_KEYS}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def canonical_json(payload: dict) -> str:
    return json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def contract_hash() -> str:
    body = {
        "schema_version": SCHEMA_VERSION, "evidence_type": EVIDENCE_TYPE,
        "implementation_version": IMPLEMENTATION_VERSION, "verdict": BEHAVIORAL_VERDICT,
        "required_domains": list(REQUIRED_BEHAVIORAL_DOMAINS),
        "proving_classes": list(PROVING_CLASSES), "required_target": REQUIRED_TARGET,
        "forbidden_target_values": sorted(FORBIDDEN_TARGET_VALUES),
        "required_disclosures": list(REQUIRED_DISCLOSURES),
        "rejected_schema_versions": list(REJECTED_SCHEMA_VERSIONS),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _git(args: list[str]) -> str:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, timeout=15)
        if out.returncode != 0:
            return GIT_UNAVAILABLE
        return out.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return GIT_UNAVAILABLE


def git_rev(ref: str) -> str:
    return _git(["rev-parse", ref])


def worktree_is_clean() -> bool:
    return _git(["status", "--porcelain", "--untracked-files=no"]) == ""


def _is_sha(v: Any, n: int) -> bool:
    return isinstance(v, str) and bool(re.fullmatch(rf"[0-9a-f]{{{n}}}", v))


def _parse_ts(v: Any) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


# --------------------------------------------------------------- validator
def validate(payload: Any, *, current_commit: str | None = None,
             current_tree: str | None = None, now: datetime | None = None) -> list[str]:
    """Return rejection reasons ([] == valid). NEVER raises."""
    r: list[str] = []
    try:
        if not isinstance(payload, dict):
            return ["profile evidence is not a JSON object"]
        now = now or datetime.now(timezone.utc)

        schema = payload.get("schema_version")
        if schema in REJECTED_SCHEMA_VERSIONS:
            r.append(f"a foreign schema {schema!r} is presented at the behavioral-profile path")
        elif schema != SCHEMA_VERSION:
            r.append(f"unknown schema_version {schema!r} (expected {SCHEMA_VERSION})")
        if payload.get("evidence_type") != EVIDENCE_TYPE:
            r.append("wrong evidence_type")
        if payload.get("implementation_version") != IMPLEMENTATION_VERSION:
            r.append("implementation_version does not match the contract module")
        if payload.get("verdict") != BEHAVIORAL_VERDICT:
            r.append("verdict is not the behavioral verdict")

        commit, tree = payload.get("git_commit"), payload.get("git_tree")
        if not _is_sha(commit, 40):
            r.append("git_commit missing/not a 40-char SHA")
        if not _is_sha(tree, 40):
            r.append("git_tree missing/not a 40-char SHA")
        exp_c = current_commit if current_commit is not None else git_rev("HEAD")
        exp_t = current_tree if current_tree is not None else git_rev("HEAD^{tree}")
        if not _is_sha(exp_c, 40):
            r.append("current commit unverifiable")
        elif commit != exp_c:
            r.append("evidence is stale: git_commit != current commit (wrong head)")
        if not _is_sha(exp_t, 40):
            r.append("current tree unverifiable")
        elif tree != exp_t:
            r.append("evidence is stale: git_tree != current tree")
        if payload.get("worktree_clean") is not True:
            r.append("evidence does not attest a clean worktree")
        elif not worktree_is_clean():
            r.append("tracked worktree is dirty now")

        declared = payload.get("canonical_payload_hash")
        if not _is_sha(declared, 64):
            r.append("canonical_payload_hash missing/not a 64-char SHA-256")
        elif declared != canonical_hash(payload):
            r.append("canonical_payload_hash does not match the canonical body")

        gen = _parse_ts(payload.get("generated_at"))
        if gen is None:
            r.append("generated_at missing/unparseable")
        elif (now - gen).total_seconds() / 86400.0 > MAX_AGE_DAYS:
            r.append("artifact is stale (> 90 days)")
        elif (now - gen).total_seconds() / 86400.0 < -1:
            r.append("artifact dated in the future")

        # target must be HONESTLY disposable, and must not claim production
        target = payload.get("target")
        if not isinstance(target, dict):
            r.append("target classification missing")
        else:
            for key, want in REQUIRED_TARGET.items():
                if target.get(key) != want:
                    r.append(f"target.{key} must be {want!r} for the disposable behavioral tier "
                             f"(got {target.get(key)!r})")
            blob = json.dumps(target).lower()
            for forbidden in FORBIDDEN_TARGET_VALUES:
                if forbidden in blob:
                    r.append(f"target dishonestly claims a production property: {forbidden!r}")

        # disclosures that keep this from masquerading as production/GA
        disc = payload.get("disclosures")
        if not isinstance(disc, dict):
            r.append("disclosures block missing")
        else:
            for key in REQUIRED_DISCLOSURES:
                if disc.get(key) is not True:
                    r.append(f"required disclosure {key!r} is not affirmed")
            if disc.get("production_target_control") not in ("BLOCKED", "NOT_ACCEPTED"):
                r.append("disclosures must record the production-target control as BLOCKED/NOT_ACCEPTED")

        # behavioral domains: every one present, PASS, from a proving class, non-empty
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
        if not isinstance(totals, dict) or not totals.get("all_passed") is True:
            r.append("totals.all_passed is not true")
        if payload.get("secret_scan_clean") is not True:
            r.append("secret_scan_clean is not true")

        # leak scan of the whole artifact
        text = json.dumps(payload)
        for pat in _LEAK_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                r.append("artifact contains a leaked DSN/credential/role/endpoint shape")
                break
    except Exception as exc:  # noqa: BLE001 - a malformed artifact must degrade, not crash
        r.append(f"validator error (fail-closed): {type(exc).__name__}")
    return r


def load_and_validate(path: Path | None = None, **kw) -> tuple[dict | None, list[str]]:
    p = path or EVIDENCE_PATH
    if not p.exists():
        return None, ["no behavioral-profile evidence artifact present"]
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, [f"artifact is not valid JSON: {type(exc).__name__}"]
    return payload, validate(payload, **kw)


def behavioral_control(path: Path | None = None, **kw) -> str:
    """The behavioral control disposition: 'PASS' iff the complete conjunction validates,
    else 'BLOCKED'. This is a SEPARATE tier from ga_postgres_adapter and never changes it."""
    _payload, reasons = load_and_validate(path, **kw)
    return "PASS" if not reasons else "BLOCKED"
