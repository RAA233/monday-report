"""Build the GA control gap assessment artifact.

Merges three sources into one machine-readable artifact:

1. ``evals/ga/blocker_registry.v1.json`` -- the authoritative control registry
   (identifiers, categories, severities, owner types, resolution conditions).
   This script NEVER writes to the registry.
2. Live dispositions from ``ga_readiness.evaluate_blockers`` in BOTH evidence
   contexts (fresh checkout with no local evidence artifact, and the verified
   environment where that artifact is present).
3. A curated, human-reviewed capability assessment (``_ASSESSMENT`` below)
   recording what the code actually implements versus what each resolution
   condition demands.

The central distinction this artifact exists to make:

    A ``BLOCKED`` disposition does NOT imply a behavioural failure.

``ga_readiness.evaluate_blockers`` dispatches a behavioural probe for only a
minority of controls. Every other control falls through to a default that
declares BLOCKED and quotes the registry's static ``description`` string. Those
descriptions were written when the registry was authored and some are now stale
(``per-user-identity`` is the clearest case). Reporting such a control as a
measured failure would be incorrect, so each entry carries an explicit
``measurement_class``.

Run: ``python scripts/build_ga_gap_assessment.py``
Writes: ``docs/GA_GAP_ASSESSMENT.v2.json``

The artifact contains no credentials, DSNs, absolute paths, or client data.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import os
import shutil
import tempfile
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
EVIDENCE_PATH = ROOT / "output" / "migrations" / "migration-evidence.v1.json"
OUTPUT_PATH = ROOT / "docs" / "GA_GAP_ASSESSMENT.v2.json"
#: Legacy path. It must NOT exist: two files either of which could be read as current is
#: exactly the ambiguity this increment removes.
LEGACY_ARTIFACT_PATH = ROOT / "docs" / "GA_GAP_ASSESSMENT.v1.json"

SCHEMA_VERSION = "ga-gap-assessment.v2"
#: v1 is superseded: it carried no source bindings, no canonical hash and no artifact
#: classification, so a reader could not tell a generated status report from evidence. Exported for
#: the drift guard rather than duplicated there.
SUPERSEDED_SCHEMA_VERSIONS = ("ga-gap-assessment.v1",)

# Measurement classes -- how a disposition was actually arrived at.
BEHAVIOURALLY_PROVEN = "BEHAVIORALLY_PROVEN"
BEHAVIOURALLY_FAILED = "BEHAVIORALLY_FAILED"
IMPLEMENTED_BUT_UNMEASURED = "IMPLEMENTED_BUT_UNMEASURED"
ABSENT = "ABSENT"
NOT_EVALUABLE = "NOT_EVALUABLE"
EXTERNAL = "EXTERNAL"

# Probe types, mirroring the dispatch in ga_readiness.evaluate_blockers.
PROBE_BEHAVIOURAL = "behavioral_probe"
PROBE_EVIDENCE = "evidence_driven_probe"
PROBE_DELEGATED = "delegated_readiness_check"
PROBE_HARDCODED = "hardcoded_disposition"
PROBE_NONE = "registry_default_no_evaluator"

_EVAL = "backend/app/ga_readiness.py:evaluate_blockers"

# --------------------------------------------------------------------------- #
# Curated capability assessment.
#
# Derived from a read-only subsystem audit of the tree at 02536db in which every
# finding was independently re-checked against the implementation before being
# recorded here. "implemented_capability" describes what demonstrably exists;
# "missing_capability" describes what the resolution condition still demands.
# --------------------------------------------------------------------------- #
_ASSESSMENT: dict[str, dict] = {
    "ga_migration_runner": dict(
        probe_type=PROBE_EVIDENCE, probe_location=f"{_EVAL} -> _migration_runner_probe",
        measurement_class=BEHAVIOURALLY_PROVEN, effort="DONE",
        implemented_capability=(
            "Deterministic runner with schema_migrations metadata, session advisory lock, "
            "per-migration transactions, checksum-drift refusal; proven on real PostgreSQL 16.14."),
        missing_capability="None. PASS requires the local evidence artifact to be present.",
        technical_dependencies=[], external_dependencies=["disposable PostgreSQL 16 with pgvector"],
        sequence=None,
        notes=("Evidence artifact lives under output/ which is gitignored, so a fresh checkout "
               "correctly falls back to BLOCKED. That is fail-closed behaviour, not a regression."),
    ),
    "ga_migration_validity": dict(
        probe_type=PROBE_EVIDENCE, probe_location=f"{_EVAL} -> _migration_validity_probe",
        measurement_class=BEHAVIOURALLY_FAILED, effort="EXTERNAL_DECISION",
        implemented_capability=(
            "Corrected fresh-install baseline in db/baseline/ applies cleanly on real PostgreSQL."),
        missing_capability=(
            "The immutable legacy sequence remains un-appliable: 0003 references projects(id) and "
            "reports(id), which no earlier legacy migration creates. Fails on real PostgreSQL at "
            "version 3 with 'relation \"projects\" does not exist'."),
        technical_dependencies=[], external_dependencies=[],
        sequence=None,
        notes=("Deliberately BLOCKED. The historical migration is NOT rewritten because its "
               "never-deployed status cannot be proven. The probe independently re-runs the static "
               "validator over db/migrations/, so a passing baseline cannot flip it."),
    ),
    "ga_rbac_role_separation": dict(
        probe_type=PROBE_BEHAVIOURAL, probe_location=f"{_EVAL} -> _rbac_role_separation_probe",
        measurement_class=BEHAVIOURALLY_PROVEN, effort="DONE",
        implemented_capability="Route-level RBAC with complete route coverage, proven by probe.",
        missing_capability="None.",
        technical_dependencies=[], external_dependencies=[], sequence=None, notes="",
    ),
    "ga_verified_reviewer_identity": dict(
        probe_type=PROBE_BEHAVIOURAL, probe_location=f"{_EVAL} -> _verified_reviewer_probe",
        measurement_class=BEHAVIOURALLY_PROVEN, effort="DONE",
        implemented_capability="Terminal validation outcomes attribute a verified authenticated human.",
        missing_capability="None.",
        technical_dependencies=[], external_dependencies=[], sequence=None, notes="",
    ),
    "ga_audit_keyed_integrity": dict(
        probe_type=PROBE_BEHAVIOURAL, probe_location=f"{_EVAL} -> _audit_keyed_integrity_probe",
        measurement_class=NOT_EVALUABLE, effort="SMALL",
        implemented_capability=(
            "Versioned HMAC-SHA256 audit chain with key rotation and retained verification-only "
            "keys; the probe signs a fresh event and requires a public-SHA forgery to be rejected. "
            "Backed by an 86-check behavioural guard. Evaluates PASS whenever an active key is set."),
        missing_capability=(
            "No code gap. The control reads BLOCKED only when the evaluated environment has no "
            "MONDAY_REPORT_AUDIT_HMAC_KEY. The resolution phrase 'a state-file writer cannot forge' "
            "additionally assumes key custody separate from the state file, which env-var injection "
            "on the same host does not by itself establish."),
        technical_dependencies=[], external_dependencies=["operator-provisioned audit HMAC key"],
        sequence=1,
        notes=("The GA client env generator previously omitted this key entirely, producing an "
               "environment in which every protected route failed closed. Fixed on this branch."),
    ),
    "ga_per_user_identity": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=IMPLEMENTED_BUT_UNMEASURED, effort="SMALL",
        implemented_capability=(
            "Per-user identity is implemented: opaque high-entropy credentials, SHA-256 + optional "
            "pepper at-rest hashing with constant-time compare, non-secret fingerprints, "
            "active/revoked credential status, per-user records with roles and account_status, "
            "admin-gated HTTP provisioning, an offline provisioning CLI, request-scoped identity in "
            "a ContextVar, and audit actor fields derived from the resolved caller. Client mode "
            "explicitly REJECTS the legacy shared key for authentication."),
        missing_capability=(
            "No behavioural evaluator exists, so the control defaults to BLOCKED. Closing it "
            "honestly requires an evidence-driven probe plus a behavioural guard exercising real "
            "routes, and removal of the assertion that currently pins it BLOCKED."),
        technical_dependencies=[], external_dependencies=[], sequence=2,
        notes=("The registry DESCRIPTION for this control is stale -- it predates the authenticated "
               "identity work. The RESOLUTION CONDITION is not stale and is not modified."),
    ),
    "ga_tenant_authorization": dict(
        probe_type=PROBE_BEHAVIOURAL, probe_location=f"{_EVAL} -> _tenant_authorization_probe",
        measurement_class=BEHAVIOURALLY_FAILED, effort="LARGE",
        implemented_capability=(
            "API-layer per-request tenant ownership is enforced and proven: every resource-scoped "
            "route carries a tenant-ownership dependency, the ownership graph fails closed on a "
            "contradictory chain, cross-tenant access is an existence-hiding 404, and list "
            "aggregates are tenant-filtered before counting."),
        missing_capability=(
            "The resolution condition also requires Postgres RLS active over the normalized store. "
            "The Postgres adapter stores one JSONB snapshot per tenant_slug, and the normalized "
            "migration leaves every tenant_isolation policy commented out."),
        technical_dependencies=["normalized persistence", "per-transaction tenant context"],
        external_dependencies=["provisioned PostgreSQL"], sequence=6,
        notes="Route-level enforcement alone is explicitly insufficient for this condition.",
    ),
    "ga_persistence_locking": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability=(
            "Nothing for application mutations. The universal pattern is refresh() -> mutate in "
            "memory -> save() rewriting the entire payload. The local store's tmp-file + replace is "
            "atomic FILE replacement only; it prevents torn files, not lost updates. "
            "PostgresStateStore.save() is a single-statement whole-payload upsert whose preceding "
            "read uses a separate connection and therefore a separate transaction."),
        missing_capability=(
            "No SELECT FOR UPDATE, no advisory lock, no revision/CAS column, no conflict retry, no "
            "idempotency key. The only advisory lock in the repository belongs to the migration "
            "runner, which this control explicitly excludes. Three in-process RLocks concede "
            "last-writer-wins across processes in their own comments."),
        technical_dependencies=["transactional PostgreSQL snapshot mutation path"],
        external_dependencies=["provisioned PostgreSQL"], sequence=3,
        notes=("Resolution language quoted verbatim: 'Multi-entity mutations run under a "
               "transaction/lock; no cross-process whole-snapshot last-writer-wins.' It does NOT "
               "mandate normalized tables, so a transactional snapshot with row locking and "
               "revision compare-and-swap can satisfy it."),
    ),
    "ga_correction_cross_process_atomicity": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability=(
            "Correction lineage is enforced only by an in-process lock. There is no "
            "field_corrections table at all."),
        missing_capability=(
            "A normalized corrections table with row/advisory locking or a uniqueness constraint on "
            "the active lineage."),
        technical_dependencies=["normalized persistence for corrections"],
        external_dependencies=["provisioned PostgreSQL"], sequence=7,
        notes=("Resolution language quoted verbatim: 'Correction lineage integrity is guaranteed "
               "across processes via normalized persistence with row/advisory locking or a "
               "uniqueness constraint.' Unlike persistence-locking-transactions this explicitly "
               "requires NORMALIZED persistence, so a transactional snapshot cannot close it."),
    ),
    "ga_postgres_adapter": dict(
        probe_type=PROBE_EVIDENCE,
        probe_location=f"{_EVAL} -> _postgres_adapter_probe -> "
                       "backend/app/production_database_adapter_evidence.py",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability=(
            "An ACCEPTED static evidence contract (production-database-adapter-evidence.v1) with a "
            "fail-closed validator and an isolated readiness consumer. A functional PostgresStateStore "
            "exists with RLS enabled and forced, proven on the accepted restricted runtime."),
        missing_capability=(
            "No production database-adapter evidence artifact exists at any commit. The control now "
            "requires one: a named production target that is not loopback/docker-bridge, not a "
            "test/staging/development environment and not ephemeral storage, with verified TLS, "
            "credential rotation, least-privilege runtime roles, executed backup/restore and "
            "failover drills, monitoring and capacity thresholds. A disposable PostgreSQL, the "
            "restricted runtime functional matrix, tenant-authorization evidence and the "
            "dual-backend UI proof are each explicitly non-qualifying."),
        technical_dependencies=[],
        external_dependencies=["provisioned PRODUCTION PostgreSQL", "operational evidence collection"],
        sequence=4,
        notes=("Static contract ACCEPTED; production execution NOT accepted. Contract acceptance is "
               "not adapter acceptance."),
    ),
    "ga_redis_adapter": dict(
        probe_type=PROBE_EVIDENCE,
        probe_location=f"{_EVAL} -> _queue_adapter_probe -> "
                       "backend/app/production_queue_adapter_evidence.py",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability=(
            "An ACCEPTED static evidence contract (production-queue-adapter-evidence.v1) with a "
            "fail-closed validator and an isolated readiness consumer. The queue itself is a "
            "best-effort index over authoritative store state."),
        missing_capability=(
            "No production queue-adapter evidence artifact exists at any commit, and the present "
            "queue cannot satisfy the contract: delivery is at-most-once, enqueue is a non-atomic "
            "SADD+RPUSH, dequeue is an LPOP with no lease or acknowledgement, the loss window is "
            "PERMANENT because the dedupe-set entry blocks re-derivation, and there is no retry "
            "counter, dead-letter queue or per-tenant namespace in the queue keys. Queue "
            "reachability (a liveness ping), a disposable Docker Redis, the restricted worker "
            "matrix, tenant-authorization evidence, the dual-backend UI proof and production "
            "DATABASE-adapter evidence are each explicitly non-qualifying."),
        technical_dependencies=[],
        external_dependencies=["provisioned PRODUCTION queue service", "operational evidence collection"],
        sequence=8,
        notes=("Static contract ACCEPTED; production execution NOT accepted. Contract acceptance is "
               "not adapter acceptance."),
    ),
    "ga_backup_restore_drill": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None. The only repository-wide match for pg_dump/RPO/RTO is the registry entry itself.",
        missing_capability="A backup mechanism, an evidenced restore drill, and organizationally approved RPO/RTO.",
        technical_dependencies=["normalized or transactional PostgreSQL persistence"],
        external_dependencies=["human-executed drill", "approved RPO/RTO targets"], sequence=9,
        notes="Cannot reach PASS from documentation alone.",
    ),
    "ga_audit_tail_truncation": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability="None. HMAC protects entry content, not entry existence.",
        missing_capability=(
            "An external anchor in a second trust domain. audit_integrity_status derives "
            "total_events from len(events), so a truncated chain still verifies clean -- the "
            "project proves this deliberately in its own guard."),
        technical_dependencies=[], external_dependencies=["external anchor service or immutable object-lock storage"],
        sequence=10, notes="docs/AUDIT_INTEGRITY.md explicitly rejects a same-process checkpoint as a substitute.",
    ),
    "ga_ci_execution": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None. No .github directory exists anywhere in the repository.",
        missing_capability=(
            "A committed workflow AND an observed run for the exact commit with no required job "
            "skipped, bound to an immutable run identifier."),
        technical_dependencies=[], external_dependencies=["GitHub Actions execution"], sequence=5,
        notes="Committing YAML alone must not flip this control.",
    ),
    "ga_dependency_vuln_scan": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None. No CI, no Dependabot, no scanner configuration.",
        missing_capability="A pinned scanner, severity policy, fail behaviour, and documented expiring exceptions.",
        technical_dependencies=["ga_ci_execution"], external_dependencies=["CI execution"], sequence=11, notes="",
    ),
    "ga_external_malware_scanner": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="A builtin heuristic scanner blocking EICAR-style content and risky extensions.",
        missing_capability="A real external scanning engine with quarantine, result persistence, and timeout policy.",
        technical_dependencies=[], external_dependencies=["external scanning engine"], sequence=12, notes="",
    ),
    "ga_structured_logging": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None.", missing_capability="Structured logs with safe correlation fields across API, worker, persistence and security paths.",
        technical_dependencies=[], external_dependencies=[], sequence=13, notes="",
    ),
    "ga_metrics_monitoring": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None.", missing_capability="Metrics exposed in a form consumable by standard monitoring, plus alert-ready signals.",
        technical_dependencies=["ga_structured_logging"], external_dependencies=["monitoring system"], sequence=14, notes="",
    ),
    "ga_worker_heartbeat": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="None. worker.py is a minimal run-once entry point.",
        missing_capability="Persisted heartbeats, worker identity, stale detection, and honest unhealthy reporting when dependencies are down.",
        technical_dependencies=[], external_dependencies=[], sequence=15, notes="",
    ),
    "ga_official_export_gate": dict(
        probe_type=PROBE_HARDCODED, probe_location=f"{_EVAL} ga_official_export_gate branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="Exports are blocked with HTTP 409 while any validation task is open.",
        missing_capability="A provenance-enforcing gate. The evaluator explicitly refuses callable-method presence as evidence.",
        technical_dependencies=["ga_formatted_export_provenance"], external_dependencies=[], sequence=16, notes="",
    ),
    "ga_formatted_export_provenance": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="MEDIUM",
        implemented_capability="Exports embed benchmark and validation posture fields.",
        missing_capability="Deterministic, verifiable provenance binding report id, revision, tenant, generator version, source hashes, review/approval status and an audit-chain reference.",
        technical_dependencies=[], external_dependencies=[], sequence=17, notes="",
    ),
    "ga_phase06_trust_boundary": dict(
        probe_type=PROBE_NONE, probe_location=f"{_EVAL} default branch",
        measurement_class=ABSENT, effort="LARGE",
        implemented_capability="Archive entry/size limits and sanitized tenant-scoped storage paths.",
        missing_capability="A complete extraction trust boundary including parser crash isolation and export formula-injection neutralisation.",
        technical_dependencies=[], external_dependencies=[], sequence=18, notes="",
    ),
    "ga_parser_coverage_evidence": dict(
        probe_type=PROBE_BEHAVIOURAL, probe_location=f"{_EVAL} -> _forge_probe",
        measurement_class=NOT_EVALUABLE, effort="SMALL",
        implemented_capability="A FORGE corpus evaluation harness exists with a manifest and expectations.",
        missing_capability="A passing forge report must be supplied; the probe currently receives none.",
        technical_dependencies=[], external_dependencies=["reviewed parser evaluation report"], sequence=19, notes="",
    ),
    "ga_reviewed_fixture_evidence": dict(
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(fixture readiness ids)",
        measurement_class=NOT_EVALUABLE, effort="MEDIUM",
        implemented_capability="Golden-fixture and parser-eval readiness checks exist.",
        missing_capability="A reviewed anonymized-client fixture manifest with an authenticated reviewer attestation.",
        technical_dependencies=[], external_dependencies=["human fixture review"], sequence=20, notes="",
    ),
    "ga_production_configuration": dict(
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(config readiness ids)",
        measurement_class=NOT_EVALUABLE, effort="MEDIUM",
        implemented_capability="A fail-closed client-data readiness module with roughly 25 checks already exists and is reusable.",
        missing_capability="Delegated readiness ids are absent from the supplied map in a bare evaluation, so the control cannot evaluate.",
        technical_dependencies=[], external_dependencies=["provisioned production configuration"], sequence=21, notes="",
    ),
    "ga_clean_client_state": dict(
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(demo_seed_removed)",
        measurement_class=NOT_EVALUABLE, effort="MEDIUM",
        implemented_capability="A demo-seed marker triggers a self-wipe to a clean workspace.",
        missing_capability="A read-only clean-state validator plus a separately authorized cleanup process.",
        technical_dependencies=[], external_dependencies=[], sequence=22, notes="",
    ),
    "ga_local_ai_runtime": dict(
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(local_llm_runtime)",
        measurement_class=NOT_EVALUABLE, effort="SMALL",
        implemented_capability="Runtime and pinned model are checked via local_ai.py.",
        missing_capability="Requires a reachable local runtime to evaluate; model digest pinning is not enforced.",
        technical_dependencies=[], external_dependencies=["running local AI runtime"], sequence=23, notes="",
    ),
    "ga_client_organizational_approval": dict(
        probe_type=PROBE_HARDCODED, probe_location=f"{_EVAL} ga_client_organizational_approval branch",
        measurement_class=EXTERNAL, effort="EXTERNAL_DECISION",
        implemented_capability="None.",
        missing_capability="An authenticated approver identity with signature verification, approval version binding and revocation.",
        technical_dependencies=["ga_per_user_identity"],
        external_dependencies=["authorized client/organizational signatory"], sequence=24,
        notes="Must never be self-approved.",
    ),
}


def _git(args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=str(ROOT), text=True).strip()
    except Exception:
        return "unknown"


def _all_evidence_paths() -> list:
    """Every gitignored ``output/`` artifact the evaluator consults.

    Hiding only the migration artifact made the "fresh checkout" context a lie: an independent
    review showed at least three other local artifacts leaking into the generated prose, and at
    exact head they would move dispositions themselves. Read from the evaluator module so a newly
    added evidence path cannot be silently omitted.
    """
    import backend.app.ga_readiness as _g
    paths, seen = [], set()
    for name in dir(_g):
        if not name.endswith("_PATH") and "EVIDENCE" not in name:
            continue
        value = getattr(_g, name, None)
        if isinstance(value, Path) and "output" in value.as_posix() and value not in seen:
            seen.add(value)
            paths.append(value)
    for extra in (EVIDENCE_PATH,):
        if extra not in seen:
            paths.append(extra)
    return paths


def _dispositions() -> tuple[dict[str, str], dict[str, str], str, str, bool]:
    """Return (fresh, verified, ga_fresh, ga_verified, evidence_present).

    The evidence artifact is temporarily moved aside -- never deleted -- so the
    fresh-checkout semantics can be measured on this machine.

    ``evidence_present`` is False when this checkout has no local evidence
    artifact at all. In that case the two contexts are necessarily identical and
    the second one must NOT be presented as a verified-environment measurement.
    """
    import backend.app.ga_readiness as G

    _CAPTURED.clear()

    def snap(hermetic_env: bool = False) -> tuple[dict[str, str], str]:
        """Evaluate the registry. ``hermetic_env`` additionally hides MONDAY_REPORT_* variables.

        The artifact asserts that the fresh-checkout context "is reproducible from the TRACKED
        repository alone". That was FALSE while only local FILES were hidden: an exact-head review
        showed that exporting MONDAY_REPORT_AUDIT_HMAC_KEY/_ID/_VERSION flips
        ga_audit_keyed_integrity from BLOCKED to PASS, so the authoritative context silently
        depended on the operator's shell. Environment is machine-local state exactly as the
        gitignored artifacts are, so the fresh snapshot hides both.
        """
        saved = {}
        if hermetic_env:
            for key in [k for k in os.environ if k.startswith("MONDAY_REPORT_")]:
                saved[key] = os.environ.pop(key)
        try:
            checks = G.evaluate_blockers({})
        finally:
            os.environ.update(saved)
        _CAPTURED["reasons"] = {c["id"]: str(c.get("detail") or "") for c in checks}
        status, _ = G.decide_ga(mode="client", parity_ok=True, checks=checks,
                                commands_skipped=False, commands_passed=True, worktree_clean=True)
        return {c["id"]: c["disposition"] for c in checks}, status

    # Move every local evidence artifact into a private temp directory, not to a fixed sibling
    # name: a fixed target raises FileExistsError on a leftover from an interrupted run, and an
    # interrupted run would otherwise strand the developer's real artifacts.
    stash = Path(tempfile.mkdtemp(prefix="gap-assessment-hidden-"))
    moved = []
    try:
        for index, path in enumerate(_all_evidence_paths()):
            if path.exists():
                target = stash / f"{index}-{path.name}"
                os.replace(path, target)
                moved.append((path, target))
        fresh, ga_fresh = snap(hermetic_env=True)
    finally:
        for path, target in moved:
            path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(target, path)
        shutil.rmtree(stash, ignore_errors=True)
    # The blocking reasons that go into the canonical body are the HERMETIC ones, captured while
    # every local artifact was hidden. Capturing them afterwards made the canonical hash a function
    # of an untracked file's CONTENTS -- an independent review changed the hash by planting garbage.
    _CAPTURED["hermetic_reasons"] = dict(_CAPTURED.get("reasons") or {})
    had = bool(moved)
    verified, ga_verified = snap() if had else (fresh, ga_fresh)
    return fresh, verified, ga_fresh, ga_verified, had


#: Scratch space for the hermetic snapshot's blocking reasons.
_CAPTURED: dict = {}

#: Controls whose disposition is driven by an evidence artifact that must be bound to the CURRENT
#: head. Absent or stale evidence keeps them BLOCKED; nothing here may report otherwise.
_EVIDENCE_DRIVEN = {
    "ga_postgres_adapter", "ga_redis_adapter", "ga_tenant_authorization",
    "ga_migration_runner", "ga_migration_validity", "ga_persistence_locking",
    "ga_correction_cross_process_atomicity", "ga_audit_keyed_integrity",
    "ga_verified_reviewer_identity", "ga_rbac_role_separation",
}


def _evidence_status(check_id: str, probe_type: str | None, fresh_disposition: str | None) -> str:
    """How this control's evidence stands AT THE CURRENT HEAD.

    ``absent`` is the honest answer for every evidence-driven control here: no exact-head artifact
    exists in the tracked repository. A locally present, gitignored artifact is NOT repository state
    and never yields ``present`` -- see ``local_evidence_artifact`` in the payload.
    """
    # Only an EVIDENCE-DRIVEN probe can have an artifact at all. A behavioural probe that passes has
    # no evidence artifact, and reporting present_exact_head for it was false -- an independent
    # review found two such controls in the shipped artifact.
    if probe_type != PROBE_EVIDENCE:
        return "not_evidence_driven"
    return "present_exact_head" if fresh_disposition == "PASS" else "absent"


#: The only notes ``_local_evidence_binding`` may emit. Hoisted to a closed set because the block is
#: excluded from the canonical hash: a review replaced the note with "Production adapter evidence
#: collected and accepted at this head." and the forgery still collided with the honest hash.
LOCAL_EVIDENCE_NOTES = (
    "no local migration evidence artifact on this machine",
    "local artifact unreadable",
    "This artifact is gitignored and is NOT repository state. It is bound to a different commit "
    "than the current head, so the verified-environment context it produces is a MACHINE-LOCAL "
    "observation, not a repository fact.",
    "Local artifact is bound to the current head.",
)

#: The only notes the verified-environment context may carry, for the same reason.
VERIFIED_CONTEXT_NOTES = (
    "Measured against the local evidence artifact.",
    "NOT MEASURED: this checkout has no local evidence artifact, so this context is identical to "
    "the fresh-checkout context. Regenerate evidence to measure it.",
)

#: Verbatim disclosure of what the curated prose is and is not. See ``_ASSESSMENT``.
CURATED_PROSE_DISCLOSURE = (
    "implemented_capability, missing_capability, estimated_effort, technical_dependencies, "
    "external_dependencies and notes are AUTHOR-SUPPLIED commentary. They are not derived from any "
    "evaluator and no guard can verify them, because there is no source of truth to check them "
    "against. The authoritative, machine-derived fields are current_disposition_fresh_checkout and "
    "blocking_reason, both produced by ga_readiness.evaluate_blockers; where the commentary and "
    "those fields disagree, the derived fields govern."
)

#: Exact key set of the local-evidence block.
LOCAL_EVIDENCE_KEYS = frozenset({"present", "tracked", "bound_to_commit", "matches_current_head",
                                 "note"})


def _local_evidence_binding() -> dict:
    """Disclose the machine-local migration artifact's binding, if one is present.

    It is gitignored, so it is NOT part of the repository state this assessment describes. Recording
    its commit binding makes a stale local artifact visible instead of silently flipping a control.
    """
    if not EVIDENCE_PATH.exists():
        return {"present": False, "tracked": False, "bound_to_commit": None,
                "matches_current_head": False,
                "note": LOCAL_EVIDENCE_NOTES[0]}
    try:
        payload = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"present": True, "tracked": False, "bound_to_commit": None,
                "matches_current_head": False, "note": LOCAL_EVIDENCE_NOTES[1]}
    bound = payload.get("git_commit")
    head = _git(["rev-parse", "HEAD"])
    return {
        "present": True,
        "tracked": False,
        "bound_to_commit": bound,
        "matches_current_head": bound == head,
        "note": LOCAL_EVIDENCE_NOTES[2] if bound != head else LOCAL_EVIDENCE_NOTES[3],
    }


def _source_bindings(registry_bytes: bytes) -> dict:
    """Hashes of the sources this assessment is derived from, so drift is detectable."""
    bindings = {"registry_sha256": hashlib.sha256(registry_bytes).hexdigest()}
    try:
        from backend.app import readiness_contexts as _rc
        bindings["readiness_context_inventory_hash"] = _rc.canonical_hash()
    except Exception:  # noqa: BLE001
        bindings["readiness_context_inventory_hash"] = None
    for name, module_path in (("production_database_adapter_contract_hash",
                               "production_database_adapter_evidence"),
                              ("production_queue_adapter_contract_hash",
                               "production_queue_adapter_evidence")):
        try:
            module = __import__(f"backend.app.{module_path}", fromlist=["contract_hash"])
            bindings[name] = module.contract_hash()
        except Exception:  # noqa: BLE001
            bindings[name] = None
    return bindings


#: Excluded from the canonical hash: the hash itself, and the MACHINE-LOCAL observations. Everything
#: else -- including the fresh-checkout context and its tallies -- is covered.
#:
#: `contexts` was previously excluded wholesale, which let a GA_BLOCKED artifact and a GA_READY /
#: 28-PASS artifact share a canonical hash. Only the verified-environment half, which depends on
#: gitignored local artifacts, is excluded now.
# ``local_evidence_paths_present`` counts GITIGNORED artifacts, so it is machine-local exactly like
# the two fields beside it. Admitting it to the canonical body made the hash a function of untracked
# state: a pristine checkout computed 0 where the author's machine computed 5, so the tracked
# artifact was green on one machine and RED everywhere else, with the fault battery reporting zero
# mutations. That is the defect this whole increment exists to prevent.
NON_CANONICAL_KEYS = frozenset({"canonical_payload_hash", "local_evidence_artifact",
                                "local_evidence_artifact_present",
                                "local_evidence_paths_present"})
NON_CANONICAL_CONTEXT_KEYS = frozenset({"verified_environment_with_evidence"})
NON_CANONICAL_CONTROL_KEYS = frozenset({"current_disposition_verified_environment"})


def canonical_body(payload: dict) -> dict:
    """The hermetic, tracked-repository-only content of the assessment."""
    body = {k: v for k, v in payload.items() if k not in NON_CANONICAL_KEYS}
    if isinstance(body.get("contexts"), dict):
        body["contexts"] = {k: v for k, v in body["contexts"].items()
                            if k not in NON_CANONICAL_CONTEXT_KEYS}
    if isinstance(body.get("controls"), list):
        body["controls"] = [{k: v for k, v in c.items() if k not in NON_CANONICAL_CONTROL_KEYS}
                            for c in body["controls"] if isinstance(c, dict)]
    return body


def canonical_json(payload: dict) -> str:
    return json.dumps(canonical_body(payload), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def canonical_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def assessment_keys() -> set:
    """Check ids the curated ``_ASSESSMENT`` block covers.

    Exposed so the guard can require it to equal the registry's check-id set exactly: silently
    dropping a control from ``_ASSESSMENT`` blanked that control's whole assessment and went
    undetected.
    """
    return set(_ASSESSMENT)


def registry_inventory() -> dict:
    """``{registry id: check id}`` loaded from the REAL registry.

    The single authority for which controls exist. Nothing in this repository maintains a second
    hand-authored list of the 28, and no editable constant may redefine the expected set.
    """
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return {entry["id"]: entry["check_id"] for entry in registry["blockers"]}


def registry_inventory_fingerprint() -> str:
    """A REPORTING fingerprint derived from the loaded registry.

    Emitted for humans and diffs. It is computed from the registry, never compared against a stored
    literal, and it does not define the expected set -- a pin that can be edited alongside the thing
    it protects is not an authority.
    """
    inventory = registry_inventory()
    return hashlib.sha256(
        json.dumps(sorted(inventory.items()), separators=(",", ":")).encode("utf-8")).hexdigest()


def source_file_hashes() -> dict:
    """SHA-256 of every file this assessment is derived from, so drift is detectable per file."""
    sources = {
        # The generator carries the curated _ASSESSMENT prose -- implemented/missing capability,
        # measurement class, effort. An independent review edited it to claim an executed
        # backup/restore drill with approved RPO/RTO and BOTH guards certified, because this file
        # was absent from the hash set. It is the most important source of all.
        "scripts/build_ga_gap_assessment.py": pathlib.Path(__file__).resolve(),
        "evals/ga/blocker_registry.v1.json": REGISTRY_PATH,
        "backend/app/ga_readiness.py": ROOT / "backend" / "app" / "ga_readiness.py",
        "backend/app/readiness_contexts.py": ROOT / "backend" / "app" / "readiness_contexts.py",
        "backend/app/production_database_adapter_evidence.py":
            ROOT / "backend" / "app" / "production_database_adapter_evidence.py",
        "backend/app/production_queue_adapter_evidence.py":
            ROOT / "backend" / "app" / "production_queue_adapter_evidence.py",
    }
    out = {}
    for label, path in sources.items():
        try:
            out[label] = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:  # noqa: BLE001
            out[label] = None
    return out


def build() -> dict:
    registry_bytes = REGISTRY_PATH.read_bytes()
    registry = json.loads(registry_bytes.decode("utf-8"))
    fresh, verified, ga_fresh, ga_verified, evidence_present = _dispositions()
    blocking_reasons = dict(_CAPTURED.get("hermetic_reasons") or {})

    controls = []
    for entry in sorted(registry["blockers"], key=lambda b: b["check_id"]):
        cid = entry["check_id"]
        a = _ASSESSMENT.get(cid, {})
        klass = a.get("measurement_class", ABSENT)
        # A curated BEHAVIORALLY_PROVEN class describes the capability, not this
        # checkout. When the live disposition is not PASS the control was not
        # actually measured here (its evidence artifact is absent), so downgrade
        # rather than overstate.
        # Downgrade against the AUTHORITATIVE fresh context, not the machine-local verified one:
        # a curated BEHAVIORALLY_PROVEN class must not survive on the strength of a gitignored
        # artifact. This left migration-runner recorded PROVEN while its fresh disposition was
        # BLOCKED.
        live = fresh.get(cid)
        if klass == BEHAVIOURALLY_PROVEN and live != "PASS":
            klass = NOT_EVALUABLE
        controls.append({
            "id": entry["id"],
            "check_id": cid,
            "category": entry["category"],
            "severity": entry["severity"],
            "owner_type": entry["owner_type"],
            "resolution_condition": entry["resolution_condition"],
            "current_disposition_fresh_checkout": fresh.get(cid),
            "current_disposition_verified_environment": verified.get(cid),
            "probe_type": a.get("probe_type", PROBE_NONE),
            "probe_location": a.get("probe_location", f"{_EVAL} default branch"),
            "measurement_class": klass,
            "behaviorally_measured": a.get("probe_type") in {PROBE_BEHAVIOURAL, PROBE_EVIDENCE},
            "evidence_status": _evidence_status(cid, a.get("probe_type"), fresh.get(cid)),
            "blocking_reason": (blocking_reasons.get(cid) or "")[:400],
            "implemented_capability": a.get("implemented_capability", ""),
            "missing_capability": a.get("missing_capability", ""),
            "technical_dependencies": a.get("technical_dependencies", []),
            "external_dependencies": a.get("external_dependencies", []),
            "estimated_effort": a.get("effort", "UNKNOWN"),
            "recommended_sequence": a.get("sequence"),
            "notes": a.get("notes", ""),
        })

    def tally(d: dict[str, str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for v in d.values():
            out[v] = out.get(v, 0) + 1
        return dict(sorted(out.items()))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_from_commit": _git(["rev-parse", "HEAD"]),
        "generated_from_tree": _git(["rev-parse", "HEAD^{tree}"]),
        # TRACKED-only. Bare porcelain counts untracked files, so the untracked partner documents
        # made this permanently false -- the artifact accused itself of a dirty tree on a clean
        # checkout.
        "worktree_clean": _git(["status", "--porcelain", "--untracked-files=no"]) == "",
        "registry_version": registry.get("registry_version"),
        "registry_path": "evals/ga/blocker_registry.v1.json",
        "control_count": len(controls),
        # What this artifact IS. It carries source bindings and a canonical hash, but it is a
        # generated STATUS REPORT derived from current code and registry state -- not an acceptance
        # artifact and not evidence of anything.
        "artifact_class": "generated_status_assessment",
        "is_acceptance_artifact": False,
        "is_evidence": False,
        "authoritative_context": "fresh_checkout_no_local_evidence",
        "authoritative_context_note": (
            "The fresh-checkout context is authoritative because it is reproducible from the TRACKED "
            "repository alone. The verified-environment context depends on a gitignored machine-local "
            "artifact and is disclosed, not relied upon."),
        # A tracked artifact cannot contain the commit that first introduces it: writing it changes
        # the tree. The model is therefore explicit -- the recorded commit is the immediate PARENT of
        # the commit that carries this artifact, and the per-file source hashes below are what
        # actually detect drift.
        "artifact_generation_model": "tracked-derived-assessment",
        "source_commit_relationship": "immediate-parent-of-artifact-commit",
        "source_bindings": _source_bindings(registry_bytes),
        "source_file_hashes": source_file_hashes(),
        "registry_inventory_fingerprint": registry_inventory_fingerprint(),
        "registry_inventory_fingerprint_note": (
            "Derived from the loaded registry for reporting and diffing only. It does NOT define the "
            "expected control set; the registry itself does."),
        "local_evidence_artifact": _local_evidence_binding(),
        "execution_verdicts": {
            "production_database_adapter": "PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED",
            "production_queue_adapter": "PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED",
            "four_readiness_contexts": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        },
        "static_contracts_accepted": {
            "production_database_adapter_contract": True,
            "production_queue_adapter_contract": True,
            "readiness_context_contract": True,
            "readiness_context_execution_harness": True,
            "tenant_authorization_evidence_contract": True,
        },
        "static_contract_acceptance_is_not_execution_acceptance": True,
        "exact_head_tenant_evidence_present": False,
        "four_contexts_executed_at_this_head": False,
        "capacity_gate": "blocked",
        "client_data_ready": False,
        "release_candidate_ready": False,
        "ga_ready": False,
        "release_recommendation": "GA_BLOCKED",
        "measurement_class_legend": {
            BEHAVIOURALLY_PROVEN: "A probe executed and the control's condition was met.",
            BEHAVIOURALLY_FAILED: "A probe executed and the control's condition was NOT met.",
            IMPLEMENTED_BUT_UNMEASURED: (
                "The capability demonstrably exists but no evaluator measures it, so the control "
                "defaults to BLOCKED. This is NOT a behavioural failure."),
            ABSENT: "The capability genuinely does not exist.",
            NOT_EVALUABLE: "A prerequisite (service, evidence artifact, configuration) is unavailable.",
            EXTERNAL: "Resolution is owned outside engineering and must never be self-approved.",
        },
        # An author who edits the curated block and regenerates produces a self-consistent
        # artifact: there is no oracle for authored commentary, so no guard can verify it. A review
        # proved this by rewording a claim to evade the phrase floor. The limitation is therefore
        # DISCLOSED in the artifact rather than papered over.
        "curated_prose_disclosure": CURATED_PROSE_DISCLOSURE,
        # Kept consistent with local_evidence_artifact.present by construction. A review set this
        # to false / to prose / to null / to {"ga": "GA_READY"} and every variant certified green
        # with a BYTE-IDENTICAL canonical hash, because no check read it at all.
        "local_evidence_artifact_present": evidence_present,
        # How many of the gitignored evidence artifacts actually exist here. The single boolean
        # above reflects only the MIGRATION artifact, which is why GA47f could neither bound the
        # verified half honestly nor refuse a forged one: seven paths drive that half.
        "local_evidence_paths_present": sum(1 for p in _all_evidence_paths() if p.exists()),
        "contexts": {
            "fresh_checkout_no_local_evidence": {
                "ga": ga_fresh,
                "tally": tally(fresh),
                # The only context reproducible from the tracked repository alone -- now genuinely
                # so, since the fresh snapshot hides MONDAY_REPORT_* as well as the local files.
                "informational_only": False,
                "authoritative_for_release": True,
            },
            "verified_environment_with_evidence": {
                "ga": ga_verified,
                "tally": tally(verified),
                "measured": evidence_present,
                # Machine-local observation, NOT repository state and NOT exact-head evidence.
                # Declared in machine-readable form: the distinction previously lived only in a
                # prose note, so a consumer reading the structure could mistake this for the
                # authoritative context.
                "informational_only": True,
                "authoritative_for_release": False,
                "note": (VERIFIED_CONTEXT_NOTES[0] if evidence_present
                         else VERIFIED_CONTEXT_NOTES[1]),
            },
        },
        "controls": controls,
    }


def main() -> int:
    payload = build()
    payload["canonical_payload_hash"] = canonical_hash(payload)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    counts: dict[str, int] = {}
    for c in payload["controls"]:
        counts[c["measurement_class"]] = counts.get(c["measurement_class"], 0) + 1
    print(f"controls        : {payload['control_count']}")
    print(f"fresh checkout  : {payload['contexts']['fresh_checkout_no_local_evidence']['ga']} "
          f"{payload['contexts']['fresh_checkout_no_local_evidence']['tally']}")
    print(f"verified env    : {payload['contexts']['verified_environment_with_evidence']['ga']} "
          f"{payload['contexts']['verified_environment_with_evidence']['tally']}")
    print("measurement     :", dict(sorted(counts.items())))
    print(f"canonical hash  : {payload['canonical_payload_hash']}")
    print(f"registry sha256 : {payload['source_bindings']['registry_sha256']}")
    print(f"artifact class  : {payload['artifact_class']} "
          f"(is_evidence={payload['is_evidence']})")
    print(f"wrote           : {OUTPUT_PATH.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
