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
Writes: ``docs/GA_GAP_ASSESSMENT.v1.json``

The artifact contains no credentials, DSNs, absolute paths, or client data.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
EVIDENCE_PATH = ROOT / "output" / "migrations" / "migration-evidence.v1.json"
OUTPUT_PATH = ROOT / "docs" / "GA_GAP_ASSESSMENT.v1.json"

SCHEMA_VERSION = "ga-gap-assessment.v1"

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
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(postgres_repository)",
        measurement_class=NOT_EVALUABLE, effort="SMALL",
        implemented_capability=(
            "A functional PostgresStateStore exists with RLS enabled/forced on the snapshot table "
            "and a tenant_slug GUC policy."),
        missing_capability=(
            "Requires a reachable PostgreSQL configured as the ACTIVE adapter to evaluate at all. "
            "Two latent defects: readiness reads boot-time store attributes, so the 'live probe' is "
            "live only at process construction; and the Postgres SQL path has no test coverage -- "
            "no guard ever instantiates PostgresStateStore against a database."),
        technical_dependencies=[], external_dependencies=["provisioned PostgreSQL"], sequence=4,
        notes="",
    ),
    "ga_redis_adapter": dict(
        probe_type=PROBE_DELEGATED, probe_location=f"{_EVAL} -> _delegate(redis_queue)",
        measurement_class=NOT_EVALUABLE, effort="SMALL",
        implemented_capability="A Redis queue backend exists as an advisory filter over the snapshot.",
        missing_capability=(
            "Requires a reachable Redis to evaluate. No ack, visibility timeout, retry or DLQ "
            "semantics, so it does not mitigate the lost-update problem."),
        technical_dependencies=[], external_dependencies=["provisioned Redis"], sequence=8, notes="",
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


def _dispositions() -> tuple[dict[str, str], dict[str, str], str, str, bool]:
    """Return (fresh, verified, ga_fresh, ga_verified, evidence_present).

    The evidence artifact is temporarily moved aside -- never deleted -- so the
    fresh-checkout semantics can be measured on this machine.

    ``evidence_present`` is False when this checkout has no local evidence
    artifact at all. In that case the two contexts are necessarily identical and
    the second one must NOT be presented as a verified-environment measurement.
    """
    import backend.app.ga_readiness as G

    def snap() -> tuple[dict[str, str], str]:
        checks = G.evaluate_blockers({})
        status, _ = G.decide_ga(mode="client", parity_ok=True, checks=checks,
                                commands_skipped=False, commands_passed=True, worktree_clean=True)
        return {c["id"]: c["disposition"] for c in checks}, status

    hidden = EVIDENCE_PATH.with_suffix(".json.gap-assessment-hidden")
    had = EVIDENCE_PATH.exists()
    if had:
        EVIDENCE_PATH.rename(hidden)
    try:
        fresh, ga_fresh = snap()
    finally:
        if had:
            hidden.rename(EVIDENCE_PATH)
    verified, ga_verified = snap() if had else (fresh, ga_fresh)
    return fresh, verified, ga_fresh, ga_verified, had


def build() -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    fresh, verified, ga_fresh, ga_verified, evidence_present = _dispositions()

    controls = []
    for entry in sorted(registry["blockers"], key=lambda b: b["check_id"]):
        cid = entry["check_id"]
        a = _ASSESSMENT.get(cid, {})
        klass = a.get("measurement_class", ABSENT)
        # A curated BEHAVIORALLY_PROVEN class describes the capability, not this
        # checkout. When the live disposition is not PASS the control was not
        # actually measured here (its evidence artifact is absent), so downgrade
        # rather than overstate.
        live = verified.get(cid)
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
        "worktree_clean": _git(["status", "--porcelain"]) == "",
        "registry_version": registry.get("registry_version"),
        "registry_path": "evals/ga/blocker_registry.v1.json",
        "control_count": len(controls),
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
        "local_evidence_artifact_present": evidence_present,
        "contexts": {
            "fresh_checkout_no_local_evidence": {"ga": ga_fresh, "tally": tally(fresh)},
            "verified_environment_with_evidence": {
                "ga": ga_verified,
                "tally": tally(verified),
                "measured": evidence_present,
                "note": (
                    "Measured against the local evidence artifact."
                    if evidence_present else
                    "NOT MEASURED: this checkout has no local evidence artifact, so this context is "
                    "identical to the fresh-checkout context. Regenerate evidence to measure it."
                ),
            },
        },
        "controls": controls,
    }


def main() -> int:
    payload = build()
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
    print(f"wrote           : {OUTPUT_PATH.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
