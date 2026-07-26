"""audit:production-database-adapter-contract-faults -- integrity battery for the adapter contract.

The evidence guard proves the validator rejects bad *artifacts*. This battery proves the *contract*
cannot be quietly weakened, which is the other half: a requirement deleted from the contract would
make every artifact-level test pass while the bar silently dropped.

Each mutation weakens one contract constant and asserts BOTH:

  1. the weakening is **detectable** -- the pinned contract hash changes; and
  2. the constant is **load-bearing** -- with it weakened, the real validator stops rejecting an
     artifact it rejected before (or the readiness probe stops blocking).

(2) matters as much as (1): a constant that no code consults would satisfy a hash pin while proving
nothing. Every predicate here comes from the real contract module -- ``P.validate`` and the real
``ga_readiness`` probe -- never from a local copy of the rules.

No production infrastructure, database, container or network target is contacted. Artifacts are
synthetic and used only to drive the real validator.

Honest scope: claim_scope = production-database-adapter-contract-integrity-only;
real_production_adapter_executed = false; production_adapter_accepted = false;
release_recommendation = GA_BLOCKED.
"""
from __future__ import annotations

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
from backend.app import production_database_adapter_evidence as P  # noqa: E402
import production_database_adapter_evidence_guard as EG  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("CD", "CT", "CR", "CB", "CP", "CE")

#: The contract hash at acceptance. Pinned as a LITERAL so a weakening is detectable without
#: re-deriving the contract from itself.
PINNED_CONTRACT_HASH = "7b17dcda69a4f81d1b95aade635d67871862c30f3896bcb5ff124305f7a2aff3"

EXPECTED_CHECK_IDS = [
    "FC00 contract-hash-pinned", "FC01 baseline-rejects-nothing-valid",
    # required domains
    "CD01 proof-domain-removed", "CD02 backup-domain-removed", "CD03 restore-test-removed",
    "CD04 monitoring-removed", "CD05 capacity-thresholds-removed",
    "CD06 incident-rollback-removed", "CD07 domain-field-requirement-removed",
    "CD08 non-proving-class-promoted",
    # target / environment
    "CT01 test-evidence-promoted", "CT02 development-environment-accepted",
    "CT03 loopback-target-accepted", "CT04 docker-bridge-accepted",
    "CT05 ephemeral-storage-accepted", "CT06 provider-unknown-accepted",
    # runtime roles
    "CR01 superuser-accepted", "CR02 bypassrls-accepted", "CR03 owner-accepted",
    "CR04 migration-principal-reuse-accepted", "CR05 rls-force-requirement-removed",
    # bindings / hashing
    "CB01 canonical-hash-ignored", "CB02 commit-tree-binding-ignored",
    "CB03 dirty-worktree-accepted", "CB04 non-canonical-keys-widened",
    # parity / disclosure / privacy
    "CP01 production-parity-omitted", "CP02 parity-true-without-observations",
    "CP03 disclosure-requirement-removed", "CP04 non-qualifying-list-emptied",
    "CP05 secret-scan-ignored",
    # evaluator isolation
    "CE01 evaluator-exception-is-pass", "CE02 tenant-v3-cannot-promote",
    "CE03 ui-evidence-cannot-promote", "CE04 runtime-functional-cannot-promote",
    "CE05 registry-untouched",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]
EXPECTED_TOTAL_CHECKS = 37
EXPECTED_MUTATION_COUNT = 33


def rec(cid, ok, desc, level="contract mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def valid() -> dict:
    return EG.build_valid_artifact()


def validate(payload) -> list[str]:
    """The REAL validator, at the real head."""
    return P.validate(payload, current_commit=EG.COMMIT, current_tree=EG.TREE)


def weaken(attr: str, value):
    """Context-managed monkeypatch of one contract constant."""
    class _Patch:
        def __enter__(self):
            self.saved = getattr(P, attr)
            setattr(P, attr, value)
            return self

        def __exit__(self, *exc):
            setattr(P, attr, self.saved)
            return False
    return _Patch()


def detectable_and_load_bearing(cid, attr, weakened_value, artifact_mutation, desc, *,
                                level="contract mutation"):
    """One mutation: assert the weakening changes the pinned hash AND changes real behaviour."""
    payload = valid()
    artifact_mutation(payload)
    payload = EG.rehash(payload)

    # Compare reason SETS, not "was there any reason". Environment-level reasons (e.g. a dirty
    # worktree during development) appear in BOTH runs and would mask the constant's effect
    # entirely -- which is exactly what the first cut of this battery did.
    before = set(validate(payload))
    with weaken(attr, weakened_value):
        hash_changed = P.contract_hash() != PINNED_CONTRACT_HASH
        after = set(validate(payload))
    eliminated = sorted(before - after)
    load_bearing = bool(eliminated)
    rec(cid, hash_changed and load_bearing, desc, level=level,
        extra={"detectable_by_hash": hash_changed, "constant_is_load_bearing": load_bearing,
               "reasons_eliminated_by_weakening": eliminated[:2]})


def run() -> int:
    # ------------------------------------------------------------------ anchors
    rec("FC00 contract-hash-pinned", P.contract_hash() == PINNED_CONTRACT_HASH,
        "the contract hash equals the pinned literal, so any change to the required domains, "
        "rejection sets, provenance classes or disclosure is detectable without reading the diff",
        level="structural source check", extra={"contract_hash": P.contract_hash()})
    rec("FC01 baseline-rejects-nothing-valid", validate(valid()) == [],
        "ANCHOR: the unmutated contract accepts the complete synthetic artifact, so every mutation "
        "below is discriminating",
        level="structural source check", extra={"reasons": validate(valid())[:3]})

    # ------------------------------------------------------------------ required proof domains
    def drop_domain(name):
        return tuple(d for d in P.REQUIRED_PROOF_DOMAINS if d != name)

    for cid, name, desc in (
        ("CD01 proof-domain-removed", "transaction_and_isolation_policy",
         "removing a required proof domain from the contract is detectable and changes behaviour"),
        ("CD02 backup-domain-removed", "backup_policy",
         "removing the backup domain is detectable and changes behaviour"),
        ("CD03 restore-test-removed", "restore_test",
         "removing the restore-test domain is detectable and changes behaviour -- a backup policy "
         "without a proven restore is not recovery evidence"),
        ("CD04 monitoring-removed", "monitoring_and_alerting",
         "removing the monitoring domain is detectable and changes behaviour"),
        ("CD05 capacity-thresholds-removed", "capacity_and_disk_thresholds",
         "removing the capacity-threshold domain is detectable and changes behaviour"),
        ("CD06 incident-rollback-removed", "incident_and_rollback_process",
         "removing the incident/rollback domain is detectable and changes behaviour"),
    ):
        detectable_and_load_bearing(
            cid, "REQUIRED_PROOF_DOMAINS", drop_domain(name),
            lambda p, n=name: p["proof_domains"].pop(n), desc)

    detectable_and_load_bearing(
        "CD07 domain-field-requirement-removed", "REQUIRED_DOMAIN_FIELDS",
        ("status",),
        lambda p: p["proof_domains"]["tls_configuration"].pop("binding_fingerprint"),
        "dropping the per-domain provenance field requirement is detectable and lets a domain "
        "without a binding fingerprint through")

    detectable_and_load_bearing(
        "CD08 non-proving-class-promoted", "PROVING_OBSERVATION_CLASSES",
        P.PROVING_OBSERVATION_CLASSES + ("repository_setting",),
        lambda p: p["proof_domains"].__setitem__(
            "monitoring_and_alerting",
            EG.domain("monitoring", observation_class="repository_setting")),
        "promoting a non-proving observation class (a repository setting) to a proving one is "
        "detectable and would let 'a setting exists' count as production evidence")

    # ------------------------------------------------------------------ target / environment
    for cid, attr, weakened, mutation, desc in (
        ("CT01 test-evidence-promoted", "REJECTED_ENVIRONMENTS", (),
         lambda p: p["target"].__setitem__("environment_classification", "test"),
         "allowing a test environment is detectable and would promote disposable test "
         "infrastructure to production evidence"),
        ("CT02 development-environment-accepted", "REJECTED_ENVIRONMENTS", ("test",),
         lambda p: p["target"].__setitem__("environment_classification", "development"),
         "allowing a development environment is detectable and changes behaviour"),
        ("CT03 loopback-target-accepted", "REJECTED_ENDPOINT_CLASSIFICATIONS",
         ("docker-bridge", "unknown"),
         lambda p: p["target"].__setitem__("endpoint_classification", "loopback"),
         "allowing a loopback endpoint is detectable and changes behaviour"),
        ("CT04 docker-bridge-accepted", "REJECTED_ENDPOINT_CLASSIFICATIONS",
         ("loopback", "unknown"),
         lambda p: p["target"].__setitem__("endpoint_classification", "docker-bridge"),
         "allowing a Docker-bridge endpoint is detectable and changes behaviour"),
        ("CT05 ephemeral-storage-accepted", "REJECTED_STORAGE_CLASSIFICATIONS", (),
         lambda p: p["target"].__setitem__("storage_classification", "ephemeral"),
         "allowing ephemeral storage is detectable and changes behaviour"),
        ("CT06 provider-unknown-accepted", "REJECTED_PROVIDER_CLASSIFICATIONS", (),
         lambda p: p["target"].__setitem__("provider_classification", "unknown"),
         "allowing an unknown provider is detectable and would let an unidentifiable target "
         "certify"),
    ):
        detectable_and_load_bearing(cid, attr, weakened, mutation, desc)

    # ------------------------------------------------------------------ runtime roles / bindings /
    # parity / disclosure. These live inside validate()'s body rather than in a constant, so the
    # mutation is applied to the ARTIFACT and the assertion is that the validator still refuses.
    def refuses_artifact(cid, mutation, desc, *, rehash_after=True):
        payload = valid()
        mutation(payload)
        payload = EG.rehash(payload) if rehash_after else payload
        reasons = validate(payload)
        rec(cid, bool(reasons), desc, level="predicate/unit mutation",
            extra={"first_reason": reasons[0] if reasons else None})

    for cid, mutation, desc in (
        ("CR01 superuser-accepted",
         lambda p: p["runtime_roles"].__setitem__("runtime_not_superuser", False),
         "a superuser runtime principal is refused"),
        ("CR02 bypassrls-accepted",
         lambda p: p["runtime_roles"].__setitem__("runtime_not_bypassrls", False),
         "a BYPASSRLS runtime principal is refused"),
        ("CR03 owner-accepted",
         lambda p: p["runtime_roles"].__setitem__("runtime_not_table_owner", False),
         "a runtime principal owning protected tables is refused"),
        ("CR04 migration-principal-reuse-accepted",
         lambda p: p["runtime_roles"].__setitem__(
             "migration_principal_distinct_from_runtime", False),
         "reusing the test-only migration administrator as the runtime principal is refused"),
        ("CR05 rls-force-requirement-removed",
         lambda p: p["runtime_roles"].__setitem__("rls_enabled_and_forced", False),
         "RLS not enabled and forced is refused"),
        ("CP01 production-parity-omitted", lambda p: p.pop("production_parity"),
         "omitting production_parity entirely is refused, not defaulted to true"),
        ("CP02 parity-true-without-observations",
         lambda p: p.__setitem__("proof_domains", {}),
         "production_parity=true with no proof domains at all is refused: parity cannot come from "
         "a literal"),
        ("CP03 disclosure-requirement-removed",
         lambda p: p["non_qualifying_evidence_disclosure"].pop("restricted_runtime_disclosure"),
         "removing the restricted-runtime disclosure from the artifact is refused"),
        ("CP04 non-qualifying-list-emptied",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "non_qualifying_sources", []),
         "emptying the non-qualifying evidence list is refused"),
        ("CP05 secret-scan-ignored", lambda p: p.__setitem__("secret_scan_clean", False),
         "a non-clean secret scan is refused"),
        ("CB03 dirty-worktree-accepted", lambda p: p.__setitem__("worktree_clean", False),
         "an artifact not attesting a clean worktree is refused"),
        ("CB02 commit-tree-binding-ignored", lambda p: p.__setitem__("git_tree", "f" * 40),
         "an artifact bound to a different tree is refused"),
    ):
        refuses_artifact(cid, mutation, desc)

    refuses_artifact("CB01 canonical-hash-ignored",
                     lambda p: p.__setitem__("canonical_payload_hash", "b" * 64),
                     "a canonical hash that does not match the body is refused",
                     rehash_after=False)

    # Demonstrated directly rather than through a validate() reason diff: widening the excluded-key
    # set must make two SUBSTANTIVELY different artifacts collide on the canonical hash. (The first
    # cut of this check mutated the hash field itself, which canonical_body already excludes, so it
    # proved nothing.)
    base_a = valid()
    base_b = copy.deepcopy(base_a)
    base_b["target"]["environment_classification"] = "staging"
    real_differs = P.canonical_hash(base_a) != P.canonical_hash(base_b)
    with weaken("NON_CANONICAL_KEYS", frozenset(P.NON_CANONICAL_KEYS | {"target"})):
        widened_collides = P.canonical_hash(base_a) == P.canonical_hash(base_b)
        cb04_hash_changed = P.contract_hash() != PINNED_CONTRACT_HASH
    rec("CB04 non-canonical-keys-widened",
        real_differs and widened_collides and cb04_hash_changed,
        "widening the non-canonical key set makes two substantively different artifacts collide on "
        "the canonical hash, and the widening is itself detectable by the pinned contract hash",
        extra={"differs_under_real_contract": real_differs,
               "collides_when_widened": widened_collides,
               "detectable_by_hash": cb04_hash_changed})

    # ------------------------------------------------------------------ evaluator isolation
    real_validate = P.validate
    try:
        def boom(*a, **k):
            raise RuntimeError("validator exploded")
        P.validate = boom
        disposition = EG.probe_with(valid())
    finally:
        P.validate = real_validate
    rec("CE01 evaluator-exception-is-pass", disposition == "BLOCKED",
        "an exception inside the contract validator leaves the control BLOCKED; it is never treated "
        "as a PASS and never crashes the readiness evaluator",
        level="predicate/unit mutation", extra={"disposition": disposition})

    # Other accepted evidence must not move this control. Each is placed at ITS OWN real path.
    import tenant_authorization_evidence_guard as TAEG

    def adapter_disposition_with(**paths) -> str:
        saved = {name: getattr(GA, name) for name in paths}
        tmp = Path(tempfile.mkdtemp(prefix="pdae-iso-"))
        try:
            for name, payload in paths.items():
                target = tmp / f"{name}.json"
                target.write_text(json.dumps(payload), encoding="utf-8")
                setattr(GA, name, target)
            return GA._postgres_adapter_probe()[0]
        finally:
            for name, original in saved.items():
                setattr(GA, name, original)
            shutil.rmtree(tmp, ignore_errors=True)

    rec("CE02 tenant-v3-cannot-promote",
        adapter_disposition_with(
            TENANT_AUTHORIZATION_EVIDENCE_PATH=TAEG.build_valid_v3(),
            TENANT_RLS_EVIDENCE_PATH=TAEG.build_valid_v2_rls()) == "BLOCKED",
        "a VALID tenant-authorization evidence v3 artifact plus a valid RLS sub-proof leaves the "
        "database-adapter control BLOCKED: tenant isolation is not adapter production-readiness",
        level="evaluator integration")

    ui_like = {"schema_version": "dual-backend-ui-certification.v1", "certification": "passed",
               "local_backend_certified": True, "restricted_postgres_backend_certified": True}
    runtime_like = {"schema_version": "restricted-postgres-runtime.v1", "certification": "passed",
                    "full_functional_matrix": "passed", "passed": 266, "failed": 0}
    rec("CE03 ui-evidence-cannot-promote",
        EG.probe_with(ui_like) == "BLOCKED",
        "a passing dual-backend UI certification cannot satisfy the database-adapter control",
        level="evaluator integration")
    rec("CE04 runtime-functional-cannot-promote",
        EG.probe_with(runtime_like) == "BLOCKED",
        "a passing restricted-runtime functional matrix (266/0) cannot satisfy the database-adapter "
        "control -- functional behaviour in disposable infrastructure is not production evidence",
        level="evaluator integration")

    registry = GA.load_registry()
    entry = next((e for e in registry["blockers"] if e["check_id"] == "ga_postgres_adapter"), None)
    rec("CE05 registry-untouched",
        len(registry["blockers"]) == 28 and entry is not None
        and entry["id"] == "production-database-adapter"
        and not entry.get("allow_not_applicable"),
        "the registry still declares 28 controls and the database-adapter entry is unchanged: this "
        "increment altered the CONSUMER, not the registry",
        level="structural source check")

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
        extra={"missing": missing, "unknown": unknown, "duplicates": dupes, "unknown_prefix": stray})

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    mutation_ids = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]

    print(json.dumps({
        "guard": "audit:production-database-adapter-contract-faults",
        "claim_scope": "production-database-adapter-contract-integrity-only",
        "contract_hash": P.contract_hash(),
        "pinned_contract_hash": PINNED_CONTRACT_HASH,
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "mutations": len(mutation_ids),
                    "non_mutation_checks": len(checks) - len(mutation_ids),
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        "real_production_adapter_executed": False,
        "synthetic_artifact_used_for_parser_coverage": True,
        "production_adapter_accepted": False,
        "production_parity": False,
        "docker_used": False,
        "eligible_for_readiness": False,
        "adapter_execution_verdict": "PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
