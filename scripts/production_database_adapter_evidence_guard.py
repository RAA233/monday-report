"""audit:production-database-adapter-evidence -- fail-closed guard for the production adapter contract.

Drives the REAL validator (``backend.app.production_database_adapter_evidence.validate``) and the
REAL readiness probe (``ga_readiness._postgres_adapter_probe``) once per rejection category in the
contract, and proves the database-adapter control is isolated: nothing but a valid production
artifact can move it.

**No production infrastructure is touched.** No database, container, network target, provider API or
process is contacted. A fully valid artifact is *synthesised* purely so the parser and the
evaluator's accept path can be exercised at all -- without it every rejection test would compare two
identical BLOCKED results and prove nothing. That synthetic artifact is NOT evidence about any real
adapter, and the summary says so.

Execution levels are classified honestly:
  * ``evaluator integration``   -- the real readiness probe over a crafted artifact
  * ``schema mutation``         -- one field of an otherwise-valid artifact mutated
  * ``predicate/unit mutation`` -- the real validator over a crafted payload
  * ``structural source check`` -- assertions over the parsed contract/consumer source

Honest scope: claim_scope = production-database-adapter-contract-only;
real_production_adapter_executed = false; production_adapter_accepted = false;
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
from backend.app import production_database_adapter_evidence as P  # noqa: E402

checks: list[dict] = []
MUTATION_PREFIXES = ("MS", "MT", "MR", "MD", "MP", "MO", "MI")

COMMIT = P.git_rev("HEAD")
TREE = P.git_rev("HEAD^{tree}")
ADAPTER_CONTROL = "ga_postgres_adapter"

EXPECTED_CHECK_IDS = [
    # anchors
    "FA00 synthetic-valid-artifact-passes", "FA01 no-artifact-blocks",
    "FA02 parity-false-blocks", "FA03 only-adapter-control-moves",
    "FA04 test-runtime-artifact-blocks", "FA05 tenant-v3-alone-blocks",
    "FA06 demo-ui-alone-blocks", "FA07 restricted-runtime-alone-blocks",
    # schema identity / binding
    "MS01 v0-schema", "MS02 unknown-schema", "MS03 foreign-schema",
    "MS04 wrong-evidence-type", "MS05 wrong-commit", "MS06 wrong-tree",
    "MS07 abbreviated-commit", "MS08 dirty-binding", "MS09 wrong-canonical-hash",
    "MS10 missing-canonical-hash", "MS11 implementation-version-drift",
    # target classification
    "MT01 provider-unknown", "MT02 environment-development", "MT03 environment-test",
    "MT04 endpoint-loopback", "MT05 endpoint-docker-bridge", "MT06 storage-ephemeral",
    "MT07 tls-not-verified", "MT08 credential-rotation-absent",
    "MT09 service-identity-fingerprint-absent",
    # runtime role safety
    "MR01 runtime-superuser", "MR02 runtime-bypassrls", "MR03 runtime-table-owner",
    "MR04 rls-force-disabled", "MR05 migration-principal-reused", "MR06 policy-inventory-empty",
    # proof domains
    "MD01 missing-proof-domain", "MD02 bare-literal-assertion",
    "MD03 non-proving-observation-class", "MD04 stale-observation",
    "MD05 domain-not-pass", "MD06 fingerprint-not-sha256", "MD07 proven-by-insubstantial",
    "MD08 unknown-proof-domain", "MD09 pitr-claimed-without-proof",
    # disclosure / parity / privacy
    "MP01 disclosure-missing", "MP02 disclosure-altered",
    "MP03 non-qualifying-list-incomplete", "MP04 non-qualifying-source-promoted",
    "MP05 secret-scan-not-clean", "MP06 production-parity-false",
    "MP07 raw-endpoint-leaked", "MP08 raw-dsn-leaked",
    # evaluator isolation / robustness
    "MO01 malformed-artifact-crashes", "MO02 not-an-object",
    "MO03 unreadable-artifact", "MO04 absent-artifact",
    "MI01 canonical-hash-deterministic", "MI02 canonical-hash-covers-substance",
    "MI03 runner-never-simulates", "MI04 runner-refuses-without-target",
    # structural
    "FS01 consumer-requires-artifact", "FS02 consumer-no-longer-delegates",
    "FS03 guard-drives-real-validator", "FS04 contract-touches-no-infrastructure",
    "FZ00 completeness", "FZ01 battery-size-pinned",
]

EXPECTED_TOTAL_CHECKS = 65
EXPECTED_MUTATION_COUNT = 51


def rec(cid, ok, desc, level="predicate/unit mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def fp(label: str) -> str:
    """A deterministic stand-in binding fingerprint (never random -- the battery must be stable)."""
    return hashlib.sha256(f"synthetic-binding:{label}".encode("utf-8")).hexdigest()


def _now() -> datetime:
    # Derived from the artifact's own generated_at below; no wall clock is used for hashing.
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def domain(label: str, observed_days_ago: int = 1,
           observation_class: str = "live_target_observation", status: str = "PASS") -> dict:
    return {
        "status": status,
        "proven_by": f"observed on the configured production target: {label}",
        "observation_class": observation_class,
        "observed_at": (_now() - timedelta(days=observed_days_ago)).isoformat(),
        "binding_fingerprint": fp(label),
    }


def build_valid_artifact() -> dict:
    """A complete, contract-VALID artifact.

    SYNTHETIC: it describes no real target. It exists so the accept path can be exercised; without
    it every rejection test would compare two identical BLOCKED results.
    """
    payload = {
        "schema_version": P.SCHEMA_VERSION,
        "implementation_version": P.IMPLEMENTATION_VERSION,
        "evidence_type": P.EVIDENCE_TYPE,
        "git_commit": COMMIT,
        "git_tree": TREE,
        "worktree_clean": True,
        "generated_at": _now().isoformat(),
        "claims_point_in_time_recovery": False,
        "target": {
            "provider_classification": "managed-postgresql",
            "service_identity_fingerprint": fp("service-identity"),
            "environment_classification": "production",
            "endpoint_classification": "private-network",
            "storage_classification": "durable-replicated",
            "tls_verified": True,
            "credential_rotation_configured": True,
        },
        "runtime_roles": {
            "runtime_not_superuser": True,
            "runtime_not_bypassrls": True,
            "runtime_not_table_owner": True,
            "rls_enabled_and_forced": True,
            "migration_principal_distinct_from_runtime": True,
            "policy_inventory": [
                {"table_classification": "protected", "policy_count": 2, "forced": True},
            ],
        },
        "non_qualifying_evidence_disclosure": {
            "restricted_runtime_disclosure": P.RESTRICTED_RUNTIME_DISCLOSURE,
            "non_qualifying_sources": list(P.NON_QUALIFYING_EVIDENCE),
            "promoted_sources": [],
        },
        "proof_domains": {name: domain(name) for name in P.REQUIRED_PROOF_DOMAINS},
        "secret_scan_clean": True,
        "production_parity": True,
    }
    payload["canonical_payload_hash"] = P.canonical_hash(payload)
    return payload


def rehash(payload: dict) -> dict:
    payload = copy.deepcopy(payload)
    payload.pop("canonical_payload_hash", None)
    payload["canonical_payload_hash"] = P.canonical_hash(payload)
    return payload


def mutated(mutate, *, rehash_after=True) -> dict:
    payload = build_valid_artifact()
    mutate(payload)
    return rehash(payload) if rehash_after else payload


def rejects(mutate, *, rehash_after=True) -> tuple[bool, list[str]]:
    """The REAL validator must return at least one reason for this mutation."""
    reasons = P.validate(mutated(mutate, rehash_after=rehash_after),
                         current_commit=COMMIT, current_tree=TREE)
    return bool(reasons), reasons


def probe_with(artifact) -> str:
    """Drive the REAL readiness probe with a patched evidence path; return the disposition."""
    original = GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH
    tmp = Path(tempfile.mkdtemp(prefix="pdae-probe-"))
    try:
        target = tmp / "artifact.json"
        if artifact is not None:
            target.write_text(json.dumps(artifact) if not isinstance(artifact, str) else artifact,
                              encoding="utf-8")
        GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH = target
        return GA._postgres_adapter_probe()[0]
    finally:
        GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH = original
        shutil.rmtree(tmp, ignore_errors=True)


def dispositions_with(artifact) -> dict[str, str]:
    """Full 28-control disposition map with the adapter artifact patched in."""
    original = GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH
    tmp = Path(tempfile.mkdtemp(prefix="pdae-full-"))
    try:
        target = tmp / "artifact.json"
        if artifact is not None:
            target.write_text(json.dumps(artifact), encoding="utf-8")
        GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH = target
        readiness = {"postgres_repository": "fail", "redis_queue": "fail",
                     "local_llm_runtime": "fail", "demo_seed_removed": "fail"}
        return {c["id"]: c["disposition"]
                for c in GA.evaluate_blockers(readiness, forge_report=None)}
    finally:
        GA.PRODUCTION_DATABASE_ADAPTER_EVIDENCE_PATH = original
        shutil.rmtree(tmp, ignore_errors=True)


def run() -> int:
    valid = build_valid_artifact()

    # ------------------------------------------------------------------ anti-vacuity anchors
    baseline_reasons = P.validate(valid, current_commit=COMMIT, current_tree=TREE)
    rec("FA00 synthetic-valid-artifact-passes", baseline_reasons == [],
        "ANCHOR: a complete synthetic artifact validates, so every rejection below is "
        "discriminating rather than an always-fail validator",
        level="evaluator integration", extra={"reasons": baseline_reasons[:4]})

    disp_valid = dispositions_with(valid)
    disp_none = dispositions_with(None)
    rec("FA01 no-artifact-blocks", disp_none.get(ADAPTER_CONTROL) == "BLOCKED",
        "case A: with NO production adapter artifact the control is BLOCKED",
        level="evaluator integration")

    parity_false = rehash({**copy.deepcopy(valid), "production_parity": False})
    rec("FA02 parity-false-blocks",
        probe_with(parity_false) == "BLOCKED",
        "case B: a structurally valid artifact with production_parity=false remains BLOCKED -- the "
        "expected safe state today keeps the evidence non-accepting",
        level="evaluator integration")

    changed = sorted(k for k in disp_valid if disp_valid[k] != disp_none.get(k))
    rec("FA03 only-adapter-control-moves", changed == [ADAPTER_CONTROL],
        "case C differential: a valid production adapter artifact changes EXACTLY the "
        "database-adapter control; every other control is canonically identical",
        level="evaluator integration", extra={"changed_controls": changed})

    # test-scoped artifact: honest about being the restricted runtime, and therefore refused
    test_runtime = rehash({**copy.deepcopy(valid), "target": {
        **copy.deepcopy(valid["target"]),
        "environment_classification": "test",
        "endpoint_classification": "loopback",
        "storage_classification": "ephemeral",
        "tls_verified": False,
    }})
    rec("FA04 test-runtime-artifact-blocks", probe_with(test_runtime) == "BLOCKED",
        "an artifact describing the accepted restricted runtime as it really is (test environment, "
        "loopback endpoint, ephemeral storage, unverified TLS) is BLOCKED -- disposable test "
        "infrastructure cannot certify a production adapter",
        level="evaluator integration")

    for cid, other_schema, label in (
        ("FA05 tenant-v3-alone-blocks", "tenant-authorization-evidence.v3", "tenant evidence v3"),
        ("FA06 demo-ui-alone-blocks", "dual-backend-ui-certification.v1", "demo-mode UI proof"),
        ("FA07 restricted-runtime-alone-blocks", "restricted-postgres-runtime.v1",
         "restricted runtime functional matrix"),
    ):
        foreign = rehash({**copy.deepcopy(valid), "schema_version": other_schema})
        rec(cid, probe_with(foreign) == "BLOCKED",
            f"an accepted {label} artifact placed at the production-adapter path is BLOCKED: it is "
            "evidence about a different thing and cannot satisfy this control",
            level="evaluator integration")

    # ------------------------------------------------------------------ schema identity / binding
    for cid, mutate, desc in (
        ("MS01 v0-schema", lambda p: p.__setitem__("schema_version",
                                                   "production-database-adapter-evidence.v0"),
         "a v0 artifact is rejected"),
        ("MS02 unknown-schema", lambda p: p.__setitem__("schema_version", "something-else.v9"),
         "an unknown schema id is rejected"),
        ("MS03 foreign-schema", lambda p: p.__setitem__("schema_version",
                                                        "tenant-rls-enforcement-evidence.v2"),
         "a foreign accepted schema presented at this path is rejected"),
        ("MS04 wrong-evidence-type", lambda p: p.__setitem__("evidence_type", "tenant-authorization"),
         "a wrong evidence_type is rejected"),
        ("MS05 wrong-commit", lambda p: p.__setitem__("git_commit", "0" * 40),
         "an artifact bound to a different commit is rejected as stale"),
        ("MS06 wrong-tree", lambda p: p.__setitem__("git_tree", "1" * 40),
         "an artifact bound to a different tree is rejected as stale"),
        ("MS07 abbreviated-commit", lambda p: p.__setitem__("git_commit", COMMIT[:12]),
         "an abbreviated commit binding is rejected"),
        ("MS08 dirty-binding", lambda p: p.__setitem__("worktree_clean", False),
         "an artifact that does not attest a clean worktree is rejected"),
        ("MS11 implementation-version-drift",
         lambda p: p.__setitem__("implementation_version", "0.1.0"),
         "an implementation_version that drifts from the contract module is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # hash mutations must NOT be re-hashed, or the mutation would be laundered
    ok, reasons = rejects(lambda p: p.__setitem__("canonical_payload_hash", "a" * 64),
                          rehash_after=False)
    rec("MS09 wrong-canonical-hash", ok, "a canonical_payload_hash that does not match the body is "
        "rejected", extra={"first_reason": reasons[0] if reasons else None})
    ok, _ = rejects(lambda p: p.pop("canonical_payload_hash"), rehash_after=False)
    rec("MS10 missing-canonical-hash", ok, "a missing canonical_payload_hash is rejected")

    # ------------------------------------------------------------------ target classification
    def tgt(field, value):
        return lambda p: p["target"].__setitem__(field, value)

    for cid, mutate, desc in (
        ("MT01 provider-unknown", tgt("provider_classification", "unknown"),
         "provider_classification 'unknown' is rejected: an unidentified target is not auditable"),
        ("MT02 environment-development", tgt("environment_classification", "development"),
         "a development environment is rejected"),
        ("MT03 environment-test", tgt("environment_classification", "test"),
         "a test environment is rejected"),
        ("MT04 endpoint-loopback", tgt("endpoint_classification", "loopback"),
         "a loopback endpoint is rejected"),
        ("MT05 endpoint-docker-bridge", tgt("endpoint_classification", "docker-bridge"),
         "a Docker-bridge endpoint is rejected"),
        ("MT06 storage-ephemeral", tgt("storage_classification", "ephemeral"),
         "ephemeral storage is rejected"),
        ("MT07 tls-not-verified", tgt("tls_verified", False),
         "unverified TLS is rejected"),
        ("MT08 credential-rotation-absent", tgt("credential_rotation_configured", False),
         "absent credential rotation is rejected"),
        ("MT09 service-identity-fingerprint-absent",
         lambda p: p["target"].pop("service_identity_fingerprint"),
         "a missing service identity fingerprint is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ runtime role safety
    def rt(field, value):
        return lambda p: p["runtime_roles"].__setitem__(field, value)

    for cid, mutate, desc in (
        ("MR01 runtime-superuser", rt("runtime_not_superuser", False),
         "a superuser runtime role is rejected"),
        ("MR02 runtime-bypassrls", rt("runtime_not_bypassrls", False),
         "a BYPASSRLS runtime role is rejected"),
        ("MR03 runtime-table-owner", rt("runtime_not_table_owner", False),
         "a runtime role owning protected tables is rejected"),
        ("MR04 rls-force-disabled", rt("rls_enabled_and_forced", False),
         "RLS not enabled and forced is rejected"),
        ("MR05 migration-principal-reused",
         rt("migration_principal_distinct_from_runtime", False),
         "reusing the migration administrator as the runtime principal is rejected"),
        ("MR06 policy-inventory-empty", rt("policy_inventory", []),
         "an empty policy inventory is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ proof domains
    first_domain = P.REQUIRED_PROOF_DOMAINS[0]
    for cid, mutate, desc in (
        ("MD01 missing-proof-domain", lambda p: p["proof_domains"].pop("backup_policy"),
         "a missing required proof domain is rejected -- never treated as NOT_APPLICABLE"),
        ("MD02 bare-literal-assertion",
         lambda p: p["proof_domains"].__setitem__("restore_test", True),
         "a bare boolean in place of a proof domain is rejected"),
        ("MD03 non-proving-observation-class",
         lambda p: p["proof_domains"].__setitem__(
             "monitoring_and_alerting",
             domain("monitoring", observation_class="repository_setting")),
         "a PASS whose observation_class is a repository setting is rejected: the existence of a "
         "setting is not evidence about a production target"),
        ("MD04 stale-observation",
         lambda p: p["proof_domains"].__setitem__(
             "restore_test", domain("restore", observed_days_ago=400)),
         "an observation older than the contract's staleness limit is rejected"),
        ("MD05 domain-not-pass",
         lambda p: p["proof_domains"].__setitem__(
             "failover_behavior", domain("failover", status="NOT_PROVEN")),
         "a domain that is not PASS is rejected"),
        ("MD06 fingerprint-not-sha256",
         lambda p: p["proof_domains"]["tls_configuration"].__setitem__(
             "binding_fingerprint", "abc"),
         "a PASS without a full SHA-256 binding fingerprint is rejected"),
        ("MD07 proven-by-insubstantial",
         lambda p: p["proof_domains"][first_domain].__setitem__("proven_by", "ok"),
         "a PASS without a substantive proven_by is rejected"),
        ("MD08 unknown-proof-domain",
         lambda p: p["proof_domains"].__setitem__("made_up_domain", domain("nope")),
         "an unknown proof domain is rejected"),
        ("MD09 pitr-claimed-without-proof",
         lambda p: p.__setitem__("claims_point_in_time_recovery", True),
         "claiming point-in-time recovery without the corresponding proof domain is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ disclosure / parity / privacy
    for cid, mutate, desc in (
        ("MP01 disclosure-missing",
         lambda p: p.pop("non_qualifying_evidence_disclosure"),
         "a missing non-qualifying-evidence disclosure block is rejected"),
        ("MP02 disclosure-altered",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "restricted_runtime_disclosure", "the restricted runtime proves production readiness"),
         "an altered restricted-runtime disclosure is rejected"),
        ("MP03 non-qualifying-list-incomplete",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "non_qualifying_sources", ["unit tests"]),
         "an incomplete non-qualifying-source list is rejected"),
        ("MP04 non-qualifying-source-promoted",
         lambda p: p["non_qualifying_evidence_disclosure"].__setitem__(
             "promoted_sources", ["restricted runtime functional matrix"]),
         "promoting a non-qualifying source as production proof is rejected"),
        ("MP05 secret-scan-not-clean", lambda p: p.__setitem__("secret_scan_clean", False),
         "a non-clean secret scan is rejected"),
        ("MP06 production-parity-false", lambda p: p.__setitem__("production_parity", False),
         "production_parity=false is rejected, keeping the evidence non-accepting -- the expected "
         "safe state today"),
        ("MP07 raw-endpoint-leaked",
         lambda p: p["target"].__setitem__("note", "host db-prod-01.rds.amazonaws.com"),
         "a raw provider hostname in the artifact is rejected"),
        ("MP08 raw-dsn-leaked",
         lambda p: p["target"].__setitem__("note", "postgresql://svc@10.2.3.4:5432/app"),
         "a raw database URL in the artifact is rejected"),
    ):
        ok, reasons = rejects(mutate)
        rec(cid, ok, desc, extra={"first_reason": reasons[0] if reasons else None})

    # ------------------------------------------------------------------ robustness / isolation
    hostile = [None, 42, "a string", [], {"schema_version": P.SCHEMA_VERSION},
               {"proof_domains": "not-a-dict"}, {"target": 7}, {"runtime_roles": []}]
    crashed = []
    for item in hostile:
        try:
            result = P.validate(item, current_commit=COMMIT, current_tree=TREE)
            if not isinstance(result, list) or not result:
                crashed.append(repr(item)[:30])
        except Exception as exc:  # noqa: BLE001
            crashed.append(f"{type(item).__name__}:{exc.__class__.__name__}")
    rec("MO01 malformed-artifact-crashes", crashed == [],
        "every hostile payload shape returns a non-empty reason list; the validator never raises and "
        "never accepts",
        level="schema mutation", extra={"crashed_or_accepted": crashed})
    rec("MO02 not-an-object", bool(P.validate([1, 2, 3])),
        "a non-object artifact is rejected", level="schema mutation")
    rec("MO03 unreadable-artifact", probe_with("{not valid json") == "BLOCKED",
        "an unreadable artifact leaves the control BLOCKED rather than crashing the evaluator",
        level="evaluator integration")
    rec("MO04 absent-artifact", probe_with(None) == "BLOCKED",
        "an absent artifact leaves the control BLOCKED", level="evaluator integration")

    rec("MI01 canonical-hash-deterministic",
        len({P.canonical_hash(build_valid_artifact()) for _ in range(3)}) == 1
        and P.canonical_hash(valid) == P.canonical_hash(copy.deepcopy(valid)),
        "the canonical hash is deterministic across repeated computation and deep copies",
        level="schema mutation", extra={"canonical_hash": P.canonical_hash(valid)})
    substantive = P.canonical_hash(valid)
    moved = copy.deepcopy(valid)
    moved["target"]["environment_classification"] = "staging"
    metadata_only = copy.deepcopy(valid)
    metadata_only["generated_at"] = "2000-01-01T00:00:00+00:00"
    rec("MI02 canonical-hash-covers-substance",
        P.canonical_hash(moved) != substantive
        and P.canonical_hash(metadata_only) == substantive,
        "the canonical hash changes when substance changes and is stable across the explicitly "
        "excluded generation metadata",
        level="schema mutation")

    for cid, result, desc in (
        ("MI03 runner-never-simulates", P.generate(None),
         "the runner's generate() never returns a simulated artifact"),
        ("MI04 runner-refuses-without-target", P.collect(None),
         "the runner refuses to collect without an explicit production target and never "
         "auto-discovers local infrastructure"),
    ):
        rec(cid, result.get("artifact") is None
            and result.get("certification") == "unavailable"
            and result.get("production_adapter_executed") is False
            and result.get("production_adapter_accepted") is False,
            desc, level="schema mutation")

    # ------------------------------------------------------------------ structural source checks
    consumer_src = (ROOT / "backend" / "app" / "ga_readiness.py").read_text(encoding="utf-8")
    consumer_ast = ast.parse(consumer_src)
    probe_fn = next((n for n in consumer_ast.body
                     if isinstance(n, ast.FunctionDef) and n.name == "_postgres_adapter_probe"),
                    None)
    calls_contract = probe_fn is not None and any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "_production_database_adapter_reasons"
        for n in ast.walk(probe_fn))
    rec("FS01 consumer-requires-artifact", calls_contract,
        "the readiness consumer resolves the database-adapter control through the production "
        "adapter contract, verified on the parsed source",
        level="structural source check")

    adapter_branch = [n for n in ast.walk(consumer_ast)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                      and n.func.id == "_delegate"]
    delegates_to_repo = any(
        any(isinstance(a, ast.Tuple) and any(getattr(e, "value", None) == "postgres_repository"
                                             for e in a.elts)
            for a in call.args)
        for call in adapter_branch)
    rec("FS02 consumer-no-longer-delegates", not delegates_to_repo,
        "the database-adapter control no longer delegates to the client-data readiness check "
        "'postgres_repository', which a disposable Docker container satisfies",
        level="structural source check")

    own_ast = ast.parse((ROOT / "scripts" / "production_database_adapter_evidence_guard.py")
                        .read_text(encoding="utf-8"))
    imports_contract = any(
        isinstance(n, ast.ImportFrom) and n.module == "backend.app"
        and any(a.name == "production_database_adapter_evidence" for a in n.names)
        for n in own_ast.body)
    rejects_fn = next((n for n in own_ast.body
                       if isinstance(n, ast.FunctionDef) and n.name == "rejects"), None)
    drives_real = rejects_fn is not None and any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "validate"
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "P"
        for n in ast.walk(rejects_fn))
    rec("FS03 guard-drives-real-validator", imports_contract and drives_real,
        "this guard imports the real contract module and drives the real validate(); it does not "
        "re-implement the rules it claims to test",
        level="structural source check")

    contract_src = (ROOT / "backend" / "app" / "production_database_adapter_evidence.py") \
        .read_text(encoding="utf-8")
    contract_ast = ast.parse(contract_src)
    infra_modules = {"psycopg", "psycopg2", "sqlalchemy", "docker", "boto3", "requests",
                     "httpx", "urllib", "socket", "redis"}
    imported: list[str] = []
    for node in ast.walk(contract_ast):
        if isinstance(node, ast.Import):
            imported += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".")[0])
    touched = sorted(set(imported) & infra_modules)
    rec("FS04 contract-touches-no-infrastructure", touched == [],
        "the contract module imports no database driver, cloud SDK, HTTP or socket library, so "
        "validating an artifact cannot reach any infrastructure",
        level="structural source check", extra={"infrastructure_imports": touched})

    # ------------------------------------------------------------------ completeness
    mutations_so_far = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]
    rec("FZ01 battery-size-pinned",
        len(EXPECTED_CHECK_IDS) == EXPECTED_TOTAL_CHECKS
        and len(mutations_so_far) == EXPECTED_MUTATION_COUNT,
        f"pinned at {EXPECTED_TOTAL_CHECKS} declared checks / {EXPECTED_MUTATION_COUNT} mutations, "
        "so a mutation cannot be dropped together with its expected-list entry",
        level="structural source check",
        extra={"declared": len(EXPECTED_CHECK_IDS), "mutations": len(mutations_so_far)})

    emitted = [c["check_id"] for c in checks]
    missing = [c for c in EXPECTED_CHECK_IDS if c not in emitted and c != "FZ00 completeness"]
    unknown = [c for c in emitted if c not in EXPECTED_CHECK_IDS]
    dupes = sorted({c for c in emitted if emitted.count(c) > 1})
    stray = [c for c in emitted if not c.startswith("F") and c[:2] not in MUTATION_PREFIXES]
    rec("FZ00 completeness", not (missing or unknown or dupes or stray),
        "the emitted check set equals the declared set exactly and every id belongs to a declared "
        "family",
        level="structural source check",
        extra={"missing": missing, "unknown": unknown, "duplicates": dupes, "unknown_prefix": stray})

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    mutation_ids = [c["check_id"] for c in checks if c["check_id"][:2] in MUTATION_PREFIXES]

    print(json.dumps({
        "guard": "audit:production-database-adapter-evidence",
        "claim_scope": "production-database-adapter-contract-only",
        "contract_hash": P.contract_hash(),
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "mutations": len(mutation_ids),
                    "non_mutation_checks": len(checks) - len(mutation_ids),
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        # Honest disclosure -- required by the increment and true of every check above.
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
