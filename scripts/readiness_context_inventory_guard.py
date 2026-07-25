"""audit:readiness-context-inventory -- static, Docker-free guard for the canonical readiness-context contract.

This guard validates a CONTRACT DEFINITION. It does **not** execute readiness contexts, does not
start a database, an API, a worker, a frontend, or a browser, and produces no readiness
disposition. Executing the four contexts is a separate, currently capacity-blocked increment; this
guard only proves that what the contexts *say* is internally consistent, matches the implementation
they claim to describe, and cannot silently overclaim.

The central non-vacuity property: the guard does not take "four" on faith. It re-derives the
supported configuration axes from the REAL implementation modules (``backend.app.readiness`` for
client-data mode, ``backend.app.runtime_backends`` for the repository backend), computes their
Cartesian product, and requires the inventory to be exactly that product. If the implementation
ever stops supporting one of the axis values -- or grows a third -- the product stops being four
and this guard FAILS rather than certifying an inventory the implementation cannot justify.

Fail-closed evaluation: every predicate is evaluated defensively. A malformed contract that raises
inside a predicate records that gate as FAILED (with the exception class) instead of crashing the
run, and a contract whose inventory cannot be built at all forces every dependent gate to FAIL
rather than letting ``all(...)`` pass vacuously over an empty list.

Execution levels are classified honestly:
  * ``implementation derivation``  -- axis support read from the real backend modules
  * ``inventory integration``      -- the built inventory evaluated as a whole
  * ``schema predicate``           -- one field/rule evaluated
  * ``structural source check``    -- source text inspected

Honest scope: claim_scope = readiness-context-inventory-contract-only;
contexts_executed = false; eligible_for_readiness = false; production_parity = false.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import readiness as READINESS  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402
from backend.app import runtime_backends as RB  # noqa: E402
from backend.app import store as STORE  # noqa: E402

checks: list[dict] = []

REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"

#: The frozen canonical hash of the accepted contract. Pinning it here makes ANY change to the
#: inventory -- a renamed display name, a reordered context, an edited disposition -- fail this
#: guard until the change is made deliberately and the pin updated in the same commit. Without the
#: pin, a rename that silently reuses a stable context id would pass unnoticed.
EXPECTED_CANONICAL_HASH = "b9d78ad9e8791375a03c1ef437c4c663043b087bf60f80ca72d69a0f41787d44"

#: Controls that are production-infrastructure blockers in EVERY context. No context may predict
#: PASS for any of these -- that is what "production_parity = false" means operationally.
PRODUCTION_BLOCKERS = (
    "production-database-adapter",
    "production-queue-adapter",
    "production-configuration",
    "backup-restore-drill",
    "client-organizational-approval",
)

#: Every check this guard must emit. A deleted gate leaves its id missing and fails the run.
#:
#: Precise scope, because this pin is weaker than it looks: it catches gate DELETION only. Deleting
#: a gate together with its entry here, or neutering a predicate while still emitting its id, is
#: not caught by this list -- those are caught by audit:readiness-context-inventory-faults, which
#: pins this list cross-file and re-runs the real guard per mutation. The two files must be edited
#: in concert for a weakening to go unnoticed.
EXPECTED_CHECK_IDS = [
    "CX01", "CX02", "CX03", "CX04", "CX05",
    "CI01", "CI02", "CI03", "CI04", "CI05", "CI06", "CI07", "CI08", "CI09", "CI10", "CI11", "CI12",
    "CS01", "CS02", "CS03", "CS04", "CS05", "CS06", "CS07", "CS08",
    "CD01", "CD02", "CD03", "CD04", "CD05", "CD06", "CD07",
    "CF01", "CF02", "CF03", "CF04",
    "CH01", "CH02", "CH03", "CH04", "CH05", "CH06",
    "CR01", "CR02", "CR03", "CR04", "CR05", "CR06",
]

#: Set when the inventory itself cannot be built. Every later gate then FAILS rather than being
#: evaluated against nothing (an empty inventory would make every ``all(...)`` vacuously true).
INV_ERROR: str | None = None


def rec(cid, ok, desc, level="schema predicate", extra=None):
    """Record one check. ``ok`` may be a bool or a zero-argument predicate.

    A predicate that raises is recorded as FAILED with its exception class, so a malformed contract
    can never crash the guard into producing no verdict at all.
    """
    if INV_ERROR is not None:
        extra = {**(extra or {}), "blocked_by": f"inventory could not be built: {INV_ERROR}"}
        ok = False
    elif callable(ok):
        try:
            ok = ok()
        except Exception as exc:  # noqa: BLE001 - any predicate error is a refusal, not a crash
            extra = {**(extra or {}), "predicate_exception": f"{exc.__class__.__name__}: {exc}"}
            ok = False
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def independent_canonical_hash(contexts) -> str:
    """Recompute the canonical hash WITHOUT calling RC.canonical_json/RC.canonical_hash.

    Rebuilds the payload and serialisation here so a bug (or a weakening) in the module's own
    canonicalisation is detected by disagreement rather than reproduced by reuse.
    """
    payload = {
        "schema_version": RC.SCHEMA_VERSION,
        "implementation_version": RC.IMPLEMENTATION_VERSION,
        "registry_version": RC.REGISTRY_VERSION,
        "supported_client_data_modes": list(RC.SUPPORTED_CLIENT_DATA_MODES),
        "supported_repository_backends": list(RC.SUPPORTED_REPOSITORY_BACKENDS),
        "contexts": list(contexts),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def reachable_repository_backends() -> set[str] | None:
    """Derive the repository-backend axis from the IMPLEMENTATION's actual reachable values.

    ``detect_active_repository_backend()`` cannot simply be driven the way ``client_data_mode()``
    can: reaching its PostgreSQL branch requires a live database, which this Docker-free guard must
    not start. So the range is derived statically instead -- every ``return`` in the real function
    is resolved against the real module namespace and collected.

    Returns ``None`` (a refusal, never an optimistic guess) if any return value cannot be resolved
    to a string constant, so an added branch returning something dynamic fails closed rather than
    being silently ignored.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(RB.detect_active_repository_backend)))
    values: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return):
            continue
        if node.value is None:
            return None
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            values.add(node.value.value)
        elif isinstance(node.value, ast.Name):
            resolved = getattr(RB, node.value.id, None)
            if not isinstance(resolved, str):
                return None
            values.add(resolved)
        else:
            return None
    return values or None


def observed_client_data_modes() -> set[str]:
    """Drive the REAL readiness.client_data_mode() across recognised and unrecognised inputs."""
    observed = set()
    env = READINESS.CLIENT_DATA_MODE_ENV
    previous = os.environ.get(env)
    try:
        for raw in ["", "demo", "client", "1", "true", "yes", "production", "prod", "real",
                    "nonsense", "CLIENT", " client ", "0", "false"]:
            os.environ[env] = raw
            observed.add(READINESS.client_data_mode())
    finally:
        if previous is None:
            os.environ.pop(env, None)
        else:
            os.environ[env] = previous
    return observed


def run() -> int:
    global INV_ERROR
    INV_ERROR = None

    # ------------------------------------------------------------------ axes from implementation
    observed_modes = observed_client_data_modes()
    rec("CX01", observed_modes == set(RC.SUPPORTED_CLIENT_DATA_MODES),
        "client-data mode is a TOTAL function of the environment onto exactly the declared axis "
        f"values (observed {sorted(observed_modes)} across 14 raw inputs incl. unrecognised ones)",
        level="implementation derivation", extra={"observed_modes": sorted(observed_modes)})

    impl_backends = reachable_repository_backends()
    rec("CX02", impl_backends is not None and impl_backends == set(RC.SUPPORTED_REPOSITORY_BACKENDS),
        "the repository-backend axis equals the set of values the REAL "
        "detect_active_repository_backend() can actually return (every return statement resolved "
        f"against the live module: {sorted(impl_backends) if impl_backends else None}) -- so a "
        "branch added for a third backend makes this fail rather than pass on constant names",
        level="implementation derivation",
        extra={"reachable_backends": sorted(impl_backends) if impl_backends else None,
               "declared_backends": sorted(RC.SUPPORTED_REPOSITORY_BACKENDS)})

    detect_src = inspect.getsource(RB.detect_active_repository_backend)
    create_src = inspect.getsource(STORE.create_store)
    rec("CX03",
        "LOCAL_REPOSITORY_BACKEND" in detect_src and "POSTGRES_REPOSITORY_BACKEND" in detect_src
        and "PostgresStateStore" in create_src and "LocalStateStore" in create_src,
        "the repository axis is realised by two concrete store classes: create_store() builds "
        "PostgresStateStore or LocalStateStore, and detect_active_repository_backend() returns "
        "exactly the two declared constants",
        level="structural source check")

    # Axis independence: create_store() must not SELECT A STORE CLASS from the client-data mode,
    # otherwise the combinations are not free and the Cartesian product would be unjustified.
    #
    # Scope of this check, stated precisely because the honest claim is narrower than "all four
    # start unconditionally": create_store() branches only on requested_repository_backend() and
    # database_url(). The client-data mode does reach the PostgreSQL path transitively --
    # tenant_rls.enforce_runtime_role() enforces in client mode and create_store re-raises
    # TenantRuntimeRoleError -- so client-postgres carries a runtime-role safety PRECONDITION that
    # demo-postgres does not. A precondition on starting is not a mode-dependent choice of store,
    # so the axes stay independent; "all four are startable" means "given a safe runtime role".
    rec("CX04",
        "client_data_mode" not in create_src and "CLIENT_DATA_MODE" not in create_src
        and "requested_repository_backend()" in create_src and "database_url()" in create_src,
        "the axes are INDEPENDENT: create_store() selects the store class from the requested "
        "repository backend and database URL alone, never from the client-data mode. The mode "
        "affects only a runtime-role safety precondition on the PostgreSQL path, so all four "
        "combinations are startable given a safe runtime role",
        level="structural source check")

    # The product is computed from the OBSERVED implementation ranges (CX01's driven values and
    # CX02's resolved return values), not from the contract's own declared tuples -- otherwise this
    # would be contract-vs-contract and could not justify the number four at all.
    product = {(m, b) for m in observed_modes for b in (impl_backends or set())}
    rec("CX05", len(product) == 4 and len(RC.CANONICAL_CONTEXT_ORDER) == 4
        and product == {(m, b) for m in RC.SUPPORTED_CLIENT_DATA_MODES
                        for b in RC.SUPPORTED_REPOSITORY_BACKENDS},
        f"the Cartesian product of the IMPLEMENTATION-OBSERVED axes has exactly {len(product)} "
        "members and equals the declared product, so exactly four canonical contexts are "
        "justified -- the number is derived from the implementation, not assumed",
        level="implementation derivation", extra={"product_size": len(product)})

    # ------------------------------------------------------------------ build the inventory
    try:
        inv = RC.canonical_inventory()
        ids = [c["context_id"] for c in inv]
    except Exception as exc:  # noqa: BLE001 - a contract that cannot be built is a refusal
        INV_ERROR = f"{exc.__class__.__name__}: {exc}"
        inv, ids = [], []

    rec("CI01", lambda: RC.SCHEMA_VERSION == "readiness-context-inventory.v1",
        f"schema version is the canonical {RC.SCHEMA_VERSION!r}")
    rec("CI02", lambda: len(inv) == 4, f"the inventory contains exactly four contexts (got {len(inv)})",
        level="inventory integration", extra={"context_count": len(inv)})
    rec("CI03", lambda: ids == list(RC.CANONICAL_CONTEXT_ORDER),
        f"context ids are exactly the canonical set in canonical order: {ids}",
        level="inventory integration", extra={"context_ids": ids})
    rec("CI04", lambda: len(set(ids)) == len(ids) and len(ids) > 0, "no duplicate context ids")
    rec("CI05", lambda: not (set(RC.CANONICAL_CONTEXT_ORDER) - set(ids)), "no canonical context is missing")
    rec("CI06", lambda: bool(ids) and not (set(ids) - set(RC.CANONICAL_CONTEXT_ORDER)),
        "no unknown context is present")
    rec("CI07", lambda: bool(inv) and all(c["client_data_mode"] in RC.SUPPORTED_CLIENT_DATA_MODES
                                          and c["repository_backend"] in RC.SUPPORTED_REPOSITORY_BACKENDS
                                          for c in inv),
        "every context uses only supported axis values")
    rec("CI08", lambda: len({(c["client_data_mode"], c["repository_backend"]) for c in inv}) == 4
        and {(c["client_data_mode"], c["repository_backend"]) for c in inv} == product,
        "the four axis combinations are unique and cover the product exactly (no duplicate "
        "combination, no combination outside the product)",
        level="inventory integration")
    rec("CI09", lambda: bool(inv) and not any(set(RC.REQUIRED_CONTEXT_FIELDS) - set(c) for c in inv),
        "every context carries every required field",
        extra={"missing_fields": {c.get("context_id"): sorted(set(RC.REQUIRED_CONTEXT_FIELDS) - set(c))
                                  for c in inv if set(RC.REQUIRED_CONTEXT_FIELDS) - set(c)}})
    rec("CI10", lambda: bool(inv) and not any(set(c) - set(RC.REQUIRED_CONTEXT_FIELDS) for c in inv),
        "no context carries an undeclared field",
        extra={"undeclared_fields": {c.get("context_id"): sorted(set(c) - set(RC.REQUIRED_CONTEXT_FIELDS))
                                     for c in inv if set(c) - set(RC.REQUIRED_CONTEXT_FIELDS)}})
    rec("CI11", lambda: RC.canonical_inventory() == inv
        and [c["context_id"] for c in RC.canonical_inventory()] == ids,
        "ordering is stable: repeated builds produce identical content in identical order",
        level="inventory integration")
    rec("CI12", lambda: bool(inv) and all(
        c["context_id"] == RC.context_id_for(c["client_data_mode"], c["repository_backend"])
        and c["context_id"] != c["context_name"] and c["context_id"].islower() for c in inv),
        "context ids are stable, lowercase, machine-readable and derived ONLY from the axis "
        "values -- independent of the human display names")

    # ------------------------------------------------------------------ scope distinctions
    demo = [c for c in inv if c.get("client_data_mode") == "demo"]
    local = [c for c in inv if c.get("repository_backend") == "local_json"]
    pg = [c for c in inv if c.get("repository_backend") == "postgres"]

    rec("CS01", lambda: bool(demo) and all(c["expected_control_dispositions"][k] == "NOT_APPLICABLE"
                                           for c in demo for k in RC.CLIENT_IDENTITY_CONTROLS),
        "demo contexts cannot claim client authentication: every client-identity control is "
        "NOT_APPLICABLE (never PASS) in demo mode")
    rec("CS02", lambda: bool(local) and all(
        c["expected_control_dispositions"]["tenant-authorization-enforcement"] == "NOT_APPLICABLE"
        for c in local),
        "local contexts cannot claim PostgreSQL RLS: tenant-authorization-enforcement is "
        "NOT_APPLICABLE with a local JSON snapshot")
    rec("CS03", lambda: bool(pg) and all(
        c["production_parity"] is False
        and c["expected_control_dispositions"]["production-database-adapter"] != "PASS"
        and "not_production_adapter" in c["database_adapter_classification"] for c in pg),
        "PostgreSQL contexts cannot claim production adapter parity: the adapter is classified "
        "as a restricted runtime and production-database-adapter never PASSes")
    rec("CS04", lambda: bool(inv) and all(
        c["expected_control_dispositions"]["migration-validity"] != "PASS" for c in inv),
        "valid tenant evidence v3 does not satisfy migration validity in any context")
    rec("CS05", lambda: bool(inv) and all(
        c["expected_control_dispositions"]["production-database-adapter"] != "PASS" for c in inv),
        "valid tenant evidence v3 does not satisfy database-adapter readiness in any context")
    rec("CS06", lambda: bool(inv) and all(
        c["expected_control_dispositions"]["production-queue-adapter"] != "PASS" for c in inv),
        "valid tenant evidence v3 does not satisfy queue-adapter readiness in any context")
    rec("CS07", lambda: bool(inv) and all(c["expected_client_data_ready"] is False for c in inv),
        "valid tenant evidence v3 does not imply client_data_ready in any context")
    rec("CS08", lambda: bool(inv) and all(
        list(c["non_transferable_scope"]) == list(RC.NON_TRANSFERABLE_SCOPE)
        and len(c["non_transferable_scope"]) >= 4 for c in inv),
        "every context carries the non-transferable scope statements (demo!=client auth, "
        "local!=RLS, postgres!=production parity, v3!=readiness)")

    # ------------------------------------------------------------------ control dispositions
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    registry_ids = {b["id"] for b in registry["blockers"]}

    rec("CD01", lambda: bool(inv) and all(
        set(c["expected_control_dispositions"]) == set(RC.CONTROL_IDS) for c in inv),
        f"every context predicts a disposition for all {len(RC.CONTROL_IDS)} controls -- no "
        "control may be silently dropped from a context")
    rec("CD02", lambda: set(RC.CONTROL_IDS) == registry_ids
        and RC.REGISTRY_VERSION == registry["registry_version"],
        "the contract's control set equals the REAL registry file exactly "
        f"({len(registry_ids)} controls, registry {registry['registry_version']}) -- a control "
        "added to or removed from the registry fails this guard",
        level="inventory integration",
        extra={"registry_control_count": len(registry_ids),
               "only_in_contract": sorted(set(RC.CONTROL_IDS) - registry_ids),
               "only_in_registry": sorted(registry_ids - set(RC.CONTROL_IDS))})
    rec("CD03", lambda: bool(inv) and {d for c in inv for d in c["expected_control_dispositions"].values()}
        <= (set(RC.PREDICTABLE_DISPOSITIONS) & set(registry["dispositions"])),
        "only registry-valid, predictable dispositions are used; a context definition never "
        "predicts FAIL/SKIPPED/REVIEW_REQUIRED",
        extra={"dispositions_used": sorted({d for c in inv
                                            for d in c.get("expected_control_dispositions", {}).values()})})
    rec("CD04", lambda: bool(inv) and all(c["expected_control_dispositions"][b] == "BLOCKED"
                                          for c in inv for b in PRODUCTION_BLOCKERS),
        "every production-infrastructure blocker is BLOCKED in every context "
        f"({', '.join(PRODUCTION_BLOCKERS)})")
    rec("CD05", lambda: {(c["context_id"], k) for c in inv
                         for k, v in c["expected_control_dispositions"].items() if v == "PASS"}
        == {("client-postgres", "tenant-authorization-enforcement")},
        "the ONLY predicted PASS is tenant-authorization-enforcement in client-postgres -- the "
        "single control with an accepted artifact, produced in exactly that context",
        level="inventory integration",
        extra={"predicted_passes": sorted({(c.get("context_id"), k) for c in inv
                                           for k, v in c.get("expected_control_dispositions", {}).items()
                                           if v == "PASS"})})
    # Non-vacuous by construction: requires at least one PASS-predicting context to exist, so this
    # gate cannot pass by having nothing to check.
    rec("CD06", lambda: _precondition_stated(inv),
        "any context predicting a PASS states the precondition that PASS is contingent on "
        "(commit-bound evidence regenerated at the executed tree), and at least one such context "
        "exists so the gate is not vacuous")
    rec("CD07", lambda: bool(inv) and bool(RC.ACCEPTED_CONTEXT_EVIDENCE) and not [
        cid for cid, controls in RC.ACCEPTED_CONTEXT_EVIDENCE.items()
        for c in inv if c["context_id"] == cid
        and ((c["client_data_mode"] == "demo" and controls & RC.CLIENT_IDENTITY_CONTROLS)
             or (c["repository_backend"] == "local_json" and controls & RC.POSTGRES_EVIDENCE_CONTROLS))],
        "no accepted-evidence allowance conflicts with a NOT_APPLICABLE scope rule (an allowance "
        "can never resurrect a control the context structurally cannot evaluate)")

    # ------------------------------------------------------------------ readiness flags
    rec("CF01", lambda: bool(inv) and all(c["production_parity"] is False for c in inv),
        "production_parity is false in every context")
    rec("CF02", lambda: bool(inv) and all(c["expected_client_data_ready"] is False for c in inv),
        "expected_client_data_ready is false in every context")
    rec("CF03", lambda: bool(inv) and all(c["expected_release_candidate_ready"] is False for c in inv),
        "expected_release_candidate_ready is false in every context")
    rec("CF04", lambda: bool(inv) and all(c["expected_ga_ready"] is False for c in inv),
        "expected_ga_ready is false in every context")

    # ------------------------------------------------------------------ canonical hash
    rec("CH01", lambda: RC.canonical_hash() == RC.canonical_hash(),
        "the canonical hash is deterministic across repeated computation",
        extra={"canonical_inventory_hash": _safe_hash()})
    rec("CH02", lambda: independent_canonical_hash(inv) == RC.canonical_hash(),
        "the canonical hash is reproduced by an INDEPENDENT recomputation in this guard (payload "
        "and serialisation rebuilt here, not delegated to the module under test)",
        level="inventory integration")
    rec("CH03", lambda: len(RC.canonical_hash()) == 64 and RC.canonical_hash().islower()
        and all(ch in "0123456789abcdef" for ch in RC.canonical_hash()),
        "the canonical hash is a full lowercase SHA-256 hex digest")
    rec("CH04", lambda: not [t for t in ("generated_at", "timestamp", "C:\\", "/Users/", "/home/",
                                         "MONDAY_REPORT_") if t in RC.canonical_json()],
        "the canonical payload contains no timestamp, no private path and no environment-dependent "
        "value")
    rec("CH05", lambda: independent_canonical_hash(list(reversed(inv))) != RC.canonical_hash(),
        "context ORDER is load-bearing: a reordered inventory produces a different canonical hash",
        level="inventory integration")
    rec("CH06", lambda: RC.canonical_hash() == EXPECTED_CANONICAL_HASH,
        "the canonical hash equals the frozen accepted value: any edit to the inventory -- a "
        "renamed display name reusing a stable id, a reordered context, an altered disposition -- "
        "fails here until the pin is updated deliberately",
        level="inventory integration",
        extra={"expected": EXPECTED_CANONICAL_HASH, "observed": _safe_hash()})

    # ------------------------------------------------------------------ runner interface
    rec("CR01", lambda: _runner_is_unavailable(RC.run_context("client-postgres")),
        "run_context() returns a controlled unavailable result -- never a simulated disposition",
        level="inventory integration")
    rec("CR02", lambda: _runner_is_unavailable(RC.run_all_contexts()),
        "run_all_contexts() returns a controlled unavailable result")
    rec("CR03", lambda: _rejects_unknown_context(),
        "an unknown context id is rejected rather than quietly accepted")
    rec("CR04", lambda: _no_disposition_in(RC.serialize_result(RC.run_all_contexts())),
        "no execution entry point emits a readiness disposition: the serialised result contains "
        "no PASS and states unavailable/accepted=false")
    rec("CR05", lambda: RC.execution_order() == list(RC.CANONICAL_CONTEXT_ORDER)
        and RC.execution_order(reverse=True) == list(reversed(RC.CANONICAL_CONTEXT_ORDER))
        and RC.execution_order(seed=1234) == RC.execution_order(seed=1234)
        and sorted(RC.execution_order(seed=1234)) == sorted(RC.CANONICAL_CONTEXT_ORDER)
        and RC.execution_order(seed=99) != RC.execution_order(seed=1234),
        "the runner interface supports canonical, reverse and deterministically seeded ordering "
        "(same seed => same permutation; a different seed => a different one)",
        level="inventory integration")
    rec("CR06", lambda: _run_input_is_isolated(),
        "each context's run input is an ISOLATED deep copy: mutating one runner's input cannot "
        "corrupt the shared definition or another context's input",
        level="inventory integration")

    # ------------------------------------------------------------------ completeness + summary
    emitted = [c["check_id"] for c in checks]
    missing = [cid for cid in EXPECTED_CHECK_IDS if cid not in emitted]
    unknown = [cid for cid in emitted if cid not in EXPECTED_CHECK_IDS and cid != "CZ00 completeness"]
    dupes = sorted({cid for cid in emitted if emitted.count(cid) > 1})
    if missing or unknown or dupes:
        rec("CZ00 completeness", False,
            "the emitted check set must equal the expected set exactly",
            level="structural source check",
            extra={"missing": missing, "unknown": unknown, "duplicates": dupes})

    passed = sum(1 for c in checks if c["ok"])
    failed = len(checks) - passed
    summary = {
        "guard": "readiness-context-inventory",
        "claim_scope": "readiness-context-inventory-contract-only",
        "passed": passed, "failed": failed, "skipped": 0,
        "certification": "passed" if failed == 0 else "not_passed",
        "canonical_inventory_hash": _safe_hash(),
        "schema_version": RC.SCHEMA_VERSION,
        "context_ids": ids,
        "supported_client_data_modes": list(RC.SUPPORTED_CLIENT_DATA_MODES),
        "supported_repository_backends": list(RC.SUPPORTED_REPOSITORY_BACKENDS),
        "inventory_build_error": INV_ERROR,
        # honest non-execution disclosure
        "contexts_executed": False,
        "readiness_dispositions_produced": False,
        "docker_used": False,
        "eligible_for_readiness": False,
        "eligible_for_tenant_evidence": False,
        "production_parity": False,
        "execution_verdict": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }
    print(json.dumps({"summary": summary, "checks": checks}, indent=2))
    return 0 if failed == 0 else 1


def _precondition_stated(inv) -> bool:
    predicting = [c for c in inv
                  if any(v == "PASS" for v in c["expected_control_dispositions"].values())]
    return bool(predicting) and all(c["accepted_evidence_precondition"] for c in predicting)


def _safe_hash() -> str | None:
    try:
        return RC.canonical_hash()
    except Exception:  # noqa: BLE001 - reporting only
        return None


def _runner_is_unavailable(result) -> bool:
    return (result["certification"] == "unavailable" and result["accepted"] is False
            and result["executed"] is False and result["results"] == [])


def _rejects_unknown_context() -> bool:
    try:
        RC.run_context("client-oracle")
    except ValueError:
        return True
    return False


def _no_disposition_in(serialized: str) -> bool:
    return ('"certification":"unavailable"' in serialized and '"accepted":false' in serialized
            and "PASS" not in serialized)


def _run_input_is_isolated() -> bool:
    probe = RC.build_run_input("demo-local")
    probe["context_name"] = "MUTATED"
    probe["expected_control_dispositions"]["ci-execution"] = "PASS"
    fresh = RC.build_run_input("demo-local")
    return (fresh["context_name"] != "MUTATED"
            and fresh["expected_control_dispositions"]["ci-execution"] == "BLOCKED")


if __name__ == "__main__":
    raise SystemExit(run())
