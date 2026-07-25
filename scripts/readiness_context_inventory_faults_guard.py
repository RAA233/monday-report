"""audit:readiness-context-inventory-faults -- non-vacuity battery for the readiness-context contract.

Every mutation below is driven through the REAL guard: it patches the module under test
(``backend.app.readiness_contexts``, or the implementation modules the contract derives its axes
from), re-runs ``readiness_context_inventory_guard.run()``, and requires the guard to REFUSE.

Two properties make the battery discriminating rather than decorative:

  * a baseline unmutated run must PASS first, so the gates are not always-fail; and
  * each mutation names the SPECIFIC semantic gate that must catch it, and the mutation only
    passes when that gate is among the failures. A non-zero exit alone is not accepted -- otherwise
    the frozen canonical-hash pin (CH06) would "catch" every content mutation and prove nothing
    about the gate that is supposed to reason about it.

This guard is Docker-free and executes no readiness context: it starts no database, API, worker,
frontend or browser and produces no readiness disposition. Checks are classified honestly as
``schema predicate mutation``, ``inventory integration`` or ``structural source check`` -- never as
an executed readiness context.

Honest scope: claim_scope = readiness-context-inventory-faults-only; contexts_executed = false;
eligible_for_readiness = false; production_parity = false.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from backend.app import readiness_contexts as RC  # noqa: E402
import readiness_context_inventory_guard as G  # noqa: E402

checks: list[dict] = []

#: Cross-file pin of the inventory guard's own gate list. Its EXPECTED_CHECK_IDS catches gate
#: DELETION; pinning it from a second file also catches a gate deleted together with its entry.
PINNED_INVENTORY_GATES = [
    "CX01", "CX02", "CX03", "CX04", "CX05",
    "CI01", "CI02", "CI03", "CI04", "CI05", "CI06", "CI07", "CI08", "CI09", "CI10", "CI11", "CI12",
    "CS01", "CS02", "CS03", "CS04", "CS05", "CS06", "CS07", "CS08",
    "CD01", "CD02", "CD03", "CD04", "CD05", "CD06", "CD07",
    "CF01", "CF02", "CF03", "CF04",
    "CH01", "CH02", "CH03", "CH04", "CH05", "CH06",
    "CR01", "CR02", "CR03", "CR04", "CR05", "CR06",
]

#: Cross-file pin of the blocker set CD04 ranges over -- a guard-side constant outside the
#: canonical hash, which could otherwise be trimmed without any gate noticing.
PINNED_PRODUCTION_BLOCKERS = [
    "production-database-adapter",
    "production-queue-adapter",
    "production-configuration",
    "backup-restore-drill",
    "client-organizational-approval",
]

#: Every check this battery must emit -- the same completeness discipline the inventory guard has,
#: so a mutation cannot be quietly deleted from the battery.
EXPECTED_CHECK_IDS = [
    "FB00",
    "MC01 context-omitted", "MC02 fifth-context-added", "MC03 duplicate-context-id",
    "MC04 duplicate-axis-combination", "MC05 unsupported-mode", "MC06 unsupported-backend",
    "MC07 renamed-name-id-reused", "MC08 required-field-omitted", "MC09 undeclared-field-added",
    "MC10 context-order-changed", "MC11 unknown-context-substituted", "MC12 canonical-context-missing",
    "MC13 schema-version-changed", "MC14 unstable-ordering", "MC15 id-equals-display-name",
    "MS01 demo-claims-client-auth", "MS02 demo-ui-promoted-to-client-auth", "MS03 local-claims-rls",
    "MS04 postgres-claims-production-parity", "MS05 pg-adapter-reclassified-as-production",
    "MS06 v3-satisfies-migration-validity", "MS07 v3-satisfies-database-adapter",
    "MS08 v3-satisfies-queue-adapter", "MS09 scope-statements-stripped",
    "MS10 v3-implies-client-data-ready",
    "MR01 client-data-ready-true", "MR02 release-candidate-ready-true", "MR03 ga-ready-true",
    "MR04 production-parity-true-everywhere",
    "MD01 unknown-disposition-value", "MD02 unpredictable-disposition-value",
    "MD03 unknown-control-added", "MD04 required-blocker-removed", "MD05 production-blocker-passed",
    "MD06 extra-pass-predicted", "MD07 pass-without-precondition", "MD08 registry-drift",
    "MD09 accepted-evidence-conflicts-with-scope",
    "MA01 axis-product-no-longer-four", "MA02 mode-axis-not-total",
    "MA03 backend-axis-diverges-from-implementation", "MA04 backend-axis-grows-third-branch",
    "MA05 store-classes-no-longer-two", "MA06 create-store-branches-on-mode",
    "MX01 runner-reports-executed-pass", "MX02 runner-emits-simulated-disposition",
    "MX03 unknown-context-id-accepted", "MX04 run-input-not-isolated",
    "MX05 nondeterministic-canonical-hash", "MX06 hash-payload-carries-timestamp",
    "MX07 hash-disagrees-with-independent-recompute", "MX08 hash-not-lowercase-sha256",
    "MX09 hash-insensitive-to-order", "MX10 runner-all-contexts-reports-executed",
    "MX11 seeded-order-ignores-seed",
    "MZ01 suppressed-gate-caught-by-completeness",
    "FS01 drives-the-real-guard", "FS02 docker-free", "FS03 non-execution-disclosed",
    "FS04 no-stub-pass-results", "FS05 expected-gate-required",
    "FP01 inventory-gate-list-pinned", "FP02 production-blockers-pinned",
    "FZ01 guard-restored",
]


def rec(cid, ok, desc, level="schema predicate mutation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def run_real_guard() -> tuple[int, list[str]]:
    """Execute the REAL inventory guard, silently, and report (exit code, failed check ids)."""
    G.checks = []
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = G.run()
    except Exception as exc:  # a crash is a refusal, but record it as such rather than a clean fail
        return 1, [f"exception:{exc.__class__.__name__}"]
    return rc, [c["check_id"] for c in G.checks if not c["ok"]]


@contextlib.contextmanager
def patched(module, **attrs):
    saved = {k: getattr(module, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(module, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(module, k, v)


def mutated_contexts(fn):
    """Return a replacement for RC._canonical_contexts that applies ``fn`` to the built list.

    Patching ``_canonical_contexts`` (rather than ``canonical_inventory``) makes the mutation
    propagate consistently to the inventory, the canonical payload/hash and the runner inputs --
    exactly as a real edit to the contract would.
    """
    original = RC._canonical_contexts

    def replacement():
        contexts = copy.deepcopy(original())
        result = fn(contexts)
        # Only a returned LIST replaces the inventory. Mutators such as ``dict.pop`` return the
        # removed value; treating that as the new inventory would silently test the wrong thing.
        return result if isinstance(result, list) else contexts

    return replacement


def refuses(cid, expect_check, desc, fn, level="schema predicate mutation"):
    """Assert the real guard refuses a mutated contract AND that ``expect_check`` is what caught it."""
    with patched(RC, _canonical_contexts=mutated_contexts(fn)):
        rc, failed = run_real_guard()
    ok = rc != 0 and expect_check in failed
    rec(cid, ok, desc, level=level,
        extra={"expected_gate": expect_check, "guard_exit": rc, "failed_gates": failed[:8]})


def refuses_patched(cid, expect_check, desc, module, level="schema predicate mutation", **attrs):
    """Same, for mutations to module-level constants or functions rather than the context list."""
    with patched(module, **attrs):
        rc, failed = run_real_guard()
    ok = rc != 0 and expect_check in failed
    rec(cid, ok, desc, level=level,
        extra={"expected_gate": expect_check, "guard_exit": rc, "failed_gates": failed[:8]})


def by_id(contexts, cid):
    return next(c for c in contexts if c["context_id"] == cid)


# --- stand-in implementations for the axis-support regressions. Defined at module level so
# inspect.getsource() (which the real guard uses to derive the axes) can read them.

def detector_with_third_backend():  # pragma: no cover - parsed, never executed
    """A faithful third branch: the implementation would then support THREE backends."""
    if requested_repository_backend() == POSTGRES_REPOSITORY_BACKEND and postgres_probe().ready:  # noqa: F821
        return POSTGRES_REPOSITORY_BACKEND  # noqa: F821
    if requested_repository_backend() == "mysql":  # noqa: F821
        return "mysql"
    return LOCAL_REPOSITORY_BACKEND  # noqa: F821


def create_store_single_class():  # pragma: no cover - parsed, never executed
    """A create_store that no longer realises the repository axis with two store classes."""
    return LocalStateStore()  # noqa: F821


def _alternating_inventory():
    """A canonical_inventory() whose ORDER alternates between calls -- i.e. not stable."""
    base = RC.canonical_inventory
    state = {"n": 0}

    def alternating():
        state["n"] += 1
        contexts = base()
        return contexts if state["n"] % 2 else list(reversed(contexts))

    return alternating


def create_store_branching_on_mode():  # pragma: no cover - parsed, never executed
    """A create_store that chooses the store class from the client-data mode: axes NOT independent."""
    if client_data_mode() == "client" and requested_repository_backend() == POSTGRES_REPOSITORY_BACKEND:  # noqa: F821
        return PostgresStateStore(database_url())  # noqa: F821
    return LocalStateStore()  # noqa: F821


def run() -> int:
    # ---------------------------------------------------------------- baseline (not always-fail)
    rc, failed = run_real_guard()
    rec("FB00", rc == 0 and not failed,
        "BASELINE: the unmutated contract PASSES the real guard, so every refusal below is caused "
        "by the mutation and not by an always-fail gate",
        level="inventory integration", extra={"guard_exit": rc, "failed_gates": failed})

    # ---------------------------------------------------------------- inventory shape
    refuses("MC01 context-omitted", "CI02",
            "omitting one canonical context is refused (the inventory is no longer the axis product)",
            lambda cs: cs.pop() and None, level="inventory integration")
    refuses("MC02 fifth-context-added", "CI02",
            "adding a fifth context is refused -- four is derived from the axis product, so a "
            "fabricated extra context cannot be certified",
            lambda cs: cs.append({**copy.deepcopy(cs[0]), "context_id": "client-oracle"}),
            level="inventory integration")
    refuses("MC03 duplicate-context-id", "CI04",
            "a duplicate context id is refused",
            lambda cs: by_id(cs, "demo-postgres").__setitem__("context_id", "demo-local"))
    refuses("MC04 duplicate-axis-combination", "CI08",
            "two contexts sharing the same (mode, backend) combination are refused",
            lambda cs: by_id(cs, "demo-postgres").__setitem__("repository_backend", "local_json"))
    refuses("MC05 unsupported-mode", "CI07",
            "a context declaring an unsupported client-data mode is refused",
            lambda cs: by_id(cs, "demo-local").__setitem__("client_data_mode", "staging"))
    refuses("MC06 unsupported-backend", "CI07",
            "a context declaring an unsupported repository backend is refused",
            lambda cs: by_id(cs, "demo-local").__setitem__("repository_backend", "mysql"))
    refuses("MC07 renamed-name-id-reused", "CH06",
            "changing a display name while silently reusing the stable context id is refused by "
            "the frozen canonical-hash pin -- a rename cannot pass unnoticed",
            lambda cs: by_id(cs, "demo-local").__setitem__("context_name", "production-ish"),
            level="inventory integration")
    refuses("MC08 required-field-omitted", "CI09",
            "omitting a required context field is refused",
            lambda cs: by_id(cs, "client-postgres").pop("migration_evidence_requirement"))
    refuses("MC09 undeclared-field-added", "CI10",
            "adding an undeclared context field is refused",
            lambda cs: by_id(cs, "demo-local").__setitem__("ga_waiver", True))
    refuses("MC10 context-order-changed", "CI03",
            "reordering the canonical contexts is refused, and the canonical hash is order-sensitive",
            lambda cs: list(reversed(cs)), level="inventory integration")
    refuses("MC11 unknown-context-substituted", "CI06",
            "substituting a canonical context for an unknown one is refused as an UNKNOWN context",
            lambda cs: by_id(cs, "demo-local").__setitem__("context_id", "demo-oracle"))
    refuses("MC12 canonical-context-missing", "CI05",
            "the same substitution is independently refused as a MISSING canonical context",
            lambda cs: by_id(cs, "demo-local").__setitem__("context_id", "demo-oracle"))
    refuses_patched("MC13 schema-version-changed", "CI01",
                    "silently changing the schema version is refused",
                    RC, SCHEMA_VERSION="readiness-context-inventory.v2")
    refuses_patched("MC14 unstable-ordering", "CI11",
                    "an inventory whose order is not stable across repeated builds is refused",
                    RC, level="inventory integration",
                    canonical_inventory=_alternating_inventory())
    refuses("MC15 id-equals-display-name", "CI12",
            "a context whose id is just its display name is refused -- ids must be independent of "
            "display names",
            lambda cs: by_id(cs, "demo-local").__setitem__("context_name", "demo-local"))

    # ---------------------------------------------------------------- scope overclaims (Part F)
    refuses("MS01 demo-claims-client-auth", "CS01",
            "promoting a demo context to claim client authentication (per-user-identity PASS) is refused",
            lambda cs: by_id(cs, "demo-postgres")["expected_control_dispositions"]
            .__setitem__("per-user-identity", "PASS"))
    refuses("MS02 demo-ui-promoted-to-client-auth", "CS01",
            "promoting demo-mode UI evidence into an authenticated client-mode claim is refused",
            lambda cs: by_id(cs, "demo-local")["expected_control_dispositions"]
            .__setitem__("tenant-authorization-enforcement", "PASS"))
    refuses("MS03 local-claims-rls", "CS02",
            "a local-JSON context claiming database-enforced tenant isolation (RLS) is refused",
            lambda cs: by_id(cs, "client-local")["expected_control_dispositions"]
            .__setitem__("tenant-authorization-enforcement", "PASS"))
    refuses("MS04 postgres-claims-production-parity", "CS03",
            "a PostgreSQL context claiming production adapter parity is refused",
            lambda cs: by_id(cs, "client-postgres").__setitem__("production_parity", True))
    refuses("MS05 pg-adapter-reclassified-as-production", "CS03",
            "reclassifying the restricted PostgreSQL runtime as a production database adapter is refused",
            lambda cs: by_id(cs, "client-postgres")
            .__setitem__("database_adapter_classification", "production_adapter"))
    refuses("MS06 v3-satisfies-migration-validity", "CS04",
            "letting valid tenant evidence v3 satisfy migration validity is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .__setitem__("migration-validity", "PASS"))
    refuses("MS07 v3-satisfies-database-adapter", "CS05",
            "letting valid tenant evidence v3 satisfy database-adapter readiness is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .__setitem__("production-database-adapter", "PASS"))
    refuses("MS08 v3-satisfies-queue-adapter", "CS06",
            "letting valid tenant evidence v3 satisfy queue-adapter readiness is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .__setitem__("production-queue-adapter", "PASS"))
    refuses("MS09 scope-statements-stripped", "CS08",
            "stripping the non-transferable scope statements from a context is refused",
            lambda cs: by_id(cs, "demo-local").__setitem__("non_transferable_scope", []))
    refuses("MS10 v3-implies-client-data-ready", "CS07",
            "letting valid tenant evidence v3 imply client_data_ready is refused by the scope gate "
            "as well as by the readiness-flag gate",
            lambda cs: by_id(cs, "client-postgres").__setitem__("expected_client_data_ready", True))

    # ---------------------------------------------------------------- readiness flag overclaims
    refuses("MR01 client-data-ready-true", "CF02",
            "flipping expected_client_data_ready to true is refused (v3 never implies readiness)",
            lambda cs: by_id(cs, "client-postgres").__setitem__("expected_client_data_ready", True))
    refuses("MR02 release-candidate-ready-true", "CF03",
            "flipping expected_release_candidate_ready to true is refused",
            lambda cs: by_id(cs, "client-postgres").__setitem__("expected_release_candidate_ready", True))
    refuses("MR03 ga-ready-true", "CF04",
            "flipping expected_ga_ready to true is refused",
            lambda cs: by_id(cs, "client-postgres").__setitem__("expected_ga_ready", True))
    refuses("MR04 production-parity-true-everywhere", "CF01",
            "flipping production_parity to true is refused",
            lambda cs: [c.__setitem__("production_parity", True) for c in cs] and None)

    # ---------------------------------------------------------------- control dispositions
    refuses("MD01 unknown-disposition-value", "CD03",
            "an unknown disposition value (outside the registry vocabulary) is refused",
            lambda cs: by_id(cs, "demo-local")["expected_control_dispositions"]
            .__setitem__("ci-execution", "PROBABLY_FINE"))
    refuses("MD02 unpredictable-disposition-value", "CD03",
            "predicting REVIEW_REQUIRED is refused -- a context definition must make a falsifiable "
            "prediction, not an open question",
            lambda cs: by_id(cs, "demo-local")["expected_control_dispositions"]
            .__setitem__("ci-execution", "REVIEW_REQUIRED"))
    refuses("MD03 unknown-control-added", "CD01",
            "adding a control that is not in the registry is refused",
            lambda cs: by_id(cs, "demo-local")["expected_control_dispositions"]
            .__setitem__("invented-control", "BLOCKED"))
    refuses("MD04 required-blocker-removed", "CD01",
            "removing a required blocker from a context's dispositions is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .pop("production-database-adapter"))
    refuses("MD05 production-blocker-passed", "CD04",
            "predicting PASS for a production-infrastructure blocker is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .__setitem__("backup-restore-drill", "PASS"))
    refuses("MD06 extra-pass-predicted", "CD05",
            "predicting a PASS for any control without an accepted artifact produced in that "
            "context is refused",
            lambda cs: by_id(cs, "client-postgres")["expected_control_dispositions"]
            .__setitem__("audit-keyed-integrity", "PASS"))
    refuses("MD07 pass-without-precondition", "CD06",
            "predicting a PASS without stating the commit-binding precondition is refused",
            lambda cs: by_id(cs, "client-postgres").__setitem__("accepted_evidence_precondition", None))
    refuses_patched("MD08 registry-drift", "CD02",
                    "dropping a control from the contract's control set is refused: the set must "
                    "equal the REAL registry file exactly",
                    RC, level="inventory integration",
                    CONTROL_IDS=tuple(c for c in RC.CONTROL_IDS if c != "worker-heartbeat"))
    refuses_patched("MD09 accepted-evidence-conflicts-with-scope", "CD07",
                    "an accepted-evidence allowance that would resurrect a control the context "
                    "structurally cannot evaluate is refused",
                    RC, ACCEPTED_CONTEXT_EVIDENCE={
                        **RC.ACCEPTED_CONTEXT_EVIDENCE,
                        "demo-local": frozenset({"tenant-authorization-enforcement"})})

    # ---------------------------------------------------------------- axis-support regressions
    # The decisive fail-closed property: when the implementation stops justifying four contexts,
    # the guard must FAIL rather than certify a fabricated inventory.
    refuses_patched("MA01 axis-product-no-longer-four", "CX05",
                    "when the implementation supports only ONE repository backend the product is "
                    "no longer four, and the guard FAILS CLOSED instead of certifying four "
                    "fabricated contexts",
                    RC, level="inventory integration",
                    SUPPORTED_REPOSITORY_BACKENDS=("local_json",))
    refuses_patched("MA02 mode-axis-not-total", "CX01",
                    "when client_data_mode() can return a value outside the declared axis, the "
                    "axis is no longer total and the guard refuses",
                    G.READINESS, client_data_mode=lambda: "staging")
    refuses_patched("MA03 backend-axis-diverges-from-implementation", "CX02",
                    "when the declared backend axis stops matching the implementation the guard "
                    "refuses (axes are derived from code, not from env-var names)",
                    RC, SUPPORTED_REPOSITORY_BACKENDS=("local_json", "cockroach"))
    refuses_patched("MA04 backend-axis-grows-third-branch", "CX02",
                    "when the REAL detect_active_repository_backend() grows a faithful third "
                    "branch, the implementation supports six configurations and the guard FAILS "
                    "CLOSED instead of certifying four -- the decisive derivation property, and "
                    "the reason the axis is resolved from actual return values rather than from "
                    "two constant names",
                    G.RB, level="implementation derivation",
                    detect_active_repository_backend=detector_with_third_backend)
    refuses_patched("MA05 store-classes-no-longer-two", "CX03",
                    "when create_store() stops realising the axis with two store classes the guard "
                    "refuses",
                    G.STORE, create_store=create_store_single_class)
    refuses_patched("MA06 create-store-branches-on-mode", "CX04",
                    "when create_store() selects the store class from the client-data mode the "
                    "axes are no longer independent and the guard refuses",
                    G.STORE, create_store=create_store_branching_on_mode)

    # ---------------------------------------------------------------- runner cannot fabricate
    def fake_pass_runner(context_id, **_kw):
        return {"schema_version": RC.SCHEMA_VERSION, "canonical_inventory_hash": RC.canonical_hash(),
                "requested_context_ids": [context_id], "certification": "passed", "accepted": True,
                "executed": True, "results": [{"control": "ci-execution", "disposition": "PASS"}],
                "reason": ""}

    refuses_patched("MX01 runner-reports-executed-pass", "CR01",
                    "a runner that reports certification=passed/accepted=true instead of the "
                    "controlled unavailable result is refused",
                    RC, level="inventory integration", run_context=fake_pass_runner)
    refuses_patched("MX02 runner-emits-simulated-disposition", "CR04",
                    "a runner whose serialised result contains a simulated readiness disposition "
                    "is refused",
                    RC, run_all_contexts=lambda **_kw: {
                        "schema_version": RC.SCHEMA_VERSION, "canonical_inventory_hash": "x",
                        "requested_context_ids": list(RC.CANONICAL_CONTEXT_ORDER),
                        "certification": "unavailable", "accepted": False, "executed": False,
                        "results": [], "reason": "simulated ci-execution PASS"})
    refuses_patched("MX03 unknown-context-id-accepted", "CR03",
                    "a runner that silently accepts an unknown context id is refused",
                    RC, run_context=lambda context_id, **_kw: {
                        "schema_version": RC.SCHEMA_VERSION, "canonical_inventory_hash": "x",
                        "requested_context_ids": [context_id], "certification": "unavailable",
                        "accepted": False, "executed": False, "results": [], "reason": ""})

    shared = {"leak": None}

    def leaky_build(context_id, **_kw):
        if shared["leak"] is None:
            shared["leak"] = next(c for c in RC.canonical_inventory() if c["context_id"] == context_id)
        return shared["leak"]

    refuses_patched("MX04 run-input-not-isolated", "CR06",
                    "a runner input that is a SHARED mutable object (not an isolated deep copy) is "
                    "refused -- one context's runner could otherwise corrupt another's input",
                    RC, build_run_input=leaky_build)

    counter = {"n": 0}

    def unstable_hash(*_a, **_kw):
        counter["n"] += 1
        return f"{counter['n']:064x}"

    refuses_patched("MX05 nondeterministic-canonical-hash", "CH01",
                    "a nondeterministic canonical hash is refused",
                    RC, level="inventory integration", canonical_hash=unstable_hash)
    refuses_patched("MX06 hash-payload-carries-timestamp", "CH04",
                    "a canonical payload carrying a timestamp (or any environment-dependent value) "
                    "is refused",
                    RC, canonical_json=lambda *_a, **_kw: json.dumps(
                        {"generated_at": "2026-07-25T00:00:00Z", "contexts": []}, sort_keys=True))
    refuses_patched("MX07 hash-disagrees-with-independent-recompute", "CH02",
                    "a canonical hash that is stable but does NOT match the guard's independent "
                    "recomputation is refused",
                    RC, level="inventory integration",
                    canonical_hash=lambda *_a, **_kw: "0" * 64)
    refuses_patched("MX08 hash-not-lowercase-sha256", "CH03",
                    "a canonical hash that is not a full lowercase SHA-256 hex digest is refused",
                    RC, canonical_hash=lambda *_a, **_kw: "ABC123")
    refuses_patched("MX09 hash-insensitive-to-order", "CH05",
                    "a canonical hash that is INSENSITIVE to context order is refused",
                    RC, level="inventory integration",
                    canonical_hash=lambda *_a, **_kw: G.independent_canonical_hash(
                        list(reversed(RC.canonical_inventory()))))
    refuses_patched("MX10 runner-all-contexts-reports-executed", "CR02",
                    "a run_all_contexts() that reports executed=true is refused",
                    RC, run_all_contexts=lambda **_kw: {
                        "schema_version": RC.SCHEMA_VERSION, "canonical_inventory_hash": "x",
                        "requested_context_ids": list(RC.CANONICAL_CONTEXT_ORDER),
                        "certification": "unavailable", "accepted": False, "executed": True,
                        "results": [], "reason": ""})
    refuses_patched("MX11 seeded-order-ignores-seed", "CR05",
                    "an execution_order() that ignores its seed (so a 'deterministic random' order "
                    "is not actually seeded) is refused",
                    RC, level="inventory integration",
                    execution_order=lambda reverse=False, seed=None: (
                        list(reversed(RC.CANONICAL_CONTEXT_ORDER)) if reverse
                        else list(RC.CANONICAL_CONTEXT_ORDER)))

    # The completeness pin itself must be load-bearing: suppressing a gate's rec() call while
    # leaving everything else intact has to be caught.
    original_rec = G.rec

    def suppressing_rec(cid, *args, **kwargs):
        if cid == "CD05":
            return None
        return original_rec(cid, *args, **kwargs)

    refuses_patched("MZ01 suppressed-gate-caught-by-completeness", "CZ00 completeness",
                    "silently suppressing a gate is caught by the inventory guard's completeness "
                    "pin, which fails the run with the gate's id reported missing",
                    G, level="inventory integration", rec=suppressing_rec)

    # ---------------------------------------------------------------- structural source checks
    inv_src = (ROOT / "scripts" / "readiness_context_inventory_guard.py").read_text(encoding="utf-8")
    fault_src = Path(__file__).read_text(encoding="utf-8")
    mod_src = (ROOT / "backend" / "app" / "readiness_contexts.py").read_text(encoding="utf-8")

    # Checked over the parsed AST, never by scanning for a literal: a text scan for
    # "import readiness_context_inventory_guard as G" would match the scan's own needle and can
    # never be false -- the exact self-referential vacuity this battery exists to catch.
    fault_ast = ast.parse(fault_src)
    imports_guard = any(
        isinstance(n, ast.Import) and any(a.name == "readiness_context_inventory_guard"
                                          for a in n.names)
        for n in ast.walk(fault_ast))
    calls_guard_run = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "run"
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "G"
        for n in ast.walk(fault_ast))
    rec("FS01 drives-the-real-guard", imports_guard and calls_guard_run,
        "this battery drives the REAL inventory guard: the parsed AST contains a real import of "
        "the guard module and a real call to G.run(); it does not reimplement the gates it tests",
        level="structural source check",
        extra={"imports_guard": imports_guard, "calls_guard_run": calls_guard_run})
    # Docker-free by CONSTRUCTION. Checked over the parsed AST, not over raw source text: a
    # text scan would match the token list in this very check (and the honest ``docker_used:
    # false`` disclosure), which is exactly the kind of self-referential vacuity this battery
    # exists to prevent. Neither guard may IMPORT a process launcher, database driver, browser
    # driver or TestClient -- so neither can start Docker, a database, an API or a browser.
    forbidden_imports = {"subprocess", "psycopg", "psycopg2", "playwright", "docker", "asyncio",
                         "fastapi.testclient", "starlette.testclient", "requests", "httpx", "socket"}

    def imported_modules(source: str) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
                found.update(a.name.lower() for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
                found.add(node.module.lower())
        return found

    inv_imports, fault_imports = imported_modules(inv_src), imported_modules(fault_src)
    offending = sorted((inv_imports | fault_imports) & forbidden_imports)
    rec("FS02 docker-free",
        not offending,
        "neither guard can start an external process at all: the parsed AST of both files imports "
        "no process launcher, database driver, browser driver or HTTP/TestClient, so Docker-free "
        "holds by construction rather than by assertion",
        level="structural source check", extra={"offending_imports": offending})
    rec("FS03 non-execution-disclosed",
        '"contexts_executed": False' in inv_src and '"readiness_dispositions_produced": False' in inv_src
        and '"execution_verdict": "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED"' in inv_src,
        "the inventory guard's summary discloses that no context was executed and that execution "
        "acceptance remains FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        level="structural source check")
    rec("FS04 no-stub-pass-results",
        '"certification": "unavailable"' in mod_src and '"accepted": False' in mod_src
        and '"results": []' in mod_src,
        "the contract module's execution entry points return a controlled unavailable result with "
        "no results, rather than stub results that report PASS",
        level="structural source check")
    # Also AST-checked: assert the real `refuses`/`refuses_patched` bodies contain a membership
    # test of expect_check against the failed-gate list, rather than scanning for that phrase in
    # source text (which would match this very check).
    def couples_expected_gate(fn_name: str) -> bool:
        for node in ast.walk(fault_ast):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                return any(
                    isinstance(sub, ast.Compare) and any(isinstance(o, ast.In) for o in sub.ops)
                    and isinstance(sub.left, ast.Name) and sub.left.id == "expect_check"
                    for sub in ast.walk(node))
        return False

    coupled = [fn for fn in ("refuses", "refuses_patched") if couples_expected_gate(fn)]
    rec("FS05 expected-gate-required", len(coupled) == 2,
        "each mutation requires its SPECIFIC semantic gate to fail: both mutation drivers contain "
        "a real membership test of the expected gate against the failed-gate list (AST-verified), "
        "so a mutation caught only by the canonical-hash pin does not count as caught",
        level="structural source check", extra={"coupled_drivers": coupled})

    # ---- cross-file pins: the inventory guard's own gate list and blocker list are constants that
    # live OUTSIDE the canonical hash and outside every mutation above, so trimming either would
    # silently narrow the guard. Pinning them here forces the two files to be edited in concert.
    rec("FP01 inventory-gate-list-pinned", list(G.EXPECTED_CHECK_IDS) == PINNED_INVENTORY_GATES,
        "the inventory guard's EXPECTED_CHECK_IDS is pinned here cross-file: deleting a gate "
        "together with its own pin entry still fails, because this file must be edited too",
        level="structural source check",
        extra={"expected_gate_count": len(PINNED_INVENTORY_GATES),
               "observed_gate_count": len(G.EXPECTED_CHECK_IDS)})
    rec("FP02 production-blockers-pinned", list(G.PRODUCTION_BLOCKERS) == PINNED_PRODUCTION_BLOCKERS,
        "the inventory guard's PRODUCTION_BLOCKERS list is pinned here cross-file: silently "
        "dropping a blocker from CD04's scope fails",
        level="structural source check",
        extra={"pinned": PINNED_PRODUCTION_BLOCKERS, "observed": list(G.PRODUCTION_BLOCKERS)})

    # ---------------------------------------------------------------- integrity of the battery
    # the real guard must be restored and passing again after every mutation
    rc_after, failed_after = run_real_guard()
    rec("FZ01 guard-restored", rc_after == 0 and not failed_after,
        "after the whole battery the real guard passes again: every mutation was reverted and none "
        "leaked into the contract",
        level="inventory integration", extra={"guard_exit": rc_after, "failed_gates": failed_after})

    emitted = [c["check_id"] for c in checks]
    missing = [cid for cid in EXPECTED_CHECK_IDS if cid not in emitted]
    unknown = [cid for cid in emitted if cid not in EXPECTED_CHECK_IDS and cid != "FZ00 completeness"]
    dupes = sorted({cid for cid in emitted if emitted.count(cid) > 1})
    if missing or unknown or dupes:
        rec("FZ00 completeness", False,
            "the emitted check set must equal the expected set exactly -- a mutation cannot be "
            "quietly deleted from the battery",
            level="structural source check",
            extra={"missing": missing, "unknown": unknown, "duplicates": dupes})

    passed = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed
    # Count ONLY real mutations: the baseline (FB00), the restoration check, the structural source
    # checks and the cross-file pins are not mutations and must not be advertised as such.
    mutation_ids = [c["check_id"] for c in checks
                    if c["check_id"][:2] in ("MC", "MS", "MR", "MD", "MA", "MX", "MZ")]
    summary = {
        "guard": "readiness-context-inventory-faults",
        "claim_scope": "readiness-context-inventory-faults-only",
        "passed": passed, "failed": failed_n, "skipped": 0,
        "certification": "passed" if failed_n == 0 else "not_passed",
        "fault_battery": "passed" if failed_n == 0 else "not_passed",
        "mutations": len(mutation_ids),
        "non_mutation_checks": len(checks) - len(mutation_ids),
        "canonical_inventory_hash": RC.canonical_hash(),
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
    return 0 if failed_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
