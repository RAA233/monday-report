"""Canonical manifest of the ACCEPTED restricted-PostgreSQL runtime slice guards (Outcome-1).

This module is the single, fail-closed source of truth that the reserved aggregate commands
(`audit:restricted-postgres-runtime` and `audit:restricted-postgres-runtime-faults`) bind to. It
declares, for every accepted child guard:

  * logical name, `audit:*` command, and script path;
  * required `claim_scope`;
  * expected check count AND the frozen expected check-id set (captured from the accepted child at the
    frozen feature head, so missing/unknown/duplicate ids are precisely detectable -- not merely a count);
  * required `full_functional_matrix` value (functional children only);
  * required evidence / readiness eligibility, production-parity, and migration-principal classification;
  * the exact normal-failure counters that child MUST emit (and which must be zero);
  * the accepted script's SHA-256.

It fails closed on a missing child, an unexpected child, a wrong command, a wrong script path, a changed
child hash, a wrong claim scope, a wrong expected count, a missing normal-failure counter, a changed
eligibility/parity classification, or a changed migration-principal classification.

The manifest binds to full 64-hex SHA-256 digests and full commands/paths -- never abbreviated commit ids.
The expected-id sets live in a frozen sidecar JSON (`restricted_postgres_runtime_manifest_ids.json`)
generated from the accepted children at the frozen head; this module fails closed if that sidecar is
absent, malformed, or inconsistent with the declared counts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_IDS_SIDECAR = ROOT / "scripts" / "restricted_postgres_runtime_manifest_ids.json"

# normal-failure counters, by emitter convention (see each accepted child's summary):
HTTP_COUNTERS = ["normal_functional_http_423", "normal_functional_http_500", "normal_functional_http_503"]
WORKER_COUNTERS = ["normal_worker_process_failures", "normal_import_process_failures"]

# every functional/fault child asserts this exact honest classification in its own summary:
FUNCTIONAL_CONTRACT = {
    "full_functional_matrix": "not_run",
    "eligible_for_tenant_evidence": False,
    "eligible_for_readiness": False,
    "production_parity": False,
    "migration_principal_class": "test-only-bootstrap-migration-admin",
}
FAULT_CONTRACT = {
    "eligible_for_tenant_evidence": False,
    "eligible_for_readiness": False,
    "production_parity": False,
    "migration_principal_class": "test-only-bootstrap-migration-admin",
}

# ---- ACCEPTED FUNCTIONAL SLICE CHILDREN (frozen head f4945704) --------------------------------------
FUNCTIONAL = [
    {"name": "core", "command": "audit:restricted-postgres-runtime-core",
     "script": "scripts/restricted_postgres_runtime_core_guard.py",
     "claim_scope": "restricted-runtime-functional-core-only", "expected_count": 31,
     "required_counters": [],
     "sha256": "f00758ea701aee942a7f519195c5428cb391d3e2b8fab0ff6e3d006b21424522"},
    {"name": "mutations", "command": "audit:restricted-postgres-runtime-mutations",
     "script": "scripts/restricted_postgres_runtime_mutations_guard.py",
     "claim_scope": "restricted-runtime-corrections-validation-idempotency-only", "expected_count": 48,
     "required_counters": HTTP_COUNTERS,
     "sha256": "e73d082e1059b1b4eb36f094b222272a027c3a4cdc2a48a95496f57ee4caf1f9"},
    {"name": "exports", "command": "audit:restricted-postgres-runtime-exports",
     "script": "scripts/restricted_postgres_runtime_exports_guard.py",
     "claim_scope": "restricted-runtime-exports-signed-references-only", "expected_count": 56,
     "required_counters": HTTP_COUNTERS,
     "sha256": "9caae925d63bd61397d63af90e1a59d61e524dd9d9a953b9a486e2751f7a242f"},
    {"name": "isolation", "command": "audit:restricted-postgres-runtime-isolation",
     "script": "scripts/restricted_postgres_runtime_isolation_guard.py",
     "claim_scope": "restricted-runtime-cross-tenant-http-rls-only", "expected_count": 102,
     "required_counters": HTTP_COUNTERS,
     "sha256": "0eebd751e4de8cab9bcaff1d59f9a06fe4d8ad576f3129db83b5711a2cf50797"},
    {"name": "worker-import", "command": "audit:restricted-postgres-runtime-worker-import",
     "script": "scripts/restricted_postgres_runtime_worker_import_guard.py",
     "claim_scope": "restricted-runtime-worker-import-only", "expected_count": 29,
     "required_counters": HTTP_COUNTERS + WORKER_COUNTERS,
     "sha256": "faba42d12e296097e700a6c3323a8f694a8d1007d216e6b5adfa4d67b30de6af"},
]

# ---- ACCEPTED FUNCTIONAL-FAULT CHILDREN -------------------------------------------------------------
FAULT = [
    {"name": "core-faults", "command": "audit:restricted-postgres-runtime-core-faults",
     "script": "scripts/restricted_postgres_runtime_core_faults_guard.py",
     "claim_scope": "restricted-runtime-functional-core-faults-only", "expected_count": 11,
     "required_counters": [],
     "sha256": "25b084f9261aa6be5dc5b08a3fdb3cd2fbd8c6b48a205d7ce74856fa04ff693a"},
    {"name": "mutations-faults", "command": "audit:restricted-postgres-runtime-mutations-faults",
     "script": "scripts/restricted_postgres_runtime_mutations_faults_guard.py",
     "claim_scope": "restricted-runtime-corrections-validation-idempotency-faults-only", "expected_count": 27,
     "required_counters": [],
     "sha256": "f99a09399ff519f584912f934e77dfe8394ed34f20cdedad3e1723a309b9ceb8"},
    {"name": "exports-faults", "command": "audit:restricted-postgres-runtime-exports-faults",
     "script": "scripts/restricted_postgres_runtime_exports_faults_guard.py",
     "claim_scope": "restricted-runtime-exports-signed-references-faults-only", "expected_count": 38,
     "required_counters": [],
     "sha256": "6b53b8701dcdd05d5560450f7fe1211dd79ebf69c07b49e04133fb12ee3ac78c"},
    {"name": "isolation-faults", "command": "audit:restricted-postgres-runtime-isolation-faults",
     "script": "scripts/restricted_postgres_runtime_isolation_faults_guard.py",
     "claim_scope": "restricted-runtime-cross-tenant-http-rls-faults-only", "expected_count": 36,
     "required_counters": [],
     "sha256": "1f1cc56dc4f83062352473a5fedc9934031b4537c5baba77ffdb172dd89724d3"},
    {"name": "worker-import-faults", "command": "audit:restricted-postgres-runtime-worker-import-faults",
     "script": "scripts/restricted_postgres_runtime_worker_import_faults_guard.py",
     "claim_scope": "restricted-runtime-worker-import-faults-only", "expected_count": 32,
     "required_counters": [],
     "sha256": "ee91deba001ba566f2d3bceb32405646696493ee597421ce5a234ef010e6ff72"},
]

EXPECTED_FUNCTIONAL_TOTAL = sum(c["expected_count"] for c in FUNCTIONAL)  # 266
EXPECTED_FAULT_TOTAL = sum(c["expected_count"] for c in FAULT)            # 144

# The unqualified aggregate command names, reserved for these complete guards:
COMPLETE_FUNCTIONAL_COMMAND = "audit:restricted-postgres-runtime"
COMPLETE_FAULT_COMMAND = "audit:restricted-postgres-runtime-faults"


def sha256_of(script_rel: str) -> str:
    return hashlib.sha256((ROOT / script_rel).read_bytes()).hexdigest()


def verify_hashes(children) -> list[str]:
    """Return a list of fail-closed problems: missing script or a changed accepted hash."""
    problems = []
    for c in children:
        p = ROOT / c["script"]
        if not p.exists():
            problems.append(f"{c['name']}: script missing at {c['script']}")
            continue
        actual = sha256_of(c["script"])
        if actual != c["sha256"]:
            problems.append(f"{c['name']}: accepted script hash changed (manifest binds a frozen digest)")
    return problems


def verify_commands(children) -> list[str]:
    """Fail-closed check that every accepted child's `audit:*` command exists in package.json and maps
    to exactly `python <script>` -- catches a wrong command or a wrong/renamed script path."""
    problems = []
    try:
        pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        scripts = pkg.get("scripts", {})
    except Exception as exc:  # noqa: BLE001
        return [f"package.json unreadable: {type(exc).__name__}"]
    for c in children:
        cmd, script = c["command"], c["script"]
        if cmd not in scripts:
            problems.append(f"{c['name']}: command '{cmd}' missing from package.json")
            continue
        expected = f"python {script}"
        if scripts[cmd] != expected:
            problems.append(f"{c['name']}: command '{cmd}' does not map to '{expected}'")
    return problems


def load_expected_ids(data=None) -> dict:
    """Load the frozen per-child expected check-id sets from the sidecar; fail closed on any drift
    from the declared counts, a missing child, an unexpected child, or a sidecar total that does not
    reconcile with the per-child lists and the manifest's declared totals.

    `data` may be supplied directly (a parsed sidecar dict) for deterministic negative testing; when
    omitted the frozen sidecar file is read."""
    if data is None:
        if not EXPECTED_IDS_SIDECAR.exists():
            raise ManifestError("expected-id sidecar missing")
        try:
            data = json.loads(EXPECTED_IDS_SIDECAR.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise ManifestError(f"expected-id sidecar malformed: {type(exc).__name__}")
    fn, fa = data.get("functional", {}), data.get("fault", {})
    out = {"functional": {}, "fault": {}}
    for kind, decl, block in (("functional", FUNCTIONAL, fn), ("fault", FAULT, fa)):
        declared = {c["name"] for c in decl}
        present = set(block)
        if declared - present:
            raise ManifestError(f"{kind} expected-id sidecar missing children: {sorted(declared - present)}")
        if present - declared:
            raise ManifestError(f"{kind} expected-id sidecar has unexpected children: {sorted(present - declared)}")
        for c in decl:
            ids = block[c["name"]]
            if not isinstance(ids, list) or len(ids) != c["expected_count"]:
                raise ManifestError(f"{c['name']}: expected-id list count {len(ids) if isinstance(ids, list) else '?'} "
                                    f"!= declared {c['expected_count']}")
            if len(set(ids)) != len(ids):
                raise ManifestError(f"{c['name']}: expected-id sidecar contains duplicates")
            out[kind][c["name"]] = list(ids)
    # reconcile the sidecar's declared totals (if present) and the per-child sums with the manifest's
    # authoritative declared totals -- a checked, fail-closed invariant (not decoration):
    exp_ft = sum(len(v) for v in out["functional"].values())
    exp_fa = sum(len(v) for v in out["fault"].values())
    if exp_ft != EXPECTED_FUNCTIONAL_TOTAL:
        raise ManifestError(f"sidecar functional total {exp_ft} != manifest {EXPECTED_FUNCTIONAL_TOTAL}")
    if exp_fa != EXPECTED_FAULT_TOTAL:
        raise ManifestError(f"sidecar fault total {exp_fa} != manifest {EXPECTED_FAULT_TOTAL}")
    ft, fa_total = data.get("_functional_total"), data.get("_fault_total")
    if ft is not None and ft != exp_ft:
        raise ManifestError(f"sidecar _functional_total {ft} != reconciled {exp_ft}")
    if fa_total is not None and fa_total != exp_fa:
        raise ManifestError(f"sidecar _fault_total {fa_total} != reconciled {exp_fa}")
    return out


class ManifestError(RuntimeError):
    pass


def child_by_name(children, name):
    for c in children:
        if c["name"] == name:
            return c
    return None
