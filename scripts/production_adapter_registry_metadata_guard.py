"""audit:production-adapter-registry-metadata -- the registry metadata matches its real consumers.

Both adapter controls stopped delegating to a client-data readiness check (``postgres_repository``,
``redis_queue``) and now require a valid production evidence artifact. Their registry metadata kept
describing the removed delegation, and ``evaluate_blockers`` emits ``resolution_condition`` verbatim
as ``remediation`` -- so each control reported BLOCKED beside instructions that provably could not
resolve it. This guard proves the metadata now describes what the evaluator actually does.

It is Docker-free and derives its expectations from the IMPLEMENTATION, not from a local copy of the
expected prose: the consumer's AST supplies which contract module each control resolves through, and
that module supplies the schema id the metadata must cite. Copying the prose here and diffing it
would only prove the guard and the registry agree with each other.

Honest scope: claim_scope = production-adapter-registry-metadata-only. This certifies metadata
accuracy. It certifies NO adapter: both remain
PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED / PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED, GA_BLOCKED.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from backend.app import ga_readiness as GA  # noqa: E402
from backend.app import production_database_adapter_evidence as DB  # noqa: E402
from backend.app import production_queue_adapter_evidence as Q  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402

REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
CONSUMER_PATH = ROOT / "backend" / "app" / "ga_readiness.py"

#: The two controls this increment may touch, and the contract each must now cite.
TARGETS: dict[str, dict] = {
    "ga_postgres_adapter": {"registry_id": "production-database-adapter", "module": DB,
                            "probe": "_postgres_adapter_probe",
                            "module_file": "backend/app/production_database_adapter_evidence.py"},
    "ga_redis_adapter": {"registry_id": "production-queue-adapter", "module": Q,
                         "probe": "_queue_adapter_probe",
                         "module_file": "backend/app/production_queue_adapter_evidence.py"},
}
ALLOWED_FIELDS = frozenset({"description", "policy_reference", "resolution_condition"})

#: Language that describes the REMOVED delegation. Its presence means the metadata is stale again.
STALE_MARKERS: dict[str, tuple[str, ...]] = {
    "ga_postgres_adapter": ("postgres_repository", "requested==active", "requested == active",
                            "active adapter is postgres", "live probe"),
    "ga_redis_adapter": ("redis_queue", "PING", "ping", "active worker is redis", "live probe"),
}

#: Patterns that would assert the evidence already exists, or that parity/acceptance is achieved.
#: Regexes, not fixed substrings: the first cut listed "evidence is present" and was defeated by
#: "evidence artifact is present" -- caught by this guard's own fault battery (MX05).
EXISTENCE_CLAIM_PATTERNS: tuple[str, ...] = (
    r"(?:evidence|artifact)\b[^.]{0,60}?\b(?:exists|is present|is available|is in place|"
    r"has been (?:generated|produced|accepted|verified))",
    r"\b(?:is|are|has been|have been)\s+(?:currently\s+)?valid\b",
    r"production parity\b[^.]{0,40}?\b(?:has been|is)\s+(?:achieved|met|established|true)",
    r"adapter is\s+(?:accepted|production[- ]ready|ready for production)",
    r"\bthis control (?:passes|is satisfied)\b",
)

checks: list[dict] = []


def rec(cid, ok, desc, level="metadata integration", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def load_registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def base_registry(ref: str = "origin/main") -> dict | None:
    """The registry as of the base commit, for the only-allowed-fields comparison."""
    out = subprocess.run(["git", "show", f"{ref}:evals/ga/blocker_registry.v1.json"],
                         cwd=str(ROOT), capture_output=True, text=True)
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return None


def consumer_contract_module(probe_name: str) -> str | None:
    """Which contract module the REAL consumer resolves this control through, from its AST."""
    try:
        tree = ast.parse(CONSUMER_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    probe = next((n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == probe_name), None)
    if probe is None:
        return None
    # the probe calls a *_reasons helper; that helper imports the contract module
    helpers = [n.func.id for n in ast.walk(probe)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    for helper_name in helpers:
        helper = next((n for n in tree.body
                       if isinstance(n, ast.FunctionDef) and n.name == helper_name), None)
        if helper is None:
            continue
        for node in ast.walk(helper):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                for alias in node.names:
                    if "evidence" in alias.name:
                        return alias.name
    return None


def run() -> int:
    registry = load_registry()
    entries = {b["check_id"]: b for b in registry["blockers"]}

    # ---------------------------------------------------------------- shape / boundary
    rec("RM01 control-count-28", len(registry["blockers"]) == 28,
        "the registry still declares exactly 28 controls",
        extra={"count": len(registry["blockers"])})
    rec("RM02 exactly-two-targets", set(TARGETS) <= set(entries),
        "both target controls exist under their expected check ids",
        extra={"targets": sorted(TARGETS)})
    rec("RM03 registry-ids-intact",
        all(entries[cid]["id"] == spec["registry_id"] for cid, spec in TARGETS.items()),
        "each target's registry identifier is unchanged")

    base = base_registry()
    if base is None:
        rec("RM04 only-allowed-fields-changed", False,
            "the base registry could not be read, so the change boundary cannot be verified",
            level="structural source check")
        rec("RM05 control-order-unchanged", False, "base registry unavailable",
            level="structural source check")
        rec("RM06 non-target-controls-unchanged", False, "base registry unavailable",
            level="structural source check")
    else:
        base_by_id = {b["check_id"]: b for b in base["blockers"]}
        differing = {}
        for cid, entry in entries.items():
            old = base_by_id.get(cid)
            if old is None:
                differing[cid] = ["<new control>"]
                continue
            fields = sorted(k for k in set(old) | set(entry) if old.get(k) != entry.get(k))
            if fields:
                differing[cid] = fields
        rec("RM04 only-allowed-fields-changed",
            set(differing) == set(TARGETS)
            and all(set(f) <= ALLOWED_FIELDS for f in differing.values()),
            "only description / policy_reference / resolution_condition changed, and only on the "
            "two adapter controls",
            level="structural source check", extra={"differing": differing})
        rec("RM05 control-order-unchanged",
            [b["id"] for b in base["blockers"]] == [b["id"] for b in registry["blockers"]],
            "control order is byte-for-byte the same sequence of ids",
            level="structural source check")
        untouched = {cid: e for cid, e in entries.items() if cid not in TARGETS}
        rec("RM06 non-target-controls-unchanged",
            all(base_by_id.get(cid) == e for cid, e in untouched.items()),
            f"all {len(untouched)} non-target controls are canonically identical to the base",
            level="structural source check")

    # immutable fields on the targets
    immutable = ("id", "check_id", "category", "severity", "owner_type", "manual_review_required",
                 "allow_not_applicable", "label", "policy_source")
    if base is not None:
        base_by_id = {b["check_id"]: b for b in base["blockers"]}
        bad = {cid: [f for f in immutable if entries[cid].get(f) != base_by_id[cid].get(f)]
               for cid in TARGETS if cid in base_by_id}
        bad = {k: v for k, v in bad.items() if v}
        rec("RM07 immutable-fields-unchanged", not bad,
            "identifier, category, severity, owner type, manual-review and applicability flags are "
            "unchanged on both targets",
            level="structural source check", extra={"changed": bad})
    else:
        rec("RM07 immutable-fields-unchanged", False, "base registry unavailable",
            level="structural source check")

    # ---------------------------------------------------------------- metadata <-> consumer
    for cid, spec in TARGETS.items():
        entry = entries.get(cid, {})
        short = cid.replace("ga_", "")
        module = spec["module"]

        resolved = consumer_contract_module(spec["probe"])
        expected_module = spec["module_file"].rsplit("/", 1)[-1][: -len(".py")]
        rec(f"RM10-{short} consumer-resolves-through-contract",
            resolved == expected_module,
            f"the real consumer {spec['probe']}() resolves this control through {expected_module}, "
            "read from the evaluator's AST rather than assumed",
            level="structural source check", extra={"resolved_module": resolved})

        # the metadata must cite the schema id the contract module actually declares
        rec(f"RM11-{short} resolution-cites-real-schema",
            module.SCHEMA_VERSION in entry.get("resolution_condition", ""),
            f"the resolution condition cites the schema id the contract module declares "
            f"({module.SCHEMA_VERSION}) -- taken from the module, not from expected prose")
        rec(f"RM12-{short} description-cites-real-schema",
            module.SCHEMA_VERSION in entry.get("description", ""),
            "the description cites the same schema id, so a reader is pointed at the contract")

        # policy_reference must resolve to a committed file, and to the module the consumer uses
        ref = entry.get("policy_reference", "")
        referenced = [tok.strip().rstrip(";,") for tok in ref.split()
                      if tok.strip().rstrip(";,").endswith(".py")]
        existing = [p for p in referenced if (ROOT / p).is_file()]
        rec(f"RM13-{short} policy-reference-resolves",
            bool(referenced) and len(existing) == len(referenced)
            and spec["module_file"] in existing,
            "every file named by policy_reference exists in the repository, and the contract module "
            "the consumer actually uses is among them",
            level="structural source check",
            extra={"referenced": referenced, "missing": sorted(set(referenced) - set(existing))})

        # The removed delegation must not be described as SUFFICIENT any more. Naming it as
        # non-qualifying is the opposite of stale and is valuable to a reader, so the rule is
        # positional: the markers may never appear in the fields that state what RESOLVES the
        # control, and in the description only inside a sentence that marks them non-qualifying.
        blob = " ".join(str(entry.get(f, "")) for f in ALLOWED_FIELDS)
        resolving = f"{entry.get('resolution_condition', '')} {entry.get('policy_reference', '')}"
        in_resolving = [m for m in STALE_MARKERS[cid] if m in resolving]
        sentences = [s for s in str(entry.get("description", "")).replace("; ", ". ").split(". ")]
        unqualified = sorted({
            m for s in sentences for m in STALE_MARKERS[cid]
            if m in s and "non-qualifying" not in s.lower()
        })
        rec(f"RM14-{short} delegation-not-described-as-sufficient",
            not in_resolving and not unqualified,
            "the removed delegation (the readiness check name, a live probe, reachability) appears "
            "nowhere in the fields that state what resolves the control, and appears in the "
            "description only inside a sentence marking it NON-QUALIFYING",
            extra={"in_resolving_fields": in_resolving,
                   "in_unqualified_sentence": unqualified,
                   "blob_len": len(blob)})

        # substance: the resolution condition must require the bindings the validator enforces
        required_substance = ("commit", "tree", "clean-worktree", "canonical", "parity",
                              "secret scan", "domain")
        missing_substance = [t for t in required_substance
                             if t.lower() not in entry.get("resolution_condition", "").lower()]
        rec(f"RM15-{short} resolution-matches-validator",
            not missing_substance,
            "the resolution condition names each binding the real validator enforces: full "
            "commit/tree binding, clean worktree, canonical hash, production parity, proof domains "
            "and a clean secret scan",
            extra={"missing": missing_substance})

        # no claim that the evidence exists, and no parity overclaim
        found_claims = [p for p in EXISTENCE_CLAIM_PATTERNS
                        if re.search(p, blob, flags=re.IGNORECASE)]
        rec(f"RM16-{short} no-existence-claim", not found_claims,
            "no field asserts that production evidence currently exists or that the adapter is "
            "accepted",
            extra={"claims_found": found_claims})

        # the non-qualifying sources must be named, so the metadata cannot be read permissively
        non_qual = ("non-qualifying",)
        rec(f"RM17-{short} names-non-qualifying-sources",
            any(t in entry.get("description", "").lower() for t in non_qual),
            "the description explicitly marks the test-scoped sources as non-qualifying")

    # queue-specific: the metadata must not describe the present queue as durable/recoverable
    q_desc = entries.get("ga_redis_adapter", {}).get("description", "").lower()
    rec("RM18 queue-not-described-as-durable",
        "not durable or recoverable" in q_desc and "at-most-once" in q_desc,
        "the queue metadata states plainly that the current implementation is not durable or "
        "recoverable and that delivery is at-most-once")

    # ---------------------------------------------------------------- dispositions unchanged
    readiness = {"redis_queue": "pass", "postgres_repository": "pass",
                 "local_llm_runtime": "pass", "demo_seed_removed": "pass", "client_mode": "pass"}
    live = {c["id"]: c["disposition"] for c in GA.evaluate_blockers(dict(readiness),
                                                                    forge_report=None)}
    rec("RM20 targets-still-blocked",
        all(live.get(cid) == "BLOCKED" for cid in TARGETS),
        "with every readiness check passing -- which a disposable PostgreSQL and a Redis answering "
        "PING produce -- both adapter controls are still BLOCKED",
        level="evaluator integration",
        extra={cid: live.get(cid) for cid in TARGETS})
    rec("RM21 remediation-now-matches-metadata",
        all(next(c for c in GA.evaluate_blockers(dict(readiness), forge_report=None)
                 if c["id"] == cid)["remediation"] == entries[cid]["resolution_condition"]
            for cid in TARGETS),
        "the remediation the evaluator emits is exactly the corrected resolution condition, so an "
        "operator is no longer told to satisfy a condition that cannot resolve the control",
        level="evaluator integration")

    # ---------------------------------------------------------------- inventory binding
    rec("RM30 inventory-hash-unchanged",
        RC.canonical_hash() == ACCEPTED_INVENTORY_HASH,
        "the canonical readiness-context inventory hash is UNCHANGED. Determined empirically, not "
        "assumed: the canonical body carries control ids and expected dispositions, never registry "
        "prose or a registry digest, so metadata-only edits cannot move it and no rebind is warranted",
        level="structural source check", extra={"inventory_hash": RC.canonical_hash()})
    ids_in_inventory = set(RC.CONTROL_IDS)
    registry_ids = {b["id"] for b in registry["blockers"]}
    rec("RM31 inventory-ids-match-registry", ids_in_inventory == registry_ids,
        "the inventory's control ids still equal the registry's exactly",
        level="structural source check")

    passed_n = sum(1 for c in checks if c["ok"])
    failed_n = len(checks) - passed_n
    print(json.dumps({
        "guard": "audit:production-adapter-registry-metadata",
        "claim_scope": "production-adapter-registry-metadata-only",
        "registry_sha256": GA.registry_sha256(),
        "inventory_hash": RC.canonical_hash(),
        "summary": {"passed": passed_n, "failed": failed_n, "skipped": 0,
                    "certification": "passed" if failed_n == 0 else "not_passed"},
        "checks": checks,
        "control_dispositions_changed": False,
        "production_database_adapter_accepted": False,
        "production_queue_adapter_accepted": False,
        "production_parity": False,
        "docker_used": False,
        "database_execution_verdict": "PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED",
        "queue_execution_verdict": "PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED",
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed_n == 0 else 1


#: The accepted inventory hash. Pinned as a literal so this guard proves the value did not move,
#: rather than comparing the contract against itself.
ACCEPTED_INVENTORY_HASH = "b9d78ad9e8791375a03c1ef437c4c663043b087bf60f80ca72d69a0f41787d44"


if __name__ == "__main__":
    raise SystemExit(run())
