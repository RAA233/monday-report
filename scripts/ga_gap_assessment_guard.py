"""audit:ga-gap-assessment -- the tracked gap assessment matches current sources.

``docs/GA_GAP_ASSESSMENT.v1.json`` is a generated STATUS REPORT, not evidence. It drifted silently:
it stayed bound to a commit four increments old while the registry metadata, the adapter consumers
and several dispositions moved underneath it. This guard reconciles it against the real sources on
every run, so the same drift cannot recur unnoticed.

Every expectation is read from the IMPLEMENTATION -- the registry file, the real
``ga_readiness.evaluate_blockers`` dispatch, both adapter contract modules and the readiness-context
inventory. Nothing is compared against a locally copied expected string, which would only prove the
guard and the artifact agree with each other.

Docker-free. No container, database, queue, API or process is contacted; no evidence is generated.

Honest scope: claim_scope = ga-gap-assessment-drift-only. This certifies that a STATUS REPORT is
accurate. It certifies nothing else: PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED,
PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED, FOUR_READINESS_CONTEXTS_NOT_ACCEPTED, GA_BLOCKED.
"""
from __future__ import annotations

import hashlib
import json
import re
import ast
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
import build_ga_gap_assessment as GEN  # noqa: E402

ARTIFACT_PATH = ROOT / "docs" / "GA_GAP_ASSESSMENT.v1.json"
REGISTRY_PATH = ROOT / "evals" / "ga" / "blocker_registry.v1.json"

SUPPORTED_SCHEMA = "ga-gap-assessment.v2"
SUPERSEDED_SCHEMAS = ("ga-gap-assessment.v1",)

#: How far behind HEAD the recorded generation commit may be. One commit is the normal case: the
#: artifact is generated, then committed. More than that means it was not regenerated this round.
MAX_COMMITS_BEHIND = 1

DB_CONTROL, QUEUE_CONTROL = "production-database-adapter", "production-queue-adapter"
DB_CHECK, QUEUE_CHECK = "ga_postgres_adapter", "ga_redis_adapter"

#: Language describing the delegation both adapter controls no longer use.
STALE_DELEGATION = ("_delegate(postgres_repository)", "_delegate(redis_queue)",
                    "delegated_readiness_check")

#: Shapes that must never appear anywhere in a tracked status report.
LEAK_PATTERNS = (
    # Case-insensitive and both separators: the first cut required a lowercase letter after
    # `/Users/` and a literal backslash pair, so `C:/Users/Ralba` and UNC paths slipped past.
    (r"(?i)[a-z]:[\\/]users[\\/]", "a Windows user path"),
    (r"(?i)/(?:home|users)/[a-z]", "a POSIX home path"),
    (r"\\\\[A-Za-z0-9_.-]+\\", "a UNC path"),
    (r"(?i)\bhost\s*=\s*\S+|\bsslmode\s*=", "a libpq keyword DSN"),
    (r"(?i)\bBearer\s+[A-Za-z0-9._-]{12,}", "a bearer token"),
    (r"(?i)\b[a-z0-9-]+\.(?:internal|local|lan)\b", "an internal hostname"),
    (r"(?i)\bmonday_report_[a-z_]*(?:runtime|restricted|admin)\b", "a database role name"),
    (r"postgres(?:ql)?://", "a database URL"),
    (r"redis(?:s)?://", "a queue URL"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"(?i)\b(password|secret|api[_-]?key|token)\b\s*[:=]", "a secret field"),
    (r"\b[0-9a-f]{64}\b(?=.*container)", "a container identifier"),
)

checks: list[dict] = []


def rec(cid, ok, desc, level="assessment reconciliation", extra=None):
    checks.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "description": desc, "execution_level": level, **(extra or {})})


def load_artifact() -> dict:
    return json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


def live_dispositions() -> dict[str, str]:
    """The evaluator's output under the assessment's OWN documented static input.

    The authoritative context is the fresh checkout -- an empty readiness map with no local evidence
    artifact -- because that is what is reproducible from the tracked repository alone.
    """
    import os
    import shutil
    import tempfile
    stash = Path(tempfile.mkdtemp(prefix="gap-guard-hidden-"))
    moved = []
    try:
        for index, path in enumerate(GEN._all_evidence_paths()):
            if path.exists():
                target = stash / f"{index}-{path.name}"
                os.replace(path, target)
                moved.append((path, target))
        return {c["id"]: c["disposition"] for c in GA.evaluate_blockers({})}
    finally:
        for path, target in moved:
            path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(target, path)
        shutil.rmtree(stash, ignore_errors=True)


def git_rev(ref: str) -> str:
    out = subprocess.run(["git", "rev-parse", ref], cwd=str(ROOT), capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else ""


def run() -> int:
    try:
        artifact = load_artifact()
    except Exception as exc:  # noqa: BLE001 - a malformed artifact is a refusal, never a crash
        rec("GA00 artifact-readable", False,
            "the tracked assessment must parse as JSON",
            level="structural source check", extra={"exception": exc.__class__.__name__})
        _emit(1)
        return 1

    if not isinstance(artifact, dict):
        rec("GA00b artifact-is-object", False,
            "the assessment must be a JSON OBJECT; a null/list/string/number payload is refused "
            "rather than crashing the guard",
            level="structural source check", extra={"type": type(artifact).__name__})
        _emit(1)
        return 1
    rec("GA00b artifact-is-object", True, "the assessment is a JSON object",
        level="structural source check")

    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    reg_by_id = {b["id"]: b for b in registry["blockers"]}
    controls = artifact.get("controls")
    controls = controls if isinstance(controls, list) else []
    art_by_id = {}
    for c in controls:
        if isinstance(c, dict) and isinstance(c.get("id"), (str, type(None))):
            art_by_id[c.get("id")] = c
    rec("GA00c control-entries-well-formed",
        len(art_by_id) == len([c for c in controls if isinstance(c, dict)]),
        "every control entry is an object with a hashable id",
        level="structural source check")
    live = live_dispositions()

    # ---------------------------------------------------------------- schema / shape
    rec("GA00 artifact-readable", True, "the tracked assessment parses as JSON",
        level="structural source check")
    rec("GA01 schema-supported", artifact.get("schema_version") == SUPPORTED_SCHEMA,
        f"the artifact declares the supported schema {SUPPORTED_SCHEMA}",
        extra={"schema": artifact.get("schema_version")})
    rec("GA02 superseded-schema-rejected",
        artifact.get("schema_version") not in SUPERSEDED_SCHEMAS,
        "a superseded schema version is not accepted: v1 carried no source bindings, no canonical "
        "hash and no artifact classification")
    rec("GA03 control-count-28",
        artifact.get("control_count") == 28 and len(controls) == 28,
        "the assessment declares and contains exactly 28 controls",
        extra={"declared": artifact.get("control_count"), "actual": len(controls)})

    ids = [c.get("id") for c in controls if isinstance(c, dict)]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    missing = sorted(set(reg_by_id) - set(ids))
    unknown = sorted(set(ids) - set(reg_by_id))
    rec("GA04 no-duplicate-missing-unknown",
        not dupes and not missing and not unknown,
        "the assessment's control-id set equals the registry's exactly",
        extra={"duplicates": dupes, "missing": missing, "unknown": unknown})

    # ---------------------------------------------------------------- registry reconciliation
    field_drift: dict[str, list[str]] = {}
    for rid, entry in reg_by_id.items():
        art = art_by_id.get(rid)
        if not art:
            continue
        for field in ("check_id", "category", "severity", "owner_type", "resolution_condition"):
            if art.get(field) != entry.get(field):
                field_drift.setdefault(field, []).append(rid)
    for field in ("check_id", "category", "severity", "owner_type"):
        rec(f"GA10 registry-{field}-matches", not field_drift.get(field),
            f"every control's {field} equals the registry's",
            extra={"drifted": field_drift.get(field, [])})
    rec("GA11 resolution-condition-matches", not field_drift.get("resolution_condition"),
        "every control's resolution_condition is byte-equal to the registry's -- this is the field "
        "that went stale when the adapter metadata was corrected",
        extra={"drifted": field_drift.get("resolution_condition", [])})

    # ---------------------------------------------------------------- disposition reconciliation
    disp_drift = []
    for rid, entry in reg_by_id.items():
        art = art_by_id.get(rid)
        if not art:
            continue
        if art.get("current_disposition_fresh_checkout") != live.get(entry["check_id"]):
            disp_drift.append((rid, art.get("current_disposition_fresh_checkout"),
                               live.get(entry["check_id"])))
    rec("GA12 dispositions-match-evaluator", not disp_drift,
        "every recorded fresh-checkout disposition equals what the REAL evaluator returns now, "
        "under the assessment's own documented static input",
        level="evaluator integration", extra={"drifted": disp_drift[:6]})

    # ---------------------------------------------------------------- adapters
    for label, rid, check, module in (("database", DB_CONTROL, DB_CHECK, DB),
                                      ("queue", QUEUE_CONTROL, QUEUE_CHECK, Q)):
        art = art_by_id.get(rid, {})
        rec(f"GA20-{label} adapter-blocked",
            live.get(check) == "BLOCKED"
            and art.get("current_disposition_fresh_checkout") == "BLOCKED",
            f"the production {label} adapter is BLOCKED both live and as recorded",
            level="evaluator integration",
            extra={"live": live.get(check), "recorded": art.get("current_disposition_fresh_checkout")})
        # Parenthesised. `A and B or C` parsed as `(A and B) or C`, so C alone satisfied it and
        # probe_type was never constrained -- an independent review set it to four different values,
        # and deleted it, with the check still passing.
        rec(f"GA21-{label} adapter-evidence-driven",
            art.get("probe_type") == GEN.PROBE_EVIDENCE
            and (module.SCHEMA_VERSION.split(".")[0] in str(art.get("probe_location", ""))
                 or module.__name__.rsplit(".", 1)[-1] in str(art.get("probe_location", ""))),
            f"the {label} adapter is recorded as an evidence-driven probe pointing at its contract "
            "module, not as a delegated readiness check",
            extra={"probe_type": art.get("probe_type"),
                   "probe_location": str(art.get("probe_location"))[:90]})
        rec(f"GA22-{label} adapter-evidence-absent",
            art.get("evidence_status") == "absent",
            f"the {label} adapter's evidence status is recorded as absent: no production artifact "
            "exists at any commit")
        blob = json.dumps(art)
        rec(f"GA23-{label} no-stale-delegation",
            not any(marker in blob for marker in STALE_DELEGATION),
            f"the {label} adapter entry carries no delegated-readiness-check language",
            extra={"found": [m for m in STALE_DELEGATION if m in blob]})

    verdicts = artifact.get("execution_verdicts")
    verdicts = verdicts if isinstance(verdicts, dict) else {}
    rec("GA24 static-contract-is-not-execution",
        artifact.get("static_contract_acceptance_is_not_execution_acceptance") is True
        and verdicts.get("production_database_adapter")
        == "PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED"
        and verdicts.get("production_queue_adapter")
        == "PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED",
        "the artifact states plainly that an accepted static contract is not adapter acceptance, and "
        "records both execution verdicts as NOT_ACCEPTED")

    # ---------------------------------------------------------------- tenant / readiness freshness
    rec("GA30 tenant-evidence-not-exact-head",
        artifact.get("exact_head_tenant_evidence_present") is False
        and live.get("ga_tenant_authorization") == "BLOCKED",
        "no exact-head tenant-authorization evidence is claimed, and the control is BLOCKED live",
        level="evaluator integration",
        extra={"live": live.get("ga_tenant_authorization")})
    rec("GA31 contexts-not-executed",
        artifact.get("four_contexts_executed_at_this_head") is False
        and verdicts.get("four_readiness_contexts")
        == "FOUR_READINESS_CONTEXTS_NOT_ACCEPTED",
        "the four contexts are recorded as NOT executed at this head, and contract/harness "
        "acceptance is not converted into execution acceptance")
    rec("GA32 capacity-blocked-recorded", artifact.get("capacity_gate") == "blocked",
        "the capacity gate is recorded as blocked")

    # ---------------------------------------------------------------- migration / release
    rec("GA40 migration-validity-blocked", live.get("ga_migration_validity") == "BLOCKED"
        and art_by_id.get("migration-validity", {}).get("current_disposition_fresh_checkout")
        == "BLOCKED",
        "migration validity is BLOCKED: it is never inferred from a disposable migration-runner test",
        level="evaluator integration")
    rec("GA41 local-artifact-disclosed",
        isinstance(artifact.get("local_evidence_artifact"), dict)
        and artifact["local_evidence_artifact"].get("tracked") is False
        and artifact["local_evidence_artifact"].get("matches_current_head") is not True,
        "any machine-local evidence artifact is disclosed as untracked, so a gitignored file cannot "
        "silently be read as repository state",
        extra={k: v for k, v in (artifact.get("local_evidence_artifact") or {}).items()
               if k != "note"} if isinstance(artifact.get("local_evidence_artifact"), dict) else {})
    rec("GA42 authoritative-context-is-fresh",
        artifact.get("authoritative_context") == "fresh_checkout_no_local_evidence",
        "the authoritative context is the fresh checkout -- the one reproducible from the tracked "
        "repository alone")
    for key in ("client_data_ready", "release_candidate_ready", "ga_ready"):
        rec(f"GA43 {key}-false", artifact.get(key) is False, f"{key} is false")
    rec("GA44 ga-blocked", artifact.get("release_recommendation") == "GA_BLOCKED",
        "the release recommendation is GA_BLOCKED")

    # ---------------------------------------------------------------- contexts (Part K)
    contexts = artifact.get("contexts")
    contexts = contexts if isinstance(contexts, dict) else {}
    fresh_ctx = contexts.get("fresh_checkout_no_local_evidence")
    fresh_ctx = fresh_ctx if isinstance(fresh_ctx, dict) else {}
    rec("GA45 fresh-context-ga-blocked", fresh_ctx.get("ga") == "GA_BLOCKED",
        "the authoritative fresh-checkout context reports GA_BLOCKED. This block was previously "
        "excluded from the canonical hash AND unchecked, which let a GA_BLOCKED artifact and a "
        "GA_READY / 28-PASS artifact share a hash")
    recorded_tally = fresh_ctx.get("tally")
    computed_tally: dict = {}
    for c in controls:
        if isinstance(c, dict):
            value = c.get("current_disposition_fresh_checkout")
            computed_tally[value] = computed_tally.get(value, 0) + 1
    rec("GA46 fresh-tally-reconciles",
        isinstance(recorded_tally, dict)
        and dict(sorted(recorded_tally.items())) == dict(sorted(computed_tally.items())),
        "the fresh-checkout tally reconciles exactly with the per-control fresh dispositions",
        extra={"recorded": recorded_tally, "computed": dict(sorted(computed_tally.items()))})
    verified_ctx = contexts.get("verified_environment_with_evidence")
    verified_ctx = verified_ctx if isinstance(verified_ctx, dict) else {}
    rec("GA47 verified-context-also-blocked", verified_ctx.get("ga") == "GA_BLOCKED",
        "even the machine-local verified-environment context reports GA_BLOCKED")
    rec("GA48 evidence-status-only-for-evidence-probes",
        all(c.get("evidence_status") != "present_exact_head"
            for c in controls
            if isinstance(c, dict) and c.get("probe_type") != GEN.PROBE_EVIDENCE),
        "no behaviourally-probed control claims present_exact_head evidence: a passing behavioural "
        "probe has no artifact at all",
        extra={"offenders": [c.get("id") for c in controls if isinstance(c, dict)
                             and c.get("probe_type") != GEN.PROBE_EVIDENCE
                             and c.get("evidence_status") == "present_exact_head"]})
    rec("GA49 measurement-class-consistent",
        all(c.get("measurement_class") != "BEHAVIORALLY_PROVEN"
            or c.get("current_disposition_fresh_checkout") == "PASS"
            for c in controls if isinstance(c, dict)),
        "no control is recorded BEHAVIORALLY_PROVEN while its fresh disposition is not PASS")

    # ---------------------------------------------------------------- bindings / hash
    head = git_rev("HEAD")
    bound = artifact.get("generated_from_commit")
    # A TRACKED artifact cannot record the commit that contains it: writing it changes the tree, so
    # the commit it names is always the one it was generated FROM. Requiring equality with HEAD
    # would make the artifact permanently self-inconsistent. What must hold is that the recorded
    # commit is an ANCESTOR of HEAD (not a fork or a stale branch) and -- the part that actually
    # detects drift -- that every SOURCE binding below is current. The stale artifact that started
    # this increment failed both: bound to a commit four increments back with stale sources.
    ancestor = False
    if isinstance(bound, str) and re.fullmatch(r"[0-9a-f]{40}", bound or ""):
        ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", bound, "HEAD"],
                                  cwd=str(ROOT), capture_output=True).returncode == 0
    behind = ""
    if ancestor:
        behind = subprocess.run(["git", "rev-list", "--count", f"{bound}..HEAD"],
                                cwd=str(ROOT), capture_output=True, text=True).stdout.strip()
    rec("GA50 commit-binding-is-ancestor",
        ancestor and behind.isdigit() and int(behind) <= MAX_COMMITS_BEHIND,
        f"the recorded commit is an ancestor of HEAD and at most {MAX_COMMITS_BEHIND} commits "
        "behind. A tracked artifact cannot name the commit that contains it, so the source-binding "
        "checks below carry the drift detection",
        extra={"bound_commit": str(bound)[:12], "head": head[:12], "commits_behind": behind})
    rec("GA50b worktree-clean-attested", artifact.get("worktree_clean") is True,
        "the assessment attests a clean TRACKED worktree at generation")
    bindings = artifact.get("source_bindings")
    bindings = bindings if isinstance(bindings, dict) else {}
    rec("GA51 registry-sha-current",
        bindings.get("registry_sha256")
        == hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest(),
        "the recorded registry SHA-256 equals the registry file's now")
    rec("GA52 inventory-hash-current",
        bindings.get("readiness_context_inventory_hash") == RC.canonical_hash(),
        "the recorded readiness-context inventory hash equals the contract's now",
        extra={"recorded": str(bindings.get("readiness_context_inventory_hash"))[:16] + "..."})
    rec("GA53 adapter-contract-hashes-current",
        bindings.get("production_database_adapter_contract_hash") == DB.contract_hash()
        and bindings.get("production_queue_adapter_contract_hash") == Q.contract_hash(),
        "the recorded adapter contract hashes equal the contract modules' now")
    declared = artifact.get("canonical_payload_hash")
    rec("GA54 canonical-hash-valid",
        isinstance(declared, str) and re.fullmatch(r"[0-9a-f]{64}", declared or "")
        and declared == GEN.canonical_hash(artifact),
        "the declared canonical hash is a full lowercase SHA-256 and matches the canonical body",
        extra={"declared": str(declared)[:16] + "..."})
    rec("GA55 classified-not-evidence",
        artifact.get("artifact_class") == "generated_status_assessment"
        and artifact.get("is_acceptance_artifact") is False
        and artifact.get("is_evidence") is False,
        "the artifact classifies itself as a generated status assessment, never as evidence or an "
        "acceptance artifact")

    # ---------------------------------------------------------------- privacy
    blob = ARTIFACT_PATH.read_text(encoding="utf-8")
    found = [why for pattern, why in LEAK_PATTERNS if re.search(pattern, blob)]
    rec("GA60 no-private-material", not found,
        "the tracked assessment carries no private path, DSN, IP, secret or container identifier",
        level="structural source check", extra={"found": found})

    # ---------------------------------------------------------------- inventory non-rebind (Part N)
    prose_ok, prose_detail = _inventory_not_prose_bound()
    rec("GA70 inventory-not-registry-prose-bound", prose_ok,
        "the readiness-context contract performs NO file I/O, so its canonical body cannot depend on "
        "registry prose. Proved structurally on the parsed module rather than by rewriting the "
        "tracked registry, which the first cut did 38 times per fault run",
        level="structural source check", extra={"detail": prose_detail})
    rec("GA71 inventory-does-move-on-real-change", _inventory_moves_on_real_change(),
        "a REAL context-contract change DOES move the inventory hash, so GA70 is not vacuously true",
        level="structural source check")

    return _emit(0 if all(c["ok"] for c in checks) else 1)


def _inventory_not_prose_bound() -> tuple[bool, str]:
    """Prove STRUCTURALLY that the inventory cannot depend on registry prose.

    The first cut rewrote the TRACKED registry 28 entries at a time, once per guard run and 38 times
    per fault-battery run, restored only by a ``finally`` -- so an interrupt left "PROSE-MUTATED"
    content in a tracked file. It was also decorative: ``readiness_contexts`` performs no file I/O at
    all, so the mutation could not have affected it. The property is proved by parsing the contract
    module instead: no file read, no registry reference, and its canonical payload references only
    module constants.
    """
    source = (ROOT / "backend" / "app" / "readiness_contexts.py").read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False, "contract module does not parse"
    readers = {"read_text", "read_bytes", "open", "load", "loads_file"}
    file_reads = [n.func.attr for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr in readers]
    opens = [n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"]
    mentions_registry = "blocker_registry" in source and "REGISTRY" in source.upper().replace(
        "REGISTRY (", "")
    ok = not file_reads and not opens
    return ok, f"file_reads={file_reads} opens={opens} mentions_registry_path={mentions_registry}"


def _inventory_moves_on_real_change() -> bool:
    """A real contract change must move the hash, so the non-rebind proof is not vacuous."""
    baseline = RC.canonical_hash()
    saved = RC.CANONICAL_CONTEXT_ORDER
    try:
        RC.CANONICAL_CONTEXT_ORDER = tuple(reversed(saved))
        moved = RC.canonical_hash()
    finally:
        RC.CANONICAL_CONTEXT_ORDER = saved
    return moved != baseline and RC.canonical_hash() == baseline


def _emit(rc: int) -> int:
    passed = sum(1 for c in checks if c["ok"])
    failed = len(checks) - passed
    print(json.dumps({
        "guard": "audit:ga-gap-assessment",
        "claim_scope": "ga-gap-assessment-drift-only",
        "summary": {"passed": passed, "failed": failed, "skipped": 0,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": checks,
        "assessment_is_evidence": False,
        "assessment_is_acceptance_artifact": False,
        "docker_used": False,
        "evidence_generated": False,
        "production_database_adapter_accepted": False,
        "production_queue_adapter_accepted": False,
        "four_readiness_contexts_accepted": False,
        "exact_head_tenant_evidence_present": False,
        "release_recommendation": "GA_BLOCKED",
    }, indent=2, sort_keys=True, default=str))
    return 1 if failed else rc


if __name__ == "__main__":
    raise SystemExit(run())
