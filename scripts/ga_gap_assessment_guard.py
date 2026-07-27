"""audit:ga-gap-assessment -- the tracked gap assessment matches current sources.

``docs/GA_GAP_ASSESSMENT.v2.json`` is a generated STATUS REPORT, not evidence. It drifted silently:
it stayed bound to a commit four increments old while the registry metadata, the adapter consumers
and several dispositions moved underneath it. This guard reconciles it against the real sources on
every run, so the same drift cannot recur unnoticed.

Expectations that CAN be derived are derived -- the control inventory from the registry file, the
dispositions from the real ``ga_readiness.evaluate_blockers`` dispatch, the contract hashes from the
adapter modules, the inventory hash from the readiness-context contract. A handful of invariants are
necessarily literal (the control count, the three ``*_NOT_ACCEPTED`` verdicts, the artifact
classification); those are policy this guard exists to assert, not expectations copied from the thing
under test.

Docker-free. No container, database, queue, API or process is contacted; no evidence is generated.

Honest scope: claim_scope = ga-gap-assessment-drift-only. This certifies that a STATUS REPORT is
accurate. It certifies nothing else: PRODUCTION_DATABASE_ADAPTER_NOT_ACCEPTED,
PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED, FOUR_READINESS_CONTEXTS_NOT_ACCEPTED, GA_BLOCKED.
"""
from __future__ import annotations

import hashlib
import json
import os
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
import ga_gap_assessment_coupling as COUPLING  # noqa: E402

# Identity comes from ONE authority -- the generator module -- so the artifact path and schema
# cannot drift apart by editing a duplicated literal here.
ARTIFACT_PATH = GEN.OUTPUT_PATH
LEGACY_ARTIFACT_PATH = GEN.LEGACY_ARTIFACT_PATH
REGISTRY_PATH = GEN.REGISTRY_PATH

SUPPORTED_SCHEMA = GEN.SCHEMA_VERSION
SUPERSEDED_SCHEMAS = GEN.SUPERSEDED_SCHEMA_VERSIONS

#: How far behind HEAD the recorded generation commit may be. One commit is the normal case: the
#: artifact is generated, then committed. More than that means it was not regenerated this round.
MAX_COMMITS_BEHIND = 1

#: Fields deliberately excluded from the canonical hash because they are MACHINE-LOCAL. Every one of
#: them is either recomputed, reconciled or closed to a known shape below -- NOT all three, and the
#: comment previously overstated it: the verified dispositions are BOUNDED (GA47f), not recomputed.
#: Reconciling such a field only against
#: another equally forgeable field is not enough: an independent review set all 28 verified
#: dispositions to PASS, set the tally to {"PASS": 28} to match, and the forgery still collided
#: byte-for-byte with the honest canonical hash.
_LIVE_PAYLOAD: dict = {}


def live_payload() -> dict:
    """Regenerate the payload once per process and cache it.

    Cached because the fault battery re-enters ``run()`` ~50 times in-process and each rebuild runs
    the real evaluator twice while relocating local evidence artifacts. The rebuild is a function of
    the CODE and the registry, never of the artifact under test, so a per-process cache cannot
    launder a mutated artifact past these checks.
    """
    if not _LIVE_PAYLOAD:
        payload = GEN.build()
        payload["canonical_payload_hash"] = GEN.canonical_hash(payload)
        _LIVE_PAYLOAD.update(payload)
    return _LIVE_PAYLOAD


#: Prose that asserts a control is satisfied, executed, or signed off. A control the real evaluator
#: reports as not-PASS may not carry any of these. An independent review edited the generator's
#: curated block to claim an EXECUTED backup/restore drill with approved RPO/RTO beside a
#: blocking_reason saying no such drill exists, regenerated, and both guards certified green.
#: What this run actually validated, recorded where the artifact IS in scope and read by _emit().
VALIDATED_IDENTITY: dict = {}

#: Filenames of every evidence artifact the EVALUATOR consults, derived from the evaluator module
#: rather than listed here, so a newly added evidence path cannot be silently omitted.
KNOWN_EVIDENCE_FILENAMES = frozenset(p.name for p in GEN._all_evidence_paths())

#: control id -> the evidence artifact filenames that control's OWN probe reads, derived from the
#: evaluator's AST. Empty for a control whose gating artifact cannot be proved, which forbids any
#: machine-local promotion of it rather than permitting one on an unrelated artifact's authority.
EVIDENCE_GRAPH = COUPLING.evaluator_graph(
    (ROOT / "backend" / "app" / "ga_readiness.py").read_text(encoding="utf-8"))
EVIDENCE_SCOPE = {cid: set(spec["artifacts"]) for cid, spec in EVIDENCE_GRAPH.items()}

#: Meaning the curated-prose disclosure MUST carry, pinned in the consumer rather than compared
#: against the generator constant it is supposed to police (see GA04k).
DISCLOSURE_REQUIRED_TERMS = (
    "author-supplied", "no guard can verify", "current_disposition_fresh_checkout",
    "blocking_reason", "govern",
)

#: Claims the disclosure may never make about itself.
DISCLOSURE_FORBIDDEN_TERMS = (
    "independently verified", "has been verified", "reconciled with the live evaluator",
    "reviewed engineering position", "commentary reflects", "may rely", "can be relied",
    "re-checked", "rechecked", "senior engineer", "more accurate", "fuller and more",
    "reviewed by", "signed off", "audited", "corroborated", "governs the assessment",
)

#: Scanned in ``implemented_capability`` and ``notes`` -- fields that describe what EXISTS.
COMPLETION_CLAIMS = (
    "was executed", "were executed", "has been executed", "drill was", "signed off",
    "operationally satisfied", "verified in production", "accepted at this head",
    "no longer blocking", "fully satisfied", "requirement is met",
)

#: Scanned in ``missing_capability`` only. That field legitimately NAMES absent things -- the real
#: backup-restore entry reads "an evidenced restore drill, and organizationally approved RPO/RTO",
#: which a naive completion-phrase scan flagged. What it may never do is assert nothing is missing.
NOTHING_MISSING_CLAIMS = (
    "nothing.", "nothing is missing", "none. this control", "operationally satisfied",
    "fully satisfied", "no longer blocking",
)

#: Reciprocal cross-file pin of the FAULTS battery's declared check set (see GA80).
PINNED_FAULTS_ID_SET_HASH = "c625020c306bcc3c0bf62c94368a46705794fc0d6ea3b78832b7e083d022f8d1"
PINNED_FAULTS_CHECK_COUNT = 97

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
    (r"[\\]{2}[A-Za-z0-9_.-]+[\\]", "a UNC path"),
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
        # Hermetic, exactly as the generator's fresh snapshot now is. Without this the two halves
        # of the guard disagreed: with the project's own documented MONDAY_REPORT_AUDIT_HMAC_KEY
        # exported, GA12 failed on an HONEST artifact while GA56 -- which regenerates
        # hermetically -- passed.
        _saved_env = {k: os.environ.pop(k) for k in
                      [k for k in os.environ if k.startswith("MONDAY_REPORT_")]}
        try:
            return {c["id"]: c["disposition"] for c in GA.evaluate_blockers({})}
        finally:
            os.environ.update(_saved_env)
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

    try:
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        rec("GA04q registry-readable", False,
            "the registry file must exist and parse as JSON; an unreadable inventory authority is "
            "refused with a structured result, never a crash",
            level="structural source check", extra={"exception": exc.__class__.__name__})
        _emit(1)
        return 1
    rec("GA04q registry-readable", True, "the registry file parses as JSON",
        level="structural source check")
    # Shape-validate BEFORE indexing. The registry is the declared inventory authority, but a
    # corrupt one killed the guard here with an uncaught TypeError and zero structured output.
    _blockers = registry.get("blockers") if isinstance(registry, dict) else None
    if not isinstance(_blockers, list) or not all(
            isinstance(b, dict) and "id" in b and "check_id" in b for b in _blockers):
        rec("GA04r registry-well-formed", False,
            "the registry must be an object with a LIST of blocker objects each carrying id and "
            "check_id; a malformed registry is refused with a structured result, never a crash",
            level="structural source check",
            extra={"blockers_type": type(_blockers).__name__})
        _emit(1)
        return 1
    rec("GA04r registry-well-formed", True,
        "the registry parses and every blocker carries an id and a check_id",
        level="structural source check", extra={"blockers": len(_blockers)})
    reg_by_id = {b["id"]: b for b in _blockers}
    controls = artifact.get("controls")
    controls = controls if isinstance(controls, list) else []
    art_by_id = {}
    for c in controls:
        if isinstance(c, dict) and isinstance(c.get("id"), (str, type(None))):
            art_by_id[c.get("id")] = c
    # Every control entry must be an object BEFORE any later check indexes into it. A review fed a
    # str/int control, a dict `controls`, and a str `controls`, and the guard died with an
    # AttributeError and ZERO stdout -- no JSON, no named failure. A malformed artifact is a
    # refusal, never a crash.
    if not isinstance(artifact.get("controls"), list) or not all(
            isinstance(c, dict) for c in artifact.get("controls") or []):
        rec("GA00c control-entries-well-formed", False,
            "controls must be a LIST of OBJECTS; any other shape is refused with a structured "
            "result rather than an uncaught exception",
            level="structural source check",
            extra={"controls_type": type(artifact.get("controls")).__name__,
                   "bad_entries": sum(1 for c in (artifact.get("controls") or [])
                                      if not isinstance(c, dict))
                   if isinstance(artifact.get("controls"), list) else None})
        _emit(1)
        return 1

    rec("GA00c control-entries-well-formed",
        len(art_by_id) == len([c for c in controls if isinstance(c, dict)]),
        "every control entry is an object with a hashable id",
        level="structural source check")
    live = live_dispositions()

    # ---------------------------------------------------------------- schema / shape
    VALIDATED_IDENTITY.update({"schema_version": artifact.get("schema_version"),
                               "path": GEN.OUTPUT_PATH.name})
    rec("GA00 artifact-readable", True, "the tracked assessment parses as JSON",
        level="structural source check")
    # The CANONICAL path constant, not ARTIFACT_PATH: the fault battery redirects the latter to a
    # temp file, and the claim is about the repository's canonical identity.
    rec("GA00d filename-matches-schema",
        GEN.OUTPUT_PATH.name.endswith(".v2.json") and SUPPORTED_SCHEMA.endswith(".v2"),
        "the artifact FILENAME and the declared schema agree on the version -- a v1 filename holding "
        "a v2 schema is the ambiguity this increment removes",
        level="structural source check",
        extra={"canonical_filename": GEN.OUTPUT_PATH.name, "schema": SUPPORTED_SCHEMA})
    # The path is pinned HERE as well. GA00d is defended by a guard-side policy literal; GA00e was
    # not, so aiming the generator's LEGACY constant at a decoy that can never exist let a real
    # docs/GA_GAP_ASSESSMENT.v1.json sit beside the v2 one with both guards green -- and MV02/MV04
    # simultaneously reporting that the disabled check was discriminating.
    rec("GA00e2 legacy-path-is-the-v1-artifact",
        LEGACY_ARTIFACT_PATH.name == "GA_GAP_ASSESSMENT.v1.json"
        and LEGACY_ARTIFACT_PATH.parent == GEN.OUTPUT_PATH.parent,
        "the legacy path the absence check consults is the real v1 artifact beside the current one, "
        "not an author-chosen decoy",
        extra={"legacy": LEGACY_ARTIFACT_PATH.name, "canonical": GEN.OUTPUT_PATH.name})
    rec("GA00e legacy-artifact-absent", not LEGACY_ARTIFACT_PATH.exists(),
        "the legacy v1 artifact does not exist: two files either of which could be read as current "
        "is not an acceptable state",
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

    # The REGISTRY is the expected inventory. Nothing here maintains a second list of the 28, and no
    # editable constant defines the expected set -- a pin that can be edited alongside the artifact
    # it protects is not an authority.
    try:
        expected_inventory = GEN.registry_inventory()
    except Exception as exc:  # noqa: BLE001
        # The registry is the declared inventory authority; a corrupt one previously killed the
        # guard with an uncaught KeyError/TypeError/JSONDecodeError and ZERO stdout.
        rec("GA04s registry-loadable", False,
            "the registry must parse and expose blockers with ids and check_ids; a malformed "
            "registry is refused with a structured result, never a crash",
            level="structural source check", extra={"exception": exc.__class__.__name__})
        _emit(1)
        return 1
    rec("GA04s registry-loadable", True,
        "the registry parses and exposes its blocker inventory",
        level="structural source check", extra={"controls": len(expected_inventory)})
    # str() coercion: a list/dict `id` is unhashable and crashed set() with no JSON report emitted.
    ids = [c.get("id") if isinstance(c.get("id"), str) else repr(c.get("id"))
           for c in controls if isinstance(c, dict)]
    check_ids = [c.get("check_id") if isinstance(c.get("check_id"), str) else repr(c.get("check_id"))
                 for c in controls if isinstance(c, dict)]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    dupe_checks = sorted({i for i in check_ids if check_ids.count(i) > 1})
    missing = sorted(set(expected_inventory) - set(ids))
    unknown = sorted(set(ids) - set(expected_inventory))
    rec("GA04 no-duplicate-missing-unknown",
        not dupes and not dupe_checks and not missing and not unknown,
        "the assessment's control-id set equals the REGISTRY'S exactly, with no duplicate control id "
        "and no duplicate check id",
        extra={"duplicates": dupes, "duplicate_check_ids": dupe_checks,
               "missing": missing, "unknown": unknown})
    mapping_drift = sorted(
        rid for rid, expected_check in expected_inventory.items()
        if isinstance(art_by_id.get(rid), dict)
        and art_by_id[rid].get("check_id") != expected_check)
    rec("GA04b check-id-mapping-matches-registry", not mapping_drift,
        "every control's registry-id -> check-id mapping equals the registry's",
        extra={"drifted": mapping_drift})
    rec("GA04c count-derived-from-registry",
        len(expected_inventory) == 28 and len(controls) == len(expected_inventory),
        "the artifact's control count equals the REGISTRY's, and the registry itself still declares "
        "28 -- the second half is a deliberate policy literal, not a derived expectation",
        extra={"registry": len(expected_inventory), "artifact": len(controls)})
    rec("GA04e curated-assessment-covers-every-control",
        GEN.assessment_keys() == set(expected_inventory.values()),
        "the generator's curated _ASSESSMENT block covers exactly the registry's check ids: dropping "
        "a control from it blanks that control's whole assessment, which was previously undetected",
        extra={"missing_from_curated": sorted(set(expected_inventory.values())
                                              - GEN.assessment_keys()),
               "extra_in_curated": sorted(GEN.assessment_keys()
                                          - set(expected_inventory.values()))})
    legend = artifact.get("measurement_class_legend")
    rec("GA04f measurement-classes-known",
        isinstance(legend, dict)
        and all(isinstance(c.get("measurement_class"), str)
                and c.get("measurement_class") in legend
                for c in controls if isinstance(c, dict)),
        "every control declares a measurement_class drawn from the artifact's own legend")
    rec("GA04h measurement-legend-is-not-self-defined",
        isinstance(legend, dict)
        and set(legend) == {GEN.BEHAVIOURALLY_PROVEN, GEN.BEHAVIOURALLY_FAILED,
                            GEN.IMPLEMENTED_BUT_UNMEASURED, GEN.ABSENT, GEN.NOT_EVALUABLE,
                            GEN.EXTERNAL},
        "the legend's class set equals the generator's module constants exactly. Validating classes "
        "against a legend the artifact itself supplies let a review invent PRODUCTION_VERIFIED, "
        "apply it to all 28 controls, and certify green",
        extra={"unexpected": sorted(set(legend) - {GEN.BEHAVIOURALLY_PROVEN,
                                                   GEN.BEHAVIOURALLY_FAILED,
                                                   GEN.IMPLEMENTED_BUT_UNMEASURED, GEN.ABSENT,
                                                   GEN.NOT_EVALUABLE, GEN.EXTERNAL})
               if isinstance(legend, dict) else None})
    static_block = artifact.get("static_contracts_accepted")
    verdict_subjects = set(artifact.get("execution_verdicts") or {})
    static_keys = set(static_block) if isinstance(static_block, dict) else set()
    # "Contract-only" is a NAMING rule plus a cross-reconciliation, not a substring ban: the
    # readiness-context EXECUTION HARNESS is itself an accepted static contract, so banning the
    # word "execution" was simply wrong. What must never appear is an acceptance keyed on a
    # CAPABILITY -- especially one this same artifact declares NOT_ACCEPTED at execution level.
    bad_shape = sorted(k for k in static_keys
                       if not (str(k).endswith("_contract") or str(k).endswith("_harness")))
    collides = sorted(static_keys & verdict_subjects)
    rec("GA04g static-contracts-block-is-contract-only",
        isinstance(static_block, dict) and bool(static_block)
        and all(v is True for v in static_block.values())
        and not bad_shape and not collides and bool(verdict_subjects),
        "every static-contract key names a CONTRACT or a HARNESS and none names a capability the "
        "artifact's own execution_verdicts declare NOT_ACCEPTED -- otherwise this unvalidated field "
        "becomes a back door for an execution-acceptance claim",
        extra={"keys": sorted(str(k) for k in static_keys), "bad_shape": bad_shape,
               "collides_with_execution_subject": collides})

    rec("GA04d artifact-cannot-supply-expected-inventory",
        not any(k in artifact for k in ("expected_controls", "expected_control_ids",
                                        "control_inventory", "expected_inventory")),
        "the artifact does not carry its own expected inventory: an artifact that declares what it "
        "should contain proves nothing",
        extra={"offending_keys": [k for k in ("expected_controls", "expected_control_ids",
                                              "control_inventory", "expected_inventory")
                                  if k in artifact]})

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

    rec("GA24b execution-verdict-subjects-closed",
        set(verdicts) == {"production_database_adapter", "production_queue_adapter",
                          "four_readiness_contexts"},
        "execution_verdicts carries EXACTLY the three known subjects. The previous check pinned the "
        "three values but ignored extra keys, so injecting ga=GA_ACCEPTED or "
        "client_data_readiness=..._ACCEPTED certified green in the artifact's most load-bearing field",
        extra={"unexpected": sorted(set(verdicts) - {"production_database_adapter",
                                                     "production_queue_adapter",
                                                     "four_readiness_contexts"})})

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
        and isinstance(artifact["local_evidence_artifact"].get("matches_current_head"), bool),
        "any machine-local evidence artifact is disclosed as untracked, so a gitignored file cannot "
        "silently be read as repository state. The head-binding is DISCLOSED, not constrained: the "
        "predicate previously demanded `matches_current_head is not True`, which rejected a CURRENT "
        "exact-head artifact and accepted a STALE one -- the exact inverse of the intent, and it "
        "made the one state in which a control is legitimately promotable unrepresentable. Whether "
        "the note agrees with that binding is GA47j's job",
        extra={k: v for k, v in (artifact.get("local_evidence_artifact") or {}).items()
               if k != "note"} if isinstance(artifact.get("local_evidence_artifact"), dict) else {})
    rec("GA42 authoritative-context-is-fresh",
        artifact.get("authoritative_context") == "fresh_checkout_no_local_evidence",
        "the authoritative context is the fresh checkout -- the one reproducible from the tracked "
        "repository alone")
    # Named individually AND asserted together. A review dropped the ga_ready arm from a loop
    # tuple -- a one-word edit that removed a gate without removing a check id -- and then certified
    # an artifact declaring ga_ready: true. Deleting a named check now also has to defeat GA43d.
    rec("GA43a client_data_ready-false", artifact.get("client_data_ready") is False,
        "client_data_ready is false")
    rec("GA43b release_candidate_ready-false", artifact.get("release_candidate_ready") is False,
        "release_candidate_ready is false")
    rec("GA43c ga_ready-false", artifact.get("ga_ready") is False, "ga_ready is false")
    rec("GA43d all-readiness-flags-false",
        [artifact.get("client_data_ready"), artifact.get("release_candidate_ready"),
         artifact.get("ga_ready")] == [False, False, False],
        "all three readiness flags are false, asserted together so that deleting any single named "
        "flag check above does not silently remove the gate")
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
    verified_tally: dict = {}
    for c in controls:
        if isinstance(c, dict):
            v = c.get("current_disposition_verified_environment")
            verified_tally[v] = verified_tally.get(v, 0) + 1
    recorded_verified = verified_ctx.get("tally")
    rec("GA47b verified-tally-reconciles",
        isinstance(recorded_verified, dict)
        and dict(sorted(recorded_verified.items())) == dict(sorted(verified_tally.items())),
        "the verified-environment tally reconciles with the per-control verified dispositions",
        extra={"recorded": recorded_verified, "computed": dict(sorted(verified_tally.items()))})

    # Internal reconciliation is NOT sufficient for a field outside the canonical hash: making two
    # forgeable fields agree with each other is a one-line edit and the result still collides with
    # the honest hash. The fix is NOT to recompute these fields and demand equality -- they are
    # machine-local by definition, and a first cut that did so made the artifact validate only on
    # the machine that generated it, which is the same defect in a new costume. What IS
    # machine-independent is the DECISION: run the real decide_ga over the dispositions the
    # artifact itself records and require the recorded GA status to follow from them.
    def decided(entries: list) -> str:
        status, _ = GA.decide_ga(mode="client", parity_ok=True,
                                 checks=[{"disposition": d} for d in entries],
                                 commands_skipped=False, commands_passed=True, worktree_clean=True)
        return status

    fresh_decided = decided([c.get("current_disposition_fresh_checkout") for c in controls
                             if isinstance(c, dict)])
    verified_decided = decided([c.get("current_disposition_verified_environment") for c in controls
                                if isinstance(c, dict)])
    rec("GA47c context-status-follows-from-its-own-dispositions",
        fresh_ctx.get("ga") == fresh_decided and verified_ctx.get("ga") == verified_decided,
        "each context's GA status is recomputed by the REAL decide_ga from the per-control "
        "dispositions that context records. Forging 28 verified PASSes now contradicts the "
        "GA_BLOCKED the same context must report, and the contradiction is detectable from any "
        "checkout because it needs no local evidence to evaluate",
        extra={"fresh_recorded": fresh_ctx.get("ga"), "fresh_decided": fresh_decided,
               "verified_recorded": verified_ctx.get("ga"), "verified_decided": verified_decided})

    local_block = artifact.get("local_evidence_artifact")
    local_block = local_block if isinstance(local_block, dict) else {}
    present_flag = artifact.get("local_evidence_artifact_present")
    paths_present = artifact.get("local_evidence_paths_present")
    promoter_mismatch = []
    for c in controls:
        if not isinstance(c, dict):
            continue
        differs = (c.get("current_disposition_verified_environment")
                   != c.get("current_disposition_fresh_checkout"))
        named = isinstance(c.get("verified_promoted_by"), list) and bool(c["verified_promoted_by"])
        if differs != named:
            promoter_mismatch.append(f"{c.get('id')}:differs={differs},named={named}")
    rec("GA47n promoter-named-exactly-when-promoted",
        not promoter_mismatch,
        "a control names its promoting artifact exactly when its machine-local disposition differs "
        "from the authoritative one -- no orphan promoter names, no unexplained promotions",
        extra={"mismatched": promoter_mismatch[:5]})

    unresolved = sorted(set(GEN._EVIDENCE_DRIVEN) - set(EVIDENCE_GRAPH))
    rec("GA47o evidence-graph-resolves",
        len(EVIDENCE_GRAPH) >= 7
        and {"ga_migration_runner", "ga_tenant_authorization", "ga_postgres_adapter",
             "ga_redis_adapter"} <= set(EVIDENCE_GRAPH)
        and EVIDENCE_GRAPH.get("ga_tenant_authorization", {}).get("conjunction") is True,
        "the evidence graph resolves every artifact-gated control from the evaluator's call graph, "
        "including the tenant-authorization CONJUNCTION. An earlier resolver returned an empty map, "
        "which made the per-control scope arm a constant False: it forbade every promotion, refused "
        "an honest artifact generated on a machine holding real evidence, and was indistinguishable "
        "from a hard-coded False",
        extra={"resolved": len(EVIDENCE_GRAPH),
               "evidence_driven_without_artifact_gate": unresolved,
               "conjunction_controls": sorted(k for k, v in EVIDENCE_GRAPH.items()
                                              if v["conjunction"])})

    rec("GA47l evidence-path-count-is-honest",
        isinstance(paths_present, int) and paths_present >= 0
        and (paths_present > 0) >= bool(local_block.get("present")),
        "the evidence-path count is a non-negative integer and is at least as large as the single "
        "migration-artifact flag it supersedes",
        extra={"paths_present": paths_present, "migration_flag": local_block.get("present")})
    rec("GA47g machine-local-presence-agrees",
        isinstance(present_flag, bool)
        and isinstance(paths_present, int)
        and present_flag == (paths_present > 0),
        "the top-level presence flag is a BOOLEAN consistent with the evidence-path COUNT, which "
        "measures the same population it does. It was previously compared against the "
        "local_evidence_artifact block, which describes the MIGRATION artifact alone: on any machine "
        "holding one of the other six artifacts the two disagreed and the generator's own honest "
        "output was refused",
        extra={"top_level": present_flag, "paths_present": paths_present,
               "block_describes": local_block.get("describes"),
               "block_present": local_block.get("present")})
    rec("GA47p local-block-declares-its-scope",
        local_block.get("describes") == GEN.EVIDENCE_PATH.name,
        "the local-evidence block names the single artifact it describes. It was read as though it "
        "spoke for all seven evidence paths, which is how the presence flags came to disagree",
        extra={"describes": local_block.get("describes"), "expected": GEN.EVIDENCE_PATH.name})
    VERIFIED_CTX_KEYS = {"ga", "tally", "measured", "note",
                         "informational_only", "authoritative_for_release"}
    rec("GA47h verified-context-closed",
        set(verified_ctx) == VERIFIED_CTX_KEYS
        and isinstance(verified_ctx.get("measured"), bool)
        and verified_ctx.get("measured") == (isinstance(paths_present, int) and paths_present > 0),
        "the machine-local context carries exactly its known keys and its measured flag is a "
        "boolean consistent with evidence presence. The whole subtree was popped from the deep "
        "comparison, so arbitrary keys and values could be injected into it undetected",
        extra={"unexpected": sorted(set(verified_ctx) - VERIFIED_CTX_KEYS),
               "measured": verified_ctx.get("measured")})
    bound_val = local_block.get("bound_to_commit")
    matches_val = local_block.get("matches_current_head")
    rec("GA47i machine-local-values-are-typed",
        (bound_val is None or (isinstance(bound_val, str)
                               and len(bound_val) == 40
                               and all(ch in "0123456789abcdef" for ch in bound_val.lower())))
        and isinstance(matches_val, bool),
        "bound_to_commit is a 40-hex commit id or null, and matches_current_head is a strict "
        "boolean. Both were unvalidated free text inside a block excluded from BOTH the canonical "
        "hash and the deep comparison: a review planted 'Production database and queue adapters "
        "were exercised and ACCEPTED at this head' in bound_to_commit and certified 81/0 with an "
        "unchanged hash. Closing the key set and the note left the VALUES open",
        extra={"bound_to_commit": str(bound_val)[:60],
               "matches_current_head": repr(matches_val)})
    DISPOSITIONS = {"PASS", "BLOCKED", "FAIL", "SKIPPED", "REVIEW_REQUIRED", "NOT_APPLICABLE"}
    bad_dispo = sorted(
        f"{c.get('id')}={str(c.get('current_disposition_verified_environment'))[:40]}"
        for c in controls
        if isinstance(c, dict)
        and c.get("current_disposition_verified_environment") not in DISPOSITIONS)
    bad_tally = sorted(str(k)[:40] for k in (verified_ctx.get("tally") or {})
                       if str(k) not in DISPOSITIONS)
    rec("GA47m verified-dispositions-are-enum-members",
        not bad_dispo and not bad_tally,
        "every machine-local disposition and every tally KEY is a member of the evaluator's "
        "disposition enum. Typing bound_to_commit and matches_current_head closed one free-text "
        "channel and a review immediately found the next one: an arbitrary sentence in a control's "
        "verified disposition, mirrored into the tally key, certified 88/0 and 86/0 with a "
        "BYTE-IDENTICAL canonical hash, because the field is outside both the hash and the deep view",
        extra={"bad_dispositions": bad_dispo[:4], "bad_tally_keys": bad_tally[:4]})
    rec("GA47j machine-local-note-agrees-with-state",
        (local_block.get("note") == GEN.LOCAL_EVIDENCE_NOTES[3]) == bool(matches_val is True)
        or not local_block.get("present"),
        "the local-evidence note agrees with the state it describes; membership of a closed set is "
        "not consistency with the fields beside it",
        extra={"note_says_current": local_block.get("note") == GEN.LOCAL_EVIDENCE_NOTES[3],
               "matches_current_head": repr(matches_val)})
    rec("GA47k verified-note-agrees-with-measured",
        (verified_ctx.get("note") == GEN.VERIFIED_CONTEXT_NOTES[0])
        == (verified_ctx.get("measured") is True),
        "the machine-local context's note agrees with its own measured flag: a 'NOT MEASURED' note "
        "beside measured=true (or the reverse) previously certified green")
    rec("GA47d machine-local-prose-is-a-closed-set",
        set(local_block) == set(GEN.LOCAL_EVIDENCE_KEYS)
        and local_block.get("note") in GEN.LOCAL_EVIDENCE_NOTES
        and verified_ctx.get("note") in GEN.VERIFIED_CONTEXT_NOTES,
        "the notes on both machine-local blocks are drawn from the generator's closed literal sets "
        "and the block carries no extra keys. Free text here was a second hash-collision channel: "
        "it sits outside the canonical body, so any sentence could be planted there",
        extra={"unexpected_keys": sorted(set(local_block) - set(GEN.LOCAL_EVIDENCE_KEYS)),
               "note_known": local_block.get("note") in GEN.LOCAL_EVIDENCE_NOTES,
               "context_note_known": verified_ctx.get("note") in GEN.VERIFIED_CONTEXT_NOTES})

    prose_offenders = []
    for c in controls:
        if not isinstance(c, dict) or c.get("current_disposition_fresh_checkout") == "PASS":
            continue
        exists = " ".join(str(c.get(k) or "") for k in
                          ("implemented_capability", "notes")).lower()
        absent = str(c.get("missing_capability") or "").lower()
        hit = ([p for p in COMPLETION_CLAIMS if p in exists]
               + [p for p in NOTHING_MISSING_CLAIMS if p in absent])
        if hit or not str(c.get("missing_capability") or "").strip() \
                or str(c.get("estimated_effort") or "").strip().upper() in {"NONE", ""}:
            prose_offenders.append({"id": c.get("id"), "claims": hit[:3],
                                    "effort": c.get("estimated_effort")})
    # Comparing the artifact against GEN.CURATED_PROSE_DISCLOSURE is invariant under any generator
    # edit, because the constant and the prose it describes live in the SAME file. A review emptied
    # the disclosure, then INVERTED it to claim the commentary had been "independently verified",
    # regenerated, and both guards stayed green. The required meaning is therefore pinned HERE, in
    # the consumer, as content that must be present and content that must never appear.
    disclosure = str(artifact.get("curated_prose_disclosure") or "")
    low = disclosure.lower()
    missing_terms = [t for t in DISCLOSURE_REQUIRED_TERMS if t not in low]
    contra_terms = [t for t in DISCLOSURE_FORBIDDEN_TERMS if t in low]
    rec("GA04k curated-prose-disclosure-says-what-it-must",
        len(disclosure) >= 200 and not missing_terms and not contra_terms,
        "KEYWORD FLOOR, not a semantic proof: the disclosure is non-trivial, states that the "
        "commentary is author-supplied and unverified, names the derived fields that govern, and "
        "carries none of a blacklist of verification claims. A determined author can still write a "
        "compliant-but-misleading disclosure -- this raises the cost, it does not close the class. "
        "Equality with the generator constant alone proved nothing: both sides move in one edit",
        extra={"length": len(disclosure), "missing_required": missing_terms,
               "forbidden_present": contra_terms})
    rec("GA04k2 curated-prose-disclosure-matches-generator",
        artifact.get("curated_prose_disclosure") == GEN.CURATED_PROSE_DISCLOSURE,
        "the artifact states verbatim that its capability/effort/notes prose is author-supplied, "
        "unverifiable, and subordinate to the derived disposition and blocking_reason. An author "
        "who edits the curated block and regenerates produces a self-consistent artifact -- a "
        "review proved the phrase floor below can be evaded by rewording -- so the honest control "
        "is disclosure, not a claim of verification",
        extra={"present": artifact.get("curated_prose_disclosure")
               == GEN.CURATED_PROSE_DISCLOSURE})
    rec("GA04i prose-consistent-with-disposition",
        not prose_offenders,
        "FLOOR, not a proof: no control the real evaluator reports as not-PASS carries prose "
        "asserting it is satisfied, executed or signed off, an empty missing_capability, or NONE "
        "effort. A determined author can reword past this, which is why GA04k requires the artifact "
        "to disclose that the prose is unverifiable",
        extra={"offenders": prose_offenders[:5]})

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
    parent = git_rev("HEAD^") if head else ""
    declared_files = artifact.get("source_file_hashes")
    declared_files = declared_files if isinstance(declared_files, dict) else {}
    actual_files = GEN.source_file_hashes()
    file_drift = sorted(k for k in actual_files if declared_files.get(k) != actual_files[k])
    rec("GA50c source-commit-is-immediate-parent-or-sources-unchanged",
        isinstance(bound, str) and bool(parent)
        and (bound in (head, parent)
             or (ancestor and bool(declared_files) and not file_drift)),
        "the recorded source commit is HEAD or its immediate parent -- the generate-then-commit "
        "shape -- OR it is an older ancestor whose every authoritative source file still hashes to "
        "its recorded value. Requiring adjacency alone meant that wiring these guards into "
        "audit:all made every later unrelated commit fail the whole suite, which is how a guard "
        "gets disabled. Drift detection lives in the per-file hashes, not in commit distance",
        extra={"bound": str(bound)[:12], "head": head[:12], "parent": parent[:12],
               "sources_unchanged": bool(declared_files) and not file_drift})
    rec("GA50d source-file-hashes-current",
        bool(declared_files) and not file_drift,
        "every authoritative source file's SHA-256 matches its recorded value: ancestry alone is not "
        "relied upon, the sources themselves are hashed",
        extra={"drifted": file_drift, "files": len(actual_files)})
    # The recorded hashes must equal the COMMITTED BLOBS, not merely the author's working copy.
    # .gitattributes pins eol=lf; the previous cut recorded a CRLF working-tree hash for the one
    # file it edited in place, so both guards were red on every fresh checkout and green only on
    # the author's machine. Comparing against the blob makes that unrepresentable.
    blob_drift = []
    for path in sorted(declared_files):
        proc = subprocess.run(["git", "cat-file", "blob", f"HEAD:{path}"],
                              capture_output=True, cwd=ROOT)
        if proc.returncode != 0:
            blob_drift.append(f"{path}:unreadable")
        elif hashlib.sha256(proc.stdout).hexdigest() != declared_files[path]:
            blob_drift.append(path)
    rec("GA50g source-hashes-match-committed-blobs",
        bool(declared_files) and not blob_drift,
        "every recorded source hash equals the hash of the COMMITTED BLOB, so the artifact is "
        "reproducible from any checkout rather than from one machine's line endings",
        extra={"drifted": blob_drift})
    bound_tree = subprocess.run(["git", "rev-parse", f"{bound}^{{tree}}"],
                                capture_output=True, text=True, cwd=ROOT)
    rec("GA50h tree-binding-matches-commit",
        bound_tree.returncode == 0
        and artifact.get("generated_from_tree") == bound_tree.stdout.strip(),
        "the recorded tree is the tree OF the recorded commit. It was emitted but never checked, so "
        "it could be set to any value",
        extra={"recorded": str(artifact.get("generated_from_tree"))[:12],
               "expected": bound_tree.stdout.strip()[:12]})
    # Closing the TOP-LEVEL key set is not enough: a review injected a whole extra context and an
    # extra static-contract key, both nested one level down, and both certified green. Every
    # code-derived sub-structure is compared against the regenerated payload. blocking_reason is
    # derived from the hermetic evaluator snapshot, so it is deterministic on any machine -- yet it
    # was never compared, and rewriting all 28 to "Resolved: verified in production." passed.
    live_by_cid = {str(c.get("check_id")): c for c in live_payload().get("controls") or []}
    # str() coercion: an unhashable check_id (dict/list) crashed the genexpr below with zero stdout.
    reason_drift = sorted(
        str(c.get("check_id")) for c in controls
        if isinstance(c, dict)
        and c.get("blocking_reason") != (live_by_cid.get(str(c.get("check_id"))) or {}).get(
            "blocking_reason"))
    rec("GA47e blocking-reasons-recomputed",
        not reason_drift,
        "every control's blocking_reason equals the reason the real evaluator produces for it in "
        "the hermetic snapshot. It is derived, not curated, so rewriting it is pure fabrication",
        extra={"drifted": reason_drift[:5], "count": len(reason_drift)})
    rec("GA45b contexts-closed",
        set(contexts) == set((live_payload().get("contexts") or {})),
        "the contexts block carries exactly the two known contexts. An injected "
        "production_verified context reporting GA_READY was previously ignored",
        extra={"unexpected": sorted(set(contexts) - set(live_payload().get("contexts") or {}))})
    rec("GA04j static-contracts-closed",
        artifact.get("static_contracts_accepted")
        == live_payload().get("static_contracts_accepted"),
        "the static-contracts block equals the generator's own literal set exactly. The naming rule "
        "alone let a review add ga_production_readiness_contract, which satisfies the suffix but "
        "asserts a contract that does not exist",
        extra={"unexpected": sorted(
            set(artifact.get("static_contracts_accepted") or {})
            - set(live_payload().get("static_contracts_accepted") or {}))})

    # ---------------------------------------------------------------- deep regeneration compare
    # THE structural check. Reconciling the artifact field by hand-picked field against a mix of
    # live sources and phrase blacklists is a losing game: two independent reviews walked straight
    # past it by editing a field nobody had thought to name (nested context keys, source_bindings,
    # per-control keys, legend VALUES, authoritative_context_note, curated prose). A complete,
    # deterministic regeneration was already being computed in this same function and used for
    # four checks. Everything that is code-derived is now compared wholesale.
    #
    # The exclusions are the only fields that legitimately differ, each with its own check:
    #   commit binding      -- the artifact names its PARENT; regeneration names HEAD (GA50/50c/50h)
    #   worktree_clean      -- a property of the generating tree, not of the payload (GA50b)
    #   machine-local half  -- explicitly NOT repository state; bounded by GA47b/c/d/f below
    DEEP_EXCLUDED = {"canonical_payload_hash", "generated_from_commit", "generated_from_tree",
                     "worktree_clean", "local_evidence_artifact", "local_evidence_artifact_present",
                     "local_evidence_paths_present"}

    def deep_view(payload: dict) -> dict:
        view = {k: v for k, v in payload.items() if k not in DEEP_EXCLUDED}
        raw_ctx = view.get("contexts")
        # A non-dict contexts value raised ValueError inside dict(); deep_view reads the RAW
        # artifact, so the earlier shape guard did not protect it.
        ctx = dict(raw_ctx) if isinstance(raw_ctx, dict) else {"<invalid>": repr(raw_ctx)[:80]}
        ctx.pop("verified_environment_with_evidence", None)
        view["contexts"] = ctx
        view["controls"] = [{k: v for k, v in (c or {}).items()
                             if k not in ("current_disposition_verified_environment",
                                          "verified_promoted_by",
                                          "verified_promotion_detail")}
                            for c in view.get("controls") or []]
        return view

    art_view, live_view = deep_view(artifact), deep_view(live_payload())
    deep_diff = []
    for key in sorted(set(art_view) | set(live_view)):
        if art_view.get(key) != live_view.get(key):
            if key == "controls":
                a_order = [str((c or {}).get("check_id")) for c in art_view.get("controls") or []]
                l_order = [str((c or {}).get("check_id")) for c in live_view.get("controls") or []]
                if a_order != l_order:
                    deep_diff.append("controls[].order")
                a_by = {str((c or {}).get("check_id")): c for c in art_view.get("controls") or []}
                l_by = {str((c or {}).get("check_id")): c for c in live_view.get("controls") or []}
                for cid in sorted(set(a_by) | set(l_by)):
                    for f in sorted(set(a_by.get(cid) or {}) | set(l_by.get(cid) or {})):
                        if (a_by.get(cid) or {}).get(f) != (l_by.get(cid) or {}).get(f):
                            deep_diff.append(f"controls[{cid}].{f}")
            else:
                deep_diff.append(key)
    rec("GA56 payload-deep-equals-regeneration",
        not deep_diff,
        "every code-derived field equals a complete regeneration of the payload, compared wholesale "
        "rather than field by field. Curated prose, legend values, nested context and binding keys, "
        "probe metadata and per-control fields are all covered by this one comparison",
        extra={"differing": deep_diff[:8], "count": len(deep_diff)})

    # The verified half is machine-local and deliberately outside both the canonical hash and the
    # deep compare, so it cannot be required to equal a regeneration -- a checkout whose local
    # evidence state differs from the generating machine's would then fail through no fault of the
    # artifact. It is BOUNDED instead, using only recorded fields, so the bound holds anywhere.
    unbounded = []
    for c in controls:
        if not isinstance(c, dict):
            continue
        fresh_d = c.get("current_disposition_fresh_checkout")
        ver_d = c.get("current_disposition_verified_environment")
        if ver_d == fresh_d:
            continue
        # Bound on the REAL evidence-driven set, not the curated probe_type. The curated block
        # marks 4 controls evidence_driven_probe while GEN._EVIDENCE_DRIVEN holds 10, so an
        # HONESTLY regenerated artifact carrying persistence or tenant-authorization evidence was
        # refused by its own guard -- pushing the author toward hand-editing the very half that is
        # least policed. The presence gate is dropped for the same reason: it reflected only the
        # migration artifact, while seven gitignored artifacts drive this half.
        # PER-CONTROL, never a count. The control must name the SPECIFIC artifact that promoted
        # it, and that name must be one the evaluator actually consults. The previous rule asked
        # only "is some unrelated evidence count non-zero", which let a review record BOTH
        # production adapters PASS in the machine-local half with no adapter evidence anywhere.
        # Membership of _EVIDENCE_DRIVEN alone is NOT sufficient either: an exact-head review
        # showed that set contains behavioural probes (ga_rbac_role_separation,
        # ga_verified_reviewer_identity) that no artifact drives, and both are legitimately PASS
        # in the authoritative half -- a blanket rule over that set would reject honest data.
        promoter = c.get("verified_promoted_by")
        required = EVIDENCE_SCOPE.get(str(c.get("check_id")), frozenset())
        named = set(promoter) if isinstance(promoter, list) else set()
        # PER CONTROL, and for a CONJUNCTION every component must be named. The scope comes from
        # the evaluator's own call graph -- dispatch, transitive helpers and composed filenames --
        # so it is a property of the code and identical on every machine. It still fails closed: a
        # control absent from the graph has an empty requirement and cannot be promoted at all.
        # Naming the required artifacts is not the same as HAVING them: a probe of this gate
        # promoted the tenant-authorization conjunction by listing both components while neither
        # artifact was present. The control's own detail block must therefore report every required
        # artifact present and nothing missing.
        detail = c.get("verified_promotion_detail")
        detail = detail if isinstance(detail, dict) else {}
        present = set(detail.get("present") or [])
        missing = set(detail.get("missing") or [])
        if (not required
                or not named
                or not named <= set(KNOWN_EVIDENCE_FILENAMES)
                or named != set(required)
                or present != set(required)
                or missing
                or detail.get("conjunction") is not (len(required) > 1)):
            unbounded.append(
                f"{c.get('id')}:{fresh_d}->{ver_d} named={sorted(named)} "
                f"required={sorted(required)} present={sorted(present)} missing={sorted(missing)}")

    rec("GA45c contexts-declare-their-authority",
        fresh_ctx.get("authoritative_for_release") is True
        and fresh_ctx.get("informational_only") is False
        and verified_ctx.get("authoritative_for_release") is False
        and verified_ctx.get("informational_only") is True
        and artifact.get("authoritative_context") == "fresh_checkout_no_local_evidence",
        "both contexts classify themselves in MACHINE-READABLE form: the fresh checkout is "
        "authoritative for release, the machine-local verified environment is informational only. "
        "The distinction previously existed only in a prose note",
        extra={"fresh": {k: fresh_ctx.get(k) for k in
                         ("informational_only", "authoritative_for_release")},
               "verified": {k: verified_ctx.get(k) for k in
                            ("informational_only", "authoritative_for_release")}})

    rec("GA47f verified-half-is-bounded",
        not unbounded,
        "a machine-local disposition may differ from the authoritative one ONLY when the control "
        "names the SPECIFIC evidence artifact that promoted it, and that artifact is one the "
        "evaluator consults. No count of unrelated evidence authorizes any control. The "
        "authoritative half itself is not bounded here at all -- it is RECOMPUTED against the "
        "hermetic evaluator by GA12, so it cannot be forged. RESIDUAL, stated plainly: the "
        "machine-local half is not repository state and a per-control promoter name is itself "
        "machine-local; the authoritative context is the only release-relevant one",
        extra={"unbounded": unbounded[:5]})

    rec("GA51b top-level-keys-closed",
        set(artifact) == set(live_payload()),
        "the artifact's top-level key set equals the regenerated payload's exactly. Unknown keys "
        "were previously ignored, so an injected executive_summary asserting that the production "
        "adapters had been accepted certified green",
        extra={"unexpected": sorted(set(artifact) - set(live_payload())),
               "missing": sorted(set(live_payload()) - set(artifact))})

    rec("GA50e generation-model-declared",
        artifact.get("artifact_generation_model") == "tracked-derived-assessment"
        and artifact.get("source_commit_relationship") == "immediate-parent-of-artifact-commit",
        "the artifact declares its generation model explicitly rather than leaving the binding "
        "semantics implicit")
    rec("GA50f inventory-fingerprint-derived",
        artifact.get("registry_inventory_fingerprint") == GEN.registry_inventory_fingerprint(),
        "the reporting fingerprint recomputes from the loaded registry; it is reporting only and "
        "does not define the expected set")

    rec("GA50 commit-binding-is-ancestor",
        ancestor and behind.isdigit() and int(behind) <= MAX_COMMITS_BEHIND,
        f"the recorded commit is an ancestor of HEAD and at most {MAX_COMMITS_BEHIND} commits "
        "behind. A tracked artifact cannot name the commit that contains it, so the source-binding "
        "checks below carry the drift detection",
        extra={"bound_commit": str(bound)[:12], "head": head[:12], "commits_behind": behind})
    # The attestation is self-asserted, so it is RE-CHECKED here, matching the pattern this
    # repository already uses in tenant_authorization_evidence.py,
    # production_database_adapter_evidence.py and production_queue_adapter_evidence.py -- two of
    # which this artifact itself hashes, and whose standard the artifact demands of the adapters
    # ("a strict clean-worktree attestation re-checked at validation time") while not meeting it.
    #
    # Why re-checking is not optional: only SIX files are in source_file_hashes, but the
    # dispositions come from evaluate_blockers, which imports store, main, permissions, audit_keys,
    # migrations, identity and schemas -- all UNBOUND. GA56 cannot catch an edit to those because
    # it regenerates from the same dirty tree. An exact-head review dirtied permissions.py,
    # regenerated (honestly getting worktree_clean=false), flipped the one boolean, rehashed, and
    # both guards certified a set of dispositions that NO clean checkout of this commit reproduces.
    tracked_dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                   capture_output=True, text=True, cwd=ROOT)
    dirty_paths = [ln[3:] for ln in tracked_dirty.stdout.splitlines() if ln.strip()]
    rec("GA50b worktree-clean-attested-and-rechecked",
        artifact.get("worktree_clean") is True
        and tracked_dirty.returncode == 0 and not dirty_paths,
        "the assessment attests a clean TRACKED worktree at generation AND the tracked tree is "
        "independently re-measured as clean now. The attestation alone is a self-report: flipping "
        "it and rehashing certified a payload computed from uncommitted code",
        extra={"attested": artifact.get("worktree_clean"),
               "dirty_now": dirty_paths[:5], "dirty_count": len(dirty_paths)})
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

    # ---------------------------------------------------------------- reciprocal cross-file pin
    # The faults battery pins THIS guard's check set. Without the reverse, deleting one of its
    # mutations plus two integers in its own file passed at 55/48 -- removing the self-pin left it
    # with no completeness authority at all. Each file now pins the other.
    try:
        import ga_gap_assessment_faults_guard as _FG
        faults_ids = sorted(_FG.EXPECTED_CHECK_IDS)
        faults_hash = hashlib.sha256("\n".join(faults_ids).encode("utf-8")).hexdigest()
    except Exception:  # noqa: BLE001
        faults_ids, faults_hash = [], ""
    rec("GA80 faults-battery-check-set-pinned",
        faults_hash == PINNED_FAULTS_ID_SET_HASH and len(faults_ids) == PINNED_FAULTS_CHECK_COUNT,
        "the fault battery's declared check-id set is hashed and pinned HERE, in a different file, "
        "so a mutation cannot be deleted together with its id and both of its own counts",
        level="structural source check",
        extra={"observed": faults_hash[:16] + "...", "count": len(faults_ids)})

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
        # Which schema and file this run actually validated: the envelope named neither, so a
        # reader could not tell a v1 run from a v2 run from the output alone.
        "assessment_schema_version": VALIDATED_IDENTITY.get("schema_version"),
        "assessment_path": VALIDATED_IDENTITY.get("path"),
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
