"""Behavioral guard for GA readiness-gate integrity.

Exercises the real registry-backed GA evaluation, disposition semantics,
registry/check parity, evidence canonicalization, and the fail-closed decision
so that a false GA_READY is impossible. It runs the actual guard subprocess for
evidence/commit/skip-command vectors and calls the real evaluator functions for
the semantic vectors — not grep-only.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.ga_readiness import (  # noqa: E402
    blocker_counts,
    canonical_json,
    check_registry_parity,
    decide_ga,
    evaluate_blockers,
    is_blocking,
    load_registry,
    not_applicable_permitted,
    payload_sha256,
    validate_registry,
    verify_evidence_hash,
)

GA_GUARD = ROOT / "scripts" / "ga_readiness_guard.py"
FORGE_REPORT_PATH = ROOT / "output" / "forge-evals" / "forge_eval_report.json"


def check(name: str, ok: bool, detail: object = "") -> dict[str, object]:
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))
    return {"name": name, "ok": ok, "detail": str(detail)[:300]}


def synthetic_check(disposition: str, category: str = "software", **extra: object) -> dict[str, object]:
    base = {
        "id": f"syn_{disposition.lower()}",
        "label": "syn",
        "status": "pass" if disposition in {"PASS", "NOT_APPLICABLE"} else "fail",
        "disposition": disposition,
        "category": category,
        "severity": "blocker",
        "owner_type": "engineering",
        "policy_reference": "x",
        "resolution_condition": "x",
    }
    base.update(extra)
    return base


def run_guard(*args: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    tmp = tempfile.mkdtemp(prefix="ga-integrity-")
    env.update(
        {
            "MONDAY_REPORT_STATE_PATH": str(Path(tmp) / "state.json"),
            "MONDAY_REPORT_STORAGE_ROOT": str(Path(tmp) / "storage"),
            "MONDAY_REPORT_EXPORT_ROOT": str(Path(tmp) / "exports"),
            # Isolate from any generated ga env file.
            "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
        }
    )
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(GA_GUARD), "--env-file", str(Path(tmp) / "none.env"), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def main() -> int:
    # Deterministic GA-gate-logic tests: evaluate blockers WITHOUT an ambient audit
    # HMAC key so ga_audit_keyed_integrity is BLOCKED (its default disposition),
    # independent of the caller's environment (the isolated verify stack sets a key).
    for _k in (
        "MONDAY_REPORT_AUDIT_HMAC_KEY",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_ID",
        "MONDAY_REPORT_AUDIT_HMAC_KEY_VERSION",
        "MONDAY_REPORT_AUDIT_HMAC_RETAINED_KEYS",
    ):
        os.environ.pop(_k, None)
    checks: list[dict[str, object]] = []
    registry = load_registry()

    # 1. Registry schema valid.
    checks.append(check("Registry schema is valid", not validate_registry(registry)))

    def rejects(name: str, mutate) -> None:
        bad = copy.deepcopy(registry)
        mutate(bad)
        checks.append(check(name, bool(validate_registry(bad))))

    # 2-5. Registry rejections.
    rejects("Duplicate blocker ID rejected", lambda r: r["blockers"].append(copy.deepcopy(r["blockers"][0])))
    rejects("Unknown category rejected", lambda r: r["blockers"][0].__setitem__("category", "made_up"))
    rejects("Missing policy reference rejected", lambda r: r["blockers"][0].__setitem__("policy_reference", ""))
    rejects("Missing resolution condition rejected", lambda r: r["blockers"][0].__setitem__("resolution_condition", ""))

    # Evaluate against demo readiness (all fixture/config checks warn -> non-pass).
    readiness_demo = {
        "postgres_repository": "warn",
        "redis_queue": "warn",
        "local_llm_runtime": "warn",
        "demo_seed_removed": "pass",
        "parser_fixture_evals": "warn",
        "golden_fixture_coverage": "warn",
        "reviewed_fixture_attestation": "warn",
        "client_mode": "warn",
        "state_path_configured": "pass",
        "storage_root_configured": "pass",
        "export_root_configured": "pass",
        "api_key_configured": "warn",
        "signed_url_secret": "warn",
        "upload_size_limit": "warn",
        "archive_limits": "warn",
        "retention_policy": "warn",
        "hosted_fallback_disabled": "pass",
    }
    ga_checks = evaluate_blockers(readiness_demo, forge_report=None)
    by_id = {c["id"]: c for c in ga_checks}

    # 6-7. Parity: registry entry without check / check without registry entry.
    parity_now = check_registry_parity(ga_checks)
    checks.append(check("Registry and emitted checks have exact parity", not parity_now, parity_now[:2]))
    checks.append(
        check(
            "A check without a registry entry fails parity",
            bool(check_registry_parity(ga_checks + [synthetic_check("BLOCKED", id="orphan_check")])),
        )
    )
    checks.append(
        check(
            "A missing emitted check fails parity",
            bool(check_registry_parity(ga_checks[:-1])),
        )
    )

    # 8-12. Disposition blocking semantics.
    checks.append(check("PASS is non-blocking", not is_blocking(synthetic_check("PASS"))))
    checks.append(check("FAIL is blocking", is_blocking(synthetic_check("FAIL"))))
    checks.append(check("BLOCKED is blocking", is_blocking(synthetic_check("BLOCKED"))))
    checks.append(check("SKIPPED is blocking", is_blocking(synthetic_check("SKIPPED"))))
    checks.append(check("REVIEW_REQUIRED is blocking", is_blocking(synthetic_check("REVIEW_REQUIRED"))))

    # 13-16. Missing evidence / commands never PASS; skip cannot be GA_READY.
    all_pass = [synthetic_check("PASS", category=c["category"], id=c["id"]) for c in ga_checks]
    _, ready_skip = decide_ga(mode="client", parity_ok=True, checks=all_pass, commands_skipped=True, commands_passed=False, worktree_clean=True)
    checks.append(check("Missing command execution (skip) is not PASS -> not GA_READY", not ready_skip))
    _, ready_empty = decide_ga(mode="client", parity_ok=True, checks=all_pass, commands_skipped=False, commands_passed=False, worktree_clean=True)
    checks.append(check("Empty/failed command results are not a pass -> not GA_READY", not ready_empty))
    _, ready_missing_evidence = decide_ga(mode="client", parity_ok=True, checks=[synthetic_check("SKIPPED")] + all_pass[1:], commands_skipped=False, commands_passed=True, worktree_clean=True)
    checks.append(check("A SKIPPED evidence check blocks GA_READY", not ready_missing_evidence))
    checks.append(check("--skip-commands cannot produce GA_READY (decision)", not ready_skip))

    # 17. Commands-skipped evidence is explicit (subprocess).
    skip_run = run_guard("--skip-commands")
    skip_json = json.loads((ROOT / "output" / "ga-readiness" / "Monday_Report_GA_READINESS.json").read_text(encoding="utf-8"))
    checks.append(
        check(
            "Commands-skipped evidence is explicit and not a full GA evaluation",
            skip_run.returncode == 0
            and skip_json.get("commands_skipped") is True
            and skip_json.get("full_ga_evaluation_complete") is False
            and skip_json.get("status") == "GA_BLOCKED",
            {"rc": skip_run.returncode, "status": skip_json.get("status")},
        )
    )

    # 18-22. NOT_APPLICABLE restrictions.
    entry0 = registry["blockers"][0]
    checks.append(check("NOT_APPLICABLE without permission is rejected", not not_applicable_permitted(entry0, "some reason")))
    permissive = dict(entry0, allow_not_applicable=True)
    checks.append(check("NOT_APPLICABLE without justification is rejected", not not_applicable_permitted(permissive, "")))
    checks.append(check("NOT_APPLICABLE with permission + justification allowed", not_applicable_permitted(permissive, "scoped reason")))
    critical_ids = {"per-user-identity", "audit-keyed-integrity", "audit-tail-truncation-detection", "backup-restore-drill", "verified-reviewer-identity", "client-organizational-approval"}
    registry_ids = {e["id"] for e in registry["blockers"]}
    # Guard against a stale id silently skipping its entry: every critical id
    # must exist AND its entry must forbid NOT_APPLICABLE.
    critical_locked = critical_ids <= registry_ids and all(
        not e.get("allow_not_applicable")
        for e in registry["blockers"]
        if e["id"] in critical_ids
    )
    checks.append(check("Critical identity/audit/backup blockers cannot be marked N/A", critical_locked))
    no_na_in_v1 = all(not e.get("allow_not_applicable") for e in registry["blockers"])
    checks.append(check("No v1 registry entry permits NOT_APPLICABLE", no_na_in_v1))

    # 23. Official export callable-only does not pass.
    checks.append(check("Official export gate is BLOCKED (not callable-only pass)", by_id["ga_official_export_gate"]["disposition"] == "BLOCKED"))

    # 24-26. Parser coverage requires real FORGE evidence.
    checks.append(check("Parser coverage without a report is SKIPPED (not PASS)", by_id["ga_parser_coverage_evidence"]["disposition"] == "SKIPPED"))
    manifest_sha = __import__("hashlib").sha256((ROOT / "evals" / "forge" / "manifest.v1.json").read_bytes()).hexdigest()
    expectations_sha = __import__("hashlib").sha256((ROOT / "evals" / "forge" / "expectations.v1.json").read_bytes()).hexdigest()
    good_report = {
        "status": "pass",
        "manifest_sha256": manifest_sha,
        "expectations_sha256": expectations_sha,
        "summary": {"required_passed": 65, "required_checks": 65, "required_failed": 0},
    }
    good = {c["id"]: c for c in evaluate_blockers(readiness_demo, forge_report=good_report)}
    checks.append(check("Parser coverage PASSES with a valid 65/65 FORGE report", good["ga_parser_coverage_evidence"]["disposition"] == "PASS"))
    stale_report = dict(good_report, manifest_sha256="0" * 64)
    stale = {c["id"]: c for c in evaluate_blockers(readiness_demo, forge_report=stale_report)}
    checks.append(check("Parser coverage FAILS on a stale/mismatched FORGE manifest", stale["ga_parser_coverage_evidence"]["disposition"] == "FAIL"))
    degenerate_report = dict(good_report, summary={"required_passed": 0, "required_checks": 0, "required_failed": 0})
    degenerate = {c["id"]: c for c in evaluate_blockers(readiness_demo, forge_report=degenerate_report)}
    checks.append(check("Parser coverage FAILS on a degenerate 0/0 FORGE report", degenerate["ga_parser_coverage_evidence"]["disposition"] == "FAIL"))

    # 27-31. Evidence commit/tree/hash.
    checks.append(check("Evidence carries a git commit and tree", bool(skip_json.get("git_commit")) and bool(skip_json.get("git_tree"))))
    checks.append(check("Evidence records worktree_clean", isinstance(skip_json.get("worktree_clean"), bool)))
    checks.append(check("Canonical evidence hash verifies", verify_evidence_hash(skip_json)))
    tampered = copy.deepcopy(skip_json)
    tampered["status"] = "GA_READY"
    checks.append(check("Tampered evidence hash fails verification", not verify_evidence_hash(tampered)))
    checks.append(check("Evidence missing commit/tree would be invalid", not (skip_json.get("git_commit") == "" or skip_json.get("git_tree") == "")))

    # 29. Dirty worktree prevents GA_READY.
    _, ready_dirty = decide_ga(mode="client", parity_ok=True, checks=all_pass, commands_skipped=False, commands_passed=True, worktree_clean=False)
    checks.append(check("Dirty worktree prevents GA_READY", not ready_dirty))

    # 32. Absolute-path evidence rejected (no leak in the written payload).
    blob = json.dumps(skip_json)
    import re as _re
    has_path = bool(_re.search(r"[A-Za-z]:\\|/Users/|/home/|AppData", blob))
    checks.append(check("Written evidence contains no machine-specific paths", not has_path))

    # 33. Client approval remains REVIEW_REQUIRED.
    checks.append(check("Client approval remains REVIEW_REQUIRED", by_id["ga_client_organizational_approval"]["disposition"] == "REVIEW_REQUIRED"))

    # 34-36. Provisioned infra / green automation still GA_BLOCKED.
    readiness_infra = dict(readiness_demo, postgres_repository="pass", redis_queue="pass", local_llm_runtime="pass")
    infra_checks = evaluate_blockers(readiness_infra, forge_report=good_report)
    status_infra, ready_infra = decide_ga(mode="client", parity_ok=True, checks=infra_checks, commands_skipped=False, commands_passed=True, worktree_clean=True)
    # Route-level RBAC role separation is now evidence-driven PASS (distinct
    # least-privilege roles + fully-enforced per-user route authorization). GA must
    # still be BLOCKED by the OTHER unresolved controls (tenant authorization,
    # per-user identity deployment, keyed audit, etc.) — resolving one control can
    # never leak GA_READY.
    rbac_pass = any(c["id"] == "ga_rbac_role_separation" and c["disposition"] == "PASS" for c in infra_checks)
    tenant_blocked = any(c["id"] == "ga_tenant_authorization" and c["disposition"] == "BLOCKED" for c in infra_checks)
    checks.append(check("Infra provisioned + RBAC resolved still GA_BLOCKED by other controls", status_infra == "GA_BLOCKED" and not ready_infra and rbac_pass and tenant_blocked))
    audit_blocked = any(c["id"] == "ga_audit_keyed_integrity" and c["disposition"] == "BLOCKED" for c in infra_checks)
    checks.append(check("All infrastructure resolved while audit keying unresolved still GA_BLOCKED", status_infra == "GA_BLOCKED" and audit_blocked))
    approval_blocking = any(c["id"] == "ga_client_organizational_approval" and is_blocking(c) for c in infra_checks)
    checks.append(check("Automated checks green while client approval absent still GA_BLOCKED", status_infra == "GA_BLOCKED" and approval_blocking))

    # 37. Blocker counts reconcile with registry categories.
    counts = blocker_counts(ga_checks)
    manual_total = sum(1 for c in ga_checks if is_blocking(c))
    checks.append(check("Blocker counts reconcile with emitted checks", counts["total"] == manual_total and counts["uncategorized"] == 0))

    # 38. Legacy status fields remain compatible.
    checks.append(check("Every emitted check has a legacy pass/warn/fail status", all(c["status"] in {"pass", "warn", "fail"} for c in ga_checks)))

    # 39. Demo mode cannot yield GA_READY.
    _, ready_demo = decide_ga(mode="demo", parity_ok=True, checks=all_pass, commands_skipped=False, commands_passed=True, worktree_clean=True)
    checks.append(check("Demo mode cannot yield GA_READY", not ready_demo))

    # 40. Deterministic evaluation (apart from timestamps/hashes).
    a = canonical_json(evaluate_blockers(readiness_demo, forge_report=None))
    b = canonical_json(evaluate_blockers(readiness_demo, forge_report=None))
    checks.append(check("Repeated evaluation is deterministic", a == b))

    # Bonus: the current repository truthfully reports non-zero software blockers.
    checks.append(check("Repository truthfully reports unresolved software blockers", counts["software"] > 0 and counts["security_review"] > 0))

    failed = [item for item in checks if not item["ok"]]
    print(json.dumps({"guard": "ga_readiness_integrity_guard", "checks": len(checks), "failed": len(failed)}, indent=2))
    if failed:
        print(f"\nGA readiness integrity guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nGA readiness integrity guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
