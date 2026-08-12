"""audit:readiness-context-local-observer -- focused, Docker-free proof that the local-JSON
readiness-context observers verify PERSISTED state.

For demo-local and client-local it executes the real local observer and asserts, from the observation
it produced (which itself reads the on-disk snapshot), that the accepted LocalStateStore atomicity
holds: the validation decision and the blocked-export transition each persisted with their audit
event exactly once, the snapshot revision advanced, the audit chain stayed sealed, and there is no
business/audit contradiction. It then proves the fail-closed direction: if the persisted read-back is
not verified, the observer refuses (ExecutionUnavailable) rather than returning an executed
observation.

Prints JSON; exits non-zero unless every check passes. No Docker, no network, isolated temp roots.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

import readiness_contexts_runner as R  # noqa: E402
from backend.app import readiness_contexts as RC  # noqa: E402

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "", extra=None) -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail, **({"extra": extra} if extra is not None else {})})


def positive(cid: str) -> None:
    obs = R._observe_local(RC.build_run_input(cid))
    p = obs.get("local_persistence") or {}
    rec(f"{cid}:executed-observer", obs.get("observer") == "local_json_isolated_root"
        and obs.get("source") == "executed", "the isolated local observer executed")
    rec(f"{cid}:validation-persisted-once",
        p.get("validation_decision_persisted") is True and p.get("validation_audit_event_count") == 1,
        "the validation decision persisted with its audit event exactly once")
    rec(f"{cid}:blocked-export-persisted-once",
        p.get("blocked_export_status_persisted") is True
        and p.get("blocked_export_audit_event_count") == 1,
        "the blocked-export status persisted with its audit event exactly once")
    rec(f"{cid}:revision-advanced", p.get("snapshot_revision_advanced") is True,
        "the snapshot revision advanced across both mutations")
    rec(f"{cid}:audit-chain-sealed", p.get("audit_chain_valid") is True
        and p.get("audit_chain_status") == "sealed", "the audit chain remained valid")
    rec(f"{cid}:no-contradiction", p.get("business_audit_contradiction") is False,
        "no business/audit contradiction")
    rec(f"{cid}:verified", p.get("local_persistence_verified") is True,
        "the persisted-state read-back is verified overall")
    # isolation preflight
    iso = obs.get("isolation") or {}
    rec(f"{cid}:isolated", iso.get("isolated") is True
        and iso.get("certified_matches_actual") is True,
        "the isolation preflight passed (own isolated state, no shared/live/.local_data target)")
    # supported workflow
    w = obs.get("workflow") or {}
    rec(f"{cid}:workflow-report-list-draft",
        w.get("tenant_scoped_report_list") is True and w.get("report_draft_retrieved") is True,
        "tenant-scoped report list and report draft observed")
    rec(f"{cid}:workflow-benchmarking", w.get("benchmarking_observed") is True,
        "benchmarking status observed")
    rec(f"{cid}:workflow-export-gate",
        w.get("export_gate_closed_on_unresolved_validation") is True
        and w.get("validation_unlocks_export_gate") is True,
        "the export gate closes on unresolved validation and unlocks once resolved")
    rec(f"{cid}:workflow-signed-reference", w.get("signed_reference_issued") is True,
        "export issuance produced a signed download reference")
    rec(f"{cid}:workflow-verified", w.get("workflow_verified") is True,
        "the supported workflow is verified overall")


def fail_closed() -> None:
    """If the read-back is not verified, the observer must refuse -- never return an executed obs."""
    original = R._local_persistence_readback

    def not_verified(store, mode):
        facts = original(store, mode)
        facts = dict(facts)
        facts["local_persistence_verified"] = False  # simulate a lost-write / unverified read-back
        return facts

    R._local_persistence_readback = not_verified
    try:
        R._observe_local(RC.build_run_input("demo-local"))
        rec("fail-closed:refuses-unverified", False,
            "the observer returned an executed observation despite an unverified read-back")
    except R.ExecutionUnavailable:
        rec("fail-closed:refuses-unverified", True,
            "an unverified persisted-state read-back fails closed (ExecutionUnavailable)")
    except Exception as exc:  # noqa: BLE001
        rec("fail-closed:refuses-unverified", False,
            f"unexpected exception type: {exc.__class__.__name__}")
    finally:
        R._local_persistence_readback = original


def main() -> int:
    for cid in ("demo-local", "client-local"):
        positive(cid)
    fail_closed()

    passed = sum(1 for c in CHECKS if c["ok"])
    failed = len(CHECKS) - passed
    print(json.dumps({
        "guard": "readiness_context_local_observer",
        "claim_scope": "local-context-persisted-state-readback-only",
        "docker_used": False,
        "eligible_for_four_context_acceptance": False,
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True, default=str))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
