"""audit:ai-provider — Phase 1 AI provider extraction: parity + safeguards.

Proves the DeterministicProvider refactor preserves the exact prior chat behavior,
and that the new backend-owned citation validation cannot alter valid output. In-
process (no server), demo mode, deterministic seed (DISABLE_DEMO_SEED), no model,
no network.

Checks:
  * all five deterministic branches preserve EXACT answer text, citations, followups,
    export_actions, tool_actions, workflow_steps, insight_cards, risk_register
    (expected values are hard-coded here, independent of the provider source);
  * representative edge/default prompts (paraphrase misses benchmark; draft+npt
    precedence) preserve behavior;
  * tenant/workspace isolation: a foreign-tenant or foreign-workspace failure never
    enters the answer;
  * citation validator rejects out-of-set/fabricated source ids and preserves valid
    citations unchanged (order + count);
  * a provider failure cannot silently alter deterministic behavior (it surfaces as
    an error rather than a fabricated 200).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail})


# --- exact expected outputs (hard-coded; NOT derived from the provider) -------
E_REPORT = (
    "Draft Monday Report workflow is ready from 2 extracted failures and "
    "9.5 NPT hours. "
    "Plan: normalize the source daily-report format into well/job information, present operations, drilling parameters, mud/BHA/survey, casing, timeline, NPT, risks, and approvals. "
    "Execute: generate the branded report, render the well schematic, attach citations, then export PDF/XLSX/HTML/CSV/JSON after the approval gate. "
    "Current gate: 1 validation task(s) must close before official issue."
)
E_EVIDENCE = (
    "Parsed evidence is available from 0 uploaded document(s) "
    "with 0 source chunk(s). The worker stores chunk lineage by file, "
    "upload, workspace, and tenant before local AI extraction runs."
)
E_NPT = "Current extracted evidence shows 9.5 NPT hours linked to failure records."
E_DEFAULT = (
    "I found 2 extracted failure record(s). "
    "The current executable slice is API-ready for local AI extraction workers."
)
E_TOOL_LABELS = ["Plan DDR", "Draft Report", "Draw Schematic", "Audit Gate"]
E_TOOL_KINDS = ["plan", "draft", "schematic", "audit"]
E_STEP_NAMES = ["Ingest", "Extract", "Plan", "Draft", "Schematic", "Export"]


def configure_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "AI Provider Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "ai-provider-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "AI Provider Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "AI provider guard workspace"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_API_KEY", "VITE_MONDAY_REPORT_API_KEY", "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_REPOSITORY_BACKEND", "MONDAY_REPORT_DATABASE_URL", "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND", "MONDAY_REPORT_REDIS_URL", "REDIS_URL",
    ]:
        os.environ.pop(key, None)


def main() -> int:  # noqa: PLR0915 - one linear battery
    with tempfile.TemporaryDirectory(prefix="ai-provider-guard-") as tmp:
        configure_env(Path(tmp))

        import backend.app.main as app_main
        from backend.app.main import chat
        from backend.app.schemas import (
            ChatRequest, Citation, FailureRecord, ValidationStatus, ValidationTask,
        )
        from backend.app.store import store
        from backend.app.identity import set_current_identity
        from backend.app.ai import (
            AIProvider, GroundedContext, DeterministicProvider, validate_citations, citation_key,
        )

        set_current_identity(store.demo_bootstrap_identity())
        workspace = next(iter(store.workspaces.values()))
        ws = workspace.id
        tenant = store.tenant.id

        c1 = Citation(
            locator_type="pdf",
            locator={"page": 3, "section": "daily drilling report"},
            snippet="Stuck pipe at 8,420 ft created 6.5 h of NPT while drilling ahead.",
            confidence=0.86,
        )
        f1 = FailureRecord(
            tenant_id=tenant, workspace_id=ws, event_type="Stuck pipe", severity="High",
            summary="Stuck pipe event.", company="Anonymized Directional Services",
            tool_type="Drill string", tool_serial="DS-01", npt_hours=8.5, confidence=0.9,
            validation_status=ValidationStatus.OPEN, citations=[c1],
        )
        f2 = FailureRecord(
            tenant_id=tenant, workspace_id=ws, event_type="Surface equipment", severity="Low",
            summary="Minor surface equipment event.", company="Rig Operations",
            tool_type="Surface", tool_serial="SE-01", npt_hours=1.0, confidence=0.8,
            validation_status=ValidationStatus.OPEN, citations=[],
        )
        # Isolation decoys: foreign tenant (same workspace id) and foreign workspace (same tenant).
        f_foreign_tenant = FailureRecord(
            tenant_id=uuid4(), workspace_id=ws, event_type="Foreign tenant failure", severity="High",
            summary="Must not surface.", company="X", tool_type="Y", tool_serial="Z",
            npt_hours=5.0, confidence=0.9, validation_status=ValidationStatus.OPEN, citations=[],
        )
        f_foreign_ws = FailureRecord(
            tenant_id=tenant, workspace_id=uuid4(), event_type="Foreign workspace failure", severity="High",
            summary="Must not surface.", company="X", tool_type="Y", tool_serial="Z",
            npt_hours=7.0, confidence=0.9, validation_status=ValidationStatus.OPEN, citations=[],
        )
        for f in (f1, f2, f_foreign_tenant, f_foreign_ws):
            store.failures[f.id] = f
        t1 = ValidationTask(
            tenant_id=tenant, target_type="failure", target_id=f1.id,
            reason="Guard validation task.", priority="high", status=ValidationStatus.OPEN,
        )
        store.validation_tasks[t1.id] = t1
        store.save()

        def ask(text: str):
            return chat(ChatRequest(workspace_id=ws, content=text, filters={}))

        # ---- branch parity (exact) --------------------------------------------
        report = ask("Draft the Monday report")
        check("report-branch answer", report.answer == E_REPORT, report.answer)
        check("report-branch citations", len(report.citations) == 1 and report.citations[0].snippet == c1.snippet, len(report.citations))
        check("report-branch followups", report.followups == [
            "Plan next morning report", "Build casing schematic", "Create draft report", "Show unresolved validation tasks"], report.followups)
        check("report-branch export_actions", report.export_actions == [
            "monday_report_pdf", "monday_report_xlsx", "monday_report_html", "monday_report_csv", "monday_report_json"], report.export_actions)
        check("report-branch tool_actions", [a.label for a in report.tool_actions] == E_TOOL_LABELS and [a.kind for a in report.tool_actions] == E_TOOL_KINDS, [a.label for a in report.tool_actions])
        steps = {s.step: s.status for s in report.workflow_steps}
        check("report-branch workflow_steps", [s.step for s in report.workflow_steps] == E_STEP_NAMES and steps["Ingest"] == "watch" and steps["Extract"] == "complete" and steps["Export"] == "blocked", steps)
        cards = {c.label: (c.value, c.tone) for c in report.insight_cards}
        check("report-branch insight_cards", len(report.insight_cards) == 4
              and cards["Evidence"] == ("0 docs / 0 chunks", "warning")
              and cards["Failures"] == ("2 records", "danger")
              and cards["Validation Gate"] == ("1 open", "warning")
              and cards["Export Stack"][1] == "info", cards)
        risks = {r.title: r.severity for r in report.risk_register}
        check("report-branch risk_register", len(report.risk_register) == 3
              and risks["Validation backlog"] == "high" and risks["Evidence coverage"] == "medium" and risks["Operational severity"] == "high", risks)

        bench = ask("Show the market benchmark drilling rate")
        # The demo store returns a populated benchmark status, so the branch takes its
        # rich (non-None) path. Assert the branch shape structurally; the golden below
        # pins the exact string against the current behavior.
        check("benchmark-branch answer shape",
              bench.answer.startswith("Market benchmark status: current ft/day is missing, seven-day average is missing.")
              and bench.answer.endswith("active benchmark anomaly/anomalies are in review."), bench.answer)
        check("benchmark-branch followups", bench.followups == [
            "Show Market Benchmark", "Explain active anomalies", "Prepare Management of Change evidence"], bench.followups)
        check("benchmark-branch export_actions", bench.export_actions == ["benchmark_evidence_json", "moc_evidence_pdf"], bench.export_actions)
        check("benchmark-branch citations", len(bench.citations) == 1, len(bench.citations))
        check("benchmark-branch adds Benchmark insight card", any(c.label == "Benchmark" for c in bench.insight_cards), [c.label for c in bench.insight_cards])

        evidence = ask("What source evidence was uploaded?")
        check("evidence-branch answer", evidence.answer == E_EVIDENCE, evidence.answer)
        check("evidence-branch followups", evidence.followups == ["Show unresolved validation tasks", "Generate Monday Report"], evidence.followups)

        npt = ask("Summarize the NPT")
        check("npt-branch answer", npt.answer == E_NPT, npt.answer)
        check("npt-branch followups", npt.followups == ["Break NPT down by company", "Show high-NPT failures"], npt.followups)

        default = ask("Who is the rig supervisor?")
        check("default-branch answer", default.answer == E_DEFAULT, default.answer)
        check("default-branch followups", default.followups == ["What failed this week?", "Which company caused most NPT?", "Generate Monday Report"], default.followups)

        # ---- edge behavior parity ---------------------------------------------
        paraphrase = ask("What is the rate of penetration trend?")
        check("paraphrase misses benchmark -> default", paraphrase.answer == E_DEFAULT, paraphrase.answer)
        precedence = ask("Draft the NPT report")
        check("draft+npt precedence -> report branch", precedence.answer == E_REPORT, precedence.answer)
        weather = ask("What's the weather tomorrow?")
        check("out-of-domain -> default branch", weather.answer == E_DEFAULT, weather.answer)

        # tool_actions identical across every response (parity of the static block)
        same_tools = all([a.label for a in r.tool_actions] == E_TOOL_LABELS for r in (report, bench, evidence, npt, default, paraphrase, precedence, weather))
        check("tool_actions identical every response", same_tools, "")

        # ---- tenant / workspace isolation -------------------------------------
        # If the decoys leaked, the report answer would count 3 or 4 failures.
        check("tenant/workspace isolation (foreign decoys excluded)", "2 extracted failures" in report.answer, report.answer[:60])

        # ---- citation validator ------------------------------------------------
        fabricated = Citation(locator_type="pdf", locator={"page": 999}, snippet="FABRICATED - not grounded.", confidence=1.0)
        kept = validate_citations([c1, fabricated], allowed=[c1])
        check("validator drops fabricated citation", len(kept) == 1 and citation_key(kept[0]) == citation_key(c1), [citation_key(x) for x in kept])
        passthru = validate_citations([c1], allowed=[c1, fabricated])
        check("validator preserves valid citation unchanged", passthru == [c1], len(passthru))
        # order preserved when all valid
        c_extra = Citation(locator_type="csv", locator={"row": 5}, snippet="Second grounded snippet.", confidence=0.7)
        ordered = validate_citations([c_extra, c1], allowed=[c1, c_extra])
        check("validator preserves order", [citation_key(x) for x in ordered] == [citation_key(c_extra), citation_key(c1)], "")

        # ---- provider failure cannot silently alter behavior -------------------
        class FailingProvider(AIProvider):
            def name(self): return "failing"
            def health(self): return None
            def capabilities(self): return None
            def generate(self, context): raise RuntimeError("provider unavailable")

        original = app_main.DETERMINISTIC_PROVIDER
        app_main.DETERMINISTIC_PROVIDER = FailingProvider()
        try:
            raised = False
            try:
                ask("Draft the Monday report")
            except RuntimeError:
                raised = True
            check("provider failure surfaces (no silent fabricated answer)", raised, "")
        finally:
            app_main.DETERMINISTIC_PROVIDER = original
        # and after restore, behavior is back to deterministic parity
        check("deterministic parity restored after failure test", ask("Draft the Monday report").answer == E_REPORT, "")

        # sanity: DeterministicProvider identity
        check("built-in provider is DeterministicProvider", isinstance(original, DeterministicProvider) and original.name() == "deterministic", original.name())

        # ---- golden parity vs the CURRENT-behavior snapshot -------------------
        # The golden was captured FROM origin/main (pre-refactor) with this exact
        # seed; verify mode asserts the refactored code reproduces it byte-for-byte
        # (volatile citation ids stripped). Re-capture: MONDAY_REPORT_AI_GUARD_CAPTURE=1.
        PROBES = [
            "Draft the Monday report",
            "Show the market benchmark drilling rate",
            "What source evidence was uploaded?",
            "Summarize the NPT",
            "Who is the rig supervisor?",
            "What is the rate of penetration trend?",
            "Draft the NPT report",
            "What's the weather tomorrow?",
        ]

        def _strip_ids(obj):
            if isinstance(obj, dict):
                return {k: _strip_ids(v) for k, v in obj.items() if k != "id"}
            if isinstance(obj, list):
                return [_strip_ids(v) for v in obj]
            return obj

        captured = {p: _strip_ids(ask(p).model_dump(mode="json")) for p in PROBES}
        golden_path = ROOT / "scripts" / "fixtures" / "ai_provider_parity_golden.json"
        if os.environ.get("MONDAY_REPORT_AI_GUARD_CAPTURE") == "1":
            golden_path.parent.mkdir(parents=True, exist_ok=True)
            golden_path.write_text(json.dumps(captured, indent=2, sort_keys=True), encoding="utf-8")
            print(f"golden captured -> {golden_path} ({len(PROBES)} probes)")
        elif not golden_path.exists():
            check("golden fixture present", False, str(golden_path))
        else:
            golden = json.loads(golden_path.read_text(encoding="utf-8"))
            mismatches = [p for p in PROBES if captured.get(p) != golden.get(p)]
            check("golden parity - every probe matches the current-behavior snapshot",
                  not mismatches and set(captured) == set(golden), mismatches or "all match")

    passed = sum(1 for c in CHECKS if c["ok"])
    for c in CHECKS:
        print(f"{'PASS' if c['ok'] else 'FAIL'}: {c['name']}" + ("" if c["ok"] else f"  -- got: {c['detail']}"))
    print(f"\nai_provider_guard: {passed}/{len(CHECKS)} passed")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
