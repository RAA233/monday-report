"""DeterministicProvider — the current Ask chat behavior, extracted unchanged.

Every f-string, keyword list, branch precedence, citation handling, and the four
enrichment builders below are lifted verbatim from the previous ``main.py`` chat
handler. This provider performs NO model inference and NO network I/O. Behavior is
proven byte-for-byte equal to the prior handler by ``scripts/ai_provider_guard.py``.
"""
from __future__ import annotations

from ..schemas import ChatResponse, FailureRecord
from .citations import dedupe_citations
from .contract import AIProvider, GroundedContext, ProviderCapabilities, ProviderStatus


# --- enrichment builders (moved verbatim from main.py; used only by the chat path) ---

def chat_insight_cards(failures: list[FailureRecord], documents: list, chunk_count: int, open_tasks: int) -> list[dict[str, str]]:
    high_count = len([failure for failure in failures if failure.severity in {"High", "Critical"}])
    total_npt = sum(failure.npt_hours for failure in failures)
    return [
        {
            "label": "Evidence",
            "value": f"{len(documents)} docs / {chunk_count} chunks",
            "detail": "Parsed source scope available to the local analyst.",
            "tone": "good" if documents else "warning",
        },
        {
            "label": "Failures",
            "value": f"{len(failures)} records",
            "detail": f"{high_count} high/critical item(s), {total_npt:.1f} NPT hours.",
            "tone": "danger" if high_count else "info",
        },
        {
            "label": "Validation Gate",
            "value": "clear" if open_tasks == 0 else f"{open_tasks} open",
            "detail": "Official exports remain validation-gated in client mode.",
            "tone": "good" if open_tasks == 0 else "warning",
        },
        {
            "label": "Export Stack",
            "value": "PDF XLSX HTML CSV JSON",
            "detail": "Signed exports are available after the approval gate.",
            "tone": "info",
        },
    ]


def chat_workflow_steps(open_tasks: int, documents: list, failures: list[FailureRecord]) -> list[dict[str, str]]:
    gate_status = "ready" if open_tasks == 0 else "blocked"
    return [
        {
            "step": "Ingest",
            "status": "complete" if documents else "watch",
            "detail": "Parse uploaded reports, tables, email notes, OCR text, and source locators.",
            "command": "Show parsed source evidence",
        },
        {
            "step": "Extract",
            "status": "complete" if failures else "watch",
            "detail": "Create structured failures, NPT, company/tool attribution, confidence, and citations.",
            "command": "Show high-NPT failures",
        },
        {
            "step": "Plan",
            "status": "ready",
            "detail": "Map evidence into normal daily-report sections, casing, risk, and next 24 hr plan.",
            "command": "Plan next morning report",
        },
        {
            "step": "Draft",
            "status": "ready",
            "detail": "Generate client-readable Monday Report language while preserving source-backed constraints.",
            "command": "Create draft report",
        },
        {
            "step": "Schematic",
            "status": "ready",
            "detail": "Render casing strings, hole sections, current depth, shoe depths, and risk markers.",
            "command": "Build casing schematic",
        },
        {
            "step": "Export",
            "status": gate_status,
            "detail": "Package signed PDF/XLSX/HTML/CSV/JSON artifacts after validation closure.",
            "command": "Generate Monday Report",
        },
    ]


def chat_risk_register(open_tasks: int, documents: list, failures: list[FailureRecord]) -> list[dict[str, str]]:
    total_npt = sum(failure.npt_hours for failure in failures)
    high_count = len([failure for failure in failures if failure.severity in {"High", "Critical"}])
    risks = [
        {
            "title": "Validation backlog",
            "severity": "high" if open_tasks else "low",
            "detail": f"{open_tasks} validation task(s) are open.",
            "mitigation": "Close or countersign validation tasks before official issue.",
        },
        {
            "title": "Evidence coverage",
            "severity": "medium" if not documents else "low",
            "detail": f"{len(documents)} parsed document(s) are available for this workspace.",
            "mitigation": "Import the latest DDR, BHA, mud, survey, and service-company files before client signoff.",
        },
        {
            "title": "Operational severity",
            "severity": "high" if high_count or total_npt >= 8 else "medium",
            "detail": f"{high_count} high/critical item(s), {total_npt:.1f} NPT hour(s).",
            "mitigation": "Prioritize high-NPT failures and confirm company/tool attribution with citations.",
        },
    ]
    return risks


def chat_tool_actions() -> list[dict[str, str]]:
    return [
        {
            "label": "Plan DDR",
            "prompt": "Plan next morning report",
            "detail": "Build the normal report section map and approval path.",
            "kind": "plan",
        },
        {
            "label": "Draft Report",
            "prompt": "Create draft report",
            "detail": "Generate report language using current evidence and validation status.",
            "kind": "draft",
        },
        {
            "label": "Draw Schematic",
            "prompt": "Build casing schematic",
            "detail": "Create casing, hole-section, depth, and risk-marker instructions.",
            "kind": "schematic",
        },
        {
            "label": "Audit Gate",
            "prompt": "Show unresolved validation tasks",
            "detail": "Review blockers before official export.",
            "kind": "audit",
        },
    ]


class DeterministicProvider(AIProvider):
    """The built-in, always-available grounded-answer generator. Stateless,
    single-shot, no model, no network."""

    def name(self) -> str:
        return "deterministic"

    def health(self) -> ProviderStatus:
        return ProviderStatus(provider="deterministic", available=True, detail="built-in deterministic analysis")

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(streaming=False, multi_turn=False, max_context_tokens=None)

    def generate(self, context: GroundedContext) -> ChatResponse:
        # Local names mirror the previous handler exactly so the branch bodies below
        # are byte-identical to what shipped.
        failures = context.failures
        documents = context.documents
        chunk_count = context.chunk_count
        citations = context.base_citations
        open_tasks = context.open_tasks
        benchmark_status = context.benchmark_status
        normalized = context.content.lower()

        insight_cards = chat_insight_cards(failures, documents, chunk_count, len(open_tasks))
        workflow_steps = chat_workflow_steps(len(open_tasks), documents, failures)
        risk_register = chat_risk_register(len(open_tasks), documents, failures)
        tool_actions = chat_tool_actions()

        wants_report_workflow = any(
            term in normalized
            for term in [
                "monday report",
                "morning report",
                "daily report",
                "generate",
                "draft",
                "schematic",
                "plan",
                "execute",
                "client package",
                "export",
            ]
        )
        if wants_report_workflow:
            validation_phrase = (
                f"{len(open_tasks)} validation task(s) must close before official issue"
                if open_tasks
                else "validation gate is clear for official export"
            )
            return ChatResponse(
                answer=(
                    f"Draft Monday Report workflow is ready from {len(failures)} extracted failures and "
                    f"{sum(failure.npt_hours for failure in failures):.1f} NPT hours. "
                    "Plan: normalize the source daily-report format into well/job information, present operations, drilling parameters, mud/BHA/survey, casing, timeline, NPT, risks, and approvals. "
                    "Execute: generate the branded report, render the well schematic, attach citations, then export PDF/XLSX/HTML/CSV/JSON after the approval gate. "
                    f"Current gate: {validation_phrase}."
                ),
                citations=citations,
                followups=[
                    "Plan next morning report",
                    "Build casing schematic",
                    "Create draft report",
                    "Show unresolved validation tasks",
                ],
                confidence_notes=[
                    "Response uses local source chunks plus structured failure data.",
                    "AI may plan and draft immediately, but official exports stay blocked by validation policy.",
                ],
                workflow_steps=workflow_steps,
                insight_cards=insight_cards,
                risk_register=risk_register,
                tool_actions=tool_actions,
                export_actions=[
                    "monday_report_pdf",
                    "monday_report_xlsx",
                    "monday_report_html",
                    "monday_report_csv",
                    "monday_report_json",
                ],
            )

        if any(term in normalized for term in ["benchmark", "market", "ft/day", "drilling rate", "dls"]):
            if benchmark_status is None:
                answer = "Benchmarking is not available for this workspace yet."
                benchmark_citations = citations
                benchmark_followups = ["Import daily drilling data", "Create draft report"]
            else:
                active = benchmark_status.active_anomalies
                comparison_text = "; ".join(
                    f"{item.metric} vs {item.benchmark_name}: {item.performance_status}"
                    for item in benchmark_status.comparisons[:4]
                )
                answer = (
                    f"Market benchmark status: current ft/day is "
                    f"{benchmark_status.current_ft_per_day if benchmark_status.current_ft_per_day is not None else 'missing'}, "
                    f"seven-day average is "
                    f"{benchmark_status.seven_day_average_ft_per_day if benchmark_status.seven_day_average_ft_per_day is not None else 'missing'}. "
                    f"{comparison_text or 'No approved comparison is available yet.'} "
                    f"{len(active)} active benchmark anomaly/anomalies are in review."
                )
                benchmark_citations = citations + [
                    citation
                    for anomaly in active
                    for citation in anomaly.supporting_citations
                ]
                benchmark_followups = [
                    "Show Market Benchmark",
                    "Explain active anomalies",
                    "Prepare Management of Change evidence",
                ]
                insight_cards = [
                    *insight_cards,
                    {
                        "label": "Benchmark",
                        "value": (
                            f"{benchmark_status.current_ft_per_day:g} ft/day"
                            if benchmark_status.current_ft_per_day is not None
                            else "missing"
                        ),
                        "detail": f"{len(active)} active anomaly/anomalies, {len(benchmark_status.comparisons)} comparison row(s).",
                        "tone": "danger" if any(item.severity == "Critical" for item in active) else "info",
                    },
                ]
            return ChatResponse(
                answer=answer,
                citations=dedupe_citations(benchmark_citations),
                followups=benchmark_followups,
                confidence_notes=[
                    "Benchmark statements are categorized in the Benchmarking module and require review before client issue.",
                    "Top-quartile gaps are performance gaps and are not presented as confirmed operational failures.",
                ],
                workflow_steps=workflow_steps,
                insight_cards=insight_cards,
                risk_register=risk_register,
                tool_actions=tool_actions,
                export_actions=["benchmark_evidence_json", "moc_evidence_pdf"],
            )

        if any(term in normalized for term in ["uploaded", "parsed", "source", "evidence", "file"]):
            return ChatResponse(
                answer=(
                    f"Parsed evidence is available from {len(documents)} uploaded document(s) "
                    f"with {chunk_count} source chunk(s). The worker stores chunk lineage by file, "
                    "upload, workspace, and tenant before local AI extraction runs."
                ),
                citations=citations,
                followups=["Show unresolved validation tasks", "Generate Monday Report"],
                confidence_notes=["This answer uses parser-worker chunks plus seeded structured failure data."],
                workflow_steps=workflow_steps,
                insight_cards=insight_cards,
                risk_register=risk_register,
                tool_actions=tool_actions,
            )

        if "npt" in normalized:
            return ChatResponse(
                answer=(
                    f"Current extracted evidence shows {sum(failure.npt_hours for failure in failures):.1f} "
                    "NPT hours linked to failure records."
                ),
                citations=citations,
                followups=["Break NPT down by company", "Show high-NPT failures"],
                workflow_steps=workflow_steps,
                insight_cards=insight_cards,
                risk_register=risk_register,
                tool_actions=tool_actions,
            )

        return ChatResponse(
            answer=(
                f"I found {len(failures)} extracted failure record(s). "
                "The current executable slice is API-ready for local AI extraction workers."
            ),
            citations=citations,
            followups=["What failed this week?", "Which company caused most NPT?", "Generate Monday Report"],
            workflow_steps=workflow_steps,
            insight_cards=insight_cards,
            risk_register=risk_register,
            tool_actions=tool_actions,
        )


#: The single built-in provider instance used by the chat handler in Phase 1.
DETERMINISTIC_PROVIDER = DeterministicProvider()
