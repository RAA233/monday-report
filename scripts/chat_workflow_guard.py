from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    checks: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="monday-report-chat-workflow-") as tmp:
        configure_guard_env(Path(tmp))

        from backend.app.main import chat
        from backend.app.schemas import (
            ChatRequest,
            Citation,
            FailureRecord,
            ValidationStatus,
            ValidationTask,
        )
        from backend.app.store import store
        from backend.app.identity import set_current_identity

        # chat now enforces route-level RBAC via the request-scoped identity the
        # HTTP middleware normally sets. This guard invokes the handler
        # in-process, so establish the same demo_bootstrap administrator identity
        # the middleware would resolve in demo mode.
        set_current_identity(store.demo_bootstrap_identity())

        workspace = next(iter(store.workspaces.values()))
        citation = Citation(
            locator_type="pdf",
            locator={"page": 7, "section": "daily drilling report"},
            snippet="MWD signal instability and circulation loss noted during drilling ahead.",
            confidence=0.92,
        )
        failure = FailureRecord(
            tenant_id=store.tenant.id,
            workspace_id=workspace.id,
            event_type="MWD signal loss",
            severity="High",
            summary="MWD signal loss created NPT while drilling ahead.",
            company="Anonymized Directional Services",
            tool_type="MWD",
            tool_serial="MWD-042",
            npt_hours=8.5,
            confidence=0.92,
            validation_status=ValidationStatus.OPEN,
            citations=[citation],
        )
        task = ValidationTask(
            tenant_id=store.tenant.id,
            target_type="failure",
            target_id=failure.id,
            reason="Guarded chat workflow validation task.",
            priority="high",
            status=ValidationStatus.OPEN,
        )
        store.failures[failure.id] = failure
        store.validation_tasks[task.id] = task
        store.save()

        response = chat(
            ChatRequest(
                workspace_id=workspace.id,
                content="Plan and execute a client-ready Monday Report with schematic.",
                filters={},
            )
        )
        payload = response.model_dump(mode="json")

        checks.append(
            assert_check(
                "Structured report answer",
                "Plan:" in response.answer and "Execute:" in response.answer and "extracted failures" in response.answer,
                response.answer,
            )
        )
        checks.append(
            assert_check(
                "Workflow steps",
                len(response.workflow_steps) >= 6
                and {step.step for step in response.workflow_steps} >= {"Ingest", "Extract", "Plan", "Draft", "Schematic", "Export"}
                and any(step.status == "blocked" for step in response.workflow_steps),
                payload.get("workflow_steps"),
            )
        )
        checks.append(
            assert_check(
                "Insight cards",
                len(response.insight_cards) >= 4
                and any(card.label == "Validation Gate" and "open" in card.value for card in response.insight_cards),
                payload.get("insight_cards"),
            )
        )
        checks.append(
            assert_check(
                "Risk register",
                len(response.risk_register) >= 3
                and any(item.title == "Validation backlog" and item.severity == "high" for item in response.risk_register),
                payload.get("risk_register"),
            )
        )
        checks.append(
            assert_check(
                "Tool actions and exports",
                len(response.tool_actions) >= 4
                and {"monday_report_pdf", "monday_report_xlsx"}.issubset(set(response.export_actions)),
                {"tool_actions": payload.get("tool_actions"), "export_actions": payload.get("export_actions")},
            )
        )

    failed = [check for check in checks if not check["ok"]]
    for check in checks:
        status = "PASS" if check["ok"] else "FAIL"
        print(f"{status}: {check['name']} - {check['detail']}")
    return 1 if failed else 0


def configure_guard_env(tmp_root: Path) -> None:
    os.environ["MONDAY_REPORT_CLIENT_DATA_MODE"] = "demo"
    os.environ["MONDAY_REPORT_DISABLE_DEMO_SEED"] = "true"
    os.environ["MONDAY_REPORT_TENANT_NAME"] = "Chat Workflow Guard Tenant"
    os.environ["MONDAY_REPORT_TENANT_SLUG"] = "chat-workflow-guard"
    os.environ["MONDAY_REPORT_USER_EMAIL"] = "reviewer@example.test"
    os.environ["MONDAY_REPORT_USER_FULL_NAME"] = "Chat Workflow Reviewer"
    os.environ["MONDAY_REPORT_DEFAULT_WORKSPACE_NAME"] = "Chat workflow guard workspace"
    os.environ["MONDAY_REPORT_STATE_PATH"] = str(tmp_root / "state.json")
    os.environ["MONDAY_REPORT_STORAGE_ROOT"] = str(tmp_root / "storage")
    os.environ["MONDAY_REPORT_EXPORT_ROOT"] = str(tmp_root / "exports")
    for key in [
        "MONDAY_REPORT_API_KEY",
        "VITE_MONDAY_REPORT_API_KEY",
        "MONDAY_REPORT_SIGNING_SECRET",
        "MONDAY_REPORT_REPOSITORY_BACKEND",
        "MONDAY_REPORT_DATABASE_URL",
        "DATABASE_URL",
        "MONDAY_REPORT_QUEUE_BACKEND",
        "MONDAY_REPORT_REDIS_URL",
        "REDIS_URL",
    ]:
        os.environ.pop(key, None)


def assert_check(name: str, ok: bool, detail: object) -> dict[str, object]:
    return {"name": name, "ok": ok, "detail": detail}


if __name__ == "__main__":
    sys.exit(main())
