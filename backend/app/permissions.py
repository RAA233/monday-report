"""Generic role/permission authorization policy.

This is the single authorization authority for the application. It defines the
stable permission identifiers, the role -> permission matrix, and default-deny
evaluation used by every route guard. It replaces the Benchmarking-specific
``benchmark_permissions`` as the source of truth (that function now delegates
here for backward compatibility).

Only the four existing roles are used (ADMIN, ENGINEER, VALIDATOR, MANAGER); the
legacy ``VIEWER`` role is intentionally NOT activated and receives no
permissions. Unknown roles, unknown permissions, and empty role sets all deny.
This module implements route-level RBAC only — it is NOT multi-tenant resource
authorization, verified reviewer workflow, or keyed audit integrity, which
remain declared blockers.
"""
from __future__ import annotations

from collections.abc import Iterable

from .schemas import Role

# --- Stable permission identifiers ----------------------------------------
# Existing keys (preserved exactly, including their role mapping below).
VIEW_BENCHMARKS = "view_benchmarks"
MANAGE_BENCHMARK_CONFIG = "manage_benchmark_config"
REVIEW_ANOMALIES = "review_anomalies"
DISMISS_ANOMALIES = "dismiss_anomalies"
RUN_DIAGNOSTICS = "run_diagnostics"
APPROVE_AI_CONTENT = "approve_ai_content"
ISSUE_CLIENT_REPORTS = "issue_client_reports"
EXPORT_EVIDENCE = "export_evidence"
EDIT_DECISION_RECORDS = "edit_decision_records"
VIEW_AUDIT_HISTORY = "view_audit_history"
RECORD_FIELD_CORRECTIONS = "record_field_corrections"
VIEW_FIELD_CORRECTIONS = "view_field_corrections"
# New, route-grounded keys added for complete route-level RBAC.
VIEW_WORKSPACES = "view_workspaces"
MANAGE_WORKSPACES = "manage_workspaces"
VIEW_SOURCE_DOCUMENTS = "view_source_documents"
MANAGE_UPLOADS = "manage_uploads"
VIEW_PROCESSING_STATUS = "view_processing_status"
VIEW_VALIDATION_QUEUE = "view_validation_queue"
RESOLVE_VALIDATION = "resolve_validation"
VIEW_REPORTS = "view_reports"
GENERATE_REPORTS = "generate_reports"
VIEW_RUNTIME_STATUS = "view_runtime_status"
RUN_RETENTION = "run_retention"
# Administrative (identity/credential provisioning) is a role gate, not a
# permission grant; represented here so the route inventory can reference it.
ADMIN_ONLY = "__admin__"

ALL_PERMISSIONS: frozenset[str] = frozenset(
    {
        VIEW_BENCHMARKS,
        MANAGE_BENCHMARK_CONFIG,
        REVIEW_ANOMALIES,
        DISMISS_ANOMALIES,
        RUN_DIAGNOSTICS,
        APPROVE_AI_CONTENT,
        ISSUE_CLIENT_REPORTS,
        EXPORT_EVIDENCE,
        EDIT_DECISION_RECORDS,
        VIEW_AUDIT_HISTORY,
        RECORD_FIELD_CORRECTIONS,
        VIEW_FIELD_CORRECTIONS,
        VIEW_WORKSPACES,
        MANAGE_WORKSPACES,
        VIEW_SOURCE_DOCUMENTS,
        MANAGE_UPLOADS,
        VIEW_PROCESSING_STATUS,
        VIEW_VALIDATION_QUEUE,
        RESOLVE_VALIDATION,
        VIEW_REPORTS,
        GENERATE_REPORTS,
        VIEW_RUNTIME_STATUS,
        RUN_RETENTION,
    }
)

# --- Role -> permission matrix --------------------------------------------
# The existing benchmarking/field-correction permission grants are preserved
# exactly (see benchmark_permissions compatibility). New permissions use
# conservative, route-grounded defaults; where repository evidence does not
# establish a permission for a role it is denied (see docs/ROUTE_RBAC.md).
_ENGINEER_PERMISSIONS = frozenset(
    {
        # preserved
        VIEW_BENCHMARKS,
        REVIEW_ANOMALIES,
        RUN_DIAGNOSTICS,
        EXPORT_EVIDENCE,
        EDIT_DECISION_RECORDS,
        RECORD_FIELD_CORRECTIONS,
        VIEW_FIELD_CORRECTIONS,
        # new
        VIEW_WORKSPACES,
        VIEW_SOURCE_DOCUMENTS,
        MANAGE_UPLOADS,
        VIEW_PROCESSING_STATUS,
        VIEW_REPORTS,
        GENERATE_REPORTS,
    }
)
_VALIDATOR_PERMISSIONS = frozenset(
    {
        # preserved
        VIEW_BENCHMARKS,
        REVIEW_ANOMALIES,
        DISMISS_ANOMALIES,
        APPROVE_AI_CONTENT,
        VIEW_AUDIT_HISTORY,
        RECORD_FIELD_CORRECTIONS,
        VIEW_FIELD_CORRECTIONS,
        # new
        VIEW_WORKSPACES,
        VIEW_SOURCE_DOCUMENTS,
        VIEW_PROCESSING_STATUS,
        VIEW_VALIDATION_QUEUE,
        RESOLVE_VALIDATION,
        VIEW_REPORTS,
    }
)
_MANAGER_PERMISSIONS = frozenset(
    {
        # preserved (MANAGER holds every existing permission)
        VIEW_BENCHMARKS,
        MANAGE_BENCHMARK_CONFIG,
        REVIEW_ANOMALIES,
        DISMISS_ANOMALIES,
        RUN_DIAGNOSTICS,
        APPROVE_AI_CONTENT,
        ISSUE_CLIENT_REPORTS,
        EXPORT_EVIDENCE,
        EDIT_DECISION_RECORDS,
        VIEW_AUDIT_HISTORY,
        RECORD_FIELD_CORRECTIONS,
        VIEW_FIELD_CORRECTIONS,
        # new
        VIEW_WORKSPACES,
        MANAGE_WORKSPACES,
        VIEW_SOURCE_DOCUMENTS,
        VIEW_REPORTS,
        GENERATE_REPORTS,
        VIEW_RUNTIME_STATUS,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.ENGINEER: _ENGINEER_PERMISSIONS,
    Role.VALIDATOR: _VALIDATOR_PERMISSIONS,
    Role.MANAGER: _MANAGER_PERMISSIONS,
    # VIEWER is intentionally unactivated: no permissions.
    Role.VIEWER: frozenset(),
}


def is_known_permission(permission: str) -> bool:
    return permission in ALL_PERMISSIONS


def permissions_for_roles(roles: Iterable[Role]) -> frozenset[str]:
    """Deterministic union of the permissions granted by the given roles.
    Unknown roles contribute nothing (default-deny)."""
    granted: set[str] = set()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def has_permission(roles: Iterable[Role], permission: str) -> bool:
    """Default-deny check. An unknown permission, an empty/unknown role set, or a
    role that lacks the permission all return False."""
    if not is_known_permission(permission):
        return False
    return permission in permissions_for_roles(roles)


def permission_map(roles: Iterable[Role]) -> dict[str, bool]:
    """A stable {permission: bool} view over ALL known permissions for the given
    roles (used for the session/config permission display)."""
    granted = permissions_for_roles(roles)
    return {permission: permission in granted for permission in sorted(ALL_PERMISSIONS)}
