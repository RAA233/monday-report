"""API-layer per-request tenant + workspace resource-ownership authorization.

This module is the single authority for the tenant-ownership boundary enforced at
the API layer. It answers exactly one question: does a resource that a handler
looked up belong to the tenant of the authenticated request?

Design invariants
-----------------
- The request tenant is resolved ONLY from the server-side authenticated identity
  (``identity.tenant_id``). Client-supplied tenant input is never trusted: no route
  accepts a tenant identifier, and nothing here reads a tenant from a request body,
  query string, or header.
- A missing/unresolved/disabled identity yields NO tenant and therefore NO access.
  It is never silently promoted to system or all-tenant access — ``request_tenant_id``
  returns ``None`` and every caller denies. (The route permission gate already denies
  a missing identity before ownership is checked; this is defense-in-depth.)
- Worker/CLI/system operations that legitimately run outside a request use an
  EXPLICIT :class:`SystemTenantContext` naming the configured tenant and an operation
  label, so non-request tenant access is intentional and auditable — never implicit.
- This is the API-layer ownership boundary only. It is NOT multi-tenant storage,
  workspace membership/ACLs, normalized persistence, or Postgres RLS — those remain
  declared GA blockers (see ``docs/TENANT_AUTHORIZATION.md`` and
  ``evals/ga/blocker_registry.v1.json`` ``tenant-authorization-enforcement``). The
  process still serves one configured tenant; this closes the API-layer IDOR gap
  where a resource's ``tenant_id`` was authenticated but never compared to the
  resource actually being accessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from uuid import UUID

from .identity import get_current_identity


def request_tenant_id() -> UUID | None:
    """The tenant of the current authenticated request, or ``None``.

    ``None`` is returned when there is no request-scoped identity or the identity is
    not active. This function NEVER falls back to a configured/system/all-tenant id:
    absence of identity must resolve to absence of access, not to system access.
    """
    identity = get_current_identity()
    if identity is None or identity.account_status != "active":
        return None
    return identity.tenant_id


def resource_tenant_id(resource: Any) -> UUID | None:
    """The tenant a resource is stamped with, or ``None`` if it carries none.

    A resource that has no ``tenant_id`` attribute is treated as owned by nobody
    (default-deny); it can never match a concrete request tenant.
    """
    return getattr(resource, "tenant_id", None)


def owns(resource: Any, tenant_id: UUID | None) -> bool:
    """True iff the resource exists, the request tenant is known, and they match.

    Default-deny: a missing resource, an unknown request tenant (``None``), or a
    resource with no stamped tenant all return ``False``.
    """
    if resource is None or tenant_id is None:
        return False
    owner = resource_tenant_id(resource)
    return owner is not None and owner == tenant_id


def tenant_visible(items: Iterable[Any], tenant_id: UUID | None) -> list[Any]:
    """Filter an iterable of resources to those owned by ``tenant_id``.

    Default-deny: an unknown request tenant (``None``) yields an empty list, never
    the full cross-tenant set.
    """
    if tenant_id is None:
        return []
    return [item for item in items if owns(item, tenant_id)]


@dataclass(frozen=True)
class SystemTenantContext:
    """An EXPLICIT non-request tenant context for worker/CLI/system operations.

    ``actor_source`` is always ``"system"`` and ``operation`` labels why the access
    happens, so a system tenant access is intentional and auditable. Request-path
    code must NEVER construct this — request handlers resolve the tenant with
    :func:`request_tenant_id`, which denies when identity is absent.
    """

    tenant_id: UUID
    operation: str
    actor_source: str = "system"


def system_tenant_context(configured_tenant_id: UUID, operation: str) -> SystemTenantContext:
    """Build an explicit system tenant context. An operation label is required so
    a system/all-tenant access can never be created silently or by default."""
    if not isinstance(operation, str) or not operation.strip():
        raise ValueError("A system tenant context requires an explicit operation label.")
    return SystemTenantContext(tenant_id=configured_tenant_id, operation=operation.strip())
