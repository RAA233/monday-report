"""Offline-first commercial licensing for Monday Report.

This package owns the SaaS-compatible licensing abstraction (``contract``), the
signed offline license format (``license_format``), privacy-preserving machine
binding (``fingerprint``), air-gapped activation (``activation``), protected
local licensing state with clock-rollback detection (``state_guard``), the fully
implemented offline provider (``offline_provider``), and the signed offline
update manifest format (``update_format``).

Only the PUBLIC verification key ships with the application. The private signing
key lives outside the repository and outside every customer installation; it is
read exclusively by the operator issuance CLI from an explicit protected path or
a process-local environment reference.
"""
