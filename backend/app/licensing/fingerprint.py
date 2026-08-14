"""``mr-machine-fingerprint.v1`` — privacy-preserving, tolerant machine binding.

Raw hardware values NEVER leave this module: collectors read them, normalize
them deterministically, hash them (SHA-256 domain-separated by fingerprint
version + component name), and discard them. Everything outside this module —
activation requests, licenses, logs, diagnostics, evidence — sees only hashes,
counts, and confidence classes.

Binding is a tolerant k-of-n match over independent components; the MAC address
is at most ONE optional component and never sufficient alone. Full machine
cloning copies every fact and therefore cannot be distinguished here — clone
resistance comes from the protected licensing state and clock lineage
(``state_guard``), and virtual-machine execution is reported explicitly via the
confidence class. Missing optional facts degrade the component count instead of
crashing activation.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass

from .canonical import canonical_hash
from .contract import BindingConfidence, MachineBindingResult

FINGERPRINT_VERSION = "mr-machine-fingerprint.v1"

#: Components strong enough to anchor a binding. A match must include at least
#: one of these — a MAC-only collision can never activate another machine.
STRONG_COMPONENTS = ("machine_guid", "smbios_uuid")

#: Documented tolerance: a license binds to all eligible components at issue
#: time and keeps matching while at least ``max(2, n-1)`` components (including
#: one strong component) still match — so ONE approved hardware change (e.g. a
#: replaced network adapter or re-serialized board) does not disable a
#: legitimate installation, while a different machine (nearly all components
#: differ) is rejected.
MIN_MATCHES = 2

#: SMBIOS strings that identify placeholder/absent serials — excluded instead of
#: bound so vendor-blank values do not create cross-machine collisions.
_PLACEHOLDER_VALUES = {
    "",
    "NONE",
    "UNKNOWN",
    "DEFAULT STRING",
    "TO BE FILLED BY O.E.M.",
    "SYSTEM SERIAL NUMBER",
    "0",
    "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
    "00000000-0000-0000-0000-000000000000",
}

_VM_MARKERS = ("VMWARE", "VIRTUALBOX", "VIRTUAL MACHINE", "HYPER-V", "QEMU", "KVM", "XEN", "PARALLELS")

#: Adapter descriptions that are transient/virtual and MUST NOT bind a license.
_EXCLUDED_ADAPTER_MARKERS = (
    "VPN",
    "TAP",
    "TUN",
    "LOOPBACK",
    "VIRTUAL",
    "HYPER-V",
    "VMWARE",
    "VETHERNET",
    "WSL",
    "DOCKER",
    "BLUETOOTH",
    "NDISWAN",
    "TEREDO",
    "ISATAP",
)


def _normalize(value: str) -> str:
    return re.sub(r"[\s:\-{}]", "", str(value)).upper()


def _component_hash(name: str, normalized_value: str) -> str:
    seed = f"{FINGERPRINT_VERSION}|{name}|{normalized_value}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()


def _powershell(script: str, timeout: int = 20) -> str:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def collect_windows_facts() -> tuple[dict[str, str], bool]:
    """Collect raw machine facts (Windows). Returns ``(facts, is_virtual)``.

    Raw values stay inside this module. Every collector tolerates absence.
    """

    facts: dict[str, str] = {}
    is_virtual = False

    if sys.platform == "win32":
        try:  # Windows cryptography MachineGuid — stable per Windows install.
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                facts["machine_guid"] = str(winreg.QueryValueEx(key, "MachineGuid")[0])
        except OSError:
            pass

        smbios = _powershell(
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID"
        )
        if smbios:
            facts["smbios_uuid"] = smbios

        board = _powershell("(Get-CimInstance Win32_BaseBoard).SerialNumber")
        if board:
            facts["board_serial"] = board

        volume = _powershell(
            "(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber"
        )
        if volume:
            facts["system_volume_serial"] = volume

        # Stable PHYSICAL adapters only; permanent (burned-in) address when
        # available. Transient/virtual adapters are excluded so VPN/container
        # churn never affects the binding. At most one aggregated component:
        # MAC material is a single optional vote, never the whole binding.
        adapters = _powershell(
            "Get-NetAdapter -Physical | Where-Object { $_.HardwareInterface } | "
            "ForEach-Object { $_.PermanentAddress + '|' + $_.InterfaceDescription }"
        )
        macs: list[str] = []
        for line in adapters.splitlines():
            address, _, description = line.strip().partition("|")
            upper_desc = description.upper()
            if any(marker in upper_desc for marker in _EXCLUDED_ADAPTER_MARKERS):
                continue
            normalized = _normalize(address)
            if len(normalized) == 12 and normalized not in {"0" * 12, "F" * 12}:
                macs.append(normalized)
        if macs:
            facts["physical_adapters"] = ",".join(sorted(set(macs)))

        system_info = _powershell(
            "$cs = Get-CimInstance Win32_ComputerSystem; $cs.Manufacturer + ' ' + $cs.Model"
        ).upper()
        is_virtual = any(marker in system_info for marker in _VM_MARKERS)

    return facts, is_virtual


@dataclass(frozen=True)
class Fingerprint:
    """Hashed machine fingerprint. Carries NO raw values."""

    version: str
    component_hashes: dict[str, str]
    is_virtual: bool

    @property
    def eligible_components(self) -> int:
        return len(self.component_hashes)

    def binding_document(self) -> dict:
        """The machine_binding object embedded in licenses and activation
        requests (hashes only)."""

        return {
            "fingerprint_version": self.version,
            "component_hashes": dict(sorted(self.component_hashes.items())),
            "match_threshold": required_matches(self.eligible_components),
            "strong_components": [
                name for name in STRONG_COMPONENTS if name in self.component_hashes
            ],
        }

    def fingerprint_hash(self) -> str:
        return canonical_hash(self.binding_document())


def required_matches(eligible: int) -> int:
    """Tolerate one changed component on well-populated machines while never
    accepting fewer than MIN_MATCHES.

    Capped at ``eligible`` so a degraded machine (only one collectable fact,
    e.g. CIM/PowerShell blocked by policy) cannot be issued a binding that can
    never match even itself. A strong component is still mandatory, so this
    never weakens cross-machine rejection.
    """

    return min(max(eligible, 1), max(MIN_MATCHES, eligible - 1))


def from_facts(facts: dict[str, str], *, is_virtual: bool = False) -> Fingerprint:
    """Build a fingerprint from raw facts, hashing and discarding them.

    Placeholder/absent values are excluded rather than bound.
    """

    hashes: dict[str, str] = {}
    for name, raw in facts.items():
        normalized = _normalize(raw)
        if normalized in _PLACEHOLDER_VALUES:
            continue
        hashes[str(name)] = _component_hash(str(name), normalized)
    return Fingerprint(
        version=FINGERPRINT_VERSION, component_hashes=hashes, is_virtual=bool(is_virtual)
    )


def collect_fingerprint() -> Fingerprint:
    """Production path: collect Windows facts, hash them, discard raws."""

    facts, is_virtual = collect_windows_facts()
    return from_facts(facts, is_virtual=is_virtual)


def evaluate_binding(local: Fingerprint, license_binding: dict) -> MachineBindingResult:
    """Compare the LOCAL fingerprint to a license's machine_binding.

    Redacted output only: counts, classes, and the match verdict.
    """

    licensed_hashes = dict(license_binding.get("component_hashes", {}))
    threshold = int(license_binding.get("match_threshold", MIN_MATCHES))
    version_ok = license_binding.get("fingerprint_version") == local.version

    matched = 0
    strong_matched = False
    if version_ok:
        for name, licensed_hash in licensed_hashes.items():
            if local.component_hashes.get(name) == licensed_hash:
                matched += 1
                if name in STRONG_COMPONENTS:
                    strong_matched = True

    if local.eligible_components == 0:
        confidence = BindingConfidence.UNAVAILABLE
    elif local.is_virtual:
        confidence = BindingConfidence.REDUCED_VIRTUAL_MACHINE
    elif local.eligible_components < 3:
        confidence = BindingConfidence.DEGRADED_FEW_COMPONENTS
    else:
        confidence = BindingConfidence.STRONG

    is_match = version_ok and strong_matched and matched >= threshold
    return MachineBindingResult(
        fingerprint_version=local.version,
        eligible_components=local.eligible_components,
        matched_components=matched,
        required_matches=threshold,
        strong_component_matched=strong_matched,
        confidence=confidence,
        matched=is_match,
    )


def redacted_diagnostic(result: MachineBindingResult) -> dict:
    """The ONLY machine-binding diagnostic the application may surface."""

    return {
        "fingerprint_version": result.fingerprint_version,
        "eligible_components": result.eligible_components,
        "binding_confidence": result.confidence.value,
        "match": "match" if result.matched else "mismatch",
    }
