"""C1 -- the ONLY way offline-boundary Python resolves or invokes a native OS
binary. Twin of ``packaging/hyperv/lib/trusted_natives.ps1``; the two must
agree on the allowlist and the trust predicate.

WHY THIS TERMINATES A CLASS
---------------------------
Six review rounds each found one more author-controllable operand behind a
"trusted" native invocation ($env:SystemRoot, PATH, profile shims, working
directory). Enumeration cannot terminate, so this module removes the operands:

* the system directory comes from ``GetSystemDirectoryW`` -- a Windows API
  answer, never an environment variable, never PATH, never a relative path;
* the allowlist is FIXED, and git is deliberately absent: a name not listed
  cannot be resolved here at all, which is what makes git structurally
  uninvokable inside the boundary (C4);
* before first use, the binary's owner must be TrustedInstaller or SYSTEM and
  no principal outside SYSTEM / TrustedInstaller / BUILTIN\\Administrators may
  hold any write-capable right on it. Failure to READ the descriptor refuses
  the run -- fail closed, never open.

SCOPE (stated honestly): this predicate verifies the BINARY's own owner and
DACL. It relies on the system directory itself (the parent) being
OS-protected -- which it is, by the same TrustedInstaller/SYSTEM ownership that
resolves it -- so a non-administrative author cannot replace a binary via
parent-directory delete/create rights. The predicate does not separately audit
the parent's DACL; that protection is a property of a correctly-installed
Windows System32, not an author-controllable operand in this threat model.
"""
from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from pathlib import Path

#: Fixed allowlist: logical name -> path relative to the system directory.
#: git is deliberately absent and must never be added (C4): provenance is
#: carried as operator-recorded manifest data, never queried from a repository
#: inside the boundary.
ALLOWLIST = {
    "icacls": "icacls.exe",
    "takeown": "takeown.exe",
    "robocopy": "Robocopy.exe",
    "schtasks": "schtasks.exe",
    "netstat": "NETSTAT.EXE",
    "tasklist": "tasklist.exe",
    "whoami": "whoami.exe",
    "bcdboot": "bcdboot.exe",
    "powershell": "WindowsPowerShell\\v1.0\\powershell.exe",
}

TRUSTED_OWNER_SIDS = (
    "S-1-5-18",                                                        # SYSTEM
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
)
TRUSTED_WRITE_SIDS = TRUSTED_OWNER_SIDS + ("S-1-5-32-544",)            # + Administrators

#: Rights that count as "can change the binary or its policy":
#: FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
#: | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE
WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_SE_FILE_OBJECT = 1
_ACCESS_ALLOWED_ACE_TYPE = 0

_verified: dict[str, bool] = {}


class TrustedNativeRefusal(RuntimeError):
    """Any C1 trust failure. Refusal is an exception so a forgotten caller
    check cannot fail open."""


def system_directory() -> Path:
    """The system directory from the OS, with no environment operand."""

    buffer = ctypes.create_unicode_buffer(wintypes.MAX_PATH + 1)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not length:
        raise TrustedNativeRefusal("TRUSTED_NATIVES_SYSTEM_DIR_UNRESOLVED")
    path = Path(buffer.value)
    if not path.is_dir():
        raise TrustedNativeRefusal("TRUSTED_NATIVES_SYSTEM_DIR_UNRESOLVED")
    return path


def _sid_to_string(sid_pointer) -> str:
    out = ctypes.c_wchar_p()
    if not ctypes.windll.advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(out)):
        raise TrustedNativeRefusal("TRUSTED_NATIVES_OWNER_UNRESOLVED")
    try:
        return str(out.value)
    finally:
        ctypes.windll.kernel32.LocalFree(out)


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte),
                ("AceFlags", ctypes.c_ubyte),
                ("AceSize", wintypes.WORD)]


def verify_descriptor(path: Path, *, write_mask: int = WRITE_MASK) -> None:
    """The trust predicate for one already-resolved binary path.

    Returns None on success; raises :class:`TrustedNativeRefusal` on any
    failure INCLUDING failure to read or parse the descriptor.

    ``write_mask`` is the set of rights that count as "can change the binary or
    its policy"; it defaults to the production mask and exists as a seam so the
    natives-trust guard can drive the DACL-parse REFUSE branch over a real
    binary's real (non-trusted) allow ACE -- the production faults are
    owner-untrusted and stop at the owner check, leaving the ACE loop witnessed
    only in the accept direction otherwise.
    """

    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = ctypes.windll.advapi32.GetNamedSecurityInfoW(
        str(path), _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner_sid), None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor))
    if status != 0:
        raise TrustedNativeRefusal(
            f"TRUSTED_NATIVES_DESCRIPTOR_UNREADABLE: {path} (win32 status {status})")
    try:
        owner = _sid_to_string(owner_sid)
        if owner not in TRUSTED_OWNER_SIDS:
            raise TrustedNativeRefusal(
                f"TRUSTED_NATIVES_OWNER_UNTRUSTED: {path} owner={owner}")

        if not dacl.value:
            # A NULL DACL grants everyone full control.
            raise TrustedNativeRefusal(
                f"TRUSTED_NATIVES_WRITABLE_BY_UNTRUSTED_PRINCIPAL: {path} (null DACL)")

        size_info = _AclSizeInformation()
        if not ctypes.windll.advapi32.GetAclInformation(
                dacl, ctypes.byref(size_info), ctypes.sizeof(size_info), 2):
            raise TrustedNativeRefusal(
                f"TRUSTED_NATIVES_DESCRIPTOR_UNREADABLE: {path} (ACL size query failed)")

        for index in range(size_info.AceCount):
            ace_pointer = ctypes.c_void_p()
            if not ctypes.windll.advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise TrustedNativeRefusal(
                    f"TRUSTED_NATIVES_DESCRIPTOR_UNREADABLE: {path} (ACE {index} unreadable)")
            header = ctypes.cast(ace_pointer, ctypes.POINTER(_AceHeader)).contents
            if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                # Deny ACEs only narrow access; unknown allow types are handled
                # below via the fail-closed branch.
                if header.AceType in (1,):  # ACCESS_DENIED_ACE_TYPE
                    continue
                # Object/callback/unknown ACE types: this predicate cannot
                # interpret them, so it refuses rather than guessing.
                raise TrustedNativeRefusal(
                    f"TRUSTED_NATIVES_DESCRIPTOR_UNREADABLE: {path} "
                    f"(unrecognized ACE type {header.AceType})")
            mask = ctypes.cast(
                ctypes.c_void_p(ace_pointer.value + ctypes.sizeof(_AceHeader)),
                ctypes.POINTER(wintypes.DWORD)).contents.value
            if not (mask & write_mask):
                continue
            sid_address = ace_pointer.value + ctypes.sizeof(_AceHeader) + ctypes.sizeof(wintypes.DWORD)
            sid = _sid_to_string(ctypes.c_void_p(sid_address))
            if sid not in TRUSTED_WRITE_SIDS:
                raise TrustedNativeRefusal(
                    f"TRUSTED_NATIVES_WRITABLE_BY_UNTRUSTED_PRINCIPAL: {path} sid={sid}")
    finally:
        if descriptor.value:
            ctypes.windll.kernel32.LocalFree(descriptor)


def resolve(name: str) -> Path:
    """Resolve an allowlisted logical name to a verified absolute path."""

    key = name.lower()
    if key not in ALLOWLIST:
        raise TrustedNativeRefusal(
            f"TRUSTED_NATIVES_NAME_NOT_ALLOWLISTED: '{name}' is not a trusted native "
            "(git and every other unlisted binary is structurally uninvokable here)")
    resolved = system_directory() / ALLOWLIST[key]
    if not resolved.is_file():
        raise TrustedNativeRefusal(f"TRUSTED_NATIVES_BINARY_ABSENT: {resolved}")
    cache_key = str(resolved).lower()
    if cache_key not in _verified:
        verify_descriptor(resolved)
        _verified[cache_key] = True
    return resolved


def run(name: str, *arguments: str, timeout: int = 120,
        capture: bool = True) -> subprocess.CompletedProcess:
    """Invoke an allowlisted native. The executable path is always the
    verified absolute path; the child never resolves anything through PATH."""

    exe = resolve(name)
    return subprocess.run([str(exe), *arguments], capture_output=capture,
                          text=True, timeout=timeout)
