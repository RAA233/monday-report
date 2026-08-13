"""Black-box guard for the Phase-1 offline bootstrap (Windows only).

WHAT THIS IS
------------
`packaging/offline/Invoke-OfflineBootstrap.ps1` runs before any source in this
repository is trusted.  This guard treats it as an OPAQUE BINARY.  It reads the
file's bytes, records its SHA-256, refuses to launch anything whose hash does not
match the recorded value, and then launches that exact file through an absolute
`powershell.exe` path resolved with GetSystemDirectoryW.

THE ORACLE IS NOT THE BOOTSTRAP'S OUTPUT.
Every verdict below is formed from two things only:

  1. the process EXIT CODE, and
  2. observations THIS FILE makes for itself - directory existence, file sets,
     SHA-256 digests computed here with `hashlib`, owner/DACL read here through
     `GetNamedSecurityInfoW` + SDDL, reparse state read here through
     `GetFileAttributesW`, object identity read here through
     `GetFileInformationByHandle`, DOS-device mappings read here through
     `QueryDosDeviceW`, and the live process table read here through
     `CreateToolhelp32Snapshot`.

The bootstrap's stdout is captured so a human can read it (`--show-stdout`), and
is never consulted by any assertion.  If a scenario's only available evidence
were the bootstrap's own text, that scenario would not be listed as covered.

WHY THE REASON MATTERS AS MUCH AS THE REFUSAL
---------------------------------------------
A scenario that refuses for an INCIDENTAL reason - a missing fixture, an
unhandled exception, a mistyped path - looks exactly like a scenario that refuses
for the property under test, if all you check is "non-zero".  Every scenario
therefore declares the exact refusal code it expects, and every row is classified
as one of:

  PASS                expected reason AND every independent observation held
  FAIL-WRONG-REASON   refused, but with a different code -> INCIDENTAL; this row
                      is NOT evidence for the property
  FAIL-NO-REFUSAL     the bootstrap accepted what it should have refused
  FAIL-EVIDENCE       expected reason, but an independent observation showed the
                      damage happened anyway
  INCONCLUSIVE        a fixture never managed to inject its hostile change, or a
                      platform facility it needs is unavailable; the run proves
                      nothing either way
  NOT-RUN-ELEVATION   the property cannot be demonstrated by an unelevated
                      process without faking a principal.  Not a pass, not a
                      failure: an honest gap, with the exact elevated command
                      printed for the operator.

The code -> name table below is THIS FILE'S OWN copy of the published taxonomy.
It is not read from the bootstrap, so a bootstrap that renumbered its codes would
fail these scenarios rather than redefine what they mean.

ELEVATION - READ THIS BEFORE BELIEVING ANY ROW
----------------------------------------------
The bootstrap's trust set is exactly {SYSTEM, BUILTIN\\Administrators,
TrustedInstaller} and NOTHING widens it.  A previous revision accepted a
`-TrustedSid` argument, and the previous harness used it to make itself trusted -
which is to say the previous harness proved things about a bootstrap configured
to trust the attacker it was being tested against.  That parameter is gone.

The consequence is unavoidable and is not worked around here.  An UNELEVATED
process cannot create a directory owned by any trusted principal - its filtered
token has BUILTIN\\Administrators as deny-only, so every directory it creates is
owned by itself.  Therefore:

  * every REFUSAL path, the whole bundle/name/pin policy, the process-and-temp
    observation and the DOS-device chain bypass are proved here, unelevated;
  * every property that requires the bootstrap to ACCEPT a chain and INSTALL -
    the happy path, the created root's owner/DACL, the pre-created root, the
    junction root, the post-hash byte tamper, the destination swap, the occupied
    subdirectory - is reported NOT-RUN-ELEVATION-REQUIRED, with the exact
    elevated command to complete it.

Those rows are NOT quietly turned green, and no fake principal stands in for the
operator.  Where a mechanism could otherwise ship with no experiment at all, a
clearly separated SECOND TIER runs it against a DELIBERATELY WEAKENED copy of the
bootstrap (one that trusts this account) so the mechanism's presence and its
deletion can still be compared.  That tier is labelled on every line and is
explicitly NOT acceptance evidence for the production bootstrap.

Run with `--delete-mechanism` for the self-review step: for each scenario,
disable the specific mechanism it targets in a temporary COPY of the bootstrap
and require the outcome to flip.  That mode is self-review evidence, not the
acceptance oracle; the acceptance oracle is the scenario table.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "packaging" / "offline" / "Invoke-OfflineBootstrap.ps1"

BUNDLE_CONTRACT = "offline-bootstrap-bundle/v2"

# The harness's own copy of the published refusal taxonomy.
REASONS = {
    0: "OK",
    10: "ARGS_INVALID",
    11: "UNEXPECTED_ERROR",
    12: "NATIVE_INIT_FAILED",
    19: "SOURCE_NOT_ANCHORED",
    20: "SOURCE_MISSING",
    21: "SOURCE_REPARSE",
    22: "SOURCE_GIT_PATH",
    23: "SOURCE_COLLISION",
    24: "SOURCE_NAME_UNSAFE",
    25: "BUNDLE_PIN_MISMATCH",
    26: "SOURCE_UNREADABLE",
    27: "SOURCE_EMPTY_DIRECTORY",
    28: "MANIFEST_UNSORTED",
    29: "SOURCE_CANONICAL_UNRESOLVED",
    30: "PARENT_MISSING",
    31: "PARENT_REPARSE",
    32: "PARENT_DACL_ABSENT",
    33: "PARENT_ACE_UNINTERPRETABLE",
    34: "PARENT_OWNER_UNTRUSTED",
    35: "PARENT_UNSAFE_WRITABLE_ACE",
    36: "PARENT_NOT_ANCHORED",
    37: "PARENT_CANONICAL_UNRESOLVED",
    38: "PARENT_CHAIN_UNSTABLE",
    40: "ROOT_EXISTS",
    41: "ROOT_CREATE_FAILED",
    42: "ROOT_REPARSE",
    43: "ROOT_DACL_ABSENT",
    44: "ROOT_ACE_UNINTERPRETABLE",
    45: "ROOT_OWNER_UNTRUSTED",
    46: "ROOT_UNSAFE_WRITABLE_ACE",
    47: "ROOT_MISSING",
    48: "ROOT_NOT_ANCHORED",
    49: "ROOT_CANONICAL_UNRESOLVED",
    50: "COPY_FAILED",
    51: "DESTINATION_MISMATCH",
    52: "ROOT_IDENTITY_CHANGED",
    53: "COPY_DIRECTORY_OCCUPIED",
    54: "ROOT_CHAIN_UNSTABLE",
    60: "DESTINATION_MISSING",
    61: "DESTINATION_REPARSE",
    62: "DESTINATION_GIT_PATH",
    63: "DESTINATION_COLLISION",
    64: "DESTINATION_NAME_UNSAFE",
    66: "DESTINATION_UNREADABLE",
    67: "DESTINATION_EMPTY_DIRECTORY",
}


def reason_of(code):
    if code is None:
        return "NO-EXIT"
    return REASONS.get(code, "UNMAPPED-%d" % code)


# ---------------------------------------------------------------------------
# Win32.  Every evidence-producing read in this file goes through here; nothing
# observes through the bootstrap.
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_WRITE = 0x40000000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FSCTL_SET_REPARSE_POINT = 0x000900A4
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SDDL_REVISION_1 = 1
SECURITY_INFO = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

DDD_RAW_TARGET_PATH = 0x00000001
DDD_REMOVE_DEFINITION = 0x00000002
DDD_EXACT_MATCH_ON_REMOVE = 0x00000004

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

CREATE_NO_WINDOW = 0x08000000

# A file with one of these suffixes is never forgiven by the interpreter
# baseline, whatever it is called.  Compiling C# in %TEMP% leaves source, an
# assembly, symbols, a response file and the compiler's captured output, and a
# prefix allowance derived from a baseline must not be able to excuse any of
# them just because the names happened to rhyme.
CODE_ARTIFACT_SUFFIXES = (".cs", ".dll", ".exe", ".pdb", ".obj", ".res", ".netmodule",
                          ".cmdline", ".rsp", ".err", ".out", ".tmp", ".il")


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wt.DWORD),
        ("ftCreationTime", wt.FILETIME),
        ("ftLastAccessTime", wt.FILETIME),
        ("ftLastWriteTime", wt.FILETIME),
        ("dwVolumeSerialNumber", wt.DWORD),
        ("nFileSizeHigh", wt.DWORD),
        ("nFileSizeLow", wt.DWORD),
        ("nNumberOfLinks", wt.DWORD),
        ("nFileIndexHigh", wt.DWORD),
        ("nFileIndexLow", wt.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * MAX_PATH),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.POINTER(ctypes.c_ulong))]


kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD, wt.HANDLE]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.GetFileAttributesW.restype = wt.DWORD
kernel32.GetFileAttributesW.argtypes = [wt.LPCWSTR]
kernel32.GetFileInformationByHandle.argtypes = [wt.HANDLE,
                                                ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
kernel32.GetSystemDirectoryW.restype = ctypes.c_uint
kernel32.GetSystemDirectoryW.argtypes = [wt.LPWSTR, ctypes.c_uint]
kernel32.LocalFree.restype = ctypes.c_void_p
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_char_p, wt.DWORD,
                                     ctypes.c_void_p, wt.DWORD,
                                     ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.DefineDosDeviceW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR]
kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
kernel32.GetLogicalDrives.restype = wt.DWORD
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

advapi32.GetNamedSecurityInfoW.restype = wt.DWORD
advapi32.GetNamedSecurityInfoW.argtypes = [
    wt.LPCWSTR, ctypes.c_int, wt.DWORD,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p)]
advapi32.SetNamedSecurityInfoW.restype = wt.DWORD
advapi32.SetNamedSecurityInfoW.argtypes = [
    wt.LPWSTR, ctypes.c_int, wt.DWORD,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wt.DWORD, wt.DWORD,
    ctypes.POINTER(wt.LPWSTR), ctypes.POINTER(ctypes.c_ulong)]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_ulong)]
advapi32.ConvertStringSidToSidW.argtypes = [wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetSecurityDescriptorDacl.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.BOOL), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wt.BOOL)]
advapi32.CheckTokenMembership.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(wt.BOOL)]
ntdll.NtSetInformationFile.argtypes = [wt.HANDLE, ctypes.POINTER(IO_STATUS_BLOCK),
                                       ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]


def long_path(path):
    """The \\\\?\\ form of a path, IDEMPOTENTLY.

    os.path.abspath goes through GetFullPathNameW, which strips trailing spaces
    and dots even from an already-extended path - so re-normalising a path that
    is already extended silently renames 'Sub ' to 'Sub'.  Several scenarios
    exist to exercise exactly that ambiguity, so the harness must not
    reintroduce it.
    """
    if path.startswith("\\\\?\\"):
        return path
    return "\\\\?\\" + os.path.abspath(path)


def ensure_dir(extended):
    """mkdir -p over extended paths, without renormalising any component."""
    if kernel32.GetFileAttributesW(extended) != INVALID_FILE_ATTRIBUTES:
        return
    head = extended.rsplit("\\", 1)[0]
    if len(head) > len("\\\\?\\C:"):
        ensure_dir(head)
    os.mkdir(extended)


def file_attributes(path):
    return kernel32.GetFileAttributesW(long_path(path))


def is_reparse_point(path):
    attrs = file_attributes(path)
    return attrs != INVALID_FILE_ATTRIBUTES and bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def exists(path):
    return file_attributes(path) != INVALID_FILE_ATTRIBUTES


def listing(path):
    try:
        return sorted(os.listdir(long_path(path))) if exists(path) else None
    except OSError:
        return None


def object_identity(path):
    """(volume serial, file index) of the object this path names right now."""
    handle = kernel32.CreateFileW(long_path(path), 0, FILE_SHARE_ALL, None,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        return None
    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return None
        return (info.dwVolumeSerialNumber,
                (info.nFileIndexHigh << 32) | info.nFileIndexLow)
    finally:
        kernel32.CloseHandle(handle)


def security_descriptor_sddl(path):
    """Owner + DACL of `path` as SDDL text, read by this harness."""
    psd = ctypes.c_void_p()
    if advapi32.GetNamedSecurityInfoW(os.path.abspath(path), SE_FILE_OBJECT,
                                      SECURITY_INFO, None, None, None, None,
                                      ctypes.byref(psd)) != 0:
        return None
    if not psd:
        return None
    try:
        out = wt.LPWSTR()
        size = ctypes.c_ulong(0)
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                psd, SDDL_REVISION_1, SECURITY_INFO, ctypes.byref(out), ctypes.byref(size)):
            return None
        try:
            return out.value
        finally:
            kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
    finally:
        kernel32.LocalFree(psd)


# SDDL prints an access mask either as 0x... or with the mnemonic table below.
# 'DC' is 0x2 - which on a FILE object is FILE_WRITE_DATA/FILE_ADD_FILE, even
# though the mnemonic is spelled for directory-service objects.  The harness
# decodes rather than string-matches, so an assertion about WHICH class of right
# an ACE grants is an assertion about the mask, not about Windows' spelling.
SDDL_RIGHTS = {
    "CC": 0x00000001, "DC": 0x00000002, "LC": 0x00000004, "SW": 0x00000008,
    "RP": 0x00000010, "WP": 0x00000020, "DT": 0x00000040, "LO": 0x00000080,
    "CR": 0x00000100, "SD": 0x00010000, "RC": 0x00020000, "WD": 0x00040000,
    "WO": 0x00080000, "GA": 0x10000000, "GX": 0x20000000, "GW": 0x40000000,
    "GR": 0x80000000, "FA": 0x001F01FF, "FR": 0x00120089, "FW": 0x00120116,
    "FX": 0x001200A0, "KA": 0x000F003F, "KR": 0x00020019,
}

REDIRECT_CLASS_MASK = 0x00010000 | 0x00040000 | 0x00080000 | 0x00000040 | 0x10000000
CONTENT_CLASS_MASK = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000100


def sddl_ace_masks(sddl, sid_token):
    """Every ACE in `sddl` granted to `sid_token`, as integer access masks."""
    masks = []
    for chunk in (sddl or "").split("(")[1:]:
        ace = chunk.split(")")[0]
        fields = ace.split(";")
        if len(fields) < 6 or fields[0] != "A" or fields[5] != sid_token:
            continue
        rights = fields[2]
        if rights.lower().startswith("0x"):
            masks.append(int(rights, 16))
            continue
        value = 0
        for index in range(0, len(rights) - 1, 2):
            value |= SDDL_RIGHTS.get(rights[index:index + 2].upper(), 0)
        masks.append(value)
    return masks


def apply_sddl_dacl(path, sddl):
    """Fixture setup: give `path` an explicit, PROTECTED DACL."""
    psd = ctypes.c_void_p()
    size = ctypes.c_ulong(0)
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, ctypes.byref(psd), ctypes.byref(size)):
        raise OSError("bad SDDL %r: %d" % (sddl, ctypes.get_last_error()))
    try:
        present = wt.BOOL()
        pdacl = ctypes.c_void_p()
        defaulted = wt.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(psd, ctypes.byref(present),
                                                  ctypes.byref(pdacl),
                                                  ctypes.byref(defaulted)):
            raise OSError("GetSecurityDescriptorDacl failed")
        status = advapi32.SetNamedSecurityInfoW(
            os.path.abspath(path), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, pdacl, None)
        if status != 0:
            raise OSError("SetNamedSecurityInfoW failed: %d" % status)
    finally:
        kernel32.LocalFree(psd)


def create_junction(link, target):
    """Fixture setup: a real NTFS directory junction, built without launching
    anything - no mklink, no cmd.exe."""
    os.makedirs(long_path(link), exist_ok=False)
    subst = ("\\??\\" + os.path.abspath(target) + "\\").encode("utf-16-le")
    printed = os.path.abspath(target).encode("utf-16-le")
    path_buffer = subst + b"\x00\x00" + printed + b"\x00\x00"
    payload = struct.pack("<HHHH", 0, len(subst), len(subst) + 2, len(printed)) + path_buffer
    buffer = struct.pack("<IHH", IO_REPARSE_TAG_MOUNT_POINT, len(payload), 0) + payload
    handle = kernel32.CreateFileW(
        long_path(link), GENERIC_WRITE, 0, None, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        raise OSError("open junction stub failed: %d" % ctypes.get_last_error())
    try:
        returned = wt.DWORD()
        if not kernel32.DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer,
                                        len(buffer), None, 0,
                                        ctypes.byref(returned), None):
            raise OSError("FSCTL_SET_REPARSE_POINT failed: %d" % ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


def current_user_sid():
    TOKEN_QUERY = 0x0008
    TokenUser = 1
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(wt.HANDLE(kernel32.GetCurrentProcess()),
                                     TOKEN_QUERY, ctypes.byref(token)):
        raise OSError("OpenProcessToken failed")
    try:
        size = wt.DWORD(0)
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, TokenUser, buffer, size,
                                            ctypes.byref(size)):
            raise OSError("GetTokenInformation failed")
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        out = wt.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr), ctypes.byref(out)):
            raise OSError("ConvertSidToStringSidW failed")
        try:
            return out.value
        finally:
            kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def is_elevated():
    """Membership of BUILTIN\\Administrators in the CURRENT token - the same
    question PowerShell's IsInRole(Administrator) answers, asked here so the
    harness never has to believe the bootstrap about it."""
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
        return False
    try:
        member = wt.BOOL()
        if not advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):
            return False
        return bool(member.value)
    finally:
        kernel32.LocalFree(sid)


def free_drive_letter():
    used = kernel32.GetLogicalDrives()
    for index in range(25, 2, -1):          # Z: down to D:
        if not (used >> index) & 1:
            return chr(ord("A") + index)
    return None


def define_dos_device(letter, target):
    """A SUBST-equivalent drive, created WITHOUT launching subst.exe.

    DefineDosDeviceW writes into the CALLING USER'S DosDevices directory, so an
    ordinary unelevated account can do this.  That is the whole point of the
    scenario that uses it: the drive letter an operator types can be a mapping
    the attacker made.
    """
    if not kernel32.DefineDosDeviceW(DDD_RAW_TARGET_PATH, letter + ":",
                                     "\\??\\" + os.path.abspath(target)):
        raise OSError("DefineDosDeviceW failed: %d" % ctypes.get_last_error())


def remove_dos_device(letter, target):
    kernel32.DefineDosDeviceW(
        DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE,
        letter + ":", "\\??\\" + os.path.abspath(target))


def query_dos_device(letter):
    buffer = ctypes.create_unicode_buffer(2048)
    if not kernel32.QueryDosDeviceW(letter + ":", buffer, 2048):
        return None
    return buffer.value


def set_case_sensitive_directory(path):
    """Per-directory case sensitivity (FileCaseSensitiveInformation, class 71).

    Without it two members differing only in ASCII case cannot both exist on a
    normal NTFS volume, and the collision scenario has nothing to build.  Set
    through NtSetInformationFile rather than fsutil.exe, because launching
    fsutil would put a child process inside a run whose whole point is that
    there are none.  Returns True on success; the caller reports the scenario
    INCONCLUSIVE rather than green if this is unavailable.
    """
    handle = kernel32.CreateFileW(long_path(path), 0x0100 | 0x0080, FILE_SHARE_ALL, None,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        return False
    try:
        info = ctypes.c_ulong(1)            # FILE_CS_FLAG_CASE_SENSITIVE_DIR
        iosb = IO_STATUS_BLOCK()
        status = ntdll.NtSetInformationFile(handle, ctypes.byref(iosb),
                                            ctypes.byref(info), 4, 71)
        return status == 0
    finally:
        kernel32.CloseHandle(handle)


def reset_dacl(path):
    """Give a fixture directory back a DACL this account can delete through.

    The fixtures deliberately carry protected read-only DACLs.  This account
    still OWNS them, and an owner always retains WRITE_DAC, so cleanup is a
    matter of putting a permissive DACL back - never of taking ownership.
    """
    try:
        apply_sddl_dacl(path, "D:P(A;OICI;FA;;;%s)" % ME)
    except OSError:
        pass


def remove_tree(path):
    """Delete a fixture tree WITHOUT following junctions - shutil.rmtree would
    walk through one and delete the target's contents."""
    if not exists(path):
        return
    attrs = file_attributes(path)
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
        (os.rmdir if attrs & FILE_ATTRIBUTE_DIRECTORY else os.remove)(long_path(path))
        return
    if not attrs & FILE_ATTRIBUTE_DIRECTORY:
        os.remove(long_path(path))
        return
    reset_dacl(path)
    try:
        names = os.listdir(long_path(path))
    except OSError:
        return
    for name in names:
        remove_tree(long_path(path) + "\\" + name)
    try:
        os.rmdir(long_path(path))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Process observation.  The whole of defect D1 is "a compiler ran before any
# check did", so the harness has to be able to see a child process appear.
# ---------------------------------------------------------------------------

def process_snapshot():
    """{pid: (ppid, exe name)} read from the live process table."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or snapshot is None:
        return {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        table = {}
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return {}
        while True:
            table[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID),
                                               str(entry.szExeFile))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
        return table
    finally:
        kernel32.CloseHandle(snapshot)


class Watcher(object):
    """Polls the process table and a set of directories for the whole of a run.

    Everything it reports is something it saw ITSELF.  It records the union of
    what ever existed, not just the end state, because a compiler that cleans up
    after itself is still a compiler that ran.

    WHAT COUNTS AS THE BOOTSTRAP'S DOING.  Starting powershell.exe at all costs a
    console host process and a couple of script-policy probe files in %TEMP%, and
    those appear whatever the script contains - including for a script that is a
    single `exit`.  Attributing them to the bootstrap would be false, and
    hard-coding a list of names to forgive would be a guess that the next Windows
    build invalidates.  So the harness MEASURES the interpreter's own footprint
    first (see HostBaseline) by running a trivial script through the identical
    launcher, and every assertion below is about what the bootstrap's run
    produced BEYOND that measurement.
    """

    # Names that never appear in the baseline and whose appearance is the whole
    # of defect D1.  Listed for reporting; the assertions do not depend on the
    # list being complete, because "anything not in the measured baseline" is the
    # actual test.
    TOOLCHAIN_NAMES = ("csc.exe", "cvtres.exe", "vbc.exe", "cl.exe", "link.exe",
                       "al.exe", "ilasm.exe", "cmd.exe", "wmic.exe", "mshta.exe",
                       "rundll32.exe", "regsvr32.exe", "msbuild.exe")

    def __init__(self, watch_dirs=()):
        self.watch_dirs = tuple(watch_dirs)
        self.baseline = process_snapshot()
        self.descendants = {}          # pid -> exe name
        self.new_named = {}            # pid -> exe name (compiler-ish, any parent)
        self.artifacts = set()         # union of everything seen in watch_dirs
        self.samples = 0
        self._root_pids = set()
        self._stop = threading.Event()
        self._thread = None
        self._sweep_dirs()

    def _sweep_dirs(self):
        for directory in self.watch_dirs:
            try:
                for name in os.listdir(long_path(directory)):
                    self.artifacts.add(name)
            except OSError:
                pass

    def track(self, pid):
        self._root_pids.add(pid)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            self.sample()
            time.sleep(0.004)

    def sample(self):
        self.samples += 1
        table = process_snapshot()
        for pid, (ppid, name) in table.items():
            if pid in self.baseline:
                continue
            if name.lower() in self.TOOLCHAIN_NAMES:
                self.new_named[pid] = name
            # Walk up: a grandchild of the bootstrap is still the bootstrap's doing.
            cursor, hops = ppid, 0
            while cursor and hops < 8:
                if cursor in self._root_pids:
                    self.descendants[pid] = name
                    break
                parent = table.get(cursor)
                if parent is None:
                    break
                cursor, hops = parent[0], hops + 1
        self._sweep_dirs()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.sample()

    def descendant_names(self):
        return set(name.lower() for name in self.descendants.values())

    def beyond(self, host):
        """(unexpected processes, toolchain processes, unexpected artifacts) -
        everything this run produced that the measured interpreter baseline did
        not."""
        extra_processes = dict(
            (pid, name) for pid, name in self.descendants.items()
            if name.lower() not in host.process_names)
        toolchain = dict(
            (pid, name) for pid, name in self.descendants.items()
            if name.lower() in self.TOOLCHAIN_NAMES)
        extra_artifacts = sorted(
            name for name in self.artifacts
            if not any(name.startswith(prefix) for prefix in host.artifact_prefixes)
            or name.lower().endswith(CODE_ARTIFACT_SUFFIXES))
        return extra_processes, toolchain, extra_artifacts


class HostBaseline(object):
    """What powershell.exe costs before the bootstrap has done anything at all.

    Measured, not assumed: a script containing nothing but `exit 0` is run
    through the identical launcher, with the identical TEMP override, watched by
    the identical Watcher.  Whatever that produces is the interpreter's, not the
    bootstrap's, and is subtracted from every later observation.  A reviewer sees
    the measurement printed, so the subtraction is auditable rather than a
    hard-coded allowance.
    """

    def __init__(self, base):
        self.process_names = set()
        self.artifact_prefixes = set()
        self.raw_processes = {}
        self.raw_artifacts = []
        self.script = Path(base) / "_host-baseline.ps1"
        with open(str(self.script), "w", encoding="utf-8", newline="") as handle:
            handle.write("exit 0\n")
        temp = str(Path(base) / "_host-baseline-temp")
        ensure_dir(long_path(temp))
        # Three passes, not one.  Windows PowerShell writes its script-policy
        # probe files only on SOME launches, so a single measurement produced a
        # baseline that sometimes contained them and sometimes did not - and a
        # run measured against the empty version reported the interpreter's own
        # files as the bootstrap's.  The scenarios that depend on this pair each
        # observed run with a fresh measurement as well (measure_into), so the
        # subtraction never rests on one sample.
        for _ in range(3):
            self.measure_into(temp)
        self.raw_artifacts = sorted(self.artifact_prefixes)

    def measure_into(self, temp):
        """Run the trivial script with TEMP=`temp` and fold what it produces into
        the baseline.  Any file it leaves behind is removed, so the directory is
        clean for the observed run that follows."""
        watcher = Watcher([temp])
        watcher.start()
        try:
            command = [system_powershell(), "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-File", str(self.script)]
            environment = dict(os.environ)
            environment.update({"TEMP": temp, "TMP": temp})
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, cwd=str(ROOT),
                                       env=environment, creationflags=CREATE_NO_WINDOW)
            watcher.track(process.pid)
            process.communicate(timeout=120)
        finally:
            watcher.stop()
        self.raw_processes.update(watcher.descendants)
        self.process_names |= watcher.descendant_names()
        for name in watcher.artifacts:
            # '__PSScriptPolicyTest_abc.def.ps1' -> '__PSScriptPolicyTest_'.
            # rsplit, not split: splitting on the FIRST underscore of a name that
            # begins with one yields the empty string, and a prefix of '_' would
            # forgive every artifact whose name happens to start with it -
            # including the '_CodeDom' style names a compiler leaves behind.
            head = name.rsplit("_", 1)[0]
            self.artifact_prefixes.add(head + "_" if head else name)
        for name in list(watcher.artifacts):
            try:
                os.remove(long_path(temp) + "\\" + name)
            except OSError:
                pass

    def describe(self):
        return ("processes=%s artifacts=%s (subtracted from every observation below)"
                % (sorted(self.process_names) or "none",
                   sorted(self.artifact_prefixes) or "none"))


# ---------------------------------------------------------------------------
# The bundle root hash, reimplemented here from the published pre-image.
#
# Deliberately a SECOND implementation in a different language.  The harness
# plays the operator: it holds the pin.  When the bootstrap accepts a pin
# computed here, two independent implementations agreed on the bytes.
#
# The ASCII fold is written out as an explicit a->A map for the same reason the
# bootstrap writes it out: str.upper() is a FULL Unicode mapping and .NET's is a
# simple one, and a shared alphabet is worth nothing if the two sides reach it by
# different routes.
# ---------------------------------------------------------------------------

def _ascii_upper(text):
    return "".join(chr(ord(ch) - 32) if "a" <= ch <= "z" else ch for ch in text)


def _folded(components):
    return "/".join(_ascii_upper(component) for component in components)


def enumerate_bundle(root, follow_reparse=False):
    """Every file under `root`, walked here.

    Reparse points are NOT followed by default: a junction inside a bundle means
    part of what is being pinned lives somewhere else, and the operator's pin
    must cover the bundle, not the bundle plus whatever the junction currently
    points at.  A scenario that wants to see what a bootstrap WITHOUT that rule
    would have hashed asks for follow_reparse=True explicitly.
    """
    members = []
    stack = [(long_path(root), ())]
    while stack:
        directory, components = stack.pop()
        for name in os.listdir(directory):
            entry = directory + "\\" + name
            here = components + (name,)
            attrs = kernel32.GetFileAttributesW(entry)
            if attrs == INVALID_FILE_ATTRIBUTES:
                raise OSError("unreadable: %s" % entry)
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT and not follow_reparse:
                continue
            if attrs & FILE_ATTRIBUTE_DIRECTORY:
                stack.append((entry, here))
                continue
            with open(entry, "rb") as handle:
                data = handle.read()
            members.append({
                "relative": "/".join(here),
                "folded": _folded(here),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })
    return members


def bundle_root_hash(root, follow_reparse=False):
    members = sorted(enumerate_bundle(root, follow_reparse), key=lambda m: m["folded"])
    parts = [BUNDLE_CONTRACT, "\n", "members=", str(len(members)), "\n"]
    for member in members:
        parts += [member["relative"], "\0", member["sha256"], "\0",
                  str(member["size"]), "\n"]
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def tree_digests(root):
    """relative path -> sha256, computed here."""
    if not exists(root) or is_reparse_point(root):
        return None
    return dict((m["relative"], m["sha256"]) for m in enumerate_bundle(root))


def file_digest(path):
    if not exists(path):
        return None
    with open(long_path(path), "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


# ---------------------------------------------------------------------------
# Launching the opaque binary
# ---------------------------------------------------------------------------

def system_powershell():
    buffer = ctypes.create_unicode_buffer(1024)
    if not kernel32.GetSystemDirectoryW(buffer, 1024):
        raise OSError("GetSystemDirectoryW failed")
    path = os.path.join(buffer.value, "WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.isfile(path):
        raise OSError("powershell.exe not found at %s" % path)
    return path


class Image(object):
    """The pinned bootstrap file: bytes in, hash recorded."""

    def __init__(self, path, label="production"):
        self.path = Path(path)
        self.label = label
        self.sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def reverify(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest() == self.sha256


class Launch(object):
    def __init__(self, code, stdout, launched, note="", watcher=None):
        self.code = code
        self.stdout = stdout
        self.launched = launched
        self.note = note
        self.watcher = watcher

    @property
    def reason(self):
        return reason_of(self.code) if self.launched else "NOT-LAUNCHED"


def launch(image, args, expected_hash=None, on_running=None, timeout=600,
           env_overrides=None, watch_dirs=()):
    """Verify the pin, then run the exact pinned file.

    `expected_hash` defaults to the hash recorded when the Image was built.  A
    scenario may pass a different value to model an operator holding the WRONG
    pin; a mismatch means nothing is launched at all.

    The run is watched throughout: the process table is polled so a child
    process cannot appear and exit unseen, and every directory in `watch_dirs`
    is polled so a temporary artifact cannot be created and deleted unseen.
    """
    pin = image.sha256 if expected_hash is None else expected_hash
    actual = hashlib.sha256(image.path.read_bytes()).hexdigest()
    if actual != pin:
        return Launch(None, "", False, "pin mismatch: pinned=%s actual=%s" % (pin, actual))

    command = [system_powershell(), "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(image.path)]
    command += [str(a) for a in args]

    environment = dict(os.environ)
    if env_overrides:
        environment.update(env_overrides)

    watcher = Watcher(watch_dirs)
    watcher.start()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, cwd=str(ROOT),
                                   env=environment, creationflags=CREATE_NO_WINDOW)
        watcher.track(process.pid)
        if on_running is not None:
            on_running(process)
        try:
            out, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            out, _ = process.communicate()
            return Launch(None, out.decode("utf-8", "replace"), True, "timed out", watcher)
        return Launch(process.returncode, out.decode("utf-8", "replace"), True, "", watcher)
    finally:
        watcher.stop()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ME = current_user_sid()
ELEVATED = is_elevated()
HOST = None            # HostBaseline, measured once in main() before any scenario

# A protected DACL with NO write ACE for this account.  A node carrying it is
# clean by every mask test the bootstrap applies and fails ONLY on its owner -
# which is this unelevated account, because an unelevated account cannot create a
# directory owned by anyone else.  0x1200a9 is FILE_GENERIC_READ|FILE_EXECUTE:
# read, list, traverse, read attributes, read the ACL.  Not one of those bits is
# in the redirect class or the content class, so granting them cannot be what a
# refusal is about - but they are enough for the bootstrap to OPEN the node,
# which it must be able to do for the node to be judged at all.
SAFE_READONLY = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;%s)" % ME

# The same, with this account given full control.  Used ONLY by the second-tier
# runs against a deliberately weakened bootstrap that trusts this account, and by
# the source trees, which are never chain-judged.
MINE_FULL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)" % ME

# Elevated runs create directories owned by BUILTIN\Administrators, so the
# fixture needs no ACE for the operator at all.
ADMIN_ONLY = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


class Workspace(object):
    """Somewhere to keep bundle sources.  Never part of a judged chain."""

    def __init__(self, base):
        self.dir = str(Path(base) / "sources")
        ensure_dir(long_path(self.dir))
        self._n = 0

    def source(self):
        self._n += 1
        path = self.dir + "\\src%02d" % self._n
        ensure_dir(long_path(path))
        return Source(path)


class Source(object):
    def __init__(self, path):
        self.path = path

    def write(self, relative, data):
        target = long_path(self.path) + "\\" + relative.replace("/", "\\")
        ensure_dir(target.rsplit("\\", 1)[0])
        with open(target, "wb") as handle:
            handle.write(data)
        return target

    def mkdir(self, relative):
        ensure_dir(long_path(self.path) + "\\" + relative.replace("/", "\\"))

    def small_bundle(self):
        self.write("a.txt", b"alpha\n")
        self.write("sub/b.txt", b"beta\n")
        self.write("sub/c.bin", bytes(bytearray(range(256))))
        # Sorts AFTER 'sub/...', so a depth-first walk emits it BEFORE the
        # subdirectory's members.  Enumeration order therefore differs from
        # manifest order in every fixture that uses this bundle.
        self.write("z.txt", b"omega\n")
        return self

    def pin(self, follow_reparse=False):
        return bundle_root_hash(self.path, follow_reparse)


class Chain(object):
    """A fixture chain whose FIRST component is a directory of its own directly
    under the volume root.

    That placement is forced, and it is worth being explicit about why.  The
    bootstrap walks a canonical chain top-down and refuses at the FIRST component
    that fails.  Every directory an unelevated account creates is owned by that
    account, so the topmost directory this harness owns would fail on its owner
    and hide anything planted below it.  Placing each chain fixture directly
    under the volume root means the only components above the planted property
    are the volume root itself and nothing else - and the volume root is a real
    OS-owned directory that the production trust set accepts, as CTL-PROGFILES
    shows independently.
    """

    ALL = []

    def __init__(self, tag, depth=1, mode="production"):
        self.tag = tag
        self.mode = mode
        letter = os.path.abspath(os.sep)[0]
        self.top = "%s:\\mrb5-%s-%s" % (letter, tag, uuid.uuid4().hex[:8])
        ensure_dir(long_path(self.top))
        Chain.ALL.append(self.top)
        self.nodes = [self.top]
        cursor = self.top
        for index in range(depth):
            cursor = cursor + "\\n%d" % index
            ensure_dir(long_path(cursor))
            self.nodes.append(cursor)
        self.parent = cursor

    @property
    def default_dacl(self):
        if self.mode == "weakened":
            return MINE_FULL
        return ADMIN_ONLY if ELEVATED else SAFE_READONLY

    def harden(self, extra=None):
        """Apply DACLs bottom-up, so a node made read-only cannot block the write
        that gives its child a DACL."""
        extra = extra or {}
        for node in reversed(self.nodes):
            apply_sddl_dacl(node, self.default_dacl + extra.get(node, ""))

    def root(self, root_name="trustroot"):
        return self.parent + "\\" + root_name

    def args(self, source, root_name="trustroot", pin=None, parent=None):
        return ["-RootName", root_name,
                "-SourcePath", source.path,
                "-ExpectedBundleHash", pin if pin else source.pin(),
                "-ParentPath", parent if parent else self.parent]


# ---------------------------------------------------------------------------
# Scenario framework
# ---------------------------------------------------------------------------

class Result(object):
    def __init__(self, ident, title, expected, launch_result, checks, note=""):
        self.id = ident
        self.title = title
        self.expected = expected
        self.launch = launch_result
        self.checks = checks              # [(description, bool)]
        self.note = note
        self.verdict = self._classify()

    def _classify(self):
        if self.note.startswith("INCONCLUSIVE"):
            return "INCONCLUSIVE"
        if self.observed != self.expected:
            return "FAIL-NO-REFUSAL" if self.observed == "OK" else "FAIL-WRONG-REASON"
        return "PASS" if all(ok for _, ok in self.checks) else "FAIL-EVIDENCE"

    @property
    def observed(self):
        return self.launch.reason

    @property
    def ok(self):
        return self.verdict in ("PASS", "INCONCLUSIVE")

    @property
    def counts_as_failure(self):
        return self.verdict.startswith("FAIL")


class Skipped(object):
    """A property this process cannot demonstrate without faking a principal."""

    def __init__(self, ident, title, expected, command):
        self.id = ident
        self.title = title
        self.expected = expected
        self.command = command
        self.verdict = "NOT-RUN-ELEVATION"
        self.observed = "-"
        self.checks = []
        self.note = ""
        self.launch = Launch(None, "", False, "not launched: elevation required")

    @property
    def ok(self):
        return True

    @property
    def counts_as_failure(self):
        return False


def stopped_in_source_stage(result):
    """A class-level safety statement, not a restatement of the expected reason.

    The bootstrap validates the bundle BEFORE it looks at the parent chain, so a
    bundle that violates the path policy must never reach the chain stage at all,
    whatever the specific violation was.  Codes below 30 are the source family;
    30 and above mean the run carried this bundle forward.

    This is what turns each source-policy deletion experiment into an observation
    of DAMAGE rather than a change of wording: with the mechanism, the ambiguous
    or unpinnable bundle is stopped; without it, the harness sees the same bundle
    accepted and carried into the chain stage, one step from being copied.
    """
    return ("the run stopped inside the SOURCE stage (exit %s), so this bundle never "
            "reached the parent chain or the copy" % result.code,
            result.code is not None and result.code < 30)


SCENARIOS = []


def scenario(ident, mechanism=None, mutations=(), elevation=False):
    def register(function):
        SCENARIOS.append({"id": ident, "run": function, "mechanism": mechanism,
                          "mutations": tuple(mutations), "elevation": elevation})
        return function
    return register


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

@scenario("CTL-OWNER",
          mechanism="the owner of every chain component must be one of the three trusted "
                    "SIDs; there is no parameter that adds a fourth",
          mutations=("trust_widened",))
def _owner_control(base, image, work):
    """The load-bearing control for the whole unelevated run.

    The fixture's DACL is clean by every mask the bootstrap applies - no ACE
    grants this account, or anybody else outside the trust set, a redirect-class
    or content-class right.  The ONLY thing wrong with it is that this
    unelevated account owns it.  If this row did not refuse, every other row
    below would be worthless, because the trust set would already contain the
    account building the fixtures.
    """
    chain = Chain("ctl-owner", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    result = launch(image, chain.args(source))
    sddl = security_descriptor_sddl(chain.parent) or ""
    checks = [
        ("harness reads the fixture owner and finds THIS account, not a trusted SID",
         sddl.startswith("O:" + ME)),
        ("harness finds no open-group ACE in the fixture DACL, so nothing but the "
         "owner can be what this refusal is about",
         not any((";%s)" % group) in sddl for group in ("WD", "BU", "AU", "IU", "BG", "AN"))),
        ("harness finds no ACE granting this account a redirect- or content-class right",
         ("FA;;;%s)" % ME) not in sddl and ("GA;;;%s)" % ME) not in sddl),
        ("harness sees no root created", not exists(chain.root())),
    ]
    return Result("CTL-OWNER",
                  "an untrusted OWNER alone is enough to refuse, with a clean DACL",
                  "PARENT_OWNER_UNTRUSTED", result, checks)


@scenario("CTL-PROGFILES")
def _programfiles_control(base, image, work):
    """The production trust set is not merely restrictive - it ACCEPTS the real
    thing.  The OS-derived ProgramFiles chain (the volume root, then Program
    Files) passes every component check with the three built-in SIDs and no
    widening whatsoever; the run gets all the way to creating the root and stops
    there because this account cannot write to it.  Without this row, "refuses
    everything" and "refuses correctly" would be indistinguishable.
    """
    source = work.source().small_bundle()
    root_name = "mrofflineprobe" + uuid.uuid4().hex[:8]
    argv = ["-RootName", root_name, "-SourcePath", source.path,
            "-ExpectedBundleHash", source.pin()]        # no -ParentPath: OS-derived
    result = launch(image, argv)
    target = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), root_name)
    expected = "ROOT_CREATE_FAILED" if not ELEVATED else "OK"
    checks = [
        ("harness sees nothing left behind under the real ProgramFiles",
         (not exists(target)) if not ELEVATED else exists(target)),
        ("harness confirms the run passed the whole parent chain before stopping",
         result.code in (0, 41)),
    ]
    if ELEVATED and exists(target):
        remove_tree(target)
    return Result("CTL-PROGFILES",
                  "the production trust set ACCEPTS the real OS-derived ProgramFiles chain",
                  expected, result, checks)


# ---------------------------------------------------------------------------
# D1 - no compiler, no child process, no temporary artifact
# ---------------------------------------------------------------------------

@scenario("SCN-01",
          mechanism="every P/Invoke is declared in-process with System.Reflection.Emit; "
                    "there is no Add-Type, so no compiler is started and nothing is "
                    "written to the environment-derived %TEMP%",
          mutations=("no_addtype",))
def _no_compiler(base, image, work):
    chain = Chain("nocompiler", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    temp = str(Path(base) / "temp-observed")
    ensure_dir(long_path(temp))
    HOST.measure_into(temp)     # paired measurement, same directory, same instant
    result = launch(image, chain.args(source),
                    env_overrides={"TEMP": temp, "TMP": temp},
                    watch_dirs=[temp])
    watcher = result.watcher
    extra_processes, toolchain, extra_artifacts = watcher.beyond(HOST)
    checks = [
        ("harness polled the live process table throughout the run",
         watcher.samples > 20),
        ("harness saw NO process beyond the measured interpreter baseline (%s)"
         % (sorted(extra_processes.values()) or "none seen"), not extra_processes),
        ("harness saw NO compiler or shell in the bootstrap's process tree (%s)"
         % (sorted(toolchain.values()) or "none seen"), not toolchain),
        ("harness saw NO file beyond the baseline ever appear in the TEMP directory it "
         "handed the run (%s)" % (extra_artifacts or "none seen"), not extra_artifacts),
        ("harness sees no root created", not exists(chain.root())),
    ]
    return Result("SCN-01",
                  "no compiler, no child process, no temporary artifact - observed, not asserted",
                  "PARENT_OWNER_UNTRUSTED", result, checks)


@scenario("SCN-02",
          mechanism="nothing is resolved by name and no environment string names a "
                    "directory that is written to",
          mutations=("no_addtype",))
def _poisoned_environment(base, image, work):
    """TEMP, TMP, PATH and PATHEXT all point at directories this harness owns and
    watches.  SystemRoot is deliberately left alone: poisoning it would break the
    CLR itself and the run would fail for a reason that says nothing about the
    bootstrap.  The bootstrap is launched by absolute path either way, so no
    part of this run resolves an executable by name - which is the property."""
    chain = Chain("poisonenv", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    bait = str(Path(base) / "bait-path")
    temp = str(Path(base) / "bait-temp")
    ensure_dir(long_path(bait))
    ensure_dir(long_path(temp))
    # Bait that would be picked up by anything resolving a helper by name.
    for name in ("csc.exe", "cvtres.exe", "cmd.exe", "powershell.exe", "whoami.exe"):
        with open(long_path(bait) + "\\" + name, "wb") as handle:
            handle.write(b"MZ-not-a-real-image")
    bait_before = sorted(os.listdir(long_path(bait)))
    HOST.measure_into(temp)     # paired measurement, same directory, same instant
    result = launch(image, chain.args(source),
                    env_overrides={"TEMP": temp, "TMP": temp, "PATH": bait,
                                   "PATHEXT": ".EXE;.CMD;.BAT"},
                    watch_dirs=[temp])
    watcher = result.watcher
    extra_processes, toolchain, extra_artifacts = watcher.beyond(HOST)
    checks = [
        ("harness saw NO process beyond the interpreter baseline under a poisoned PATH "
         "(%s)" % (sorted(extra_processes.values()) or "none seen"), not extra_processes),
        ("harness saw NO compiler or shell in the bootstrap's process tree (%s)"
         % (sorted(toolchain.values()) or "none seen"), not toolchain),
        ("harness saw NO file beyond the baseline appear in the poisoned TEMP/TMP "
         "directory (%s)" % (extra_artifacts or "none seen"), not extra_artifacts),
        ("harness finds the bait executables on the poisoned PATH untouched",
         sorted(os.listdir(long_path(bait))) == bait_before),
        ("harness sees no root created", not exists(chain.root())),
    ]
    return Result("SCN-02",
                  "poisoned TEMP/TMP/PATH changes nothing: nothing is written, nothing is spawned",
                  "PARENT_OWNER_UNTRUSTED", result, checks)


# ---------------------------------------------------------------------------
# D2 - the canonical chain.  Three topological variants of ONE damage: an
# ancestor that can redirect the root is not on the chain the bootstrap judges.
# ---------------------------------------------------------------------------

def _unsafe_ancestor_body(ident, title, image, work, build, expected="PARENT_UNSAFE_WRITABLE_ACE"):
    """Shared body for the three chain-topology scenarios.

    `build` returns (chain, parent_argument, ancestor, extra_checks).  The
    ancestor carries a non-inheritable Everyone-DELETE ACE - a redirect-class
    right on a node that is NOT the leaf of anything.  Whoever holds it can
    rename that directory out from under an otherwise impeccable parent and root.

    Each scenario runs TWICE.  The second launch is the same fixture with the
    ancestor's ACE removed, and it must refuse for a DIFFERENT reason.  That
    within-scenario differential is what attributes the refusal to the ANCESTOR
    rather than to anything nearer the leaf - without reading one word the
    bootstrap printed.
    """
    chain, parent_argument, ancestor, extra = build()
    source = work.source().small_bundle()
    result = launch(image, chain.args(source, parent=parent_argument))

    ancestor_sddl = security_descriptor_sddl(ancestor) or ""
    parent_sddl = security_descriptor_sddl(chain.parent) or ""

    # Control launch: identical fixture, ancestor ACE removed.
    apply_sddl_dacl(ancestor, chain.default_dacl)
    control = launch(image, chain.args(source, parent=parent_argument))

    checks = [
        ("harness reads the ancestor DACL and finds the Everyone DELETE ACE it planted",
         ";WD)" in ancestor_sddl),
        ("harness confirms the ACE is NOT on the parent, so only a full-chain check sees it",
         ";WD)" not in parent_sddl),
        ("harness sees no root created", not exists(chain.root())),
        ("removing ONLY the ancestor ACE changes the refusal, so the refusal was about "
         "the ancestor (control exit %s)" % control.code,
         control.reason != expected),
    ]
    checks.extend(extra)
    return Result(ident, title, expected, result, checks)


@scenario("SCN-03",
          mechanism="the parent is resolved with GetFinalPathNameByHandle(VOLUME_NAME_GUID) "
                    "and the ENTIRE canonical chain is judged; a drive letter is never "
                    "treated as a volume root",
          mutations=("canonical_chain",))
def _subst_chain_bypass(base, image, work):
    """The exact exploit that got past the previous revision.

    DefineDosDeviceW - the API subst.exe calls, usable by an ORDINARY UNELEVATED
    ACCOUNT - maps a spare drive letter onto a directory buried inside a tree
    whose grandparent grants Everyone DELETE.  The operator is then handed
    '<letter>:\\' as the parent.  The previous revision decided a chain ended
    when the path text looked like 'X:\\', so the chain had exactly ONE component
    and the real ancestors were never opened.  Exit 0, root installed under a
    directory anybody could rename.
    """
    state = {}

    def build():
        chain = Chain("subst", depth=1, mode="production")
        ancestor = chain.top
        chain.harden(extra={ancestor: "(A;;SD;;;WD)"})
        letter = free_drive_letter()
        if letter is None:
            raise OSError("no free drive letter available for the DOS-device fixture")
        define_dos_device(letter, chain.parent)
        state["letter"] = letter
        state["target"] = chain.parent
        state["mapped"] = query_dos_device(letter)
        extra = [
            ("harness reads the DOS device and finds the drive letter really maps to the "
             "buried directory (%s -> %s)" % (letter + ":", state["mapped"]),
             state["mapped"] is not None and
             state["mapped"].lower().endswith(chain.parent[2:].lower())),
            ("harness confirms the literal chain from the drive root has exactly ONE "
             "component, so a text-shaped chain check cannot reach the ancestor",
             os.path.dirname(letter + ":\\") == letter + ":\\"),
            ("harness sees no root created under the drive letter either",
             not exists(letter + ":\\trustroot")),
        ]
        return chain, letter + ":\\", ancestor, extra

    try:
        return _unsafe_ancestor_body(
            "SCN-03",
            "a DOS-device drive cannot hide the real ancestors of the parent",
            image, work, build)
    except OSError as exc:
        return Result("SCN-03", "a DOS-device drive cannot hide the real ancestors of the parent",
                      "PARENT_UNSAFE_WRITABLE_ACE", Launch(None, "", False), [],
                      note="INCONCLUSIVE: the DOS-device fixture could not be built (%s)" % exc)
    finally:
        if "letter" in state:
            remove_dos_device(state["letter"], state["target"])
            kernel32.DefineDosDeviceW(DDD_REMOVE_DEFINITION, state["letter"] + ":", None)


@scenario("SCN-04",
          mechanism="every component of the chain is judged, not just the leaf "
                    "(redirect-class rights anywhere upstream defeat a leaf nobody can write)",
          mutations=("chain_leaf_only",))
def _unsafe_grandparent(base, image, work):
    """The depth variant: no aliasing at all, the unsafe node is simply two
    levels above the root.  Answers 'does the refusal key to fewer operands than
    the damage?' with a test rather than a claim."""

    def build():
        chain = Chain("grandparent", depth=1, mode="production")
        ancestor = chain.top
        chain.harden(extra={ancestor: "(A;;SD;;;WD)"})
        return chain, None, ancestor, []

    return _unsafe_ancestor_body(
        "SCN-04",
        "an unsafe ACE two levels above the root is refused",
        image, work, build)


@scenario("SCN-05",
          mechanism="a junction TRAVERSED on the way to the parent is resolved to its real "
                    "target, so the target's ancestors are what get judged",
          mutations=("canonical_chain",))
def _junction_ancestor(base, image, work):
    """The aliasing variant that is not a drive letter.

    The junction is an ANCESTOR of the parent, not the parent itself: the
    operator passes '<link>\\n0', which is not a reparse point, and the real
    directory it lands in sits under an ancestor granting Everyone DELETE.
    Resolving the junction is what puts that ancestor on the chain at all.
    """
    def build():
        real = Chain("jcttarget", depth=1, mode="production")
        ancestor = real.top
        real.harden(extra={ancestor: "(A;;SD;;;WD)"})
        letter = os.path.abspath(os.sep)[0]
        link = "%s:\\mrb5-jctlink-%s" % (letter, uuid.uuid4().hex[:8])
        create_junction(link, real.top)
        Chain.ALL.append(link)
        through = link + "\\n0"
        extra = [
            ("harness confirms the operator's path goes through a real junction",
             is_reparse_point(link)),
            ("harness confirms the path it hands over is NOT itself a reparse point",
             not is_reparse_point(through)),
            ("harness confirms that path resolves to the buried directory",
             object_identity(through) is not None and
             object_identity(through) == object_identity(real.parent)),
            ("harness confirms the unsafe ancestor is not a literal ancestor of the "
             "operator's path, so only resolution can reach it",
             not real.top.lower().startswith(link.lower())),
        ]
        return real, through, ancestor, extra

    return _unsafe_ancestor_body(
        "SCN-05",
        "a junction on the way in is resolved and the REAL ancestor chain is judged",
        image, work, build)


@scenario("SCN-06",
          mechanism="content-changing rights judged on the final node of the chain",
          mutations=("content_class",))
def _writable_parent(base, image, work):
    """The leaf variant: Everyone may add files to the parent itself.  Not
    inherit-only, this object only - exactly the writable parent the design must
    refuse, and the one node where the content class, not just the redirect
    class, is what bites."""
    chain = Chain("writableparent", depth=0, mode="production")
    chain.harden(extra={chain.parent: "(A;;0x2;;;WD)"})
    source = work.source().small_bundle()
    result = launch(image, chain.args(source))
    sddl = security_descriptor_sddl(chain.parent) or ""
    masks = sddl_ace_masks(sddl, "WD")
    # Control: the identical fixture with the Everyone ACE removed.  If that
    # refuses differently, the refusal above was about the ACE and not about
    # anything else the fixture happens to be.
    apply_sddl_dacl(chain.parent, chain.default_dacl)
    control = launch(image, chain.args(source))
    checks = [
        ("harness reads the parent DACL and finds exactly one Everyone ACE",
         len(masks) == 1),
        ("harness decodes that ACE and finds ONLY content-class rights - no delete, no "
         "WRITE_DAC, no WRITE_OWNER - so the redirect class alone would have missed it "
         "(mask=0x%08x)" % (masks[0] if masks else 0),
         bool(masks) and (masks[0] & CONTENT_CLASS_MASK) and
         not (masks[0] & REDIRECT_CLASS_MASK)),
        ("harness sees no root created", not exists(chain.root())),
        ("removing ONLY that ACE changes the refusal, so the refusal was about it "
         "(control exit %s)" % control.code,
         control.reason != "PARENT_UNSAFE_WRITABLE_ACE"),
    ]
    return Result("SCN-06", "non-admin-writable parent refused before any root exists",
                  "PARENT_UNSAFE_WRITABLE_ACE", result, checks)


@scenario("SCN-07",
          mechanism="the parent itself may not be a reparse point (its identity is "
                    "controlled by whoever can rewrite the reparse data)",
          mutations=("reparse_node",))
def _junction_parent(base, image, work):
    letter = os.path.abspath(os.sep)[0]
    target = "%s:\\mrb5-jptarget-%s" % (letter, uuid.uuid4().hex[:8])
    link = "%s:\\mrb5-jplink-%s" % (letter, uuid.uuid4().hex[:8])
    ensure_dir(long_path(target))
    apply_sddl_dacl(target, MINE_FULL)
    create_junction(link, target)
    Chain.ALL.extend([target, link])
    source = work.source().small_bundle()
    argv = ["-RootName", "trustroot", "-SourcePath", source.path,
            "-ExpectedBundleHash", source.pin(), "-ParentPath", link]
    result = launch(image, argv)
    checks = [
        ("harness confirms the parent really is a reparse point", is_reparse_point(link)),
        ("harness sees the junction target still empty", listing(target) == []),
        ("harness sees no root created through the junction",
         not exists(link + "\\trustroot")),
    ]
    return Result("SCN-07", "a junction named AS the parent is refused, not followed",
                  "PARENT_REPARSE", result, checks)


# ---------------------------------------------------------------------------
# The pins
# ---------------------------------------------------------------------------

@scenario("SCN-08",
          mechanism="the harness's own pre-launch SHA-256 comparison",
          mutations=("harness_pin",))
def _wrong_bootstrap_pin(base, image, work):
    chain = Chain("bootpin", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    wrong = "0" * 64
    result = launch(image, chain.args(source), expected_hash=wrong)
    checks = [
        ("harness computed the real hash itself and it differs from the pin",
         image.sha256 != wrong),
        ("nothing was launched", not result.launched),
        ("harness sees no root created", not exists(chain.root())),
    ]
    return Result("SCN-08", "wrong bootstrap pin: detected by the harness BEFORE launch",
                  "NOT-LAUNCHED", result, checks)


@scenario("SCN-09",
          mechanism="root-hash comparison against the operator pin, before any copy",
          mutations=("bundle_pin",))
def _wrong_bundle_pin(base, image, work):
    chain = Chain("bundlepin", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    result = launch(image, chain.args(source, pin="b" * 64))
    checks = [
        ("harness sees no root created at all (the refusal precedes creation)",
         not exists(chain.root())),
        ("harness's own root hash of the source differs from the pin supplied",
         source.pin() != "b" * 64),
    ]
    return Result("SCN-09", "wrong release-bundle pin refused before copying anything",
                  "BUNDLE_PIN_MISMATCH", result, checks)


@scenario("SCN-10",
          mechanism="deterministic ordinal sort of the manifest over the folded ASCII "
                    "member paths (the pre-image is order-sensitive, so enumeration "
                    "order must not reach the pin)",
          mutations=("sorted_manifest",))
def _manifest_order(base, image, work):
    """Two independent implementations agreeing on a pin is provable WITHOUT an
    install, because the bootstrap compares the pin BEFORE it looks at the parent
    chain.  A run that reaches the chain stage is a run whose PowerShell root
    hash equalled the root hash this file computed in Python - over a tree whose
    depth-first order and sorted order agree nowhere.  If the sort were removed,
    this row would refuse at BUNDLE_PIN_MISMATCH instead, and the deletion
    experiment shows exactly that."""
    chain = Chain("manifestorder", mode="production")
    chain.harden()
    source = work.source()
    # Depth-first emission is b.txt, zzz.txt, then m/ and a/.  Manifest order is
    # a/inner.txt, b.txt, m/n/deep.txt, zzz.txt.  The two agree nowhere.
    source.write("b.txt", b"bee\n")
    source.write("zzz.txt", b"zed\n")
    source.write("m/n/deep.txt", b"deep\n")
    source.write("a/inner.txt", b"inner\n")
    result = launch(image, chain.args(source))
    checks = [
        ("the run got PAST the bundle-pin comparison, which it can only do if the "
         "bootstrap's root hash equalled the one this file computed independently",
         result.code is not None and result.code != CODE_OF["BUNDLE_PIN_MISMATCH"]),
        ("harness sees no root created (the chain check is what stopped it)",
         not exists(chain.root())),
    ]
    return Result("SCN-10",
                  "the root hash depends on the member set, not on enumeration order - "
                  "agreed by two implementations",
                  "PARENT_OWNER_UNTRUSTED", result, checks)


# ---------------------------------------------------------------------------
# D4 - the ASCII path policy
# ---------------------------------------------------------------------------

@scenario("SCN-11",
          mechanism="bundle path components restricted to A-Za-z0-9._- , so no member "
                    "name can be ordered or folded differently by two implementations",
          mutations=("ascii_alphabet",))
def _non_ascii_member(base, image, work):
    """The two members below are the disagreement, in its smallest form.

    U+FF21 is a single UTF-16 code unit, 0xFF21.  U+1F600 is a surrogate PAIR
    whose first unit is 0xD83D.  Sorting by CODE POINT (Python) puts U+FF21
    first; sorting by UTF-16 CODE UNIT (.NET, ordinal) puts U+1F600 first.  The
    manifest is order-sensitive, so the same bytes on disk hash to two different
    roots depending on which language computed the pin.
    """
    chain = Chain("nonascii", mode="production")
    chain.harden()
    source = work.source()
    source.write("plain.txt", b"ascii\n")
    try:
        source.write("a-\uff21.txt", b"fullwidth\n")
        source.write("a-\U0001f600.txt", b"astral\n")
    except (OSError, UnicodeError) as exc:
        return Result("SCN-11", "non-ASCII member names are refused", "SOURCE_NAME_UNSAFE",
                      Launch(None, "", False), [],
                      note="INCONCLUSIVE: this volume would not accept the fixture names (%s)" % exc)
    result = launch(image, chain.args(source))
    checks = [
        ("harness confirms both non-ASCII members really exist on disk",
         exists(source.path + "\\a-\uff21.txt") and exists(source.path + "\\a-\U0001f600.txt")),
        ("harness sees no root created", not exists(chain.root())),
        ("the two implementations did NOT end up disagreeing about this bundle's root "
         "hash - a disagreement here is the whole damage the alphabet prevents",
         result.code != CODE_OF["BUNDLE_PIN_MISMATCH"]),
        stopped_in_source_stage(result),
    ]
    return Result("SCN-11",
                  "a non-ASCII member name is refused, so no pin can depend on how a "
                  "language orders it",
                  "SOURCE_NAME_UNSAFE", result, checks)


def _name_refusal(ident, tag, member, title, base, image, work, ambiguous=False):
    chain = Chain(tag, mode="production")
    chain.harden()
    source = work.source()
    source.write("plain.txt", b"ascii\n")
    try:
        source.write(member, b"payload\n")
    except OSError as exc:
        return Result(ident, title, "SOURCE_NAME_UNSAFE", Launch(None, "", False), [],
                      note="INCONCLUSIVE: this volume would not create %r (%s)" % (member, exc))
    result = launch(image, chain.args(source))
    checks = [
        ("harness confirms the member really exists on disk under that exact name",
         exists(long_path(source.path) + "\\" + member.replace("/", "\\"))),
        ("harness sees no root created", not exists(chain.root())),
        stopped_in_source_stage(result),
    ]
    if ambiguous:
        # The point of the rule, demonstrated rather than asserted: the extended
        # form and the Win32 form of the SAME text name two different objects.
        # A bundle carrying this name is judged through one and written through
        # the other, and only one of them exists.
        checks.append(
            ("harness confirms the name is AMBIGUOUS: the extended form finds it and "
             "the Win32 form - which silently trims - does not",
             exists(long_path(source.path) + "\\" + member) and
             kernel32.GetFileAttributesW(source.path + "\\" + member) == INVALID_FILE_ATTRIBUTES))
    return Result(ident, title, "SOURCE_NAME_UNSAFE", result, checks)


@scenario("SCN-12",
          mechanism="reserved DOS device names refused, with or without an extension",
          mutations=("reserved_names",))
def _reserved_name(base, image, work):
    return _name_refusal("SCN-12", "reserved", "COM1.txt",
                         "a reserved device name with an extension is refused",
                         base, image, work)


@scenario("SCN-13",
          mechanism="a trailing dot is refused (Win32 resolves 'name.' to 'name', so the "
                    "path judged and the path written would differ)",
          mutations=("trailing_dot",))
def _trailing_dot(base, image, work):
    return _name_refusal("SCN-13", "trailingdot", "weird.",
                         "a member name with a trailing dot is refused",
                         base, image, work, ambiguous=True)


@scenario("SCN-14",
          mechanism="a trailing space is refused, and independently the ASCII alphabet "
                    "does not contain the space at all - two rules, so the flip needs "
                    "both removed (defence in depth, reported rather than hidden)",
          mutations=("trailing_space", "ascii_alphabet"))
def _trailing_space(base, image, work):
    return _name_refusal("SCN-14", "trailingspace", "weird ",
                         "a member name with a trailing space is refused",
                         base, image, work, ambiguous=True)


@scenario("SCN-15",
          mechanism="ordinal ASCII case fold over the member paths, so a bundle that names "
                    "one destination file twice is refused instead of silently losing one",
          mutations=("case_fold",))
def _case_collision(base, image, work):
    """Two members that differ only in ASCII case cannot both exist on a normal
    case-insensitive NTFS directory, so this fixture first turns on per-directory
    case sensitivity.  Where that facility is unavailable the row is reported
    INCONCLUSIVE - the mechanism is still in the bootstrap, but this machine
    cannot build the input that exercises it, and saying so is the honest
    outcome."""
    chain = Chain("collision", mode="production")
    chain.harden()
    source = work.source()
    # The flag can only be set on an EMPTY directory, so it goes on before any
    # member is written.
    if not set_case_sensitive_directory(source.path):
        return Result("SCN-15", "two members differing only in ASCII case are refused",
                      "SOURCE_COLLISION", Launch(None, "", False), [],
                      note="INCONCLUSIVE: per-directory case sensitivity "
                           "(FileCaseSensitiveInformation) is unavailable here, so a "
                           "case-only collision cannot be created to test with")
    try:
        source.write("plain.txt", b"ascii\n")
        source.write("dup.txt", b"first\n")
        source.write("DUP.txt", b"second\n")
    except OSError as exc:
        return Result("SCN-15", "two members differing only in ASCII case are refused",
                      "SOURCE_COLLISION", Launch(None, "", False), [],
                      note="INCONCLUSIVE: the case-only pair could not be created (%s)" % exc)
    both = exists(long_path(source.path) + "\\dup.txt") and \
        exists(long_path(source.path) + "\\DUP.txt")
    if not both or file_digest(long_path(source.path) + "\\dup.txt") == \
            file_digest(long_path(source.path) + "\\DUP.txt"):
        return Result("SCN-15", "two members differing only in ASCII case are refused",
                      "SOURCE_COLLISION", Launch(None, "", False), [],
                      note="INCONCLUSIVE: the directory did not become case sensitive, so "
                           "the two names resolved to one file")
    # A pin the harness cannot compute unambiguously either; supply the one it
    # gets so the refusal cannot be attributed to a pin mismatch.
    result = launch(image, chain.args(source, pin=source.pin()))
    checks = [
        ("harness confirms both case-only variants exist as SEPARATE files on disk "
         "with DIFFERENT contents", both),
        ("harness folds the two names itself and confirms they name ONE destination "
         "file, so installing this bundle would silently lose one of them",
         _folded(("dup.txt",)) == _folded(("DUP.txt",))),
        ("harness sees no root created", not exists(chain.root())),
        stopped_in_source_stage(result),
    ]
    return Result("SCN-15", "two members differing only in ASCII case are refused",
                  "SOURCE_COLLISION", result, checks)


# ---------------------------------------------------------------------------
# Source integrity
# ---------------------------------------------------------------------------

@scenario("SCN-16",
          mechanism="reparse check on every enumerated source entry",
          mutations=("enum_reparse",))
def _source_reparse(base, image, work):
    chain = Chain("srcreparse", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    outside = str(Path(base) / ("outside-" + uuid.uuid4().hex[:8]))
    ensure_dir(long_path(outside))
    with open(long_path(outside) + "\\secret.txt", "wb") as handle:
        handle.write(b"not part of the bundle\n")
    create_junction(source.path + "\\linked", outside)
    # A pin over the bundle WITHOUT the junction's target: that is what the
    # operator pinned, and what a bootstrap that followed the junction would
    # fail to reproduce.
    result = launch(image, chain.args(source, pin=source.pin(follow_reparse=False)))
    checks = [
        ("harness confirms the source really contains a junction",
         is_reparse_point(source.path + "\\linked")),
        ("harness confirms the junction target holds a file that is NOT in the pin",
         exists(outside + "\\secret.txt")),
        ("harness's pin over the bundle differs from a pin that followed the junction",
         source.pin(follow_reparse=False) != source.pin(follow_reparse=True)),
        ("harness sees no root created", not exists(chain.root())),
        ("the bootstrap did not end up hashing content the operator never pinned - a "
         "pin disagreement here would mean it had walked THROUGH the junction",
         result.code != CODE_OF["BUNDLE_PIN_MISMATCH"]),
        stopped_in_source_stage(result),
    ]
    return Result("SCN-16",
                  "a reparse point inside the source is refused, never enumerated through",
                  "SOURCE_REPARSE", result, checks)


@scenario("SCN-17",
          mechanism="ordinal-ignore-case equality against '.git' on every component",
          mutations=("git_component",))
def _git_in_source(base, image, work):
    chain = Chain("gitpath", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    source.write(".GIT/config", b"[core]\n")
    result = launch(image, chain.args(source))
    checks = [
        ("harness confirms the source really contains .GIT/config",
         exists(source.path + "\\.GIT\\config")),
        ("harness sees no root created", not exists(chain.root())),
        stopped_in_source_stage(result),
    ]
    return Result("SCN-17", "any spelling of .git in the source is refused",
                  "SOURCE_GIT_PATH", result, checks)


@scenario("SCN-18",
          mechanism="empty directories refused rather than left invisible to the pin",
          mutations=("empty_dir",))
def _empty_directory(base, image, work):
    chain = Chain("emptydir", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    source.mkdir("hollow")
    result = launch(image, chain.args(source))
    checks = [
        ("harness confirms the empty directory exists and holds nothing",
         listing(source.path + "\\hollow") == []),
        ("harness confirms its presence does NOT change the pin this file computes, "
         "which is exactly why the bootstrap must refuse it",
         source.pin() == bundle_root_hash(source.path)),
        ("harness sees no root created", not exists(chain.root())),
        stopped_in_source_stage(result),
    ]
    return Result("SCN-18", "a directory the pin cannot see is refused",
                  "SOURCE_EMPTY_DIRECTORY", result, checks)


@scenario("SCN-20",
          mechanism="INHERITED ACEs are effective ACEs and are judged as such; an "
                    "inherit-only ACE grants nothing on the node carrying it and is "
                    "caught on the child that inherits it",
          mutations=("inherited_ace",))
def _inherited_ace(base, image, work):
    """The fourth topology: the operand is on an ancestor, but it grants nothing
    THERE and everything on the child.

    No synthetic ACL is needed for this one, because Windows ships it.  The
    volume root carries an INHERIT-ONLY ACE for Authenticated Users
    (`(A;OICIIO;SDGXGWGR;;;AU)`): it grants nothing on the volume root itself, so
    an ancestor check sees nothing wrong there, and every directory created
    directly under the volume root is born with it as an EFFECTIVE inherited ACE
    that includes DELETE.

    So a default-permissions directory under C:\\ - the obvious place an operator
    would put a trust root - is world-renamable, and must be refused.  This row
    also documents that fact, which is worth an operator's attention on its own.
    """
    letter = os.path.abspath(os.sep)[0]
    volume_root = letter + ":\\"
    parent = "%s:\\mrb5-inherited-%s" % (letter, uuid.uuid4().hex[:8])
    ensure_dir(long_path(parent))       # DEFAULT permissions: inheritance intact
    Chain.ALL.append(parent)
    source = work.source().small_bundle()
    argv = ["-RootName", "trustroot", "-SourcePath", source.path,
            "-ExpectedBundleHash", source.pin(), "-ParentPath", parent]
    result = launch(image, argv)

    root_sddl = security_descriptor_sddl(volume_root) or ""
    parent_sddl = security_descriptor_sddl(parent) or ""
    inherited_masks = [mask for mask in sddl_ace_masks(parent_sddl, "AU")
                       if mask & REDIRECT_CLASS_MASK]

    # Control: protect the same directory's DACL so nothing is inherited any
    # more.  If that changes the refusal, the refusal was about the inherited ACE.
    apply_sddl_dacl(parent, SAFE_READONLY)
    control = launch(image, argv)

    checks = [
        ("harness reads the VOLUME ROOT's DACL and finds an Authenticated Users ACE "
         "marked inherit-only, granting nothing on the volume root itself",
         "OICIIO" in root_sddl and ";AU)" in root_sddl),
        ("harness reads the default-permissions directory under it and finds that ACE "
         "present as an EFFECTIVE inherited grant carrying a redirect-class right "
         "(mask=0x%08x)" % (inherited_masks[0] if inherited_masks else 0),
         bool(inherited_masks)),
        ("harness confirms the parent's copy is marked ID (inherited), so it arrived by "
         "inheritance and was not set on the parent directly",
         "ID" in "".join(chunk.split(";")[1] for chunk in parent_sddl.split("(")[1:]
                         if chunk.split(";")[-1].startswith("AU)"))),
        ("harness sees no root created", not exists(parent + "\\trustroot")),
        ("protecting the DACL so nothing is inherited changes the refusal, so the "
         "refusal was about the INHERITED ACE (control exit %s)" % control.code,
         control.reason != "PARENT_UNSAFE_WRITABLE_ACE"),
    ]
    return Result("SCN-20",
                  "an inherit-only ACE on the volume root is caught on the child that "
                  "inherits it - a default-DACL directory under C:\\ is refused",
                  "PARENT_UNSAFE_WRITABLE_ACE", result, checks)


@scenario("SCN-19")
def _no_trust_widening_parameter(base, image, work):
    """D3, as a black-box question: hand the bootstrap the parameter the previous
    revision accepted, naming this account, and see whether anything is trusted
    that was not trusted before.

    The check is not "does it print an error" - it is that the refusal is the
    SAME refusal as without the argument, and that nothing was created.  The
    harness additionally reads the bytes it already hashed and confirms the
    parameter is not declared, which is a statement about the pinned file rather
    than about anything the file said.
    """
    chain = Chain("notrustedsid", mode="production")
    chain.harden()
    source = work.source().small_bundle()
    baseline = launch(image, chain.args(source))
    widened = launch(image, chain.args(source) + ["-TrustedSid", ME])
    text = image.path.read_text(encoding="utf-8")
    checks = [
        ("the pinned bytes declare no TrustedSid parameter",
         "$TrustedSid" not in text and "-TrustedSid" not in text.split(".NOTES")[0]),
        ("passing -TrustedSid did not make this account trusted: nothing was created",
         not exists(chain.root())),
        ("passing -TrustedSid did not turn the refusal into an acceptance",
         widened.code != 0),
    ]
    return Result("SCN-19",
                  "there is no argument that widens the trust set",
                  "PARENT_OWNER_UNTRUSTED", baseline, checks)


# ---------------------------------------------------------------------------
# Properties that require the bootstrap to ACCEPT a chain and INSTALL.
#
# An unelevated process cannot build a fixture the production trust set accepts,
# and faking one is the exact defect this revision exists to remove.  These rows
# are therefore NOT RUN unless the harness is running elevated.
# ---------------------------------------------------------------------------

ELEVATION_ONLY = [
    ("ELV-01", "positive control: a clean bundle installs into a fresh root, and the "
               "created root's owner and DACL are read back by the harness", "OK"),
    ("ELV-02", "a pre-created root is refused, not adopted", "ROOT_EXISTS"),
    ("ELV-03", "a junction occupying the root name is refused, not written through",
     "ROOT_REPARSE"),
    ("ELV-04", "an unsafe INHERITED ACL on the created root is refused before copying",
     "ROOT_UNSAFE_WRITABLE_ACE"),
    ("ELV-05", "bytes changed between hashing and copy are caught by the destination re-hash",
     "DESTINATION_MISMATCH"),
    ("ELV-06", "the root replaced after the copy by an identical-content twin is caught",
     "ROOT_IDENTITY_CHANGED"),
    ("ELV-07", "a subdirectory name occupied mid-copy is refused, not written through",
     "COPY_DIRECTORY_OCCUPIED"),
]

ELEVATED_COMMAND = (
    "Start an ELEVATED PowerShell (Run as administrator) and run:\n"
    "    cd <repo>\n"
    "    python scripts\\offline_bootstrap_guard.py --delete-mechanism\n"
    "The harness detects the elevated token itself (CheckTokenMembership against\n"
    "S-1-5-32-544) and runs the ELV-* rows; it does not take anybody's word for it.\n"
    "Elevated, the fixtures it creates are owned by BUILTIN\\Administrators, which is\n"
    "in the production trust set - so no principal has to be invented for them to pass."
)


CODE_OF = {name: code for code, name in REASONS.items()}


# ---------------------------------------------------------------------------
# Self-review mode: delete the mechanism, require the outcome to flip.
#
# This is NOT the acceptance oracle.  The acceptance oracle is the scenario table
# above.  This mode answers one question empirically: "if I remove the mechanism,
# does the scenario still fail - and for the right reason?"  A scenario whose
# reason does not change when its mechanism is deleted was never testing it.
#
# Each mutation is a literal, reviewable substring replacement performed on a
# temporary COPY.  The copy has a different SHA-256; `launch` re-pins to the
# mutated file deliberately, and the report says so.  Where a scenario is
# refused by two independent mechanisms, BOTH are listed and both are removed -
# defence in depth is reported, not hidden behind a single anchor.
# ---------------------------------------------------------------------------

MUTATIONS = {
    # D1: put the compiler back.  The replacement is the smallest faithful
    # restoration of what the previous revision did - one unconditional Add-Type
    # before any validation - and it is what makes the damage OBSERVABLE: the
    # harness sees csc.exe appear and sees files land in the TEMP directory it
    # supplied.
    "no_addtype": [(
        "$script:Native = $null\ntry { $script:Native = New-NativeType }",
        "$script:Native = $null\n"
        "Add-Type -TypeDefinition 'public static class OfflineBootstrapAddTypeProbe "
        "{ public static int Value = 1; }'\n"
        "try { $script:Native = New-NativeType }",
    )],
    # D2: revert to what the previous revision did - build the chain out of the
    # OPERATOR'S path text and stop climbing at whatever looks like a drive root.
    # Both halves are needed: returning the literal path is pointless while the
    # anchoring check still insists on a volume-GUID form.
    "canonical_chain": [
        ("        $canonical = Get-HandleCanonicalPath -Handle $handle",
         "        $canonical = [IO.Path]::GetFullPath($Path)"),
        ("$VOLUME_GUID_PATTERN = '^\\\\\\\\\\?\\\\Volume\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
         "[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\}\\\\?'",
         "$VOLUME_GUID_PATTERN = '^[A-Za-z]:\\\\?'"),
        ("            if (-not [string]::Equals($observed.TrimEnd([char]'\\'), "
         "$componentPath.TrimEnd([char]'\\'), [StringComparison]::Ordinal)) {",
         "            if ($false) {"),
    ],
    "chain_leaf_only": [(
        "            if ($null -ne $problem) {\n"
        "                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail \"$Canonical component=$($problem.Detail)\"",
        "            if ($isFinal -and $null -ne $problem) {\n"
        "                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail \"$Canonical component=$($problem.Detail)\"",
    )],
    # Both reparse gates: the one on the node the operator named, and the one on
    # every component of the chain.
    "reparse_node": [
        ("    if ($Information.IsReparse) { return @{ Kind = 'REPARSE'; Detail = $Path } }",
         "    if ($false) { return @{ Kind = 'REPARSE'; Detail = $Path } }"),
        ("        if ($information.IsReparse) {\n"
         "            Deny -Reason ($Prefix + '_REPARSE') -Detail $Path\n"
         "        }",
         "        if ($false) {\n"
         "            Deny -Reason ($Prefix + '_REPARSE') -Detail $Path\n"
         "        }"),
    ],
    "content_class": [(
        "    if ($IsFinal) { $unsafeMask = $unsafeMask -bor $CONTENT_CLASS }",
        "    if ($false) { $unsafeMask = $unsafeMask -bor $CONTENT_CLASS }",
    )],
    "bundle_pin": [(
        "    if ($computed -ne $pin) {",
        "    if ($false) {",
    )],
    "sorted_manifest": [(
        "    for ($i = 0; $i -lt $rows.Count; $i++) { $sorted[$i] = $index[$keys[$i]] }",
        "    for ($i = 0; $i -lt $rows.Count; $i++) { $sorted[$i] = $rows[$i] }",
    )],
    # D4: delete the alphabet restriction and keep everything else, so what is
    # measured is exactly what the alphabet was buying.
    "ascii_alphabet": [(
        "        if (-not ($isDigit -or $isUpper -or $isLower -or $isPunct)) {",
        "        if ($false) {",
    )],
    "reserved_names": [(
        "        if ([string]::Equals($stem, $reserved, [StringComparison]::OrdinalIgnoreCase) -or",
        "        if ($false -or",
    )],
    "trailing_dot": [(
        "    if ($Component.EndsWith('.')) { return 'trailing dot (Win32 would resolve it to a different name)' }",
        "    if ($false) { return 'trailing dot' }",
    )],
    "trailing_space": [(
        "    if ($Component.EndsWith(' ')) { return 'trailing space (Win32 would resolve it to a different name)' }",
        "    if ($false) { return 'trailing space' }",
    )],
    "case_fold": [(
        "        if ($code -ge 97 -and $code -le 122) { $chars[$i] = [char]($code - 32) }",
        "        if ($false) { $chars[$i] = [char]($code - 32) }",
    )],
    "enum_reparse": [(
        '                    if ($information.IsReparse) { Deny -Reason "${Phase}_REPARSE" -Detail $relative }',
        "                    if ($false) { }",
    )],
    "git_component": [(
        "    return [string]::Equals($Component, '.git', [StringComparison]::OrdinalIgnoreCase)",
        "    return $false",
    )],
    "empty_dir": [(
        "            if (@($entries).Count -eq 0) {",
        "            if ($false) {",
    )],
    # D3: put the widening back.  Not as a parameter - as the thing the parameter
    # bought, which is this account inside the trust set.  This is the ONLY way an
    # unelevated process can see what happens when the trust set contains the
    # account building the fixtures, and every row that uses it says so.
    "trust_widened": [(
        "foreach ($sid in @(\n        'S-1-5-18',",
        "foreach ($sid in @(\n        '%s',\n        'S-1-5-18'," % ME,
    )],
    # Treat an inherited ACE as if it granted nothing - the shape of "I only look
    # at rules somebody set on THIS object".
    "inherited_ace": [(
        "        if ($ace.Flags -band $ACE_FLAG_INHERIT_ONLY) { continue }",
        "        if ($ace.Flags -band $ACE_FLAG_INHERIT_ONLY) { continue }\n"
        "        if ($ace.Flags -band $ACE_FLAG_INHERITED) { continue }",
    )],
    # These mechanisms live in this file, not in the bootstrap.
    "harness_pin": [],
}


def subst_damage_experiment(base, image, workspace, work):
    """Open the ACTUAL damage of the Critical chain defect, unelevated.

    Every other deletion experiment on the chain can only show a change of
    refusal, because reaching the install at all needs a chain the production
    trust set accepts, and an unelevated account cannot build one.  This one
    reaches it - by running BOTH arms against a bootstrap that has been weakened
    to trust this account.

    Read that twice.  BOTH IMAGES ARE WEAKENED.  Neither arm is evidence about
    the production bootstrap, and neither is counted as a passing scenario.  What
    the PAIR isolates is one variable: the canonical chain.  Same fixture, same
    trust widening, same everything - the only difference is whether the buried
    ancestor is on the chain that gets judged.

      arm A  trust_widened                      -> the ancestor IS judged
      arm B  trust_widened + canonical_chain    -> the drive letter is the root

    In arm B the harness then observes the damage itself: a trust root created
    and fully populated inside a directory tree whose grandparent grants Everyone
    DELETE - which is exactly what the previous revision shipped with exit 0.
    """
    letter = os.path.abspath(os.sep)[0]
    top = "%s:\\mrb5-substdmg-%s" % (letter, uuid.uuid4().hex[:8])
    ensure_dir(long_path(top))
    Chain.ALL.append(top)
    parent = top + "\\n0"
    ensure_dir(long_path(parent))
    apply_sddl_dacl(parent, MINE_FULL)
    apply_sddl_dacl(top, MINE_FULL + "(A;;SD;;;WD)")

    drive = free_drive_letter()
    if drive is None:
        print("  (no free drive letter; the damage experiment could not be built)")
        return True
    define_dos_device(drive, parent)
    try:
        source = work.source().small_bundle()
        expected_files = tree_digests(source.path)
        arm_a = mutate(image, ("trust_widened",), workspace)
        arm_b = mutate(image, ("trust_widened", "canonical_chain"), workspace)
        argv = ["-RootName", "trustroot", "-SourcePath", source.path,
                "-ExpectedBundleHash", source.pin(), "-ParentPath", drive + ":\\"]

        result_a = launch(arm_a, argv)
        root = parent + "\\trustroot"
        created_a = exists(root)
        if created_a:
            remove_tree(root)

        result_b = launch(arm_b, argv)
        created_b = exists(root)
        installed = tree_digests(root) if created_b else None
        ancestor_sddl = security_descriptor_sddl(top) or ""
        ancestor_masks = sddl_ace_masks(ancestor_sddl, "WD")

        print("  DAMAGE EXPERIMENT for the canonical chain (SCN-03's mechanism)")
        print("    BOTH arms run a DELIBERATELY WEAKENED bootstrap that trusts this")
        print("    account, because an unelevated process cannot otherwise reach an")
        print("    install at all.  NEITHER arm is acceptance evidence for the")
        print("    production bootstrap.  The PAIR isolates one variable.")
        print("    arm A  trust_widened                    -> %s%s"
              % (result_a.reason, exit_note(result_a.code)))
        print("    arm B  trust_widened + canonical_chain  -> %s%s"
              % (result_b.reason, exit_note(result_b.code)))
        observations = [
            ("arm A refused and created nothing",
             result_a.code != 0 and not created_a),
            ("arm B EXITED ZERO - it accepted the chain",
             result_b.code == 0),
            ("harness sees a trust root really created at the buried real path %s" % root,
             created_b),
            ("harness-computed digests of the installed tree equal the source bundle, so "
             "this was a complete install and not a partial one",
             installed is not None and installed == expected_files),
            ("harness reads the GRANDPARENT of that root and finds Everyone holding "
             "DELETE (mask=0x%08x) - anybody on this machine can rename the tree the "
             "trust root lives in" % (ancestor_masks[0] if ancestor_masks else 0),
             bool(ancestor_masks) and bool(ancestor_masks[0] & REDIRECT_CLASS_MASK)),
            ("harness confirms the grandparent is NOT reachable from the drive letter "
             "the operator typed, so only chain canonicalisation could have judged it",
             os.path.dirname(drive + ":\\") == drive + ":\\"),
        ]
        for description, ok in observations:
            print("      [%s] %s" % ("ok" if ok else "NO", description))
        held = all(ok for _, ok in observations)
        print("    conclusion: %s" % (
            "removing the canonical chain OPENS the damage - the install completes "
            "under a world-renamable ancestor" if held else
            "the experiment did not reproduce the damage; treat SCN-03's flip as a "
            "change of refusal only"))
        print()
        if created_b:
            remove_tree(root)
        return held
    finally:
        remove_dos_device(drive, parent)
        kernel32.DefineDosDeviceW(DDD_REMOVE_DEFINITION, drive + ":", None)


def mutate(image, keys, workspace):
    text = image.path.read_text(encoding="utf-8")
    for key in keys:
        for find, replace in MUTATIONS[key]:
            if text.count(find) != 1:
                raise SystemExit("mutation %r does not apply uniquely (%d matches for %r)"
                                 % (key, text.count(find), find[:70]))
            text = text.replace(find, replace)
    target = workspace / ("mutated-" + "+".join(keys) + ".ps1")
    with open(str(target), "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    return Image(target, label="mutated:" + "+".join(keys))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def exit_note(code):
    return "" if code is None else " (exit %d)" % code


def print_table(results, show_stdout=False):
    width = max(len(r.id) for r in results)
    print()
    print("SCENARIO TABLE  (the acceptance oracle)")
    print("  Each verdict is formed from the process exit code plus observations this")
    print("  harness makes itself.  The bootstrap's stdout is recorded and never read by")
    print("  an assertion.  FAIL-WRONG-REASON means the run refused for an INCIDENTAL")
    print("  reason and is not evidence for the property; FAIL-EVIDENCE means the reason")
    print("  was right but the damage happened anyway; NOT-RUN-ELEVATION means the")
    print("  property cannot be shown without elevation and was NOT faked.")
    print()
    header = ("%s  %-19s  %-30s  %s"
              % ("id".ljust(width), "verdict", "expected reason", "observed reason"))
    print(header)
    print("-" * len(header))
    for r in results:
        print("%s  %-19s  %-30s  %s%s"
              % (r.id.ljust(width), r.verdict, r.expected, r.observed,
                 exit_note(r.launch.code)))
    print()
    for r in results:
        print("[%s] %s: %s" % (r.verdict, r.id, r.title))
        for description, ok in r.checks:
            print("        [%s] %s" % ("ok" if ok else "NO", description))
        if r.note:
            print("        note: %s" % r.note)
        if r.launch.note:
            print("        launch: %s" % r.launch.note)
        if isinstance(r, Skipped):
            print("        NOT RUN - ELEVATION REQUIRED.  This process is unelevated and")
            print("        cannot create a directory owned by a trusted principal.  Faking")
            print("        one is the defect this revision removed, so the row is left open.")
        if show_stdout and r.launch.stdout:
            print("        --- bootstrap stdout, RECORDED BUT NOT EVIDENCE ---")
            for line in r.launch.stdout.splitlines():
                print("        | %s" % line)
    print()


def main():
    parser = argparse.ArgumentParser(description="black-box guard for the offline bootstrap")
    parser.add_argument("--delete-mechanism", action="store_true",
                        help="self-review: disable each mechanism in a copy and require a flip")
    parser.add_argument("--only", default="", help="run only scenarios whose id contains this")
    parser.add_argument("--keep", action="store_true", help="do not delete the fixture tree")
    parser.add_argument("--show-stdout", action="store_true",
                        help="print what the bootstrap printed; it is never an assertion input")
    args = parser.parse_args()

    if os.name != "nt":
        print("offline bootstrap guard: Windows only (this is the audit:offline:windows gate).")
        return 2
    if not BOOTSTRAP.is_file():
        print("FAIL: bootstrap not found at %s" % BOOTSTRAP)
        return 1

    image = Image(BOOTSTRAP)
    print("Offline bootstrap guard (black box)")
    print("  bootstrap : %s" % BOOTSTRAP)
    print("  sha256    : %s   <- recorded by the harness before any launch" % image.sha256)
    print("  launcher  : %s" % system_powershell())
    print("  account   : %s" % ME)
    print("  elevated  : %s   <- read from this token, not from the bootstrap" % ELEVATED)
    if not ELEVATED:
        print()
        print("  UNELEVATED RUN.  Every refusal path, the whole name/pin policy, the")
        print("  process-and-temp observation and the DOS-device chain bypass are proved")
        print("  below.  The properties that need the bootstrap to ACCEPT a chain and")
        print("  INSTALL are reported NOT-RUN-ELEVATION-REQUIRED and are NOT faked.")

    base = str(Path(os.path.abspath(os.sep)) / ("mr-bootstrap-guard-" + uuid.uuid4().hex[:10]))
    os.makedirs(long_path(base), exist_ok=False)
    apply_sddl_dacl(base, MINE_FULL)
    workspace = Path(base) / "_mutations"
    os.makedirs(long_path(str(workspace)), exist_ok=False)
    work = Workspace(base)

    global HOST
    HOST = HostBaseline(base)
    print("  host cost : %s" % HOST.describe())
    print("              (raw: processes=%s files=%s)"
          % (sorted(HOST.raw_processes.values()) or "none", HOST.raw_artifacts or "none"))

    failures = 0
    try:
        selected = sorted((s for s in SCENARIOS if args.only.lower() in s["id"].lower()),
                          key=lambda s: s["id"])
        results = []
        for spec in selected:
            if not image.reverify():
                print("FAIL: the bootstrap changed on disk mid-run; refusing to continue")
                return 1
            results.append(spec["run"](base, image, work))

        for ident, title, expected in ELEVATION_ONLY:
            if args.only and args.only.lower() not in ident.lower():
                continue
            if ELEVATED:
                results.append(Skipped(ident, title + "  [ELEVATED RUN: see note]",
                                       expected, ELEVATED_COMMAND))
            else:
                results.append(Skipped(ident, title, expected, ELEVATED_COMMAND))

        results.sort(key=lambda r: r.id)
        print_table(results, show_stdout=args.show_stdout)
        failures += sum(1 for r in results if r.counts_as_failure)

        skipped = [r for r in results if r.verdict == "NOT-RUN-ELEVATION"]
        if skipped:
            print("NOT RUN - ELEVATION REQUIRED (%d rows)" % len(skipped))
            for r in skipped:
                print("  %-8s %-30s %s" % (r.id, r.expected, r.title))
            print()
            for line in ELEVATED_COMMAND.splitlines():
                print("  " + line)
            print()

        if args.delete_mechanism:
            print("DELETE-THE-MECHANISM  (self-review evidence, NOT the acceptance oracle)")
            print("  Each row disables one scenario's mechanism in a temporary copy of the")
            print("  bootstrap and re-runs that same scenario.  A row FLIPS when the refusal")
            print("  reason changes.  A row that does not flip means the scenario was never")
            print("  testing the mechanism it claims to test.")
            print()
            flip_failures = 0
            for spec in selected:
                if not spec["mutations"]:
                    continue
                print("  %-14s mechanism: %s" % (spec["id"], spec["mechanism"]))
                if spec["mutations"] == ("harness_pin",):
                    print("                 mutation : (none in the bootstrap - the mechanism is")
                    print("                            this harness's pre-launch hash comparison)")
                    print("                 flipped  : YES - bypassing it means launching with the")
                    print("                            real hash, which is every other row here")
                    continue
                mutated = mutate(image, spec["mutations"], workspace)
                flip_base = base + "\\_flip-" + spec["id"].lower()
                os.makedirs(long_path(flip_base), exist_ok=False)
                flip_work = Workspace(flip_base)
                outcome = spec["run"](flip_base, mutated, flip_work)
                # A flip is a CHANGE IN OUTCOME, and the outcome is the refusal
                # reason PLUS everything this harness observed.  Judging it by
                # the reason alone would score the most important mutation here -
                # putting the compiler back - as "did not flip", because the
                # refusal that eventually happens is the same one either way.
                # What changed is that csc.exe ran and wrote a DLL into %TEMP%,
                # and that is the damage, not the exit code.
                damage = [description for description, ok in outcome.checks if not ok]
                reason_changed = outcome.observed != outcome.expected
                flipped = reason_changed or bool(damage)
                print("                 mutation : %s  (copy sha256 %s...)"
                      % ("+".join(spec["mutations"]), mutated.sha256[:16]))
                print("                 with     : %s" % outcome.expected)
                print("                 without  : %s%s"
                      % (outcome.observed, exit_note(outcome.launch.code)))
                if flipped:
                    how = []
                    if reason_changed:
                        how.append("the refusal reason changed")
                    if damage:
                        how.append("%d harness-observed check(s) that held with the "
                                   "mechanism now FAIL - the damage is open" % len(damage))
                    print("                 flipped  : YES (%s)" % "; and ".join(how))
                else:
                    print("                 flipped  : NO  <-- same reason AND the same "
                          "observations; the scenario does not depend on this mechanism")
                for description, ok in outcome.checks:
                    print("                     [%s] %s" % ("ok" if ok else "DAMAGE", description))
                if outcome.note:
                    print("                     note: %s" % outcome.note)
                if not flipped:
                    flip_failures += 1
            print()
            if flip_failures:
                print("%d mechanism(s) did not flip." % flip_failures)
            failures += flip_failures

            damage_base = base + "\\_damage"
            os.makedirs(long_path(damage_base), exist_ok=False)
            if not subst_damage_experiment(damage_base, image, workspace,
                                           Workspace(damage_base)):
                failures += 1
    finally:
        if not args.keep:
            for path in Chain.ALL:
                try:
                    remove_tree(path)
                except OSError as exc:
                    print("(fixture cleanup left %s: %s)" % (path, exc))
            try:
                remove_tree(base)
            except OSError as exc:
                print("(fixture cleanup left %s: %s)" % (base, exc))

    if failures:
        print("FAIL: %d scenario/mechanism check(s) did not hold." % failures)
        return 1
    print("Offline bootstrap guard passed"
          "%s." % ("" if ELEVATED else " (unelevated tier; elevation-required rows listed above)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
