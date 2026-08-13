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
     `GetFileAttributesW`, and object identity read here through
     `GetFileInformationByHandle`.

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
  INCONCLUSIVE        a timing-dependent fixture never managed to inject its
                      hostile change; the run proves nothing either way

The code -> name table below is THIS FILE'S OWN copy of the published taxonomy.
It is not read from the bootstrap, so a bootstrap that renumbered its codes would
fail these scenarios rather than redefine what they mean.

ELEVATION
---------
This harness runs UNELEVATED.  It therefore cannot build a fixture owned by
BUILTIN\\Administrators, and it substitutes its own SID through the bootstrap's
documented `-TrustedSid` widening parameter.  Three things keep that honest:

  * CTL-OWNER runs the identical fixture WITHOUT `-TrustedSid` and requires
    PARENT_OWNER_UNTRUSTED - so the default trust set demonstrably excludes the
    current user;
  * SCN-15 shows `-TrustedSid` cannot be handed an open group; and
  * CTL-PROGFILES runs against the real OS-derived ProgramFiles parent and shows
    it is not writable by this account.

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
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "packaging" / "offline" / "Invoke-OfflineBootstrap.ps1"

BUNDLE_CONTRACT = "offline-bootstrap-bundle/v1"

# The harness's own copy of the published refusal taxonomy.
REASONS = {
    0: "OK",
    10: "ARGS_INVALID",
    11: "UNEXPECTED_ERROR",
    20: "SOURCE_MISSING",
    21: "SOURCE_REPARSE",
    22: "SOURCE_GIT_PATH",
    23: "SOURCE_COLLISION",
    24: "SOURCE_NAME_UNSAFE",
    25: "BUNDLE_PIN_MISMATCH",
    26: "SOURCE_UNREADABLE",
    27: "SOURCE_EMPTY_DIRECTORY",
    28: "MANIFEST_UNSORTED",
    30: "PARENT_MISSING",
    31: "PARENT_REPARSE",
    32: "PARENT_DACL_ABSENT",
    33: "PARENT_ACE_UNINTERPRETABLE",
    34: "PARENT_OWNER_UNTRUSTED",
    35: "PARENT_UNSAFE_WRITABLE_ACE",
    36: "PARENT_NOT_ANCHORED",
    40: "ROOT_EXISTS",
    41: "ROOT_CREATE_FAILED",
    42: "ROOT_REPARSE",
    43: "ROOT_DACL_ABSENT",
    44: "ROOT_ACE_UNINTERPRETABLE",
    45: "ROOT_OWNER_UNTRUSTED",
    46: "ROOT_UNSAFE_WRITABLE_ACE",
    47: "ROOT_MISSING",
    48: "ROOT_NOT_ANCHORED",
    50: "COPY_FAILED",
    51: "DESTINATION_MISMATCH",
    52: "ROOT_IDENTITY_CHANGED",
    53: "COPY_DIRECTORY_OCCUPIED",
    60: "DESTINATION_MISSING",
    61: "DESTINATION_REPARSE",
    62: "DESTINATION_GIT_PATH",
    63: "DESTINATION_COLLISION",
    64: "DESTINATION_NAME_UNSAFE",
    66: "DESTINATION_UNREADABLE",
    67: "DESTINATION_EMPTY_DIRECTORY",
}
CODE_OF = {name: code for code, name in REASONS.items()}


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
advapi32.GetSecurityDescriptorDacl.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wt.BOOL), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wt.BOOL)]


def long_path(path):
    """The \\\\?\\ form of a path, IDEMPOTENTLY.

    os.path.abspath goes through GetFullPathNameW, which strips trailing spaces
    and dots even from an already-extended path - so re-normalising a path that
    is already extended silently renames 'Sub ' to 'Sub'.  That is precisely the
    ambiguity SCN-08 exists to exercise, so the harness must not reintroduce it.
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
    return sorted(os.listdir(long_path(path))) if exists(path) else None


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
    for name in os.listdir(long_path(path)):
        remove_tree(long_path(path) + "\\" + name)
    os.rmdir(long_path(path))


# ---------------------------------------------------------------------------
# The bundle root hash, reimplemented here from the published pre-image.
#
# Deliberately a SECOND implementation in a different language.  The harness
# plays the operator: it holds the pin.  When the bootstrap accepts a pin
# computed here, two independent implementations agreed on the bytes.
# ---------------------------------------------------------------------------

def _folded(components):
    return "/".join(c.rstrip(" .").upper() for c in components)


def enumerate_bundle(root):
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


def bundle_root_hash(root):
    members = sorted(enumerate_bundle(root), key=lambda m: m["folded"])
    parts = [BUNDLE_CONTRACT, "\n", "members=", str(len(members)), "\n"]
    for member in members:
        parts += [member["relative"], "\0", member["sha256"], "\0",
                  str(member["size"]), "\n"]
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def tree_digests(root):
    """relative path -> sha256, computed here.  The root itself is refused if it
    is a reparse point; junctions BELOW it are walked, because a scenario that
    plants one needs to see what actually landed on the other side."""
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
    def __init__(self, code, stdout, launched, note=""):
        self.code = code
        self.stdout = stdout
        self.launched = launched
        self.note = note

    @property
    def reason(self):
        return reason_of(self.code) if self.launched else "NOT-LAUNCHED"


def launch(image, args, expected_hash=None, on_running=None, timeout=300):
    """Verify the pin, then run the exact pinned file.

    `expected_hash` defaults to the hash recorded when the Image was built.  A
    scenario may pass a different value to model an operator holding the WRONG
    pin; a mismatch means nothing is launched at all.
    """
    pin = image.sha256 if expected_hash is None else expected_hash
    actual = hashlib.sha256(image.path.read_bytes()).hexdigest()
    if actual != pin:
        return Launch(None, "", False, "pin mismatch: pinned=%s actual=%s" % (pin, actual))

    command = [system_powershell(), "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(image.path)]
    command += [str(a) for a in args]
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, cwd=str(ROOT))
    if on_running is not None:
        on_running(process)
    try:
        out, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        out, _ = process.communicate()
        return Launch(None, out.decode("utf-8", "replace"), True, "timed out")
    return Launch(process.returncode, out.decode("utf-8", "replace"), True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ME = current_user_sid()
# Protected and explicit: SYSTEM + Administrators + this account, full control,
# inherited by children.  No open group appears anywhere in a fixture chain, so
# a refusal that names one is a refusal the fixture planted on purpose.
HARDENED = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)" % ME


class Fixture(object):
    """One scenario's private corner of the filesystem."""

    def __init__(self, base, name):
        self.dir = str(Path(base) / name)
        ensure_dir(long_path(self.dir))
        self.parent = self.dir + "\\parent"
        ensure_dir(long_path(self.parent))
        self.source = self.dir + "\\src"
        ensure_dir(long_path(self.source))

    def hardened_parent(self, extra_aces=""):
        apply_sddl_dacl(self.parent, HARDENED + extra_aces)

    def write(self, relative, data):
        target = long_path(self.source) + "\\" + relative.replace("/", "\\")
        ensure_dir(target.rsplit("\\", 1)[0])
        with open(target, "wb") as handle:
            handle.write(data)
        return target

    def small_bundle(self):
        self.write("a.txt", b"alpha\n")
        self.write("sub/b.txt", b"beta\n")
        self.write("sub/c.bin", bytes(bytearray(range(256))))
        # Sorts AFTER 'sub/...', so a depth-first walk emits it BEFORE the
        # subdirectory's members.  Enumeration order therefore differs from
        # manifest order in every fixture that uses this bundle.
        self.write("z.txt", b"omega\n")

    def timed_bundle(self, small_files=400, blob_bytes=64 * 1024 * 1024):
        """A bundle big enough that the copy and the destination re-hash each
        take long enough for a hostile change to be injected at an observable
        moment.  Folded ordinal order is aa-bulk.bin, f####.txt, sub/s.txt,
        zz-tail.txt - so `sub/` and the tail file are written late and the
        harness can watch the destination for the exact moment to strike."""
        self.write("aa-bulk.bin", os.urandom(blob_bytes))
        for index in range(small_files):
            self.write("f%04d.txt" % index, ("payload %d\n" % index).encode())
        self.write("sub/s.txt", b"nested\n")
        self.write("zz-tail.txt", b"tail-original\n")

    def swap_bundle(self, small_files=200, blob_bytes=160 * 1024 * 1024):
        """A bundle shaped for the destination-swap scenario.

        A directory swap is two renames, and Windows only lets the first one
        through when the subtree has no open handle - which is exactly the
        instant the bootstrap closes a file and issues its next path call.  Aim
        there and the swap lands in the gap between the two renames and the run
        refuses for an incidental reason instead of the property.

        So the largest member is named to come LAST both in copy order and in
        directory-index order: the destination re-hash therefore ends with one
        long read through a single handle, and the handle-close that finally lets
        the rename through is followed by the pure-CPU manifest comparison rather
        than by another path call.
        """
        for index in range(small_files):
            self.write("b%04d.txt" % index, ("payload %d\n" % index).encode())
        self.write("zz-bulk.bin", os.urandom(blob_bytes))

    def pin(self):
        return bundle_root_hash(self.source)

    def args(self, root_name="trustroot", pin=None, trusted=True):
        argv = ["-RootName", root_name,
                "-SourcePath", self.source,
                "-ExpectedBundleHash", pin if pin else self.pin(),
                "-ParentPath", self.parent]
        if trusted:
            argv += ["-TrustedSid", ME]
        return argv

    def root(self, root_name="trustroot"):
        return self.parent + "\\" + root_name


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
        return self.verdict == "PASS"


SCENARIOS = []


def scenario(ident, mechanism=None, mutations=()):
    def register(function):
        SCENARIOS.append({"id": ident, "run": function,
                          "mechanism": mechanism, "mutations": tuple(mutations)})
        return function
    return register


# --- controls ------------------------------------------------------------

@scenario("CTL-HAPPY",
          mechanism="deterministic ordinal sort of the manifest (the pre-image is "
                    "order-sensitive, so enumeration order must not reach the pin)",
          mutations=("sorted_manifest",))
def _happy(base, image):
    fx = Fixture(base, "ctl-happy")
    fx.hardened_parent()
    fx.small_bundle()
    expected_files = tree_digests(fx.source)
    result = launch(image, fx.args())
    root = fx.root()
    sddl = security_descriptor_sddl(root) or ""
    checks = [
        ("harness sees the root created", exists(root)),
        ("harness sees the root is not a reparse point", not is_reparse_point(root)),
        ("harness-computed digests of the installed tree equal the source tree",
         tree_digests(root) == expected_files),
        ("harness reads the root owner and finds the trusted SID",
         sddl.startswith("O:" + ME)),
        ("harness finds no open-group ACE in the root DACL",
         not re.search(r"\(A;[^)]*;(WD|BU|AU|IU|BG)\)", sddl)),
    ]
    return Result("CTL-HAPPY", "positive control: clean bundle into a fresh root",
                  "OK", result, checks)


@scenario("CTL-OWNER")
def _owner_control(base, image):
    fx = Fixture(base, "ctl-owner")
    fx.hardened_parent()
    fx.small_bundle()
    result = launch(image, fx.args(trusted=False))
    checks = [("harness sees no root created", not exists(fx.root()))]
    return Result("CTL-OWNER",
                  "control: without -TrustedSid the default trust set rejects this account",
                  "PARENT_OWNER_UNTRUSTED", result, checks)


@scenario("CTL-PROGFILES")
def _programfiles_control(base, image):
    fx = Fixture(base, "ctl-progfiles")
    fx.small_bundle()
    root_name = "mr-offline-probe-" + uuid.uuid4().hex[:8]
    argv = ["-RootName", root_name, "-SourcePath", fx.source,
            "-ExpectedBundleHash", fx.pin()]        # no -ParentPath: OS-derived
    result = launch(image, argv)
    target = os.path.join(os.path.abspath(os.sep), "Program Files", root_name)
    checks = [("harness sees nothing created under the real ProgramFiles",
               not exists(target))]
    return Result("CTL-PROGFILES",
                  "control: OS-derived ProgramFiles parent is not writable unelevated",
                  "ROOT_CREATE_FAILED", result, checks)


# --- the required scenarios ---------------------------------------------

@scenario("SCN-01",
          mechanism="atomic create-or-refuse (CreateDirectoryW; never Test-Path-then-create)",
          mutations=("createdirw_root",))
def _pre_created_root(base, image):
    fx = Fixture(base, "scn-01")
    fx.hardened_parent()
    fx.small_bundle()
    root = fx.root()
    os.makedirs(long_path(root), exist_ok=False)
    with open(long_path(root) + "\\squatter.txt", "wb") as handle:
        handle.write(b"i was here first\n")
    result = launch(image, fx.args())
    checks = [
        ("harness sees the pre-existing root still holding only its own file",
         listing(root) == ["squatter.txt"]),
        ("harness confirms no bundle member was written into it",
         not exists(root + "\\a.txt")),
    ]
    return Result("SCN-01", "pre-created root is refused, not adopted",
                  "ROOT_EXISTS", result, checks)


@scenario("SCN-02",
          mechanism="reparse-state judged on every component of the parent chain",
          mutations=("reparse_node",))
def _junction_parent(base, image):
    fx = Fixture(base, "scn-02")
    target = fx.dir + "\\parent-target"
    os.makedirs(long_path(target), exist_ok=False)
    remove_tree(fx.parent)
    create_junction(fx.parent, target)
    fx.small_bundle()
    result = launch(image, fx.args())
    checks = [
        ("harness confirms the parent really is a reparse point", is_reparse_point(fx.parent)),
        ("harness sees the junction target still empty", listing(target) == []),
    ]
    return Result("SCN-02", "junction as parent is refused, not followed",
                  "PARENT_REPARSE", result, checks)


@scenario("SCN-03",
          mechanism="atomic create-or-refuse + the root reparse check (defence in depth: "
                    "either alone refuses, so the flip needs both removed)",
          mutations=("createdirw_root", "reparse_node"))
def _junction_root(base, image):
    fx = Fixture(base, "scn-03")
    fx.hardened_parent()
    fx.small_bundle()
    target = fx.dir + "\\root-target"
    os.makedirs(long_path(target), exist_ok=False)
    create_junction(fx.root(), target)
    result = launch(image, fx.args())
    checks = [
        ("harness confirms the root name really is a junction", is_reparse_point(fx.root())),
        ("harness sees the junction target still empty", listing(target) == []),
    ]
    return Result("SCN-03", "junction occupying the root name is refused, not written through",
                  "ROOT_REPARSE", result, checks)


@scenario("SCN-04",
          mechanism="content-changing rights judged on the final node of the chain",
          mutations=("content_class",))
def _writable_parent(base, image):
    fx = Fixture(base, "scn-04")
    # Everyone may add files to the parent itself (this object only, NOT
    # inherit-only): exactly the writable parent the design must refuse.
    fx.hardened_parent(extra_aces="(A;;0x2;;;WD)")
    fx.small_bundle()
    result = launch(image, fx.args())
    sddl = security_descriptor_sddl(fx.parent) or ""
    checks = [
        ("harness reads the parent DACL and finds the Everyone write ACE it planted",
         ";WD)" in sddl),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-04", "non-admin-writable parent refused before any root exists",
                  "PARENT_UNSAFE_WRITABLE_ACE", result, checks)


@scenario("SCN-05",
          mechanism="the harness's own pre-launch SHA-256 comparison",
          mutations=("harness_pin",))
def _wrong_bootstrap_pin(base, image):
    fx = Fixture(base, "scn-05")
    fx.hardened_parent()
    fx.small_bundle()
    wrong = "0" * 64
    result = launch(image, fx.args(), expected_hash=wrong)
    checks = [
        ("harness computed the real hash itself and it differs from the pin",
         image.sha256 != wrong),
        ("nothing was launched", not result.launched),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-05", "wrong bootstrap pin: detected by the harness before launch",
                  "NOT-LAUNCHED", result, checks)


@scenario("SCN-06",
          mechanism="root-hash comparison against the operator pin, before any copy",
          mutations=("bundle_pin", "dest_roothash"))
def _wrong_bundle_pin(base, image):
    fx = Fixture(base, "scn-06")
    fx.hardened_parent()
    fx.small_bundle()
    result = launch(image, fx.args(pin="b" * 64))
    checks = [
        ("harness sees no root created at all (the refusal precedes creation)",
         not exists(fx.root())),
        ("harness's own root hash of the source differs from the pin supplied",
         fx.pin() != "b" * 64),
    ]
    return Result("SCN-06", "wrong release-bundle pin refused before copying anything",
                  "BUNDLE_PIN_MISMATCH", result, checks)


@scenario("SCN-07",
          mechanism="destination re-hash compared member-by-member to the source manifest",
          mutations=("dest_rehash", "dest_roothash"))
def _tamper_after_hash(base, image):
    fx = Fixture(base, "scn-07")
    fx.hardened_parent()
    fx.timed_bundle()
    pin = fx.pin()
    tail = long_path(fx.source) + "\\zz-tail.txt"
    with open(tail, "rb") as handle:
        original_digest = hashlib.sha256(handle.read()).hexdigest()
    tampered = b"tail-TAMPERED\n"            # same length as the original
    tampered_digest = hashlib.sha256(tampered).hexdigest()
    state = {"struck": False}

    def strike(process):
        # The root can only appear AFTER the source was fully enumerated and
        # hashed and the pin matched.  That is the moment to change the bytes.
        deadline = time.time() + 120
        while time.time() < deadline and process.poll() is None:
            if exists(fx.root()):
                with open(tail, "wb") as handle:
                    handle.write(tampered)
                state["struck"] = True
                return
            time.sleep(0.002)

    result = launch(image, fx.args(pin=pin), on_running=strike)
    installed_digest = file_digest(fx.root() + "\\zz-tail.txt")
    landed = installed_digest == tampered_digest
    note = "" if (state["struck"] and landed) else (
        "INCONCLUSIVE: the tampered bytes never reached the copy, so this run "
        "proves nothing either way")
    checks = [
        ("harness injected the tamper once the root appeared", state["struck"]),
        ("harness-computed digest of the INSTALLED file equals the tampered bytes", landed),
        ("harness-computed digest of the installed file differs from the pinned original",
         installed_digest != original_digest),
    ]
    return Result("SCN-07", "bytes changed between hashing and copy are caught",
                  "DESTINATION_MISMATCH", result, checks, note=note)


@scenario("SCN-08",
          mechanism="collision fold: per-component trailing dot/space trim + ordinal "
                    "case fold (with the trailing-space name check as the second line, "
                    "so the flip needs both removed)",
          mutations=("case_fold", "trim_name_check"))
def _collision(base, image):
    fx = Fixture(base, "scn-08")
    fx.hardened_parent()
    fx.write("sub/x.bin", b"first\n")
    # 'Sub ' is a DIFFERENT NTFS entry from 'sub', reachable only through \\?\,
    # but Win32 resolves both to the same directory - so the bundle names one
    # destination file twice and copy order, not the pin, decides which survives.
    fx.write("Sub /x.bin", b"second\n")
    # A CORRECT pin for this source, so the refusal cannot be attributed to a
    # pin mismatch and removing the mechanism installs the ambiguity rather than
    # tripping over an unrelated check.
    result = launch(image, fx.args())
    checks = [
        ("harness confirms both colliding directories exist on disk",
         exists(fx.source + "\\sub") and exists(long_path(fx.source) + "\\Sub ")),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-08", "ordinal-ignore-case path collision refused",
                  "SOURCE_COLLISION", result, checks)


@scenario("SCN-09",
          mechanism="reparse check on every enumerated source entry",
          mutations=("enum_reparse",))
def _source_reparse(base, image):
    fx = Fixture(base, "scn-09")
    fx.hardened_parent()
    fx.small_bundle()
    outside = fx.dir + "\\outside"
    os.makedirs(long_path(outside), exist_ok=False)
    with open(long_path(outside) + "\\secret.txt", "wb") as handle:
        handle.write(b"not part of the bundle\n")
    create_junction(fx.source + "\\linked", outside)
    # A CORRECT pin, so the refusal cannot be attributed to a pin mismatch and
    # removing the mechanism installs the damage instead of tripping over an
    # unrelated check.
    result = launch(image, fx.args())
    checks = [
        ("harness confirms the source really contains a junction",
         is_reparse_point(fx.source + "\\linked")),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-09", "reparse point inside the source refused, never enumerated through",
                  "SOURCE_REPARSE", result, checks)


@scenario("SCN-10",
          mechanism="root object identity re-checked after installation",
          mutations=("final_identity",))
def _destination_swap(base, image):
    fx = Fixture(base, "scn-10")
    fx.hardened_parent()
    fx.swap_bundle()
    pin = fx.pin()
    blob_size = os.path.getsize(long_path(fx.source) + "\\zz-bulk.bin")
    replica = fx.parent + "\\replica"
    shutil.copytree(long_path(fx.source), long_path(replica))
    replica_identity = object_identity(replica)
    evicted = fx.parent + "\\evicted"
    state = {"struck": False, "original": None, "aim": 0.0}

    def strike(process):
        blob = fx.root() + "\\zz-bulk.bin"
        deadline = time.time() + 600
        opened = None
        small_phase = None
        while time.time() < deadline and process.poll() is None:
            if opened is None and exists(fx.root()):
                opened = time.time()                       # the copy has begun
            elif opened is not None and small_phase is None and exists(blob):
                small_phase = time.time() - opened         # 200 small members
            elif small_phase is not None:
                try:
                    if os.path.getsize(long_path(blob)) >= blob_size:
                        state["original"] = object_identity(fx.root())
                        break                              # the copy is done
                except OSError:
                    pass
            time.sleep(0.002)
        if state["original"] is None:
            return
        # The destination re-hash repeats the same walk the copy just made, so
        # the time the copy spent on the 200 small members is a measured estimate
        # of how long the re-hash will spend on them.  Waiting that long puts the
        # strike inside the final 160 MB read, where the bootstrap resolves no
        # paths at all; the handle-close that finally lets the rename through is
        # then followed by the pure-CPU manifest comparison, not by another path
        # call, so the instant between the two renames is not observed.
        #
        # This delay is a fixture parameter, not part of the oracle.  A mistimed
        # strike surfaces as INCONCLUSIVE or as a reported wrong reason - never as
        # a pass.
        state["aim"] = small_phase
        time.sleep(small_phase)
        root_l, evicted_l, replica_l = long_path(fx.root()), long_path(evicted), long_path(replica)
        while time.time() < deadline and process.poll() is None:
            try:
                os.rename(root_l, evicted_l)
            except OSError:
                continue
            os.rename(replica_l, root_l)
            state["struck"] = True
            return

    result = launch(image, fx.args(pin=pin), on_running=strike)
    final_identity = object_identity(fx.root())
    note = "" if state["struck"] else (
        "INCONCLUSIVE: the swap never landed, so this run proves nothing either way")
    checks = [
        ("harness performed the swap after the last member was copied", state["struck"]),
        ("harness-read identity of the root equals the replica it swapped in",
         final_identity is not None and final_identity == replica_identity),
        ("harness-read identity of the root differs from the object the bootstrap created",
         state["original"] is not None and final_identity != state["original"]),
        ("harness sees the evicted original still on disk", exists(evicted)),
    ]
    return Result("SCN-10", "root replaced after the copy by an identical-content twin is caught",
                  "ROOT_IDENTITY_CHANGED", result, checks, note=note)


@scenario("SCN-11",
          mechanism="owner/DACL of the CREATED root judged, inherited ACEs included",
          mutations=("root_chain", "root_chain_final"))
def _unsafe_destination_acl(base, image):
    fx = Fixture(base, "scn-11")
    # Inherit-only: grants nothing ON the parent, so the parent passes; the root
    # the bootstrap creates inherits it as an EFFECTIVE ACE.
    fx.hardened_parent(extra_aces="(A;OICIIO;0x2;;;WD)")
    fx.small_bundle()
    result = launch(image, fx.args())
    sddl = security_descriptor_sddl(fx.root()) or ""
    checks = [
        ("harness reads the created root's DACL and finds the inherited Everyone ACE",
         ";WD)" in sddl),
        ("harness sees the root exists but received no bundle member",
         listing(fx.root()) == []),
    ]
    return Result("SCN-11", "unsafe inherited ACL on the destination refused before copying",
                  "ROOT_UNSAFE_WRITABLE_ACE", result, checks)


@scenario("SCN-12",
          mechanism="destination subdirectories created with CreateDirectoryW (create-or-refuse)",
          mutations=("createdirw_child",))
def _copy_junction_injection(base, image):
    fx = Fixture(base, "scn-12")
    fx.hardened_parent()
    fx.timed_bundle()
    pin = fx.pin()
    outside = fx.dir + "\\outside"
    os.makedirs(long_path(outside), exist_ok=False)
    state = {"struck": False}

    def strike(process):
        deadline = time.time() + 120
        while time.time() < deadline and process.poll() is None:
            if exists(fx.root()):
                try:
                    create_junction(fx.root() + "\\sub", outside)
                    state["struck"] = True
                except OSError:
                    pass
                return
            time.sleep(0.002)

    result = launch(image, fx.args(pin=pin), on_running=strike)
    note = "" if state["struck"] else (
        "INCONCLUSIVE: the junction was never injected, so this run proves nothing")
    checks = [
        ("harness injected a junction at <root>\\sub during the run", state["struck"]),
        ("harness sees ZERO bytes written through the junction to the outside directory",
         listing(outside) == []),
    ]
    return Result("SCN-12", "a subdirectory name occupied mid-copy is refused, not written through",
                  "COPY_DIRECTORY_OCCUPIED", result, checks, note=note)


@scenario("SCN-13",
          mechanism="ordinal-ignore-case equality against '.git' on every component",
          mutations=("git_component",))
def _git_in_source(base, image):
    fx = Fixture(base, "scn-13")
    fx.hardened_parent()
    fx.small_bundle()
    fx.write(".GIT/config", b"[core]\n")
    # A CORRECT pin, so the refusal cannot be attributed to a pin mismatch and
    # removing the mechanism installs the damage instead of tripping over an
    # unrelated check.
    result = launch(image, fx.args())
    checks = [
        ("harness confirms the source really contains .GIT/config",
         exists(fx.source + "\\.GIT\\config")),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-13", "any spelling of .git in the source is refused",
                  "SOURCE_GIT_PATH", result, checks)


@scenario("SCN-14",
          mechanism="empty directories refused rather than left invisible to the pin",
          mutations=("empty_dir",))
def _empty_directory(base, image):
    fx = Fixture(base, "scn-14")
    fx.hardened_parent()
    fx.small_bundle()
    os.makedirs(long_path(fx.source) + "\\hollow", exist_ok=False)
    # A CORRECT pin, so the refusal cannot be attributed to a pin mismatch and
    # removing the mechanism installs the damage instead of tripping over an
    # unrelated check.
    result = launch(image, fx.args())
    checks = [
        ("harness confirms the empty directory exists and holds nothing",
         listing(fx.source + "\\hollow") == []),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-14", "a directory the pin cannot see is refused",
                  "SOURCE_EMPTY_DIRECTORY", result, checks)


@scenario("SCN-17",
          mechanism="every component of the chain is judged, not just the leaf "
                    "(redirect-class rights anywhere upstream defeat a leaf nobody can write)",
          mutations=("chain_leaf_only",))
def _unsafe_grandparent(base, image):
    """Answers the self-review question 'does any refusal key to fewer operands
    than the damage?' with a test rather than a claim: the ACE is planted TWO
    levels above the root, on a directory that is not the leaf of any check."""
    fx = Fixture(base, "scn-17")
    remove_tree(fx.parent)
    mid = fx.dir + "\\mid"
    ensure_dir(long_path(mid))
    fx.parent = mid + "\\parent"
    ensure_dir(long_path(fx.parent))
    fx.small_bundle()
    # DELETE for Everyone on 'mid' ONLY: not inheritable, so neither the parent
    # nor the root carries it.  Everyone can rename 'mid' out from under an
    # otherwise impeccable parent and root.
    apply_sddl_dacl(mid, HARDENED + "(A;;SD;;;WD)")
    result = launch(image, fx.args())
    mid_sddl = security_descriptor_sddl(mid) or ""
    parent_sddl = security_descriptor_sddl(fx.parent) or ""
    checks = [
        ("harness reads the grandparent DACL and finds the Everyone delete ACE",
         ";WD)" in mid_sddl),
        ("harness confirms the ACE is NOT on the parent, so only a full-chain check can see it",
         ";WD)" not in parent_sddl),
        ("harness sees no root created", not exists(fx.root())),
    ]
    return Result("SCN-17",
                  "an unsafe ACE two levels above the root is refused",
                  "PARENT_UNSAFE_WRITABLE_ACE", result, checks)


@scenario("SCN-16",
          mechanism="deterministic ordinal sort of the manifest, over a tree whose "
                    "depth-first order differs from its sorted order at every level",
          mutations=("sorted_manifest",))
def _manifest_order(base, image):
    fx = Fixture(base, "scn-16")
    fx.hardened_parent()
    # Depth-first emission is: b.txt, zzz.txt, then the members of m/ and a/.
    # Manifest order is a/inner.txt, b.txt, m/n/deep.txt, zzz.txt.  The two
    # orders agree nowhere, so a pin computed from the documented (sorted)
    # pre-image can only be accepted if the bootstrap really sorts.
    fx.write("b.txt", b"bee\n")
    fx.write("zzz.txt", b"zed\n")
    fx.write("m/n/deep.txt", b"deep\n")
    fx.write("a/inner.txt", b"inner\n")
    expected_files = tree_digests(fx.source)
    result = launch(image, fx.args())
    checks = [
        ("harness-computed digests of the installed tree equal the source tree",
         tree_digests(fx.root()) == expected_files),
        ("harness's independently sorted pre-image produced a pin the bootstrap accepted",
         result.code == 0),
    ]
    return Result("SCN-16",
                  "the root hash depends on the member set, not on enumeration order",
                  "OK", result, checks)


@scenario("SCN-15",
          mechanism="open-SID deny list on the trust-widening parameter",
          mutations=("open_sid",))
def _open_sid(base, image):
    fx = Fixture(base, "scn-15")
    # Same inherit-only Everyone ACE as SCN-11: without the deny list, naming
    # Everyone as trusted makes the root's own DACL check pass and the bundle is
    # installed into a world-writable root.  With it, nothing runs at all.
    fx.hardened_parent(extra_aces="(A;OICIIO;0x2;;;WD)")
    fx.small_bundle()
    argv = fx.args(trusted=False) + ["-TrustedSid", ME + ";S-1-1-0"]
    result = launch(image, argv)
    checks = [
        ("harness sees no root created", not exists(fx.root())),
        ("harness confirms the parent really carries the inheritable Everyone ACE",
         ";WD)" in (security_descriptor_sddl(fx.parent) or "")),
    ]
    return Result("SCN-15", "the trust-widening parameter cannot be handed Everyone",
                  "ARGS_INVALID", result, checks)


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
    "createdirw_root": (
        "    if (-not [OfflineBootstrapNative]::CreateDirectoryW($root, [IntPtr]::Zero)) {",
        "    $null = [IO.Directory]::CreateDirectory($root)\n    if ($false) {",
    ),
    "createdirw_child": (
        "                if (-not [OfflineBootstrapNative]::CreateDirectoryW($destinationPath, [IntPtr]::Zero)) {",
        "                $null = [IO.Directory]::CreateDirectory($destinationPath)\n                if ($false) {",
    ),
    "reparse_node": (
        "    if ($Information.IsReparse) { return @{ Kind = 'REPARSE'; Detail = $Path } }",
        "    if ($false) { return @{ Kind = 'REPARSE'; Detail = $Path } }",
    ),
    "content_class": (
        "    if ($IsFinal) { $unsafeMask = $unsafeMask -bor $CONTENT_CLASS }",
        "    if ($false) { $unsafeMask = $unsafeMask -bor $CONTENT_CLASS }",
    ),
    "bundle_pin": (
        "    if ($computed -ne $pin) {",
        "    if ($false) {",
    ),
    "dest_rehash": (
        "        if ($expectedMember.Sha256 -ne $actualMember.Sha256) {",
        "        if ($false) {",
    ),
    "dest_roothash": (
        "    if ($installedHash -ne $pin) {",
        "    if ($false) {",
    ),
    "case_fold": (
        "    $folded = foreach ($component in $Components) { (Get-TrimmedComponent -Component $component).ToUpperInvariant() }",
        "    $folded = foreach ($component in $Components) { (Get-TrimmedComponent -Component $component) }",
    ),
    "enum_reparse": (
        '                    if ($information.IsReparse) { Deny -Reason "${Phase}_REPARSE" -Detail $relative }',
        "                    if ($false) { }",
    ),
    "final_identity": (
        "    if ($null -eq $finalIdentity -or $finalIdentity -ne $rootIdentity) {",
        "    if ($false) {",
    ),
    "root_chain": (
        "    $rootIdentity = Assert-PathChain -Path $root -Prefix 'ROOT'",
        "    $rootIdentity = Get-ResolvedIdentity -Path $root",
    ),
    "root_chain_final": (
        "    $null = Assert-PathChain -Path $root -Prefix 'ROOT'",
        "    $null = $root",
    ),
    "git_component": (
        "    return [string]::Equals($Component, '.git', [StringComparison]::OrdinalIgnoreCase)",
        "    return $false",
    ),
    "empty_dir": (
        "            if (@($entries).Count -eq 0) {",
        "            if ($false) {",
    ),
    # Restores the defect this branch fixed: the members keep the order the
    # filesystem walk produced instead of the order the pre-image declares.
    "sorted_manifest": (
        "    for ($i = 0; $i -lt $rows.Count; $i++) { $sorted[$i] = $index[$keys[$i]] }",
        "    for ($i = 0; $i -lt $rows.Count; $i++) { $sorted[$i] = $rows[$i] }",
    ),
    # Reduces the chain check to the leaf - the defect that killed the third
    # attempt at this problem: it checked the leaf while adopting the parent.
    "chain_leaf_only": (
        "            if ($null -ne $problem) {\n"
        "                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail \"$full component=$($problem.Detail)\"",
        "            if ($isFinal -and $null -ne $problem) {\n"
        "                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail \"$full component=$($problem.Detail)\"",
    ),
    "trim_name_check": (
        """    if ((Get-TrimmedComponent -Component $Component) -ne $Component) {""",
        """    if ($false) {""",
    ),
    "open_sid": (
        "        if ($script:OpenSids.Contains($trimmed)) {",
        "        if ($false) {",
    ),
    # SCN-05's mechanism lives in this file, not in the bootstrap.
    "harness_pin": (None, None),
}


def mutate(image, keys, workspace):
    text = image.path.read_text(encoding="utf-8")
    for key in keys:
        find, replace = MUTATIONS[key]
        if text.count(find) != 1:
            raise SystemExit("mutation %r does not apply uniquely (%d matches)"
                             % (key, text.count(find)))
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
    print("SCENARIO TABLE")
    print("  Each verdict is formed from the process exit code plus observations this")
    print("  harness makes itself.  The bootstrap's stdout is recorded and never read by")
    print("  an assertion.  FAIL-WRONG-REASON means the run refused for an INCIDENTAL")
    print("  reason and is not evidence for the property; FAIL-EVIDENCE means the reason")
    print("  was right but the damage happened anyway.")
    print()
    header = ("%s  %-17s  %-28s  %s"
              % ("id".ljust(width), "verdict", "expected reason", "observed reason"))
    print(header)
    print("-" * len(header))
    for r in results:
        print("%s  %-17s  %-28s  %s%s"
              % (r.id.ljust(width), r.verdict, r.expected, r.observed, exit_note(r.launch.code)))
    print()
    for r in results:
        print("[%s] %s: %s" % (r.verdict, r.id, r.title))
        for description, ok in r.checks:
            print("        [%s] %s" % ("ok" if ok else "NO", description))
        if r.note:
            print("        note: %s" % r.note)
        if r.launch.note:
            print("        launch: %s" % r.launch.note)
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
    print("  account   : %s (UNELEVATED; see CTL-OWNER, CTL-PROGFILES, SCN-15)" % ME)

    base = str(Path(os.path.abspath(os.sep)) / ("mr-bootstrap-guard-" + uuid.uuid4().hex[:10]))
    os.makedirs(long_path(base), exist_ok=False)
    apply_sddl_dacl(base, HARDENED)
    workspace = Path(base) / "_mutations"
    os.makedirs(long_path(str(workspace)), exist_ok=False)

    failures = 0
    try:
        selected = sorted((s for s in SCENARIOS if args.only.lower() in s["id"].lower()),
                          key=lambda s: s["id"])
        results = []
        for spec in selected:
            if not image.reverify():
                print("FAIL: the bootstrap changed on disk mid-run; refusing to continue")
                return 1
            results.append(spec["run"](base, image))
        print_table(results, show_stdout=args.show_stdout)
        failures += sum(0 if r.ok else 1 for r in results)

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
                    print("                            real hash, which is exactly CTL-HAPPY (exit 0)")
                    continue
                mutated = mutate(image, spec["mutations"], workspace)
                flip_base = base + "\\_flip-" + spec["id"].lower()
                os.makedirs(long_path(flip_base), exist_ok=False)
                outcome = spec["run"](flip_base, mutated)
                flipped = outcome.observed != outcome.expected
                print("                 mutation : %s  (copy sha256 %s...)"
                      % ("+".join(spec["mutations"]), mutated.sha256[:16]))
                print("                 with     : %s" % outcome.expected)
                print("                 without  : %s%s"
                      % (outcome.observed, exit_note(outcome.launch.code)))
                print("                 flipped  : %s"
                      % ("YES" if flipped else
                         "NO  <-- the scenario does not depend on this mechanism"))
                for description, ok in outcome.checks:
                    print("                     [%s] %s" % ("ok" if ok else "NO", description))
                if not flipped:
                    flip_failures += 1
            print()
            if flip_failures:
                print("%d mechanism(s) did not flip." % flip_failures)
            failures += flip_failures
    finally:
        if not args.keep:
            try:
                remove_tree(base)
            except OSError as exc:
                print("(fixture cleanup left %s: %s)" % (base, exc))

    if failures:
        print("FAIL: %d scenario/mechanism check(s) did not hold." % failures)
        return 1
    print("Offline bootstrap guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
