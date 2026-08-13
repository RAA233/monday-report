"""Trust-Root Kernel (Phase 1) - Python twin.

This module is one of two independent implementations of the trust-root
decision predicates.  The other is packaging/trustroot/TrustRootKernel.psm1
(PowerShell).  Both twins consume IDENTICAL inputs (raw self-relative security
descriptor bytes, raw manifest bytes, raw bundle member lists) and MUST produce
identical (verdict, reason) pairs.  scripts/trust_root_kernel_guard.py runs
hostile fixtures through both and fails on any disagreement.

Nothing in this module reads source text of any component in order to decide a
security question.  Every predicate operates on bytes obtained from the object
being judged.

Deliberately dependency-free: the security-descriptor parser below is written
from the documented on-disk layout rather than delegating to pywin32, so that
the two twins do not share a parsing implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------
# Shared vocabulary.  These exact strings are mirrored in the PowerShell twin.
# --------------------------------------------------------------------------

KERNEL_CONTRACT = "trust-root-kernel/v1"

OK = "OK"
NODE_MISSING = "NODE_MISSING"
NODE_REPARSE = "NODE_REPARSE"
DACL_ABSENT = "DACL_ABSENT"
ACE_UNINTERPRETABLE = "ACE_UNINTERPRETABLE"
OWNER_UNTRUSTED = "OWNER_UNTRUSTED"
UNSAFE_WRITABLE_ACE = "UNSAFE_WRITABLE_ACE"
CHAIN_EMPTY = "CHAIN_EMPTY"
CHAIN_NOT_ANCHORED = "CHAIN_NOT_ANCHORED"
CASE_COLLISION = "CASE_COLLISION"
MANIFEST_MALFORMED = "MANIFEST_MALFORMED"
MANIFEST_DUPLICATE_KEY = "MANIFEST_DUPLICATE_KEY"
BUNDLE_PIN_MISMATCH = "BUNDLE_PIN_MISMATCH"
BUNDLE_MEMBER_MISSING = "BUNDLE_MEMBER_MISSING"
EXECUTED_NOT_IN_BUNDLE = "EXECUTED_NOT_IN_BUNDLE"

ACCEPT = "ACCEPT"
REFUSE = "REFUSE"


# Well-known SIDs that may hold modify-class rights on a trust-root path
# component without making that component attacker-controllable.
TRUSTED_SIDS = frozenset(
    {
        "S-1-5-18",  # NT AUTHORITY\SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
        # NT SERVICE\TrustedInstaller
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)


# Access-mask bits (winnt.h).
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_READ_EA = 0x00000008
FILE_WRITE_EA = 0x00000010
FILE_EXECUTE = 0x00000020
FILE_DELETE_CHILD = 0x00000040
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_ALL_ACCESS = 0x001F01FF

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

FILE_GENERIC_READ = (
    READ_CONTROL | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
)
FILE_GENERIC_WRITE = (
    READ_CONTROL
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | SYNCHRONIZE
)
FILE_GENERIC_EXECUTE = (
    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE
)

# Rights that let a principal REPLACE or REDIRECT a path component: retarget it,
# take it over, or delete it out from under us.  Checked on every component of
# the chain, not just the leaf.
REDIRECT_CLASS_RIGHTS = DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD | GENERIC_ALL

# Rights that additionally matter for the trust root itself, where content
# integrity - not only identity - is load bearing.
CONTENT_CLASS_RIGHTS = (
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
)

# ACE types this kernel is willing to reason about.  Anything else - callback
# ACEs, object ACEs, compound ACEs, or a type this build does not know - is
# uninterpretable and therefore fatal.  A descriptor we cannot fully read is a
# descriptor we cannot certify.
ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
INTERPRETABLE_ACE_TYPES = frozenset({ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED})

ACE_FLAG_INHERIT_ONLY = 0x08
ACE_FLAG_INHERITED = 0x10

SE_DACL_PRESENT = 0x0004
SE_DACL_PROTECTED = 0x1000
SE_SELF_RELATIVE = 0x8000


class DescriptorError(ValueError):
    """Raised when a security descriptor cannot be parsed exactly."""


# --------------------------------------------------------------------------
# Security-descriptor parsing (self-relative form).
# --------------------------------------------------------------------------


def _parse_sid(blob: bytes, offset: int) -> tuple[str, int]:
    if offset + 8 > len(blob):
        raise DescriptorError("SID header truncated")
    revision = blob[offset]
    sub_count = blob[offset + 1]
    authority = int.from_bytes(blob[offset + 2 : offset + 8], "big")
    end = offset + 8 + 4 * sub_count
    if end > len(blob):
        raise DescriptorError("SID sub-authorities truncated")
    subs = struct.unpack_from("<%dI" % sub_count, blob, offset + 8)
    text = "S-%d-%d" % (revision, authority)
    for sub in subs:
        text += "-%d" % sub
    return text, end - offset


def map_generic_rights(mask: int) -> int:
    """Fold generic access bits into their file-object specific equivalents."""
    resolved = mask & 0x0FFFFFFF
    if mask & GENERIC_ALL:
        resolved |= FILE_ALL_ACCESS | DELETE | WRITE_DAC | WRITE_OWNER | READ_CONTROL
    if mask & GENERIC_WRITE:
        resolved |= FILE_GENERIC_WRITE
    if mask & GENERIC_READ:
        resolved |= FILE_GENERIC_READ
    if mask & GENERIC_EXECUTE:
        resolved |= FILE_GENERIC_EXECUTE
    return resolved


@dataclass
class Ace:
    ace_type: int
    flags: int
    mask: int
    sid: str
    interpretable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ace_type": self.ace_type,
            "flags": self.flags,
            "mask": self.mask,
            "sid": self.sid,
            "interpretable": self.interpretable,
        }


@dataclass
class Descriptor:
    control: int
    owner_sid: str | None
    group_sid: str | None
    dacl_present: bool
    dacl_null: bool
    dacl_protected: bool
    aces: list[Ace] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "owner_sid": self.owner_sid,
            "group_sid": self.group_sid,
            "dacl_present": self.dacl_present,
            "dacl_null": self.dacl_null,
            "dacl_protected": self.dacl_protected,
            "aces": [ace.to_dict() for ace in self.aces],
        }


def parse_descriptor(blob: bytes) -> Descriptor:
    """Parse a self-relative SECURITY_DESCRIPTOR from raw bytes."""
    if len(blob) < 20:
        raise DescriptorError("descriptor shorter than header")
    revision = blob[0]
    if revision != 1:
        raise DescriptorError("unsupported descriptor revision %d" % revision)
    control = struct.unpack_from("<H", blob, 2)[0]
    if not control & SE_SELF_RELATIVE:
        raise DescriptorError("descriptor is not self-relative")
    off_owner, off_group, off_sacl, off_dacl = struct.unpack_from("<IIII", blob, 4)

    owner = _parse_sid(blob, off_owner)[0] if off_owner else None
    group = _parse_sid(blob, off_group)[0] if off_group else None

    dacl_present = bool(control & SE_DACL_PRESENT)
    dacl_protected = bool(control & SE_DACL_PROTECTED)
    # A NULL DACL is DACL_PRESENT with a null pointer.  It grants everyone full
    # control.  Windows also reports AreAccessRulesProtected == True for it and
    # enumerates zero rules, so "no rules found" must never be read as "safe".
    dacl_null = dacl_present and off_dacl == 0

    aces: list[Ace] = []
    if dacl_present and off_dacl:
        if off_dacl + 8 > len(blob):
            raise DescriptorError("ACL header truncated")
        acl_size, ace_count = struct.unpack_from("<HH", blob, off_dacl + 2)
        if off_dacl + acl_size > len(blob):
            raise DescriptorError("ACL body truncated")
        cursor = off_dacl + 8
        for _ in range(ace_count):
            if cursor + 4 > len(blob):
                raise DescriptorError("ACE header truncated")
            ace_type = blob[cursor]
            ace_flags = blob[cursor + 1]
            ace_size = struct.unpack_from("<H", blob, cursor + 2)[0]
            if ace_size < 4 or cursor + ace_size > len(blob):
                raise DescriptorError("ACE body truncated")
            interpretable = ace_type in INTERPRETABLE_ACE_TYPES
            mask = 0
            sid = ""
            if interpretable:
                if cursor + 8 > len(blob):
                    raise DescriptorError("ACE mask truncated")
                mask = struct.unpack_from("<I", blob, cursor + 4)[0]
                sid = _parse_sid(blob, cursor + 8)[0]
            aces.append(Ace(ace_type, ace_flags, mask, sid, interpretable))
            cursor += ace_size
    return Descriptor(control, owner, group, dacl_present, dacl_null, dacl_protected, aces)


# --------------------------------------------------------------------------
# P1 - path-component and chain safety.
# --------------------------------------------------------------------------


def _verdict(reason: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "verdict": ACCEPT if reason == OK else REFUSE,
        "reason": reason,
    }
    payload.update(extra)
    return payload


def evaluate_node(node: dict[str, Any], trusted_sids: set[str] | None = None) -> dict[str, Any]:
    """Judge ONE path component.

    ``node`` carries what was observed about the component: whether it exists,
    whether it is a reparse point, whether it is the final (trust root)
    component, and the raw descriptor bytes as hex.
    """
    trusted = set(TRUSTED_SIDS) | set(trusted_sids or ())
    path = node.get("path", "")

    if not node.get("exists", False):
        return _verdict(NODE_MISSING, path=path)

    # A reparse point anywhere on the chain means the bytes we verified and the
    # bytes that will be used are not necessarily the same object.
    if node.get("reparse", False):
        return _verdict(NODE_REPARSE, path=path)

    raw = node.get("descriptor_hex")
    if not raw:
        return _verdict(DACL_ABSENT, path=path, detail="no descriptor captured")
    try:
        descriptor = parse_descriptor(bytes.fromhex(raw))
    except (DescriptorError, ValueError) as exc:
        return _verdict(ACE_UNINTERPRETABLE, path=path, detail=str(exc))

    if not descriptor.dacl_present or descriptor.dacl_null:
        return _verdict(DACL_ABSENT, path=path)

    if descriptor.owner_sid not in trusted:
        return _verdict(OWNER_UNTRUSTED, path=path, owner=descriptor.owner_sid)

    is_final = bool(node.get("is_final", False))
    unsafe_mask = REDIRECT_CLASS_RIGHTS | (CONTENT_CLASS_RIGHTS if is_final else 0)

    for ace in descriptor.aces:
        if not ace.interpretable:
            return _verdict(
                ACE_UNINTERPRETABLE, path=path, ace_type=ace.ace_type
            )

    for ace in descriptor.aces:
        if ace.ace_type != ACE_TYPE_ACCESS_ALLOWED:
            continue
        # An inherit-only ACE does not apply to this object.  It still applies
        # to children, which is why the trust root's own descriptor is verified
        # after it is created and protected, never inferred from its parent.
        if ace.flags & ACE_FLAG_INHERIT_ONLY:
            continue
        if ace.sid in trusted:
            continue
        effective = map_generic_rights(ace.mask)
        if effective & unsafe_mask:
            return _verdict(
                UNSAFE_WRITABLE_ACE,
                path=path,
                sid=ace.sid,
                mask=ace.mask,
                effective=effective & unsafe_mask,
                inherited=bool(ace.flags & ACE_FLAG_INHERITED),
            )

    return _verdict(OK, path=path)


def evaluate_chain(
    nodes: list[dict[str, Any]], trusted_sids: set[str] | None = None
) -> dict[str, Any]:
    """Judge EVERY component from the volume root down to the trust root.

    The refusal names the failing component AND the full path under judgement,
    so a refusal can never be read as applying only to the leaf.
    """
    if not nodes:
        return _verdict(CHAIN_EMPTY, path="")

    full_path = nodes[-1].get("path", "")
    first = nodes[0].get("path", "")
    # The chain must start at a volume root.  A chain that begins part way down
    # is a chain whose upper components were never judged.
    anchored = len(first) == 3 and first[1:] == ":\\"
    if not anchored:
        return _verdict(
            CHAIN_NOT_ANCHORED, path=full_path, component=first, components=len(nodes)
        )

    for index, node in enumerate(nodes):
        result = evaluate_node(node, trusted_sids)
        if result["verdict"] != ACCEPT:
            result["path"] = full_path
            result["component"] = node.get("path", "")
            result["component_index"] = index
            result["components"] = len(nodes)
            return result

    return _verdict(OK, path=full_path, components=len(nodes))


# --------------------------------------------------------------------------
# Manifest canonicalisation (P4 fixture surface).
# --------------------------------------------------------------------------


def scan_object_keys(text: str) -> list[tuple[int, str]]:
    """Return (object_id, key) for every object member key in a JSON document.

    Written as an explicit character walk rather than delegating to a parser,
    because the two twins' stock parsers disagree about duplicate and
    case-differing keys.  Both twins run THIS algorithm so the disagreement
    cannot reach the verdict.
    """
    keys: list[tuple[int, str]] = []
    stack: list[int] = []
    next_object_id = 0
    index = 0
    length = len(text)
    expecting_key = False

    while index < length:
        ch = text[index]
        if ch == '"':
            start = index + 1
            buf = []
            index = start
            while index < length:
                c = text[index]
                if c == "\\":
                    if index + 1 >= length:
                        raise ValueError("unterminated escape")
                    buf.append(text[index : index + 2])
                    index += 2
                    continue
                if c == '"':
                    break
                buf.append(c)
                index += 1
            if index >= length:
                raise ValueError("unterminated string")
            if expecting_key and stack:
                keys.append((stack[-1], "".join(buf)))
                expecting_key = False
            index += 1
            continue
        if ch == "{":
            next_object_id += 1
            stack.append(next_object_id)
            expecting_key = True
        elif ch == "}":
            if not stack:
                raise ValueError("unbalanced object close")
            stack.pop()
            expecting_key = False
        elif ch == "[":
            stack.append(0)
            expecting_key = False
        elif ch == "]":
            if not stack:
                raise ValueError("unbalanced array close")
            stack.pop()
            expecting_key = False
        elif ch == ",":
            expecting_key = bool(stack) and stack[-1] != 0
        index += 1

    if stack:
        raise ValueError("unbalanced document")
    return keys


def canonicalize_manifest(raw: bytes) -> dict[str, Any]:
    """Accept only manifests both twins can read identically."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return _verdict(MANIFEST_MALFORMED, detail="utf-8 BOM")
    if b"\x00" in raw:
        return _verdict(MANIFEST_MALFORMED, detail="embedded NUL / non utf-8 encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _verdict(MANIFEST_MALFORMED, detail="utf-8 decode: %s" % exc)

    try:
        keys = scan_object_keys(text)
    except ValueError as exc:
        return _verdict(MANIFEST_MALFORMED, detail=str(exc))

    per_object: dict[int, dict[str, str]] = {}
    for object_id, key in keys:
        bucket = per_object.setdefault(object_id, {})
        folded = key.lower()
        if folded in bucket:
            if bucket[folded] == key:
                return _verdict(MANIFEST_DUPLICATE_KEY, key=key)
            return _verdict(CASE_COLLISION, key=key, collides_with=bucket[folded])
        bucket[folded] = key

    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except ValueError as exc:
        return _verdict(MANIFEST_MALFORMED, detail=str(exc))

    problem = _reject_unrepresentable(document)
    if problem:
        return _verdict(MANIFEST_MALFORMED, detail=problem)

    return _verdict(OK, document=document)


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite JSON constant %s" % name)


def _reject_unrepresentable(value: Any) -> str | None:
    """Reject numbers the two twins would not carry identically."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < -(2**63) or value > 2**63 - 1:
            return "integer outside int64 range"
        return None
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return "non-finite number"
        return None
    if isinstance(value, dict):
        for item in value.values():
            problem = _reject_unrepresentable(item)
            if problem:
                return problem
    elif isinstance(value, list):
        for item in value:
            problem = _reject_unrepresentable(item)
            if problem:
                return problem
    return None


# --------------------------------------------------------------------------
# P2 - atomic executed-bundle pin.
# --------------------------------------------------------------------------


def normalize_member_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def compute_bundle_pin(members: list[dict[str, Any]]) -> dict[str, Any]:
    """Pin the COMPLETE bundle: contents AND membership.

    Adding or removing a member changes the pin, because the member list itself
    is inside the hashed pre-image.  There is no per-file "self hash" list that
    could cover fewer files than are executed.
    """
    seen: dict[str, str] = {}
    rows: list[tuple[str, str, str, int]] = []
    for member in members:
        raw_path = str(member.get("path", ""))
        normalized = normalize_member_path(raw_path)
        folded = normalized.lower()
        if folded in seen:
            return _verdict(CASE_COLLISION, key=normalized, collides_with=seen[folded])
        seen[folded] = normalized
        digest = str(member.get("sha256", "")).lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return _verdict(BUNDLE_MEMBER_MISSING, key=normalized, detail="bad digest")
        rows.append((folded, normalized, digest, int(member.get("size", 0))))

    rows.sort(key=lambda row: row[0])
    lines = ["%s\x00%s\x00%d" % (row[1], row[2], row[3]) for row in rows]
    preimage = KERNEL_CONTRACT + "\nmembers=%d\n" % len(rows) + "\n".join(lines) + "\n"
    pin = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    return _verdict(OK, pin=pin, members=len(rows))


def verify_bundle(
    observed: list[dict[str, Any]], expected_pin: str, executed: list[str]
) -> dict[str, Any]:
    """Verify the pin AND that everything actually executed is a bundle member."""
    computed = compute_bundle_pin(observed)
    if computed["verdict"] != ACCEPT:
        return computed
    if computed["pin"].lower() != str(expected_pin).lower():
        return _verdict(
            BUNDLE_PIN_MISMATCH, expected=str(expected_pin).lower(), actual=computed["pin"]
        )

    member_set = {normalize_member_path(str(m.get("path", ""))).lower() for m in observed}
    for path in executed:
        normalized = normalize_member_path(str(path)).lower()
        if normalized not in member_set:
            return _verdict(EXECUTED_NOT_IN_BUNDLE, key=path, members=len(member_set))
    return _verdict(OK, pin=computed["pin"], members=len(member_set), executed=len(executed))


# --------------------------------------------------------------------------
# CLI - used by the guard to drive this twin as a separate process.
# --------------------------------------------------------------------------


def _dispatch(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    if operation == "evaluate_node":
        return evaluate_node(payload["node"], set(payload.get("trusted_sids", [])))
    if operation == "evaluate_chain":
        return evaluate_chain(payload["nodes"], set(payload.get("trusted_sids", [])))
    if operation == "canonicalize_manifest":
        return canonicalize_manifest(bytes.fromhex(payload["raw_hex"]))
    if operation == "compute_bundle_pin":
        return compute_bundle_pin(payload["members"])
    if operation == "verify_bundle":
        return verify_bundle(
            payload["observed"], payload["expected_pin"], payload.get("executed", [])
        )
    raise SystemExit("unknown operation %s" % operation)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trust-root kernel (Python twin)")
    parser.add_argument("--jobs", required=True, help="JSON file of {id, operation, payload}")
    parser.add_argument("--out", required=True, help="destination for the JSON transcript")
    args = parser.parse_args(argv)

    with open(args.jobs, encoding="utf-8") as handle:
        jobs = json.load(handle)

    transcript = []
    for job in jobs:
        try:
            result = _dispatch(job["operation"], job["payload"])
        except Exception as exc:  # fail closed, never silently accept
            result = _verdict("TWIN_ERROR", detail="%s: %s" % (type(exc).__name__, exc))
        transcript.append(
            {
                "id": job["id"],
                "twin": "python",
                "operation": job["operation"],
                "verdict": result["verdict"],
                "reason": result["reason"],
                "result": result,
            }
        )

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(transcript, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
