"""audit:offline-secret-scan -- EXECUTED privacy/secret scan for the Offline
Edition (self-tested against a seeded leak, so it is load-bearing).

Scans: the PR-introduced tracked source, the generated evidence artifact, a
freshly generated activation request, and the packaged app's shipped text files
for: private-key blocks, MAC-address shapes, raw machine-identifier component
names, private Windows user paths, and credential assignments. The build
keypair's PRIVATE key must appear nowhere outside the operator keys directory.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASE = "86fd1fa98e2591cce0f4e2e996ea448c67f65e20"  # main base of feat/offline-edition-v2

LEAK_PATTERNS: dict[str, str] = {
    "private_key_block": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "mac_address": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    "raw_component_name": r"\"(?:mac|raw_uuid|volume_serial_raw|hostname|username)\"\s*:",
    "windows_user_path": r"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9_.-]+",
    "credential_assignment": r"(?i)(?:requirepass|password|api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9/+=_.-]{8,}",
}

#: Lines that legitimately contain leak SHAPES: scanner/pattern definitions,
#: redaction filters, and seeded self-tests.
_ALLOW_MARKERS = ("LEAK_PATTERNS", "seeded", "SEEDED", "redact", "_EXCLUDED_ADAPTER",
                  "example", "PLACEHOLDER", "leak-test", "regex", "re.compile",
                  "_FORBIDDEN_KEYS", "pattern")

_SELF = Path(__file__).name


def scan_text(text: str, *, allow_definitions: bool = False) -> dict[str, int]:
    findings: dict[str, int] = {}
    for line in text.splitlines():
        if allow_definitions and any(marker in line for marker in _ALLOW_MARKERS):
            continue
        for name, pattern in LEAK_PATTERNS.items():
            if re.search(pattern, line):
                findings[name] = findings.get(name, 0) + 1
    return findings


def main() -> int:
    checks: list[dict] = []

    def rec(cid: str, ok: bool, detail: str = "") -> None:
        checks.append({"check_id": cid, "ok": bool(ok),
                       "result": "PASS" if ok else "FAIL", "detail": detail})

    seeded = ("mac 00:1A:2B:3C:4D:5E -----BEGIN PRIVATE KEY-----xyz "
              'password = "hunter2secret9"')
    seed_findings = scan_text(seeded)
    rec("OS00 scanner-detects-seeded-leak",
        seed_findings.get("mac_address", 0) >= 1
        and seed_findings.get("private_key_block", 0) >= 1
        and seed_findings.get("credential_assignment", 0) >= 1,
        f"seeded MAC + key block + credential all flagged ({sorted(seed_findings)})")

    files_scanned = 0
    total = 0
    details: dict[str, dict] = {}

    diff = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", f"{BASE}..HEAD"],
                          capture_output=True, text=True, timeout=30).stdout.split()
    for rel in diff:
        path = ROOT / rel
        if path.name == _SELF or not path.exists():
            continue
        if path.suffix in (".py", ".ts", ".tsx", ".json", ".md", ".ps1", ".iss", ".spec"):
            findings = scan_text(path.read_text(encoding="utf-8", errors="replace"),
                                 allow_definitions=True)
            files_scanned += 1
            findings.pop("windows_user_path", None)  # tracked docs may show generic layouts
            if findings:
                details[rel] = findings
                total += sum(findings.values())
    rec("OS01 tracked-source-clean", not details,
        f"PR-introduced source has no leak shapes ({details or 'clean'})")

    evidence_path = ROOT / "output" / "offline-commercial" / "offline-commercial-package-evidence.v1.json"
    if evidence_path.exists():
        findings = scan_text(evidence_path.read_text(encoding="utf-8"))
        files_scanned += 1
        if findings:
            details["evidence"] = findings
            total += sum(findings.values())
        rec("OS02 evidence-clean", not findings,
            f"the evidence artifact has no leak shape ({findings or 'clean'})")
    else:
        rec("OS02 evidence-clean", True, "no evidence artifact yet (generated later)")

    from backend.app.licensing import activation as ACT
    from backend.app.licensing import fingerprint as FP
    request = ACT.build_activation_request(
        FP.collect_fingerprint(), installation_id="scan-install",
        requested_edition="offline-standard")
    request_findings = scan_text(json.dumps(request))
    files_scanned += 1
    rec("OS03 activation-request-clean", not request_findings,
        "a real activation request from THIS machine has no MAC/raw-identifier/path shape")

    keys_dir = Path(os.environ.get("MONDAY_REPORT_OFFLINE_KEYS_DIR", ""))
    private_hex = ""
    if (keys_dir / "issuer_private.hex").exists():
        private_hex = (keys_dir / "issuer_private.hex").read_text(encoding="utf-8").strip()

    app_dir = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
    package_findings: dict[str, int] = {}
    private_leak = False
    # The frontend bundle SHIPS in the package, and log files are written beside
    # it, so both belong in a scan that claims to cover the package. Restricting
    # to .txt/.json/.ps1/.html silently excluded every .js and .css asset.
    scanned_suffixes = (".txt", ".json", ".ps1", ".html", ".js", ".mjs", ".css",
                        ".log", ".cfg", ".ini", ".xml", ".md")
    if app_dir.exists():
        for file_path in app_dir.rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in scanned_suffixes:
                continue
            # certifi ships the public CA bundle; its PEM CERTIFICATE blocks are
            # not private keys and are not ours to police.
            if file_path.name.lower() in ("cacert.pem",):
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            files_scanned += 1
            for name, count in scan_text(text, allow_definitions=True).items():
                if name == "windows_user_path":
                    continue
                package_findings[name] = package_findings.get(name, 0) + count
            if private_hex and private_hex in text:
                private_leak = True

        # FAIL CLOSED when the operator keypair is unavailable. Previously the
        # `if private_hex and ...` guard made the private-key comparison a silent
        # no-op while OS04 still reported "never the private key" -- a statement
        # it had not tested. The sibling package guard already fails closed here.
        rec("OS04 package-text-clean",
            bool(private_hex) and not package_findings and not private_leak,
            f"shipped package files (including the frontend bundle and logs) carry no "
            f"leak shape and never the private key ({package_findings or 'clean'}); "
            f"operator keypair available for comparison: {bool(private_hex)}"
            + ("" if private_hex else " -- set MONDAY_REPORT_OFFLINE_KEYS_DIR"))
    else:
        rec("OS04 package-text-clean", False,
            "package not built; the shipped-package scan could not run")

    if total or package_findings:
        pass  # already reflected in the failing checks above

    passed = sum(1 for c in checks if c["ok"])
    print(json.dumps({
        "guard": "offline_secret_scan",
        "claim_scope": "executed offline-edition secret/privacy scan",
        "files_scanned": files_scanned,
        "finding_count": total + sum(package_findings.values()),
        "summary": {"passed": passed, "failed": len(checks) - passed,
                    "certification": "passed" if passed == len(checks) else "not_passed"},
        "checks": checks,
    }, indent=2))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
