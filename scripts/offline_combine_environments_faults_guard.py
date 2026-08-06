"""audit:offline-combiner-faults -- fault battery for the two-environment combiner.

The combiner is the single place where "one environment ran twice" is separated
from "two independent environments ran the same package". Nothing else in the
offline tier re-derives that distinction, so its refusals must be proven to
discriminate rather than merely exist.

CF00 is the anchor: the honest pair MUST be accepted. Every refusal below is
only meaningful because the baseline passes. Three mutation cycles then remove a
refusal from a COPY of the module and require the mutant to accept what the real
combiner rejects — proving the rule is load-bearing. Tracked source is never
modified: the mutated source is compiled in memory against the real __file__.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import offline_combine_environments as CB  # noqa: E402

MODULE_PATH = ROOT / "scripts" / "offline_combine_environments.py"
CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok),
                   "result": "PASS" if ok else "FAIL", "detail": detail})


def load_mutant(old: str, new: str):
    """Compile a mutated copy of the combiner against the real __file__.

    The real module keeps ROOT = parents[1], so `backend.app.licensing.canonical`
    still resolves. The tracked file is read, never written.
    """

    source = MODULE_PATH.read_text(encoding="utf-8")
    if old not in source:
        return None, False
    mutated = source.replace(old, new, 1)
    namespace: dict = {"__file__": str(MODULE_PATH), "__name__": "combiner_mutant"}
    exec(compile(mutated, str(MODULE_PATH), "exec"), namespace)  # noqa: S102
    return namespace, True


def environment(label: str, *, fingerprint: str, installer: str = "1" * 64,
                commit: str = "c" * 40, tree: str = "t" * 40,
                version: str = "1.0.0", executable: str = "e" * 64,
                payload: str = "p" * 64, frontend: str = "f" * 64,
                drop_check: str | None = None, fail_check: str | None = None,
                clean_ok: bool = True, deps_ok: bool = True,
                airgap: bool = True, failed_total: int = 0) -> dict:
    """A structurally faithful pair of runner records for one environment."""

    ids = ["EC02 dependency-absence", "PK01 offline-first-launch",
           "PK04 loopback-only-binding", "PK05 activation-request-exported",
           "PK07 signed-license-received", "PK08 offline-activation-import",
           "PK11 crash-recovery", "PK13 backup", "PK14 backup-validation",
           "PK15 restore", "PK18 wrong-machine-license-rejected",
           "PK19 other-environment-license-rejected",
           "PK21 short-license-operational", "PK22 expiry-to-read-only",
           "PK23 expired-data-readable", "PK24 expired-backup-available",
           "PK25 expired-mutations-blocked", "PK27 upgrade-preserves-data-and-license",
           "PK28 uninstall-preserves-data", "PK29 reinstall-detects-preserved-data"]
    checks = []
    for cid in ids:
        if drop_check and cid.startswith(drop_check):
            continue
        ok = not (fail_check and cid.startswith(fail_check))
        checks.append({"check_id": cid, "ok": ok})

    request = {
        "environment_label": label,
        "environment_class": f"{label.lower()}-class",
        "machine_fingerprint_hash": fingerprint,
        "clean_state": {"no_prior_installation": clean_ok, "no_prior_application_data": True},
        "dependency_absence": {"node_absent": deps_ok, "python_absent": True,
                               "docker_absent": True, "postgres_absent": True,
                               "redis_absent": True},
        "totals": {"passed": len(checks), "failed": 0},
        "checks": [],
    }
    result = {
        "environment_label": label,
        "environment_class": f"{label.lower()}-class",
        "source_commit": commit, "source_tree": tree, "package_version": version,
        "installer_sha256": installer, "executable_sha256": executable,
        "payload_manifest_sha256": payload, "frontend_manifest_sha256": frontend,
        "airgap_proofs": {"signed_license_only": True} if airgap else {},
        "totals": {"passed": len(checks), "failed": failed_total},
        "checks": checks,
    }
    return {"request": request, "result": result}


def judge(env_a: dict, env_b: dict, module=CB) -> list[str]:
    redact = module["redact"] if isinstance(module, dict) else module.redact
    validate = module["validate_pair"] if isinstance(module, dict) else module.validate_pair
    return validate(redact(env_a["result"], env_a["request"]),
                    redact(env_b["result"], env_b["request"]))


def honest_pair() -> tuple[dict, dict]:
    return (environment("ENVIRONMENT_1", fingerprint="a" * 64),
            environment("ENVIRONMENT_2", fingerprint="b" * 64))


def acceptance_battery() -> None:
    env1, env2 = honest_pair()

    # CF00 -- ANCHOR. Without this every refusal below could come from an
    # always-reject combiner.
    reasons = judge(env1, env2)
    rec("CF00 baseline-accepted", not reasons,
        f"rejections: {reasons}" if reasons
        else "two distinct identities running one package are accepted")

    # CF01 -- the same label cannot stand in for two environments.
    twin_label = environment("ENVIRONMENT_1", fingerprint="b" * 64)
    reasons = judge(env1, twin_label)
    rec("CF01 same-environment-label-rejected",
        any("same environment label" in r for r in reasons), f"{reasons[:2]}")

    # CF02 -- the same result submitted twice.
    reasons = judge(env1, env1)
    rec("CF02 duplicate-result-rejected",
        any("submitted twice" in r for r in reasons), f"{reasons[:2]}")

    # CF03 -- the same machine identity under a different label.
    same_fp = environment("ENVIRONMENT_2", fingerprint="a" * 64)
    reasons = judge(env1, same_fp)
    rec("CF03 same-fingerprint-rejected",
        any("duplicate environment identity" in r for r in reasons), f"{reasons[:2]}")

    # CF04..CF10 -- every field that must match, one at a time.
    variants = {
        "installer_sha256": {"installer": "9" * 64},
        "executable_sha256": {"executable": "9" * 64},
        "payload_manifest_sha256": {"payload": "9" * 64},
        "frontend_manifest_sha256": {"frontend": "9" * 64},
        "source_commit": {"commit": "d" * 40},
        "source_tree": {"tree": "d" * 40},
        "package_version": {"version": "1.0.1"},
    }
    for index, (field, kwargs) in enumerate(sorted(variants.items()), start=4):
        drifted = environment("ENVIRONMENT_2", fingerprint="b" * 64, **kwargs)
        reasons = judge(env1, drifted)
        rec(f"CF{index:02d} differing-{field.replace('_', '-')}-rejected",
            any(field in r for r in reasons), f"{[r for r in reasons if field in r]}")

    # CF11 -- failing checks in either environment.
    failing = environment("ENVIRONMENT_2", fingerprint="b" * 64, failed_total=1)
    reasons = judge(env1, failing)
    rec("CF11 failing-checks-rejected",
        any("has failing checks" in r for r in reasons), f"{reasons[:2]}")

    # CF12 -- a false clean-state boolean.
    dirty = environment("ENVIRONMENT_2", fingerprint="b" * 64, clean_ok=False)
    reasons = judge(env1, dirty)
    rec("CF12 failed-clean-state-rejected",
        any("clean-state" in r for r in reasons), f"{reasons[:2]}")

    # CF13 -- a resolvable development dependency.
    deps = environment("ENVIRONMENT_2", fingerprint="b" * 64, deps_ok=False)
    reasons = judge(env1, deps)
    rec("CF13 failed-dependency-absence-rejected",
        any("dependency-absence" in r for r in reasons), f"{reasons[:2]}")

    # CF14 -- no air-gap proof.
    nogap = environment("ENVIRONMENT_2", fingerprint="b" * 64, airgap=False)
    reasons = judge(env1, nogap)
    rec("CF14 missing-airgap-proof-rejected",
        any("air-gap proof" in r for r in reasons), f"{reasons[:2]}")

    # CF15 -- a required proof that FAILED.
    for cid, name in (("PK07", "airgap"), ("PK01", "offline_start"), ("PK04", "localhost"),
                      ("PK15", "restore"), ("PK22", "expiry_read_only"), ("PK27", "upgrade")):
        broken = environment("ENVIRONMENT_2", fingerprint="b" * 64, fail_check=cid)
        reasons = judge(env1, broken)
        if not any(f"missing proof: {name}" in r for r in reasons):
            rec(f"CF15 required-proof-{name}-enforced", False, f"{reasons[:3]}")
            break
    else:
        rec("CF15 required-proofs-enforced", True,
            "a failed PK07/PK01/PK04/PK15/PK22/PK27 each blocks acceptance")

    # CF16 -- an ABSENT required check is not silently tolerated.
    absent = environment("ENVIRONMENT_2", fingerprint="b" * 64, drop_check="PK15")
    reasons = judge(env1, absent)
    rec("CF16 absent-required-check-rejected",
        any("missing proof: restore" in r for r in reasons), f"{reasons[:2]}")

    # CF17 -- cross-environment rejection is demanded of BOTH environments.
    one_way = environment("ENVIRONMENT_2", fingerprint="b" * 64, drop_check="PK19")
    reasons_b = judge(env1, one_way)
    env1_missing = environment("ENVIRONMENT_1", fingerprint="a" * 64, drop_check="PK19")
    reasons_a = judge(env1_missing, env2)
    rec("CF17 cross-environment-license-required-both-directions",
        any("cross_environment_license" in r for r in reasons_b)
        and any("cross_environment_license" in r for r in reasons_a),
        "an environment that never proved it rejects the other environment's "
        "license blocks acceptance, in either position")

    # CF18 -- an ACCEPTED copied license (PK19 failing) blocks acceptance.
    permissive = environment("ENVIRONMENT_2", fingerprint="b" * 64, fail_check="PK19")
    reasons = judge(env1, permissive)
    rec("CF18 accepted-copied-license-rejected",
        any("cross_environment_license" in r for r in reasons), f"{reasons[:2]}")


def redaction_battery() -> None:
    env1, env2 = honest_pair()
    body = CB.redact(env1["result"], env1["request"])

    # CF19 -- the raw fingerprint hash never survives redaction.
    raw = env1["request"]["machine_fingerprint_hash"]
    serialized = json.dumps(body)
    rec("CF19 raw-fingerprint-absent-from-redacted-record",
        raw not in serialized and len(body.get("fingerprint_identity_digest", "")) == 32,
        "only a 32-character digest of the fingerprint hash is carried forward")

    # CF20 -- the record hash is reproducible from the record's own content.
    without = {k: v for k, v in body.items() if k != "result_hash"}
    rec("CF20 result-hash-reproducible",
        CB.canonical_hash(without) == body.get("result_hash"),
        "result_hash re-derives from the redacted body")

    # CF21 -- distinct identities produce distinct digests.
    other = CB.redact(env2["result"], env2["request"])
    rec("CF21 distinct-identities-produce-distinct-digests",
        body["fingerprint_identity_digest"] != other["fingerprint_identity_digest"],
        "independent environments are distinguishable without exposing identifiers")


def cli_battery() -> None:
    """The exit code must follow acceptance, and the record must be written."""

    env1, env2 = honest_pair()
    with tempfile.TemporaryDirectory(prefix="combiner-faults-") as tmp:
        work = Path(tmp)
        paths = {}
        for name, env in (("env1", env1), ("env2", env2)):
            for kind in ("result", "request"):
                path = work / f"{name}-{kind}.json"
                path.write_text(json.dumps(env[kind], indent=2), encoding="utf-8")
                paths[f"{name}-{kind}"] = path

        out = work / "record.json"
        accept = subprocess.run(
            [sys.executable, str(MODULE_PATH),
             "--env1-result", str(paths["env1-result"]), "--env1-request", str(paths["env1-request"]),
             "--env2-result", str(paths["env2-result"]), "--env2-request", str(paths["env2-request"]),
             "--out", str(out)], capture_output=True, text=True, timeout=120)
        record = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        rec("CF22 cli-accepts-honest-pair",
            accept.returncode == 0 and record.get("accepted") is True
            and record.get("environment_count") == 2,
            f"exit={accept.returncode}, accepted={record.get('accepted')}")
        rec("CF23 cli-records-identical-package-and-independent-identities",
            record.get("identical_package_bytes") is True
            and record.get("independent_identities") is True,
            "the record states both facts explicitly rather than implying them")

        # The same environment twice must exit non-zero AND say why.
        out2 = work / "record-dup.json"
        dup = subprocess.run(
            [sys.executable, str(MODULE_PATH),
             "--env1-result", str(paths["env1-result"]), "--env1-request", str(paths["env1-request"]),
             "--env2-result", str(paths["env1-result"]), "--env2-request", str(paths["env1-request"]),
             "--out", str(out2)], capture_output=True, text=True, timeout=120)
        record2 = json.loads(out2.read_text(encoding="utf-8")) if out2.exists() else {}
        rec("CF24 cli-refuses-one-environment-submitted-twice",
            dup.returncode != 0 and record2.get("accepted") is False
            and bool(record2.get("rejection_reasons")),
            f"exit={dup.returncode}, reasons={len(record2.get('rejection_reasons', []))}")


def mutation_cycles() -> None:
    """Remove a refusal from a copy; the mutant must accept what the real one rejects."""

    env1, env2 = honest_pair()

    cases = [
        (
            "MUT-CF01 cross-environment-license-requirement-is-load-bearing",
            '    "cross_environment_license": ("PK19",),\n',
            "",
            environment("ENVIRONMENT_2", fingerprint="b" * 64, drop_check="PK19"),
        ),
        (
            "MUT-CF02 duplicate-identity-refusal-is-load-bearing",
            '    if env1.get("fingerprint_identity_digest") == env2.get("fingerprint_identity_digest"):\n'
            '        reasons.append("duplicate environment identity (same machine fingerprint)")\n',
            "",
            # Same machine, different label: exactly the shape a single host
            # would take if it tried to masquerade as two environments.
            environment("ENVIRONMENT_2", fingerprint="a" * 64),
        ),
        (
            "MUT-CF03 identical-package-requirement-is-load-bearing",
            '    "source_commit", "source_tree", "package_version", "installer_sha256",\n',
            '    "source_commit", "source_tree", "package_version",\n',
            environment("ENVIRONMENT_2", fingerprint="b" * 64, installer="9" * 64),
        ),
    ]

    before = MODULE_PATH.read_bytes()

    for cid, old, new, target in cases:
        baseline_ok = not judge(env1, env2)
        real_reasons = judge(env1, target)
        mutant, applied = load_mutant(old, new)
        if not applied or mutant is None:
            rec(cid, False, "the mutation target no longer exists in the combiner source")
            continue
        mutant_reasons = judge(env1, target, module=mutant)

        restored_ok = not judge(env1, env2)
        # The mutant must be strictly more permissive on the mutated dimension.
        loosened = len(mutant_reasons) < len(real_reasons)
        rec(cid, baseline_ok and bool(real_reasons) and loosened and restored_ok,
            f"baseline accepted={baseline_ok}, real refuses ({len(real_reasons)}), "
            f"mutant refuses ({len(mutant_reasons)}), restored accepted={restored_ok}")

    # The mutations are compiled in memory, so the tracked file must be byte
    # identical to what it was before the cycles ran. Comparing against the
    # committed blob would instead measure whether the file has uncommitted
    # edits, which is a different -- and here, expected -- property.
    after = MODULE_PATH.read_bytes()
    rec("MUT-CF04 tracked-combiner-source-untouched", after == before,
        "the tracked combiner is byte-identical before and after every mutation cycle "
        f"({len(before)} bytes)")

    # Duplicate submission is caught by three independent rules (label, machine
    # identity, whole-result hash). State that explicitly rather than asserting
    # the redundant one is individually load-bearing -- it cannot be, because an
    # identical result_hash implies an identical label and identity too.
    dup = copy.deepcopy(env1)
    dup["result"]["environment_label"] = "ENVIRONMENT_2"
    dup["request"]["environment_label"] = "ENVIRONMENT_2"
    rec("MUT-CF05 duplicate-submission-caught-by-independent-rules",
        len(judge(env1, copy.deepcopy(env1))) >= 2 and bool(judge(env1, dup)),
        "an unchanged resubmission trips the label, identity and result-hash rules; "
        "relabelling it still trips the identity rule")


def main() -> int:
    acceptance_battery()
    redaction_battery()
    cli_battery()
    mutation_cycles()

    passed = sum(1 for c in CHECKS if c["ok"])
    failed = len(CHECKS) - passed
    print(json.dumps({
        "guard": "offline_combiner_faults",
        "claim_scope": "two-environment combiner refusals, redaction and load-bearing mutations",
        "summary": {"passed": passed, "failed": failed,
                    "certification": "passed" if failed == 0 else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
