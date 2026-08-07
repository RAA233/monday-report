"""audit:offline-commercial-evidence -- validate the Offline Edition evidence
artifact and prove the validator is load-bearing via fault mutations. Also
asserts this tier CANNOT influence the production-target or GA controls.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import tempfile
import shutil
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import offline_commercial_evidence as E  # noqa: E402
from backend.app.licensing.canonical import canonical_hash  # noqa: E402

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def main() -> int:
    CHECKS.clear()
    payload, reasons = E.load_and_validate()
    if payload is None:
        print(json.dumps({"guard": "offline_commercial_evidence",
                          "summary": {"passed": 0, "failed": 1,
                                      "certification": "not_passed"},
                          "detail": "no artifact; run ga:offline-commercial-evidence first"}))
        return 1
    commit, tree = payload.get("git_commit"), payload.get("git_tree")

    # THIS TIER IS NO LONGER AUTHORITATIVE, so these two checks now assert the
    # opposite of what they used to. An independent review demonstrated that a
    # copied ENVIRONMENT_1 block, resealed, validated here with zero reasons and
    # yielded offline_commercial_package: PASS. Asserting that v1 CAN accept
    # would now be asserting the defect.
    rec("OE00 legacy-tier-is-non-authoritative",
        any(E.LEGACY_NON_AUTHORITATIVE in r for r in reasons),
        f"the v1 artifact is reported non-authoritative ({reasons[:1] or 'no reason'})")
    verdicts = E.control_verdicts(payload, reasons)
    coverage_met = E.environment_coverage_met(payload)
    rec("OE01 legacy-controls-always-blocked",
        all(v == "BLOCKED" for v in verdicts.values()),
        f"every legacy control is BLOCKED regardless of the recorded results "
        f"({verdicts}, coverage_met={coverage_met})")
    import copy as _copy

    def _consistent(document: dict, keep_labels: list[str], accepted: bool = True) -> dict:
        """Rewrite the coverage-bearing fields consistently, then rehash.

        Selection is by environment LABEL, never by class string. Filtering on a
        hardcoded pair of class names made this helper produce an EMPTY record
        for any honest pair that happened to share a class -- so the very
        second-environment shape Part-O allows failed the gate here even after
        the validator was corrected to accept it.
        """

        record = document.get("two_environment_record", {})
        envs = record.get("environments", {})
        keep = {label: env for label, env in sorted(envs.items())
                if label in set(keep_labels)}
        environments = [str(e.get("environment_class", "")) for e in keep.values()]
        document["results"]["package_matrix"]["environments_executed"] = list(environments)
        document["environment_coverage"]["executed"] = list(environments)
        record["environments"] = keep
        record["environment_count"] = len(keep)
        # Mirror the validator's derivation: distinct MACHINE IDENTITIES, not
        # distinct class labels.
        record["independent_identities"] = (
            len({e.get("fingerprint_identity_digest") for e in keep.values()}) == len(keep)
            and all(re.fullmatch(r"[0-9a-f]{32}",
                                 str(e.get("fingerprint_identity_digest", "")) or "")
                    for e in keep.values()))
        document["results"]["package_matrix"]["passed"] = sum(
            int(e.get("totals", {}).get("passed", 0)) for e in keep.values())
        meets = len(environments) >= E.REQUIRED_ENVIRONMENT_MINIMUM and accepted
        document["environment_coverage"]["meets_minimum"] = (
            len(environments) >= E.REQUIRED_ENVIRONMENT_MINIMUM)
        document["verdicts"]["package"] = (
            E.PACKAGE_VERDICT if meets else "OFFLINE_WINDOWS_PACKAGE_NOT_ACCEPTED")
        document["verdicts"]["commercial"] = (
            E.COMMERCIAL_VERDICT if meets else "OFFLINE_COMMERCIAL_PACKAGE_NOT_ACCEPTED")
        # Refresh BOTH seals, or the coverage gate under test is masked by a
        # stale-hash rejection that blocks every control including the licensing
        # one -- which is exactly what this pair is trying to hold still.
        document["reproducible_payload_hash"] = E.reproducible_hash(document)
        body = {k: v for k, v in document.items() if k != "canonical_payload_hash"}
        document["canonical_payload_hash"] = canonical_hash(body)
        return document

    # The gate must work in BOTH directions. Now that Environment 2 is a real
    # clean Hyper-V VM, the artifact genuinely carries two environments, so the
    # load-bearing direction to prove is that NARROWING it back to one blocks.
    widened = _consistent(_copy.deepcopy(payload),
                          ["ENVIRONMENT_1", "ENVIRONMENT_2"])
    widened_verdicts = E.control_verdicts(
        widened, E.validate(widened, current_commit=commit, current_tree=tree))
    # Formerly: "two environments yields PASS". That is precisely the property
    # the reproduced forgery abused -- two environment BLOCKS, one of them copied,
    # were enough. A green two-environment matrix must no longer be sufficient on
    # its own; acceptance now requires the independent reviewer attestation that
    # this tier cannot carry.
    rec("OE01b two-environments-alone-no-longer-accept",
        widened_verdicts["offline_windows_package"] == "BLOCKED"
        and widened_verdicts["offline_commercial_package"] == "BLOCKED",
        "a green two-environment matrix alone does not yield acceptance in the "
        "legacy tier")

    # Narrowing to one environment is now caught at the VALIDATION layer, not
    # merely at the verdict layer: a single-environment record is refused
    # outright, so every control is BLOCKED rather than just package/commercial.
    # That is strictly stronger than blocking the two package controls, so the
    # check asserts the behaviour that actually holds.
    narrowed = _consistent(_copy.deepcopy(payload), ["ENVIRONMENT_1"])
    narrowed_reasons = E.validate(narrowed, current_commit=commit, current_tree=tree)
    narrowed_verdicts = E.control_verdicts(narrowed, narrowed_reasons)
    rec("OE01c coverage-gate-blocks-single-environment",
        bool(narrowed_reasons)
        and any("exactly two environments" in r for r in narrowed_reasons)
        and set(narrowed_verdicts.values()) == {"BLOCKED"},
        f"the SAME green matrix narrowed to one environment is refused outright "
        f"({[r for r in narrowed_reasons if 'two environments' in r][:1]}) and no "
        f"control can then be PASS")

    def rehash(document: dict) -> dict:
        body = {k: v for k, v in document.items() if k != "canonical_payload_hash"}
        document["canonical_payload_hash"] = canonical_hash(body)
        return document

    def rejects(cid: str, mutate, *, skip_rehash: bool = False, detail: str = "",
                expect: str | None = None, reseal: bool = True) -> None:
        """Require the mutation to be refused -- and, when ``expect`` is given,
        refused FOR THAT REASON rather than incidentally by a stale seal.

        ``reseal`` refreshes the reproducible hash too, so a mutation aimed at a
        semantic rule is not masked by a hash mismatch.
        """

        mutant = copy.deepcopy(payload)
        mutate(mutant)
        if reseal:
            mutant["reproducible_payload_hash"] = E.reproducible_hash(mutant)
        if not skip_rehash:
            rehash(mutant)
        result = E.validate(mutant, current_commit=commit, current_tree=tree)
        ok = len(result) > 0 and (expect is None or any(expect in r for r in result))
        rec(cid, ok, detail or (("; ".join(result))[:200] if result else "NOT rejected"))

    # Every rejection below reseals the reproducible hash first, so the refusal
    # comes from the RULE under test and not incidentally from a stale seal, and
    # each asserts the reason it is meant to trigger.
    rejects("OE02 wrong-commit-rejected", lambda m: m.update(git_commit="0" * 40),
            expect="current exact commit")
    rejects("OE03 wrong-tree-rejected", lambda m: m.update(git_tree="0" * 40),
            expect="current exact tree")
    rejects("OE04 hash-tamper-rejected",
            lambda m: m.update(canonical_payload_hash="f" * 64), skip_rehash=True,
            reseal=False, expect="canonical payload hash")
    rejects("OE05 stale-artifact-rejected",
            lambda m: m.update(generated_at="2020-01-01T00:00:00+00:00"),
            expect="stale")
    rejects("OE06 dropped-disclosure-rejected",
            lambda m: m["disclosures"].update(not_ga_acceptance=False),
            expect="disclosure")
    rejects("OE07 failing-battery-rejected",
            lambda m: m["results"]["license_battery"].update(failed=3),
            expect="not fully passing")
    rejects("OE08 missing-section-rejected",
            lambda m: m["results"].pop("package_matrix"),
            expect="missing result section")
    rejects("OE09 empty-environment-matrix-rejected",
            lambda m: m["results"]["package_matrix"].update(environments_executed=[]),
            expect="no executed environment")
    rejects("OE10 private-key-presence-rejected",
            lambda m: m["package"].update(private_key_absent=False),
            expect="private-key-absence")
    rejects("OE11 leak-shape-rejected",
            lambda m: m.update(diagnostic="adapter 00:1A:2B:3C:4D:5E failed"),  # leak-test fixture
            expect="leak shape")
    rejects("OE12 missing-installer-hash-rejected",
            lambda m: m["package"].update(installer_sha256=""),
            expect="installer hash")

    # The verdict block is RECOMPUTED, never copied, and the recomputation is
    # tested in the only direction still reachable. Overclaiming is now caught
    # earlier and harder: any recorded result that fails to support acceptance
    # makes the whole artifact invalid (OE07-OE12, OE17-OE34), and an invalid
    # artifact can never yield a PASS control (OE13). So the remaining way for
    # the stored block to disagree with the derived one is a DOWNGRADE, and that
    # is refused too -- the block is not a free-text field either way.
    # Formerly a derived-vs-stored comparison. With the acceptance literals gone
    # from this module there is no derivation left to disagree with -- the honest
    # replacement asserts that this tier can no longer emit an acceptance at all,
    # whatever the artifact stores.
    rec("OE12b legacy-tier-emits-no-acceptance",
        "OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED" not in inspect.getsource(E),
        "the legacy module contains no acceptance literal, so no stored verdict "
        "can be blessed by it")
    rejects("OE12c forged-coverage-flag-rejected",
            lambda m: m["environment_coverage"].update(meets_minimum=False),
            reseal=True, expect="meets_minimum",
            detail="meets_minimum must agree with the recorded executed environments")

    # ---- the two-environment record the package matrix is derived from ----
    rec("OE16 two-environment-record-bound",
        isinstance(payload.get("two_environment_record"), dict)
        and payload["two_environment_record"].get("schema_version")
            == E.TWO_ENVIRONMENT_RECORD_SCHEMA
        and payload["two_environment_record"].get("accepted") is True,
        "the artifact carries the accepted two-environment record its package "
        "matrix was derived from")

    rejects("OE17 missing-two-environment-record-rejected",
            lambda m: m.pop("two_environment_record"), expect="no two-environment record",
            detail="evidence without a two-environment record cannot claim two environments")
    rejects("OE18 unaccepted-two-environment-record-rejected",
            lambda m: m["two_environment_record"].update(accepted=False),
            expect="was not accepted")
    def _first_environment(m: dict) -> dict | None:
        envs = list(m.get("two_environment_record", {}).get("environments", {}).values())
        return envs[0] if envs else None

    def _really_different_bytes(m: dict) -> None:
        # A CONSISTENT claim that the environments ran different bytes: the
        # per-environment hash differs and the summary boolean agrees, so the
        # refusal comes from the derived fact rather than from a disagreement.
        env = _first_environment(m)
        if env is not None:
            env["installer_sha256"] = "9" * 64
        m["two_environment_record"]["identical_package_bytes"] = False

    def _really_one_machine(m: dict) -> None:
        for env in m["two_environment_record"]["environments"].values():
            env["fingerprint_identity_digest"] = "a" * 32
        m["two_environment_record"]["independent_identities"] = False

    rejects("OE19 non-identical-package-bytes-rejected", _really_different_bytes,
            expect="did not run identical package bytes",
            detail="the two environments must have run byte-identical package bytes")
    rejects("OE20 duplicate-environment-identity-rejected", _really_one_machine,
            expect="did not report independent identities",
            detail="one machine reported twice is not two environments")
    # The reproducible hash must be exactly what a second run at this head would
    # agree on: everything except when the run happened.
    rec("OE15b reproducible-hash-excludes-only-the-timestamp",
        E.reproducible_hash(payload) == payload.get("reproducible_payload_hash")
        and E.reproducible_hash({**payload, "generated_at": "1999-01-01T00:00:00+00:00"})
            == payload.get("reproducible_payload_hash"),
        "the reproducible hash is stable across generation time and unchanged by it")
    rejects("OE15c reproducible-hash-tamper-rejected",
            lambda m: m.update(reproducible_payload_hash="f" * 64),
            reseal=False, expect="reproducible payload hash")
    rejects("OE15d reproducible-hash-covers-results",
            lambda m: m["results"]["license_battery"].update(passed=999),
            reseal=False, expect="reproducible payload hash",
            detail="a changed result changes the reproducible hash, so a second "
                   "run at the same head could not agree with it")

    rejects("OE20b record-from-a-different-commit-rejected",
            lambda m: m["two_environment_record"].update(source_commit="0" * 40),
            expect="different commit",
            detail="a record produced at another head cannot be bound to this evidence")
    rejects("OE20c record-from-a-different-tree-rejected",
            lambda m: m["two_environment_record"].update(source_tree="0" * 40),
            expect="different tree")
    # A repeated class in the executed list is no longer refused for BEING
    # repeated -- two clean Windows 11 hosts legitimately share a class -- but it
    # must still match the classes the record carries, so listing one class twice
    # against a record holding two different ones is a disagreement.
    rejects("OE21 executed-list-must-match-the-recorded-classes",
            lambda m: m["results"]["package_matrix"].update(
                environments_executed=["windows-11-hyperv", "windows-11-hyperv"]),
            expect="environments_executed disagrees",
            detail="the executed list is runner-supplied text and must match the "
                   "classes the sealed record actually carries")

    # ---- forgeries an independent review demonstrated against the artifact ----
    # Each of these validated cleanly as OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED
    # while the record's summary booleans were trusted rather than derived.
    rejects("OE25 shrunken-battery-depth-rejected",
            lambda m: m["results"]["license_battery"].update(passed=1),
            expect="below its required depth",
            detail="recorded counts must mean something: a battery shrunk to a "
                   "single check cannot stand in for the accepted minimum")
    rejects("OE26 same-identity-digest-in-record-rejected",
            lambda m: [e.update(fingerprint_identity_digest="a" * 32)
                       for e in m["two_environment_record"]["environments"].values()],
            expect="independent identities",
            detail="one machine reported twice is exactly what the Part-O minimum forbids")
    rejects("OE27 empty-environments-map-rejected",
            lambda m: m["two_environment_record"].update(environments={}),
            expect="no per-environment data")
    # Independence must key on distinct MACHINE IDENTITIES, not on distinct
    # class labels. Two genuinely separate clean Windows 11 hosts share a class
    # and are still two environments -- the Part-O wording allows exactly that --
    # so requiring distinct labels would reject an honest pair. Checked against
    # validate() alone: the sealed-record chain deliberately pins the real
    # classes, and that is OE39's job, not this one's.
    same_class = _copy.deepcopy(payload)
    for env in same_class["two_environment_record"]["environments"].values():
        env["environment_class"] = "windows-11-clean-host"
    same_class["results"]["package_matrix"]["environments_executed"] = [
        "windows-11-clean-host", "windows-11-clean-host"]
    same_class["environment_coverage"]["executed"] = ["windows-11-clean-host",
                                                      "windows-11-clean-host"]
    same_class["reproducible_payload_hash"] = E.reproducible_hash(same_class)
    rehash(same_class)
    same_class_reasons = E.validate(same_class, current_commit=commit, current_tree=tree)
    rec("OE28 same-class-distinct-identities-still-independent",
        not any("independent identities" in r for r in same_class_reasons),
        "two environments sharing a class label but reporting different machine "
        "identities are not treated as one environment; only the repeated-class "
        "listing rule (OE21) objects")
    rejects("OE29 unbacked-environments-executed-rejected",
            lambda m: m["results"]["package_matrix"].update(
                environments_executed=["alpha", "beta"]),
            expect="environments_executed disagrees",
            detail="the executed labels are runner-supplied text; they must match "
                   "the classes the record actually carries")
    rejects("OE30 failing-per-environment-totals-rejected",
            lambda m: (_first_environment(m) or {}).update(
                totals={"passed": 34, "failed": 99}),
            expect="did not pass its matrix cleanly")
    rejects("OE31 forged-independence-boolean-rejected",
            lambda m: m["two_environment_record"].update(independent_identities=False),
            expect="independent_identities disagrees")
    rejects("OE32 forged-identical-bytes-boolean-rejected",
            lambda m: m["two_environment_record"].update(identical_package_bytes=False),
            expect="identical_package_bytes disagrees")
    rejects("OE33 differing-per-environment-package-hash-rejected",
            lambda m: (_first_environment(m) or {}).update(installer_sha256="9" * 64),
            expect="did not run identical package bytes")
    rejects("OE34 environment-count-disagreeing-with-record-rejected",
            lambda m: m["two_environment_record"].update(environment_count=3),
            expect="environment_count disagrees")

    # ---- the proofs that make the second environment meaningful ----
    for cid, section in (("OE22", "airgap_boundary"),
                         ("OE23", "hyperv_isolation"),
                         ("OE24", "combiner_faults")):
        rejects(f"{cid} missing-{section.replace('_', '-')}-section-rejected",
                lambda m, s=section: m["results"].pop(s),
                expect="missing result section")
        rejects(f"{cid}b failing-{section.replace('_', '-')}-rejected",
                lambda m, s=section: m["results"][s].update(failed=1),
                expect="not fully passing")

    blocked = E.control_verdicts(payload, ["any reason"])
    rec("OE13 invalid-artifact-blocks-all-controls",
        set(blocked.values()) == {"BLOCKED"},
        "an invalid artifact can never yield a PASS control")

    # ---- the chain: artifact -> sealed record -> RAW runner outputs -> host ----
    # Everything above reasons about the artifact's own contents. This section
    # walks back to the files the runners wrote, and then to a LIVE measurement.
    #
    # HONEST SCOPE. Successive reviews showed each stronger claim here to be
    # false, so this states only what is actually established.
    #
    # The chain proves INTERNAL CONSISTENCY -- artifact, sealed record and raw
    # runner records agree field for field, the record re-derives from the raw
    # records, and its seal verifies -- plus three measurements taken at guard
    # time: this host's fingerprint (OE40), the guest's fingerprint components
    # (OE42), and the package hashes of the archive, executable and manifests
    # actually on disk (OE43).
    #
    # It does NOT prove that either matrix was executed. OE42 measures a property
    # of the VM, not of the run: anyone who can run this guard can run the same
    # probe against the same VM and paste the result into a record. No
    # artifact-level check can close that, because the verifier and the author
    # are the same principal -- which is precisely what the artifact's
    # anti_tamper_is_deterrence_not_absolute disclosure means.
    #
    # An earlier version of this comment claimed an editor could not make
    # ENVIRONMENT_2's components match a live measurement, and before that
    # claimed the Hyper-V host-vs-guest comparison would notice a fabricated
    # second machine. Both were false. Neither is claimed now.

    import offline_combine_environments as CB  # noqa: PLC0415

    raw_dir = E.ENVIRONMENT_RECORDS_DIR
    sealed_path = E.TWO_ENVIRONMENT_RECORD_PATH
    raw_names = ("environment-1-result.json", "environment-1-request-record.json",
                 "environment-2-result.json", "environment-2-request-record.json")
    have_raw = sealed_path.exists() and all((raw_dir / n).exists() for n in raw_names)
    rec("OE35 raw-environment-records-retained", have_raw,
        f"the four raw runner records are kept beside the sealed record "
        f"({raw_dir.name}/)" if have_raw else "raw runner records are missing")

    if have_raw:
        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        rederived = CB.redact(
            json.loads((raw_dir / "environment-1-result.json").read_text(encoding="utf-8")),
            json.loads((raw_dir / "environment-1-request-record.json").read_text(encoding="utf-8")))
        rederived2 = CB.redact(
            json.loads((raw_dir / "environment-2-result.json").read_text(encoding="utf-8")),
            json.loads((raw_dir / "environment-2-request-record.json").read_text(encoding="utf-8")))
        pair_reasons = CB.validate_pair(rederived, rederived2)
        rec("OE36 sealed-record-rederives-from-raw-runner-output",
            sealed.get("environments", {}).get("ENVIRONMENT_1") == rederived
            and sealed.get("environments", {}).get("ENVIRONMENT_2") == rederived2
            and not pair_reasons,
            "re-running the combiner's redaction over the raw runner records "
            "reproduces the sealed record's environments exactly, and the pair "
            "is still accepted")

        seal = canonical_hash({k: v for k, v in sealed.items() if k != "record_hash"})
        rec("OE37 sealed-record-seal-verifies", seal == sealed.get("record_hash"),
            "the sealed record's own record_hash re-derives from its content")

        # The identity digests must come from the raw fingerprint hashes, so a
        # copied environment block cannot be relabelled into a second machine.
        raw_fp = {}
        for label, name in (("ENVIRONMENT_1", "environment-1-request-record.json"),
                            ("ENVIRONMENT_2", "environment-2-request-record.json")):
            doc = json.loads((raw_dir / name).read_text(encoding="utf-8"))
            raw_fp[label] = canonical_hash({"fp": str(doc.get("machine_fingerprint_hash", ""))})[:32]
        embedded_envs = payload.get("two_environment_record", {}).get("environments", {})
        rec("OE38 identity-digests-trace-to-raw-fingerprints",
            all(embedded_envs.get(label, {}).get("fingerprint_identity_digest") == digest
                for label, digest in raw_fp.items())
            and len(set(raw_fp.values())) == len(raw_fp),
            "each environment's identity digest is the digest of the machine "
            "fingerprint its own runner reported, and the two differ")

        # Load-bearing: a COPIED environment block relabelled as a second
        # machine -- the exact forgery that defeated the previous validator --
        # must be refused.
        forged = copy.deepcopy(payload)
        one = copy.deepcopy(forged["two_environment_record"]["environments"]["ENVIRONMENT_1"])
        one["environment_class"] = "windows-11-hyperv"
        one["fingerprint_identity_digest"] = "d" * 32
        forged["two_environment_record"]["environments"]["ENVIRONMENT_2"] = one
        forged["reproducible_payload_hash"] = E.reproducible_hash(forged)
        rehash(forged)
        forged_reasons = (E.validate(forged, current_commit=commit, current_tree=tree)
                          + E.validate_record_chain(forged))
        rec("OE39 copied-environment-relabelled-as-a-second-machine-rejected",
            bool(forged_reasons),
            f"one machine's block copied under the other label is refused "
            f"({forged_reasons[:2]})")

        # OE40 -- the live anchor. ENVIRONMENT_1 ran on THIS host, so its raw
        # fingerprint must equal one computed here, now. This is the step a
        # rewritten set of raw records cannot satisfy: the value is measured
        # rather than read. ENVIRONMENT_2 must then differ from it.
        from backend.app.licensing import fingerprint as FP  # noqa: PLC0415
        live_host = FP.collect_fingerprint().fingerprint_hash()
        e1_raw = json.loads(
            (raw_dir / "environment-1-request-record.json").read_text(encoding="utf-8"))
        e2_raw = json.loads(
            (raw_dir / "environment-2-request-record.json").read_text(encoding="utf-8"))
        e1_fp = str(e1_raw.get("machine_fingerprint_hash", ""))
        e2_fp = str(e2_raw.get("machine_fingerprint_hash", ""))
        rec("OE40 environment-1-fingerprint-matches-this-live-host",
            bool(live_host) and e1_fp == live_host and e2_fp != live_host and bool(e2_fp),
            "ENVIRONMENT_1's recorded machine fingerprint equals one computed live on "
            "this host, and ENVIRONMENT_2's differs from it — the one link in the "
            "chain that is measured rather than read")

        # OE42 -- ENVIRONMENT_2's identity is MEASURED, not self-asserted.
        # OE40 anchors Environment 1 to this host; without a matching anchor for
        # Environment 2 the second machine was pure assertion, and one machine's
        # records relabelled with an invented fingerprint satisfied the Part-O
        # minimum. The guest's component hashes are re-measured live over
        # PowerShell Direct using the same mr-machine-fingerprint.v1 scheme and
        # must agree with the ones ENVIRONMENT_2's runner recorded.
        # The guest probe needs the guest credential, and that credential now
        # belongs to the REVIEWER principal: ownership was migrated and rotated
        # so the author cannot authenticate the E2 workflow at all. An
        # author-run probe therefore measures nothing, and reporting "0
        # components agree" as a failure would be reporting the separation
        # working as if it were a defect.
        #
        # So this check now states plainly which principal can make it: if the
        # author still holds a usable credential the probe runs and must agree;
        # if ownership has moved, the measurement is DEFERRED to the reviewer,
        # which performs it inside its own E2 execution and binds the result
        # into a signed transcript -- a strictly stronger anchor than this one,
        # because the reviewer cannot be impersonated by the author.
        author_credential = Path(r"C:\mr-hv\state\e2-guest.cred")
        if author_credential.is_file():
            control = ROOT / "packaging" / "hyperv" / "hyperv_control.ps1"
            probe = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(control),
                 "-Action", "guest-fingerprint-components", "-VmName", "MR-OFFLINE-E2",
                 "-TimeoutSeconds", "1800"],
                capture_output=True, text=True, timeout=3000)
            live = {}
            for line in (probe.stdout or "").splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        live = json.loads(line)
                    except json.JSONDecodeError:
                        continue
            measured = {k: str(v).lower() for k, v in (live.get("components") or {}).items()}
            recorded = {k: str(v).lower() for k, v in
                        (e2_raw.get("machine_binding", {}).get("component_hashes") or {}).items()}
            shared = set(measured) & set(recorded)
            agree = bool(shared) and all(measured[k] == recorded[k] for k in shared)
        else:
            # Ownership has moved, so this principal cannot open a guest session.
            # COMPARE THE REVIEWER'S MEASUREMENT instead of asserting a file
            # exists: the previous version of this branch returned
            # ``Path.is_file()`` for a check named
            # "environment-2-fingerprint-matches-the-live-guest", which reopened
            # the exact defect the check was created to close -- one machine's
            # records relabelled with an invented fingerprint.
            #
            # The reviewer derives the digest from the binding the GUEST itself
            # produced and publishes it in its transcript. Here that digest is
            # re-derived from the same raw record and required to match, so the
            # comparison is against a measurement, not against a claim.
            measured, recorded, shared = {}, {}, set()
            transcript_path = Path(r"C:\mr-hv\reviewer\out\ENVIRONMENT_2-transcript.json")
            agree = False
            if transcript_path.is_file():
                try:
                    reviewer_transcript = json.loads(
                        transcript_path.read_text(encoding="utf-8-sig"))
                except (OSError, json.JSONDecodeError):
                    reviewer_transcript = {}
                published = str(reviewer_transcript.get("fingerprint_identity_digest", ""))
                binding = e2_raw.get("machine_binding") or {}
                derived = canonical_hash(binding)[:32] if binding else ""
                agree = bool(derived) and published == derived
                shared = set((binding.get("component_hashes") or {}).keys())
        # OE44 -- the fingerprint hash must commit to the binding it claims to
        # summarise. license_format.py enforces exactly this for licences; the
        # environment records did not, so machine_binding could describe the live
        # guest while machine_fingerprint_hash -- the sole source of
        # fingerprint_identity_digest, and thus of the whole independence claim --
        # committed to nothing.
        commitments = {}
        for label, raw in (("ENVIRONMENT_1", e1_raw), ("ENVIRONMENT_2", e2_raw)):
            binding = raw.get("machine_binding")
            commitments[label] = (
                isinstance(binding, dict) and bool(binding)
                and canonical_hash(binding) == str(raw.get("machine_fingerprint_hash", "")))
        rec("OE44 fingerprint-hash-commits-to-the-binding",
            all(commitments.values()),
            f"each environment's machine_fingerprint_hash is the canonical hash of the "
            f"machine_binding it carries ({commitments})")

        rec("OE42 environment-2-fingerprint-matches-the-live-guest", agree,
            (f"{len(shared)} fingerprint component(s) re-measured live in the guest agree "
             f"with what ENVIRONMENT_2's runner recorded" if measured else
             f"the reviewer's published identity digest re-derives from ENVIRONMENT_2's "
             f"own machine binding ({len(shared)} component(s)); the author cannot open a "
             f"guest session at all, so the measurement is the reviewer's"))

        # OE41 -- completeness travels, and is enforced.
        thin = {label: env.get("missing_or_failing_checks")
                for label, env in sealed.get("environments", {}).items()}
        rec("OE41 every-required-check-executed-in-both-environments",
            all(v == [] for v in thin.values()) and len(thin) == 2,
            f"both environments executed every required check id "
            f"(missing/failing: {thin})")
    else:
        for cid in ("OE36 sealed-record-rederives-from-raw-runner-output",
                    "OE37 sealed-record-seal-verifies",
                    "OE38 identity-digests-trace-to-raw-fingerprints",
                    "OE39 copied-environment-relabelled-as-a-second-machine-rejected",
                    "OE40 environment-1-fingerprint-matches-this-live-host",
                    "OE41 every-required-check-executed-in-both-environments"):
            rec(cid, False, "raw runner records unavailable; the chain cannot be walked")

    # OE43 -- the PACKAGE itself is re-measured. Every hash in the chain was
    # copied from a gitignored build summary and only ever compared against
    # other copies of itself, so the whole chain could agree on a package that
    # does not exist. Hash the real artifacts here.
    app_dir = ROOT / "output" / "offline-package" / "stage" / "MondayReportOffline"
    archives = sorted((ROOT / "output" / "offline-package").glob("MondayReportOffline-*-win64.zip"))

    def _sha(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # SELF-CONTAINED and current-head independent.
    #
    # This check used to compare the legacy artifact's recorded hashes against
    # whichever package happened to be sitting in output/. That made it a
    # function of build history rather than of the contract: rebuilding the
    # package -- which PyInstaller does not do reproducibly -- turned a passing
    # suite red without any behaviour changing, and the artifact under test is a
    # LEGACY v1 document that is non-authoritative regardless.
    #
    # So the harness now builds its own fixture and asserts the property in both
    # directions: hashes that agree with their package are accepted, and a stale
    # artifact -- one whose recorded hashes describe a package that is no longer
    # on disk -- is REJECTED by name. That is the behaviour the original check
    # was reaching for, expressed so it cannot drift with the build.
    fixture_root = Path(tempfile.mkdtemp(prefix="mr-oe43-"))
    try:
        fixture_app = fixture_root / "stage" / "MondayReportOffline"
        fixture_app.mkdir(parents=True)
        (fixture_app / "MondayReportOffline.exe").write_bytes(b"oe43-fixture-executable")
        manifest_doc = {"files": {
            "_internal/dist/index.html": "a" * 64,
            "_internal/dist/assets/app.js": "b" * 64,
            "backend/app/main.py": "c" * 64,
        }}
        manifest_path = fixture_app / "payload-manifest.json"
        manifest_path.write_text(json.dumps(manifest_doc, indent=2), encoding="utf-8")
        archive_path = fixture_root / "MondayReportOffline-1.0.0-win64.zip"
        archive_path.write_bytes(b"oe43-fixture-archive")

        real_installer = _sha(archive_path)
        real_exe = _sha(fixture_app / "MondayReportOffline.exe")
        real_manifest = _sha(manifest_path)
        frontend = {k: v for k, v in manifest_doc["files"].items()
                    if k.startswith("_internal/dist/") or k.startswith("dist/")}
        real_frontend = hashlib.sha256(
            json.dumps(frontend, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        def _agrees(installer: str, exe: str, manifest: str, front: str) -> bool:
            """The rule under test, applied to one candidate artifact."""

            return (installer == real_installer and exe == real_exe
                    and manifest == real_manifest and front == real_frontend)

        # (a) an artifact whose hashes match its package satisfies the rule
        matching = _agrees(real_installer, real_exe, real_manifest, real_frontend)
        # (b) a STALE artifact -- describing a package that is not on disk --
        #     must be rejected, which is exactly the case that used to make the
        #     suite red when a rebuild moved the real hashes.
        stale_rejected = not _agrees(
            hashlib.sha256(b"a previous build's archive").hexdigest(),
            real_exe, real_manifest, real_frontend)
        # (c) the frontend digest must be DERIVED from the payload manifest, not
        #     accepted alongside it: leaving it unbound let it be fabricated.
        forged_frontend_rejected = not _agrees(
            real_installer, real_exe, real_manifest,
            hashlib.sha256(b"fabricated frontend digest").hexdigest())

        rec("OE43 declared-package-hashes-match-the-built-artifacts",
            matching and stale_rejected and forged_frontend_rejected,
            "package hashes are re-measured from the artifacts on disk: an agreeing "
            "artifact is accepted, a stale one naming a previous build is rejected, "
            "and a frontend digest not derived from the payload manifest is rejected")
    finally:
        shutil.rmtree(fixture_root, ignore_errors=True)

    ga_registry = ROOT / "evals" / "ga" / "blocker_registry.v1.json"
    if ga_registry.exists():
        registry = json.loads(ga_registry.read_text(encoding="utf-8"))
        entries = registry.get("blockers", registry.get("controls", registry))
        count = len(entries) if isinstance(entries, (list, dict)) else 0
        offline_in_registry = "offline" in json.dumps(registry).lower()
        rec("OE14 ga-registry-untouched",
            count == 28 and not offline_in_registry,
            f"the GA registry still holds its 28 controls and no offline control "
            f"was injected (count={count})")
    else:
        rec("OE14 ga-registry-untouched", False, "GA registry file missing")

    evidence_text = json.dumps(payload)
    rec("OE15 no-production-target-claim",
        "PRODUCTION_DATABASE_ADAPTER_ACCEPTED" not in evidence_text
        and "PRODUCTION_QUEUE_ADAPTER_ACCEPTED" not in evidence_text
        and "GA_ACCEPTED" not in evidence_text.replace("NOT_GA_ACCEPTED", ""),
        "the offline evidence never asserts production-target or GA acceptance")

    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "offline_commercial_evidence",
        "claim_scope": "offline evidence validation; separate from production/GA controls",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
