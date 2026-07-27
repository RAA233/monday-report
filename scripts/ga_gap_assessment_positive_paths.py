"""Positive-path coverage for the evidence-scope graph.

The batteries proved for a long time that WRONG promotions are refused, and never that a RIGHT one
is accepted. That asymmetry is exactly how ``EVIDENCE_SCOPE = {}`` -- an inert resolver that
forbids every promotion -- stayed green through two independent reviews: a guard that silently
stops accepting the generator's own honest output looks identical to a guard that is working.

Everything here drives the REAL evaluator and the REAL drift guard. No validator is weakened, no
result is mocked, and synthetic evidence is written only into throwaway temp directories -- never
into the developer's real ``output/`` paths, which are hidden for the duration and restored in a
``finally``.

SYNTHETIC SCOPE. The artifacts built here satisfy the contracts' PARSER and EVALUATOR only. They
are not production evidence and cannot constitute production acceptance: every one carries
``synthetic``/``parser_evaluator_coverage_only``/``real_operational_execution`` and the production
adapter verdicts are unaffected.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
from pathlib import Path

#: control -> the controls whose disposition MAY move when only that control's evidence is present.
#: ga_migration_validity shares its artifact with ga_migration_runner, so the runner necessarily
#: moves too; that is a property of the evaluator, not a leak, and is asserted rather than ignored.
EXPECTED_MOVERS = {
    "ga_migration_runner": {"ga_migration_runner"},
    "ga_migration_validity": {"ga_migration_runner"},
    "ga_persistence_locking": {"ga_persistence_locking"},
    "ga_correction_cross_process_atomicity": {"ga_correction_cross_process_atomicity"},
    "ga_postgres_adapter": {"ga_postgres_adapter"},
    "ga_redis_adapter": {"ga_redis_adapter"},
    "ga_tenant_authorization": {"ga_tenant_authorization"},
}

#: The one control an artifact cannot promote: an independent static predicate outlives the
#: evidence gate. Recognised scope is proved by the SIBLING moving, not by a fail-closed BLOCKED.
STATIC_BLOCKER_CONTROLS = {
    "ga_migration_validity": ("0003_benchmarking.sql", "ga_migration_runner"),
}


@contextlib.contextmanager
def hidden_real_evidence(gen):
    """Hide every real gitignored evidence artifact for the duration, then restore it."""
    stash = Path(tempfile.mkdtemp(prefix="pp-hide-"))
    moved = []
    try:
        for index, path in enumerate(gen._all_evidence_paths()):
            if path.exists():
                target = stash / f"{index}-{path.name}"
                os.replace(path, target)
                moved.append((path, target))
        yield
    finally:
        for path, target in moved:
            path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(target, path)
        shutil.rmtree(stash, ignore_errors=True)


def dispositions(ga) -> dict:
    return {c["id"]: c["disposition"] for c in ga.evaluate_blockers({})}


def detail_for(ga, control) -> str:
    for check in ga.evaluate_blockers({}):
        if check["id"] == control:
            return str(check.get("detail") or "")
    return ""


def install_only(syn, control, outdir):
    """Point ONLY this control's path constants at freshly built synthetic artifacts."""
    return syn.install_subset(control, outdir) if hasattr(syn, "install_subset") \
        else syn.install(outdir)


def scoped_promotion_matrix(syn, gen, ga) -> dict:
    """Per-control A/D behaviour, measured against the real evaluator.

    Returns ``{control: {"disposition":…, "movers":[…], "detail":…}}`` with only that control's
    own evidence installed, relative to a baseline with no evidence at all.
    """
    results = {}
    with hidden_real_evidence(gen):
        baseline = dispositions(ga)
        for control in sorted(syn.SEVEN_CONTROLS):
            outdir = Path(tempfile.mkdtemp(prefix="pp-syn-"))
            saved = {}
            try:
                # install() repoints ALL seven constants, so saving only this control's leaves the
                # other six dangling at deleted temp paths after the fixture runs.
                import importlib
                for slots in syn.EVIDENCE_PATH_CONSTANTS.values():
                    for module_name, const, _rel in slots:
                        key = (module_name, const)
                        if key not in saved:
                            saved[key] = getattr(importlib.import_module(module_name), const)
                written = syn.install(outdir)
                # Re-hide every artifact this control does NOT require, so the measurement is
                # genuinely per-control rather than "everything at once".
                required = {rel.rsplit("/", 1)[-1]
                            for _m, _c, rel in syn.EVIDENCE_PATH_CONSTANTS[control]}
                for name, path in list(written.items()):
                    if Path(path).name not in required and Path(path).exists():
                        os.replace(path, str(path) + ".hidden")
                after = dispositions(ga)
                movers = sorted(k for k in baseline if baseline[k] != after[k])
                results[control] = {"disposition": after.get(control), "movers": movers,
                                    "detail": detail_for(ga, control)[:200]}
            finally:
                import importlib
                for (module_name, const), value in saved.items():
                    setattr(importlib.import_module(module_name), const, value)
                shutil.rmtree(outdir, ignore_errors=True)
    return results


# --------------------------------------------------------------------------- guard-level positives
def legitimate_promotion_payload(syn, gen):
    """Build the assessment the generator HONESTLY produces when all seven artifacts are present.

    Returns ``(payload, promoted)``. Real evidence is hidden throughout and restored afterwards; the
    synthetic artifacts live in a temp directory that is removed.
    """
    outdir = Path(tempfile.mkdtemp(prefix="pp-build-"))
    saved = {}
    import importlib
    try:
        with hidden_real_evidence(gen):
            for control, slots in syn.EVIDENCE_PATH_CONSTANTS.items():
                for module_name, const, _rel in slots:
                    key = (module_name, const)
                    if key not in saved:
                        saved[key] = getattr(importlib.import_module(module_name), const)
            syn.install(outdir)
            payload = gen.build()
            payload["canonical_payload_hash"] = gen.canonical_hash(payload)
        promoted = {c["check_id"]: c.get("verified_promoted_by")
                    for c in payload["controls"] if c.get("verified_promoted_by")}
        return payload, promoted
    finally:
        for (module_name, const), value in saved.items():
            setattr(importlib.import_module(module_name), const, value)
        shutil.rmtree(outdir, ignore_errors=True)


def guard_verdict(gg, payload):
    """Run the REAL drift guard against a payload. Returns (rc, failing_check_ids)."""
    tmp = Path(tempfile.mkdtemp(prefix="pp-guard-"))
    saved = gg.ARTIFACT_PATH
    try:
        target = tmp / "assessment.json"
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        gg.ARTIFACT_PATH = target
        gg.checks.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = gg.run()
        return rc, [c["check_id"] for c in gg.checks if not c["ok"]]
    except Exception as exc:  # noqa: BLE001 - a crash is never an acceptance
        return 1, [f"<exception:{exc.__class__.__name__}>"]
    finally:
        gg.ARTIFACT_PATH = saved
        gg.checks.clear()
        shutil.rmtree(tmp, ignore_errors=True)


def scope_without(gg, controls):
    """Context manager removing named controls from the guard's derived EVIDENCE_SCOPE."""

    @contextlib.contextmanager
    def _ctx():
        original = gg.EVIDENCE_SCOPE
        try:
            gg.EVIDENCE_SCOPE = {k: v for k, v in original.items() if k not in controls}
            yield
        finally:
            gg.EVIDENCE_SCOPE = original

    return _ctx()


# --------------------------------------------------------------------------- registered fixture
#: The positive-path fixture, computed ONCE per process. Building it runs the real evaluator many
#: times and the real generator once, so every registered PP check and every scope mutation reads
#: this single measurement rather than repeating it.
_FIXTURE: dict = {}


def fixture(syn, gen, ga):
    """Measure the whole positive-path surface once: matrix, honest payload, promoters."""
    if _FIXTURE:
        return _FIXTURE
    matrix = scoped_promotion_matrix(syn, gen, ga)
    payload, promoted = legitimate_promotion_payload(syn, gen)
    _FIXTURE.update({
        "matrix": matrix,
        "payload": payload,
        "promoted": promoted,
        "controls": {c["check_id"]: c for c in payload["controls"]},
    })
    return _FIXTURE


def unrelated_and_stale_matrix(syn, gen, ga) -> dict:
    """B and C cases: an unrelated control's artifact, and a corrupted own artifact.

    The stale case for the migration artifact deliberately corrupts its migration-set hash rather
    than its commit: ``_migration_evidence_valid`` performs no commit binding at all, so a
    wrong-commit fixture would pass and the check would be vacuous.
    """
    import importlib
    results = {}
    with hidden_real_evidence(gen):
        baseline = dispositions(ga)
        outdir = Path(tempfile.mkdtemp(prefix="pp-bc-"))
        saved = {}
        try:
            for slots in syn.EVIDENCE_PATH_CONSTANTS.values():
                for module_name, const, _rel in slots:
                    key = (module_name, const)
                    if key not in saved:
                        saved[key] = getattr(importlib.import_module(module_name), const)
            written = syn.install(outdir)
            # ---- B: only the queue artifact present; every other control must stay put
            for name, path in written.items():
                if "production-queue-adapter" not in Path(path).name and Path(path).exists():
                    os.replace(path, str(path) + ".off")
            after_b = dispositions(ga)
            results["unrelated"] = sorted(k for k in baseline if baseline[k] != after_b[k])
            results["measured"] = bool(written) and len(baseline) > 20
            for name, path in written.items():
                off = Path(str(path) + ".off")
                if off.exists():
                    os.replace(off, path)
            # ---- C: corrupt each artifact so its own validator refuses it
            for path in written.values():
                target = Path(path)
                if not target.exists():
                    continue
                body = json.loads(target.read_text(encoding="utf-8"))
                for key in ("migration_set_sha256", "git_commit", "git_tree", "payload_sha256"):
                    if key in body:
                        body[key] = "0" * len(str(body[key])) if isinstance(body[key], str) else body[key]
                target.write_text(json.dumps(body), encoding="utf-8")
            after_c = dispositions(ga)
            results["stale"] = sorted(k for k in baseline if baseline[k] != after_c[k])
        finally:
            for (module_name, const), value in saved.items():
                setattr(importlib.import_module(module_name), const, value)
            shutil.rmtree(outdir, ignore_errors=True)
    return results


def graph_fingerprint(coupling, root: Path) -> dict:
    """Independently derived expected graph: artifacts, operator, validators, extra predicates.

    Derived from the evaluator's own AST every run, so it cannot be satisfied by editing a second
    hand-authored copy in tandem with the first.
    """
    graph = coupling.evaluator_graph((root / "backend" / "app" / "ga_readiness.py")
                                     .read_text(encoding="utf-8"))
    return {cid: {"artifacts": tuple(sorted(spec["artifacts"])),
                  "conjunction": bool(spec["conjunction"]),
                  "validators": tuple(sorted(spec["validators"])),
                  "extra_predicates": tuple(sorted(spec["extra_predicates"]))}
            for cid, spec in graph.items()}


def conjunction_members_matrix(syn, gen, ga, control="ga_tenant_authorization") -> dict:
    """Install each conjunction member ALONE and record the control's disposition.

    The graph derives ``conjunction`` from artifact CARDINALITY, not from the evaluator's boolean
    operator, so a review weakened the evaluator's all-of to an any-of and both batteries stayed
    green: nothing ever evaluated a single member on its own. This measures it behaviourally.
    """
    import importlib
    slots = syn.EVIDENCE_PATH_CONSTANTS[control]
    names = [rel.rsplit("/", 1)[-1] for _m, _c, rel in slots]
    results = {"members": sorted(names), "alone": {}, "both": None}
    with hidden_real_evidence(gen):
        outdir = Path(tempfile.mkdtemp(prefix="pp-conj-"))
        saved = {}
        try:
            for every in syn.EVIDENCE_PATH_CONSTANTS.values():
                for module_name, const, _rel in every:
                    key = (module_name, const)
                    if key not in saved:
                        saved[key] = getattr(importlib.import_module(module_name), const)
            written = syn.install(outdir)
            paths = {Path(p).name: Path(p) for p in written.values()}
            # every artifact NOT belonging to this control stays off for the whole measurement
            for name, path in paths.items():
                if name not in names and path.exists():
                    os.replace(path, str(path) + ".off")
            for keep in names:
                for name in names:
                    target = paths[name]
                    off = Path(str(target) + ".off")
                    if name == keep and off.exists():
                        os.replace(off, target)
                    elif name != keep and target.exists():
                        os.replace(target, off)
                results["alone"][keep] = dispositions(ga).get(control)
            for name in names:
                off = Path(str(paths[name]) + ".off")
                if off.exists():
                    os.replace(off, paths[name])
            results["both"] = dispositions(ga).get(control)
        finally:
            for (module_name, const), value in saved.items():
                setattr(importlib.import_module(module_name), const, value)
            shutil.rmtree(outdir, ignore_errors=True)
    return results
