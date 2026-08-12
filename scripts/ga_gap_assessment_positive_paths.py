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
import copy
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


# ------------------------------------------------------- informational-context isolation (Part J)
#: The machine-local half of the assessment. These fields are observations of THIS developer's
#: gitignored ``output/`` directory; they are not repository state and not exact-head evidence.
#: Nothing in this set may reach an authoritative release output or the canonical hash.
INFORMATIONAL_PAYLOAD_KEYS = ("local_evidence_artifact", "local_evidence_artifact_present",
                              "local_evidence_paths_present")
INFORMATIONAL_CONTROL_KEYS = ("current_disposition_verified_environment", "verified_promoted_by",
                              "verified_promotion_detail")
INFORMATIONAL_CONTEXT = "verified_environment_with_evidence"

#: Retained EMPTY and unused. The forgery used to be a table of literals, and the check that the
#: forgery was real compared against that same table -- one editable source on both sides, so
#: emptying it made the payload arm inert while the battery stayed green. The forgery is now a set
#: of deterministic TRANSFORMATIONS of each honest value, and the check verifies the type-specific
#: PROPERTY each transformation must produce. Neither side can be neutralised by editing a table.
FORGED_PAYLOAD_VALUES: dict = {}

#: Appended to forged strings so a forged value is recognisable without being looked up.
FORGE_SENTINEL = "::FORGED::"

#: How much a forged integer must move. Any nonzero constant works; the CHECK asserts "strictly
#: greater than the honest value", not this number, so changing it cannot make the check vacuous.
FORGE_INT_DELTA = 1000


def deterministic_forge(value):
    """Transform a value into a recognisably different one, by type.

    Deterministic so two runs agree, and type-driven so the verifying side can assert a PROPERTY
    ("the boolean flipped", "the integer grew", "the string carries the sentinel") instead of
    looking up an expected literal from a table the forgery itself owns.
    """
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + FORGE_INT_DELTA
    if isinstance(value, float):
        return value + FORGE_INT_DELTA
    if isinstance(value, str):
        return value + FORGE_SENTINEL
    if value is None:
        return FORGE_SENTINEL
    if isinstance(value, list):
        return list(value) + [FORGE_SENTINEL]
    if isinstance(value, dict):
        return dict(value, forged=FORGE_SENTINEL)
    return FORGE_SENTINEL


def forgery_is_real(honest, forged) -> bool:
    """Did ``deterministic_forge`` actually transform this value, in the way its type requires?"""
    if isinstance(honest, bool):
        return forged is (not honest)
    if isinstance(honest, (int, float)):
        return isinstance(forged, (int, float)) and forged > honest
    if isinstance(honest, str):
        return isinstance(forged, str) and forged.endswith(FORGE_SENTINEL) and forged != honest
    if honest is None:
        return forged == FORGE_SENTINEL
    if isinstance(honest, list):
        return isinstance(forged, list) and FORGE_SENTINEL in forged and forged != honest
    if isinstance(honest, dict):
        return isinstance(forged, dict) and forged.get("forged") == FORGE_SENTINEL
    return forged != honest

#: The outputs a release decision is actually read from.
AUTHORITATIVE_PAYLOAD_KEYS = ("client_data_ready", "release_candidate_ready", "ga_ready",
                              "release_recommendation")

#: The per-control field a release decision is actually read from.
AUTHORITATIVE_DISPOSITION_KEY = "current_disposition_fresh_checkout"


def release_surface(payload: dict) -> dict:
    """Every authoritative output a consumer could base a release decision on."""
    controls = [c for c in payload.get("controls") or [] if isinstance(c, dict)]
    return {
        "payload": {k: payload.get(k) for k in AUTHORITATIVE_PAYLOAD_KEYS},
        "authoritative_context": (payload.get("contexts") or {}).get(
            "fresh_checkout_no_local_evidence"),
        # The authoritative per-control disposition is `current_disposition_fresh_checkout`.
        # Reading a plain `disposition` key -- which no control has -- made every value None and
        # every blocker set empty, so PJ02 compared two constants and reported "blockers: 0" for an
        # artifact with twenty of them.
        "dispositions": {c.get("check_id"): c.get(AUTHORITATIVE_DISPOSITION_KEY)
                         for c in controls},
        "blockers": sorted(str(c.get("check_id")) for c in controls
                           if c.get(AUTHORITATIVE_DISPOSITION_KEY) == "BLOCKED"),
        "blocking_reasons": {c.get("check_id"): c.get("blocking_reason") for c in controls},
    }


def informational_forgery(payload: dict) -> dict:
    """Forge EVERY informational field at once, as maximally as the schema allows.

    This is deliberately a COORDINATED forgery rather than one field at a time: a consumer that
    reads the machine-local half is fooled by a self-consistent lie, not by a single odd value. The
    verified context is rewritten to a fully green 28-PASS GA_READY environment, both self-describing
    honesty flags are inverted, every control claims a verified PASS with a forged promoter, and the
    evidence counters are inflated. If any authoritative output or the canonical hash moves, the
    machine-local half is load-bearing and the "informational only" declaration is false.
    """
    forged = copy.deepcopy(payload)
    controls = [c for c in forged.get("controls") or [] if isinstance(c, dict)]
    for key in INFORMATIONAL_PAYLOAD_KEYS:
        forged[key] = deterministic_forge(forged.get(key))
    ctx = (forged.get("contexts") or {}).get(INFORMATIONAL_CONTEXT)
    if isinstance(ctx, dict):
        ctx["ga"] = "GA_READY"
        ctx["tally"] = {"PASS": len(controls)}
        ctx["measured"] = True
        ctx["informational_only"] = False
        ctx["authoritative_for_release"] = True
        ctx["note"] = "FORGED: this environment is authoritative and every control passes."
    for control in controls:
        for key in INFORMATIONAL_CONTROL_KEYS:
            control[key] = deterministic_forge(control.get(key))
    return forged


def authoritative_touch(payload: dict) -> dict:
    """Change exactly ONE authoritative field.

    Anti-vacuity partner for the forgery above: if the canonical hash does not move for THIS, it is
    insensitive to everything and proving it does not move for the informational forgery says
    nothing at all.
    """
    touched = copy.deepcopy(payload)
    for control in touched.get("controls") or []:
        if (isinstance(control, dict)
                and control.get(AUTHORITATIVE_DISPOSITION_KEY) == "BLOCKED"):
            control[AUTHORITATIVE_DISPOSITION_KEY] = "PASS"
            return touched
    touched["release_recommendation"] = "GA_READY"
    return touched


# ------------------------------------------------------------ independent arm expectations (Part I)
def expected_arms(syn, coupling, root: Path, graph: dict = None) -> dict:
    """Per-control arm expectations derived INDEPENDENTLY of the AST dispatch parse.

    Part I forbids checking one hand-authored mapping against another hand-authored mapping, because
    the two can be edited in tandem. So nothing here is a literal list:

    * artifacts come from the LIVE module path constants (``syn.EVIDENCE_PATH_CONSTANTS`` reads
      ``getattr(module, const)`` at runtime) -- a completely different route to the same fact than
      parsing the evaluator's if/elif dispatch;
    * validators are re-derived by READING EACH FUNCTION'S SOURCE: a validator is exactly a function
      in the control's call closure whose own body mentions that control's artifact path constant;
    * extra predicates are the complement -- closure functions that do NOT mention it.

    Changing a validator in the evaluator therefore changes both derivations; editing only the
    guard's copy changes neither.
    """
    import importlib
    import inspect

    module = importlib.import_module("backend.app.ga_readiness")
    # The caller may supply the reference graph. A mutation test that corrupts the AST extraction
    # must not be allowed to corrupt BOTH sides of the comparison -- if it did, the two derivations
    # would agree on the lie and the check would be vacuous. Passing the pristine graph keeps the
    # reference immune. NOTE the honest limit this exposes: closure MEMBERSHIP comes from the AST
    # extraction on both sides, so PP11 cross-derives an arm's CONTENTS, not the extraction itself.
    if graph is None:
        graph = coupling.evaluator_graph((root / "backend" / "app" / "ga_readiness.py")
                                         .read_text(encoding="utf-8"))
    expectations = {}
    for cid, slots in syn.EVIDENCE_PATH_CONSTANTS.items():
        constants = [const for _m, const, _rel in slots]
        artifacts = tuple(sorted(Path(str(getattr(importlib.import_module(mod), const))).name
                                 for mod, const, _rel in slots))
        closure = sorted(set(graph.get(cid, {}).get("validators", ()))
                         | set(graph.get(cid, {}).get("extra_predicates", ())))
        validators, extras, unresolved = [], [], []
        for name in closure:
            body = None
            fn = getattr(module, name, None)
            if fn is not None and callable(fn):
                try:
                    body = inspect.getsource(fn)
                except (OSError, TypeError):
                    body = None
            if body is None:
                # NESTED definitions are not module attributes -- the evaluator defines `_as_int`
                # inside `_tenant_rls_evidence_reasons`. Falling back to "unresolved" here silently
                # dropped a real closure member from the comparison and made the tenant arm look
                # inexact, so nested defs are located in the module source instead.
                body = _nested_source(root, name)
            if body is None:
                unresolved.append(name)
                continue
            (validators if any(c in body for c in constants) else extras).append(name)
        expectations[cid] = {
            "artifacts": artifacts,
            "validators": tuple(sorted(validators)),
            "extra_predicates": tuple(sorted(extras)),
            "conjunction": len(artifacts) > 1,
            "unresolved": tuple(sorted(unresolved)),
        }
    return expectations


_NESTED_SOURCE_CACHE: dict = {}


def _nested_source(root: Path, name: str):
    """Source of a function defined ANYWHERE in the evaluator, including nested definitions."""
    key = str(root)
    index = _NESTED_SOURCE_CACHE.get(key)
    if index is None:
        import ast

        text = (root / "backend" / "app" / "ga_readiness.py").read_text(encoding="utf-8")
        lines = text.splitlines()
        index = {}
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index.setdefault(node.name,
                                 chr(10).join(
                                     lines[node.lineno - 1:(node.end_lineno or node.lineno)]))
        _NESTED_SOURCE_CACHE[key] = index
    return index.get(name)


def hermetic_reference_payload(gen):
    """The assessment the generator produces with NO evidence present at all.

    The authoritative half is defined to be reproducible from the tracked repository alone. So the
    authoritative outputs of this payload must equal those of the evidence-present payload; anything
    that differs is machine-local state leaking into the release decision.
    """
    with hidden_real_evidence(gen):
        payload = gen.build()
        payload["canonical_payload_hash"] = gen.canonical_hash(payload)
    return payload


def informational_surface(gen) -> dict:
    """The exact machine-local surface, derived from the generator's own exclusion sets.

    All THREE exclusion sets are read, including the context one. PJ06 previously unioned only two,
    so a machine-local key added to the context set alone would never have been forged -- the very
    hole the check exists to close, open on one of its three surfaces.
    """
    return {
        "payload": sorted(set(gen.NON_CANONICAL_KEYS) - {"canonical_payload_hash"}),
        "control": sorted(gen.NON_CANONICAL_CONTROL_KEYS),
        "context": sorted(gen.NON_CANONICAL_CONTEXT_KEYS),
    }


def forgery_surface() -> dict:
    """What the forgery actually covers, so the two can be compared for EXACT set equality."""
    return {
        "payload": sorted(INFORMATIONAL_PAYLOAD_KEYS),
        "control": sorted(INFORMATIONAL_CONTROL_KEYS),
        "context": [INFORMATIONAL_CONTEXT],
    }
