"""Behavioral witnesses for the GA gap-assessment battery's own self-audits.

Three review rounds defeated a shape-based self-audit one token at a time: ``return {}`` was
caught, ``return dict()`` was not; then ``return dict()`` was caught and
``{k: True for k in REQUIRED_SELF_TEST_PROBES}`` was not. Enumerating the shapes a canned answer can
take is an arms race, and each round the battery certified itself green while its own audits were
inert.

So shape classification is no longer an acceptance authority anywhere. What decides whether a
protected audit still works is whether MUTATING IT ACTUALLY BREAKS SOMETHING OBSERVABLE: each
witness writes a mutated but valid copy of the guard tree, runs the real probe entry point in a
SUBPROCESS, and requires the child to emit valid structured JSON, exit non-zero, and fail the
specific named check the mutation should break. A canned non-empty return of exactly the right shape
fails that just as surely as ``return {}``, because the witness never looks at the return's syntax --
only at whether the protected property still holds.

WHAT THIS DOES NOT ESTABLISH. The witnesses detect the isolated hollowing and handler mutations
registered here. They cannot detect a coordinated rewrite that edits a witness, its expectation and
the production logic together -- nothing inside a repository can, because such a change is
indistinguishable from a legitimate one by construction. Independent exact-head review remains the
control for that.

INDEPENDENCE. A witness must not compute its expectation from the same constant the production check
consults. Mutations are located by AST and expectations are literal check ids observed in emitted
output, so editing a production pin does not silently retarget the witness that protects it.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
GUARD_RELATIVE = "scripts/ga_gap_assessment_faults_guard.py"
PROBE_FLAG = "--witness-probe"
#: WT05/WT06 plant a pinned false-completeness phrase to prove the scanner finds it. This module is
#: itself scanned now, so the literal is assembled at runtime -- embedding it would make the payload
#: trip the very check it exists to exercise.
PLANTED_PHRASE_COMMENT = "# " + "all heavy " + "boundaries" + " are wrapped"
#: A witness child is a narrow, fixture-free run. Well under a second in practice.
WITNESS_TIMEOUT_SECONDS = 180


# --------------------------------------------------------------------------- AST pin resolution
def resolve_module_assignment(source: str, name: str) -> dict:
    """Locate the single live module-level assignment of ``name`` from the AST.

    Raw-text searching located this by ``str.partition`` on the first occurrence of the assignment
    text, so a COMMENT containing that text, placed above the real assignment, redefined the span
    the scanner excluded and the check went inert. Comments, docstrings and string literals cannot
    influence an AST lookup.

    Returns a report rather than raising, so the caller can name precisely what is wrong.
    """
    report = {"name": name, "resolved": False, "reason": None, "lineno": None, "end_lineno": None,
              "col_offset": None, "end_col_offset": None, "value_count": 0, "duplicates": [],
              "live_assignments": 0, "nested_assignments": 0, "dead_assignments": 0}
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        report["reason"] = f"unparseable:{exc.__class__.__name__}"
        return report

    dead_lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While)):
            test = getattr(node, "test", None)
            if isinstance(test, ast.Constant) and not test.value:
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        dead_lines.add(child.lineno)

    module_level, nested, dead = [], 0, 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if node.lineno in dead_lines:
            dead += 1
            continue
        module_level.append(node) if node in tree.body else nested_append(nested_list := [], node)
        if node not in tree.body:
            nested += 1

    report["live_assignments"] = len(module_level)
    report["nested_assignments"] = nested
    report["dead_assignments"] = dead
    if nested:
        report["reason"] = "assignment is not at module scope"
        return report
    if dead:
        report["reason"] = "assignment appears in dead code"
        return report
    if not module_level:
        report["reason"] = "no live module-level assignment"
        return report
    if len(module_level) > 1:
        report["reason"] = "multiple live module-level assignments"
        return report

    node = module_level[0]
    value = node.value if isinstance(node, ast.Assign) else node.value
    elements = getattr(value, "elts", None)
    if elements is None:
        report["reason"] = "assigned value is not a literal sequence"
        return report
    literals = []
    for element in elements:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            report["reason"] = "sequence contains a non-string element"
            return report
        literals.append(element.value)
    if not literals:
        report["reason"] = "assigned sequence is empty"
        return report
    duplicates = sorted({v for v in literals if literals.count(v) > 1})
    if duplicates:
        report["reason"] = "sequence contains duplicate entries"
        report["duplicates"] = duplicates
        return report

    report.update({"resolved": True, "lineno": node.lineno, "end_lineno": node.end_lineno,
                   "col_offset": node.col_offset, "end_col_offset": node.end_col_offset,
                   "value_count": len(literals), "values": literals,
                   "span": (node.lineno, node.end_lineno)})
    return report


def nested_append(container, node):  # pragma: no cover - tiny helper kept explicit for clarity
    container.append(node)
    return container


def excluded_span(source: str, name: str):
    """The exact source line range occupied by a pin assignment, or ``None``."""
    report = resolve_module_assignment(source, name)
    if not report["resolved"]:
        return None
    return report["lineno"], report["end_lineno"]


# --------------------------------------------------------------------------- handler validation
#: The only call names accepted as the structured emitter in the process handler.
CANONICAL_EMITTERS = ("emit_structured_internal_failure", "_emit_and_exit")
#: Statement types forbidden anywhere in the handler body. The contract is a WHITELIST: the handler
#: must be a flat sequence of an emitter call then a non-zero termination, and nothing else.
FORBIDDEN_HANDLER_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With,
                           ast.AsyncWith, ast.Return, ast.Pass, ast.Lambda, ast.ListComp,
                           ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.FunctionDef,
                           ast.AsyncFunctionDef)
if hasattr(ast, "Match"):  # pragma: no branch - version dependent
    FORBIDDEN_HANDLER_NODES = FORBIDDEN_HANDLER_NODES + (ast.Match,)


def process_handler_contract(source: str) -> dict:
    """Validate the top-level exception handler against a deliberately MINIMAL canonical form.

    The previous version tried to decide reachability in general, and lost: an emitter behind
    ``for _ in ():`` or behind a false module flag was judged reachable, so the handler passed while
    a real escape exited rc=0 with no output. Deciding reachability in general is undecidable and
    every extra syntax case is another arms-race round.

    So the shape is fixed instead of analysed. The handler body must be exactly a flat sequence
    containing one emitter call and, after it, one unconditional non-zero ``raise SystemExit``.
    Any conditional, loop, try, with, match, comprehension, lambda, nested function, ``return`` or
    ``pass`` anywhere in the body is a refusal -- there is nowhere left to hide an unreachable
    emitter, because nothing that could make a statement conditional is permitted at all.
    """
    report = {"handler_found": False, "catches_base_exception": False, "emits": False,
              "terminates_nonzero": False, "is_pass": None, "forbidden_nodes": [],
              "emitter_index": None, "termination_index": None, "handler_count": 0,
              "reason": None}
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        report["reason"] = f"unparseable:{exc.__class__.__name__}"
        return report

    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "run"
                for c in ast.walk(node)):
            target = node
            break
    if target is None:
        report["reason"] = "no top-level Try around run()"
        return report

    handlers = [h for h in target.handlers
                if getattr(h.type, "id", None) == "BaseException"]
    report["handler_count"] = len(handlers)
    if len(handlers) != 1:
        report["reason"] = ("exactly one BaseException handler is required; found "
                            f"{len(handlers)}")
        return report
    handler = handlers[0]
    report["handler_found"] = report["catches_base_exception"] = True
    report["is_pass"] = all(isinstance(s, ast.Pass) for s in handler.body)

    forbidden = sorted({type(n).__name__ for s in handler.body for n in ast.walk(s)
                        if isinstance(n, FORBIDDEN_HANDLER_NODES)})
    report["forbidden_nodes"] = forbidden
    if forbidden:
        report["reason"] = f"handler body contains forbidden constructs: {forbidden}"
        return report

    for index, statement in enumerate(handler.body):
        if (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name)
                and statement.value.func.id in CANONICAL_EMITTERS):
            report["emits"] = True
            report["emitter_index"] = index
            break
    if not report["emits"]:
        report["reason"] = "handler body has no direct structured emitter call"
        return report

    for index, statement in enumerate(handler.body):
        if not isinstance(statement, ast.Raise) or not isinstance(statement.exc, ast.Call):
            continue
        func = statement.exc.func
        if not (isinstance(func, ast.Name) and func.id == "SystemExit"):
            continue
        args = statement.exc.args
        if args and isinstance(args[0], ast.Constant) and args[0].value in (0, None):
            report["reason"] = "handler terminates with success"
            return report
        report["terminates_nonzero"] = True
        report["termination_index"] = index
        break
    if not report["terminates_nonzero"]:
        report["reason"] = "handler body has no direct non-zero SystemExit"
        return report
    if report["termination_index"] <= report["emitter_index"]:
        report["reason"] = "termination precedes the emitter"
        return report
    return report


def handler_contract_holds(source: str) -> bool:
    """Convenience predicate. The guard applies the same conditions itself and does not rely on it."""
    report = process_handler_contract(source)
    return bool(report["handler_found"] and report["catches_base_exception"] and report["emits"]
                and report["terminates_nonzero"] and not report["is_pass"]
                and not report["forbidden_nodes"] and report["reason"] is None)


def rehash_boundary_contract(source: str) -> dict:
    """BC08's real property: ``rehash`` classifies a canonical-hash failure instead of escaping.

    BC08 was the literal ``True``. This is the behaviour it was supposed to stand for: the call runs
    once per artifact mutation, and a raise there must become a named failure rather than an escape.
    """
    report = {"function_found": False, "call_guarded": False, "emits": False, "reason": None}
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        report["reason"] = f"unparseable:{exc.__class__.__name__}"
        return report
    node = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "rehash"), None)
    if node is None:
        report["reason"] = "rehash is not defined"
        return report
    report["function_found"] = True
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Try) or not inner.handlers:
            continue
        hashes = any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                     and c.func.attr == "canonical_hash" for c in ast.walk(inner))
        if not hashes:
            continue
        report["call_guarded"] = True
        for handler in inner.handlers:
            live = [s for s in handler.body if not isinstance(s, ast.Pass)]
            names = {c.func.id for s in live for c in ast.walk(s)
                     if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            if "_emit_and_exit" in names:
                report["emits"] = True
        break
    if not report["call_guarded"]:
        report["reason"] = "the canonical_hash call in rehash is not inside a handler"
    elif not report["emits"]:
        report["reason"] = "the handler does not emit a structured failure"
    return report


# --------------------------------------------------------------------------- mutation primitives
def _function_span(source: str, name: str):
    tree = ast.parse(source)
    node = next((n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)
    if node is None:
        raise LookupError(f"function {name} not found")
    return node


def replace_function_body(source: str, name: str, body_lines) -> str:
    """Replace a function's body, keeping its signature. Located by AST, never by text search."""
    node = _function_span(source, name)
    lines = source.splitlines()
    signature = lines[node.lineno - 1:(node.body[0].lineno - 1)]
    indent = " " * (node.col_offset + 4)
    replacement = list(signature) + [indent + line for line in body_lines]
    return "\n".join(lines[:node.lineno - 1] + replacement + lines[node.end_lineno:]) + "\n"


def replace_handler_body(source: str, body_lines) -> str:
    """Replace the top-level BaseException handler's body."""
    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        if not any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "run"
                   for c in ast.walk(node)):
            continue
        for handler in node.handlers:
            if getattr(handler.type, "id", None) != "BaseException":
                continue
            first = handler.body[0]
            indent = " " * first.col_offset
            head = lines[:first.lineno - 1]
            tail = lines[(handler.body[-1].end_lineno or first.lineno):]
            return "\n".join(head + [indent + line for line in body_lines] + tail) + "\n"
    raise LookupError("top-level BaseException handler not found")


def insert_before_line(source: str, lineno: int, text_lines) -> str:
    lines = source.splitlines()
    return "\n".join(lines[:lineno - 1] + list(text_lines) + lines[lineno - 1:]) + "\n"


def append_lines(source: str, text_lines) -> str:
    return source.rstrip("\n") + "\n" + "\n".join(text_lines) + "\n"


# --------------------------------------------------------------------------- witness execution
def build_mutation(witness_id: str, source: str) -> dict:
    """Construct one mutation and return its ACTUAL bytes plus an identity record.

    Identity comes from the real changed bytes -- original digest, mutated digest, canonical unified
    diff digest, changed path set, parse result and the declared target -- not from metadata. Witness
    fingerprints previously hashed the description, so swapping two payloads while keeping their
    descriptions left every fingerprint unchanged.
    """
    witness = next((w for w in WITNESS_REGISTRY if w["witness_id"] == witness_id), None)
    if witness is None:
        return {"witness_id": witness_id, "error": "unknown witness id"}
    record = {"witness_id": witness_id, "target": witness["target"],
              "expect_pass": bool(witness.get("expect_pass")),
              "changed_paths": [GUARD_RELATIVE],
              "original_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}
    try:
        mutated = witness["mutation"](source)
    except Exception as exc:  # noqa: BLE001
        record.update({"error": f"constructor raised {exc.__class__.__name__}", "mutated_source": None})
        return record
    if not isinstance(mutated, str):
        record.update({"error": "constructor did not return source text", "mutated_source": None})
        return record
    record["mutated_sha256"] = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
    try:
        ast.parse(mutated)
        record["parses"] = True
    except SyntaxError as exc:
        record.update({"parses": False, "error": f"mutated source does not parse: {exc.lineno}"})
        return record
    diff = list(difflib.unified_diff(source.splitlines(), mutated.splitlines(),
                                    fromfile="original", tofile="mutated", lineterm="", n=0))
    record["diff_sha256"] = hashlib.sha256("\n".join(diff).encode("utf-8")).hexdigest()
    record["diff_lines"] = len(diff)
    record["is_noop"] = not diff
    record["mutated_source"] = mutated
    return record


def constructor_ids() -> list:
    return sorted(w["witness_id"] for w in WITNESS_REGISTRY)


def run_witness_child(mutated_guard_source: str, extra_files=None):
    """Run the REAL probe entry point over a mutated copy, in a subprocess.

    Copying the whole ``scripts/`` tree keeps every import the guard needs, so the child is the real
    program rather than a fragment of it.
    """
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="gga-witness-"))
    try:
        shutil.copytree(REPO_ROOT / "scripts", workspace / "scripts")
        for relative in ("backend", "evals", "db", "docs"):
            source_dir = REPO_ROOT / relative
            if source_dir.exists():
                shutil.copytree(source_dir, workspace / relative,
                                ignore=shutil.ignore_patterns("__pycache__"))
        (workspace / GUARD_RELATIVE).write_text(mutated_guard_source, encoding="utf-8", newline="\n")
        for relative, text in (extra_files or {}).items():
            target = workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        completed = subprocess.run(
            [sys.executable, GUARD_RELATIVE, PROBE_FLAG],
            cwd=str(workspace), capture_output=True, text=True,
            timeout=WITNESS_TIMEOUT_SECONDS)
        return {"rc": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr, "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "stdout": "", "stderr": "", "timed_out": True}
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def diagnostic_evaluate(result: dict, expected_failing_check: str,
                        expect_pass: bool = False) -> dict:
    """DIAGNOSTIC ONLY. Never an acceptance authority -- the main guard adjudicates.

    A crash, a syntax error, a timeout, empty stdout or malformed JSON is NEVER a detection -- those
    are the outcomes an inert guard also produces, which is the whole reason this harness exists.
    """
    verdict = {"parsed": False, "structured": False, "rc": result.get("rc"),
               "timed_out": bool(result.get("timed_out")), "failing": [],
               "expected_failing_check": expected_failing_check, "detected": False,
               "reason": None}
    if verdict["timed_out"]:
        verdict["reason"] = "timeout is not a detection"
        return verdict
    stdout = result.get("stdout") or ""
    if not stdout.strip():
        verdict["reason"] = "empty stdout is not a detection"
        return verdict
    try:
        payload = json.loads(stdout)
    except Exception:  # noqa: BLE001
        verdict["reason"] = "malformed JSON is not a detection"
        return verdict
    verdict["parsed"] = verdict["structured"] = True
    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        verdict["reason"] = "child emitted no checks"
        return verdict
    failing = [c.get("check_id") for c in checks if isinstance(c, dict) and not c.get("ok")]
    verdict["failing"] = failing
    verdict["emitted"] = len(checks)
    if expect_pass:
        verdict["detected"] = result.get("rc") == 0 and not failing
        if not verdict["detected"]:
            verdict["reason"] = "the no-op control must leave the probe passing"
        return verdict
    if result.get("rc") == 0:
        verdict["reason"] = "child exited zero; a mutation that changes nothing is not a detection"
        return verdict
    if expected_failing_check not in failing:
        verdict["reason"] = "the expected named check did not fail; the failure is not attributable"
        return verdict
    verdict["detected"] = True
    return verdict


# --------------------------------------------------------------------------- the registry
def _canned_probe_dict(source: str) -> str:
    """Return the exact shape the production check expects -- built WITHOUT reading its constant."""
    return replace_function_body(source, "audit_self_test", [
        "keys = [k for k in _witness_probe_names()]",
        "return {k: True for k in keys}",
    ])


def _witness_probe_names_shim(source: str) -> str:
    """Give the canned mutation a way to name the probes without importing the production pin."""
    return source.replace("def audit_self_test(", (
        "def _witness_probe_names():\n"
        "    return list(REQUIRED_SELF_TEST_PROBES)\n"
        "\n"
        "\n"
        "def audit_self_test("), 1)


WITNESS_REGISTRY = (
    {
        "witness_id": "WT01",
        "protected_property": "source-audit execution: audit_self_test really runs its probes",
        "target": "audit_self_test",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: _canned_probe_dict(_witness_probe_names_shim(s)),
        "note": ("a canned NON-EMPTY dict of exactly the expected shape, built from the production "
                 "pin -- the mutation that defeated the shape heuristic"),
    },
    {
        "witness_id": "WT02",
        "protected_property": "source-audit execution: audit_self_test reports per-probe results",
        "target": "audit_self_test",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: replace_function_body(s, "audit_self_test", [
            'return {k: {"status": "pass"} for k in REQUIRED_SELF_TEST_PROBES}']),
        "note": "canned non-empty dict whose values are the wrong type",
    },
    {
        "witness_id": "WT03",
        "protected_property": "source-audit execution: the copied-body report really analyses source",
        "target": "_copied_body_report",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: replace_function_body(s, "_copied_body_report", [
            'return {"defined": 3, "duplicate_bodies": [], "constant_only_functions": [],',
            '        "unreferenced": []}']),
        "note": "canned non-empty report of exactly the right shape",
    },
    {
        "witness_id": "WT04",
        "protected_property": "source-audit execution: the boundary audit really walks the AST",
        "target": "_boundary_call_audit",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: replace_function_body(s, "_boundary_call_audit", [
            'return (["PP.fake:1"], [])']),
        "note": "canned non-empty classified list with nothing unclassified",
    },
    {
        "witness_id": "WT05",
        "protected_property": "inline source scan: a pinned false-completeness phrase is found",
        "target": "_false_phrase_report",
        "expected_failing_check": "FZ13 no-known-false-completeness-claims",
        "mutation": lambda s: append_lines(s, [
            PLANTED_PHRASE_COMMENT]),
        "note": "a verbatim pinned phrase planted in a scanned source",
    },
    {
        "witness_id": "WT06",
        "protected_property": "inline source scan: a comment cannot hide the pin assignment",
        "target": "FALSE_COMPLETENESS_PHRASES",
        "expected_failing_check": "FZ13 no-known-false-completeness-claims",
        "mutation": lambda s: append_lines(
            insert_before_line(
                s, resolve_module_assignment(s, "FALSE_COMPLETENESS_PHRASES")["lineno"],
                ["# FALSE_COMPLETENESS_PHRASES = (",
                 "#     \"decoy\",",
                 "# )"]),
            [PLANTED_PHRASE_COMMENT]),
        "note": ("the exact raw-text bypass: a comment carrying the assignment text, above the real "
                 "assignment, plus a planted phrase"),
    },
    {
        "witness_id": "WT07",
        "protected_property": "pin-set completeness: the phrase pin cannot be emptied",
        "target": "FALSE_COMPLETENESS_PHRASES",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: _replace_pin(s, "FALSE_COMPLETENESS_PHRASES", []),
        "note": ("an empty pin tuple certifies nothing. FZ14 observes it first, because the "
                 "self-test can no longer find a phrase to plant"),
    },
    {
        "witness_id": "WT08",
        "protected_property": "pin-set completeness: the probe set cannot drift downward",
        "target": "REQUIRED_SELF_TEST_PROBES",
        "expected_failing_check": "FZ14 source-audits-are-behaviourally-discriminating",
        "mutation": lambda s: _drop_pin_entry(s, "REQUIRED_SELF_TEST_PROBES"),
        "note": "removing one required probe while updating nothing else",
    },
    {
        "witness_id": "WT09",
        "protected_property": "process handler: a swallowing handler is refused",
        "target": "process handler",
        "expected_failing_check": "BC07 no-unstructured-exit",
        "mutation": lambda s: replace_handler_body(s, ["pass"]),
        "note": "handler body is pass",
    },
    {
        "witness_id": "WT10",
        "protected_property": "process handler: a dead emitter in the try body does not satisfy it",
        "target": "process handler",
        "expected_failing_check": "BC07 no-unstructured-exit",
        "mutation": lambda s: replace_handler_body(
            _dead_emitter_in_try(s), ["pass"]),
        "note": "the exact bypass: dead _emit_and_exit in the try body, handler is pass",
    },
    {
        "witness_id": "WT11",
        "protected_property": "process handler: a handler that exits zero after output is refused",
        "target": "process handler",
        "expected_failing_check": "BC07 no-unstructured-exit",
        "mutation": lambda s: replace_handler_body(s, ['print("{}")', "raise SystemExit(0)"]),
        "note": "handler emits output then terminates with SUCCESS",
    },
    {
        "witness_id": "WT12",
        "protected_property": "process handler: a handler that exits zero is refused",
        "target": "process handler",
        "expected_failing_check": "BC07 no-unstructured-exit",
        "mutation": lambda s: replace_handler_body(s, ["raise SystemExit(0)"]),
        "note": "handler terminates with success",
    },
    {
        "witness_id": "WT13",
        "protected_property": "process handler: an emitter only in an unreachable branch is refused",
        "target": "process handler",
        "expected_failing_check": "BC07 no-unstructured-exit",
        "mutation": lambda s: replace_handler_body(s, [
            "if False:", "    _emit_and_exit({})", "pass"]),
        "note": "emitter present but provably unreachable",
    },
    {
        "witness_id": "WT14",
        "protected_property": "BC08's real property: the rehash canonical-hash call is classified",
        "target": "rehash",
        "expected_failing_check": "BC08 canonical-hash-boundary",
        "mutation": lambda s: replace_function_body(s, "rehash", [
            "artifact = copy.deepcopy(artifact)",
            'artifact.pop("canonical_payload_hash", None)',
            'artifact["canonical_payload_hash"] = GEN.canonical_hash(artifact)',
            "return artifact"]),
        "note": "the handler around the canonical-hash call removed",
    },
    {
        "witness_id": "WC01",
        "protected_property": "control: a legitimate non-trivial tuple return is NOT rejected",
        "target": "none",
        "expected_failing_check": None,
        "expect_pass": True,
        "mutation": lambda s: append_lines(s, [
            "def _witness_legitimate_pair(a, b):",
            "    return (a, b)",
            "",
            "",
            "def _witness_legitimate_mapping(x):",
            '    return {"k": x}',
            "",
            "",
            "_WITNESS_LEGITIMATE_USE = (_witness_legitimate_pair, _witness_legitimate_mapping)"]),
        "note": ("legitimate implementations returning a tuple and a dict must not be classified as "
                 "hollow -- shape is no longer an authority"),
    },
    {
        "witness_id": "WC02",
        "protected_property": "control: an unmodified copy still passes the probe",
        "target": "none",
        "expected_failing_check": None,
        "expect_pass": True,
        "mutation": lambda s: s,
        "note": ("the no-op control. Without it every witness above would be satisfied by a harness "
                 "that fails merely because a temporary copy was made"),
    },
)


def _replace_pin(source: str, name: str, values) -> str:
    report = resolve_module_assignment(source, name)
    if not report["resolved"]:
        raise LookupError(f"cannot resolve {name}: {report['reason']}")
    lines = source.splitlines()
    body = [f"{name} = ("] + [f'    "{v}",' for v in values] + [")"]
    return "\n".join(lines[:report["lineno"] - 1] + body
                     + lines[report["end_lineno"]:]) + "\n"


def _drop_pin_entry(source: str, name: str) -> str:
    report = resolve_module_assignment(source, name)
    if not report["resolved"]:
        raise LookupError(f"cannot resolve {name}: {report['reason']}")
    return _replace_pin(source, name, report["values"][:-1])


def _dead_emitter_in_try(source: str) -> str:
    """Park an unreachable ``_emit_and_exit`` in the try body."""
    return source.replace("        raise SystemExit(run())",
                          "        if False:\n"
                          "            _emit_and_exit({})\n"
                          "        raise SystemExit(run())", 1)


# --------------------------------------------------------------------------- manifest + pins
def witness_manifest() -> list:
    """The declared CONSTRUCTOR inventory, in canonical form, with no callables.

    Deliberately does NOT include the expected failing check: the guard's own authoritative manifest
    owns every expectation. A module that both builds a mutation and declares what its success looks
    like can be edited on both sides at once.
    """
    return [{"witness_id": w["witness_id"],
             "protected_property": w["protected_property"],
             "target": w["target"],
             "expect_pass": bool(w.get("expect_pass")),
             "note": w["note"]}
            for w in WITNESS_REGISTRY]


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def manifest_hash() -> str:
    return hashlib.sha256(_canonical(witness_manifest()).encode("utf-8")).hexdigest()


def protected_property_hash() -> str:
    properties = sorted(w["protected_property"] for w in WITNESS_REGISTRY)
    return hashlib.sha256(_canonical(properties).encode("utf-8")).hexdigest()


def witness_id_hash() -> str:
    ids = sorted(w["witness_id"] for w in WITNESS_REGISTRY)
    return hashlib.sha256(_canonical(ids).encode("utf-8")).hexdigest()


def diagnostic_run_all(source: str = None) -> list:
    """DIAGNOSTIC ONLY. Never an acceptance authority.

    An independent review canned this function to report every witness detected and the battery
    stayed green -- so the module that constructs the mutations was also the module that judged
    them. The main fault guard now performs its own execution and adjudication; this remains only
    as a convenience for interactive debugging and its result reaches no verdict.
    """
    if source is None:
        source = (REPO_ROOT / GUARD_RELATIVE).read_text(encoding="utf-8")
    results = []
    for witness in WITNESS_REGISTRY:
        entry = {"witness_id": witness["witness_id"],
                 "protected_property": witness["protected_property"],
                 "expected_failing_check": witness["expected_failing_check"]}
        try:
            mutated = witness["mutation"](source)
            ast.parse(mutated)
        except Exception as exc:  # noqa: BLE001
            entry.update({"detected": False, "parsed": False,
                          "reason": f"mutation did not produce valid Python: {exc.__class__.__name__}"})
            results.append(entry)
            continue
        outcome = run_witness_child(mutated)
        entry.update(diagnostic_evaluate(outcome, witness["expected_failing_check"],
                                         expect_pass=bool(witness.get("expect_pass"))))
        results.append(entry)
    return results
