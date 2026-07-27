"""Structural + behavioral coupling proof for the gap-assessment drift guard's key gates.

Replaces a raw-text presence scan. The scan asked only ``needle not in guard_src``, so a comment, a
docstring, a dead branch or an unused variable satisfied it while the predicate it claimed to pin
was ``True``. An exact-head review hollowed GA50b, GA04k and GA47f in exactly that way and both
batteries stayed green.

What is proved here:

* STRUCTURAL -- the guard is parsed with ``ast``. For each protected gate the real ``rec(...)`` call
  is located, and its PREDICATE EXPRESSION is inspected: it must not be a constant, it must
  reference the names and calls that make it load-bearing, it must be reachable, and its id must be
  unique. Comments, docstrings and unused strings are invisible to this because only the predicate
  subtree is read.
* BEHAVIORAL -- each hollowing is actually performed on an isolated copy of the guard source and the
  structural verifier is re-run against it; a mutation that is not detected is a failure.

HONEST SCOPE. This detects accidental or isolated weakening of the protected gates under the tested
mutation model. It does NOT defend against an author who coordinates edits across the guard, this
verifier and the expected values together. Independent exact-head review remains the external
control against coordinated guard rewrites.
"""
from __future__ import annotations

import ast

#: Gates whose predicates carry the accepted hardening, and what makes each load-bearing.
#: ``names``/``attrs``/``calls`` are matched against the PREDICATE SUBTREE only.
PROTECTED_GATES = {
    "GA50b": {
        "why": "re-measures the tracked tree instead of trusting the artifact's self-report",
        "names": {"dirty_paths", "tracked_dirty"},
        "attrs": set(),
        "calls": set(),
    },
    "GA04k": {
        "why": "requires disclosure length, required terms and forbidden terms",
        "names": {"disclosure", "missing_terms", "contra_terms"},
        "attrs": set(),
        "calls": {"len"},
    },
    "GA47f": {
        "why": "bounds the machine-local half per control, with no count escape",
        "names": {"unbounded"},
        "attrs": set(),
        "calls": set(),
    },
}


def _predicate_of(call: ast.Call):
    return call.args[1] if len(call.args) >= 2 else None


def _rec_calls(tree: ast.AST) -> list:
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "rec" and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            out.append(node)
    return out


def _unreachable_nodes(tree: ast.AST) -> set:
    """Node ids sitting under a statically false test, or after an unconditional return."""
    dead = set()

    def mark(node):
        for sub in ast.walk(node):
            dead.add(id(sub))

    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While)):
            test = node.test
            if isinstance(test, ast.Constant) and not test.value:
                for stmt in node.body:
                    mark(stmt)
        body = getattr(node, "body", None)
        if isinstance(body, list):
            for index, stmt in enumerate(body):
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    for later in body[index + 1:]:
                        mark(later)
                    break
    return dead


def _trivially_used(predicate, required: set) -> set:
    """Names whose every occurrence is an existence test rather than a real use."""
    real_use = set()
    trivial_nodes = set()
    for node in ast.walk(predicate):
        if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Is, ast.IsNot))
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value is None):
            trivial_nodes.add(id(node.left))
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "bool" and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)):
            trivial_nodes.add(id(node.args[0]))
    for node in ast.walk(predicate):
        if isinstance(node, ast.Name) and node.id in required and id(node) not in trivial_nodes:
            real_use.add(node.id)
    return required - real_use


def _constant_rebindings(tree, call, required: set) -> set:
    """Required names whose LAST write before the gate is an inert constant.

    A predicate can be left byte-identical and neutered one line earlier by rebinding its inputs to
    an empty literal -- invisible to any predicate-only inspection. Ordering matters: ``unbounded =
    []`` followed by ``unbounded.append(...)`` is a legitimate accumulator, so only a constant write
    with NO later feed before the gate actually hollows it.
    """
    enclosing = None
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(node is call for node in ast.walk(fn)):
            enclosing = fn
    if enclosing is None:
        return set()

    last_inert, last_feed = {}, {}
    for node in ast.walk(enclosing):
        line = getattr(node, "lineno", 0)
        if not line or line >= call.lineno:
            continue
        if isinstance(node, ast.Assign):
            value = node.value
            inert = (isinstance(value, ast.Constant)
                     or (isinstance(value, (ast.List, ast.Tuple, ast.Set)) and not value.elts)
                     or (isinstance(value, ast.Dict) and not value.keys))
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id not in required:
                    continue
                book = last_inert if inert else last_feed
                book[target.id] = max(book.get(target.id, 0), line)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name)
              and node.func.value.id in required
              and node.func.attr in ("append", "extend", "update", "add", "insert")):
            name = node.func.value.id
            last_feed[name] = max(last_feed.get(name, 0), line)
        elif (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
              and node.target.id in required):
            name = node.target.id
            last_feed[name] = max(last_feed.get(name, 0), line)

    return {n for n, line in last_inert.items() if line > last_feed.get(n, 0)}


def verify_coupling(source: str) -> list:
    """Return a list of problems. Empty means every protected gate is load-bearing.

    Never raises on malformed input: a SyntaxError is itself reported as a problem, because a guard
    that cannot be parsed cannot be trusted to be enforcing anything.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"guard source does not parse: {exc.__class__.__name__}"]

    problems = []
    dead = _unreachable_nodes(tree)
    calls = _rec_calls(tree)

    for gate, spec in sorted(PROTECTED_GATES.items()):
        matching = [c for c in calls if c.args[0].value.split(" ", 1)[0] == gate]
        if not matching:
            problems.append(f"{gate}: no rec() call emits this id")
            continue
        if len(matching) > 1:
            problems.append(f"{gate}: {len(matching)} rec() calls share this id")
            continue
        call = matching[0]
        if id(call) in dead:
            problems.append(f"{gate}: the rec() call is unreachable")
            continue
        predicate = _predicate_of(call)
        if predicate is None:
            problems.append(f"{gate}: rec() has no predicate argument")
            continue
        if isinstance(predicate, ast.Constant):
            problems.append(f"{gate}: predicate is the constant {predicate.value!r}")
            continue

        names, attrs, called = set(), set(), set()
        for sub in ast.walk(predicate):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                attrs.add(sub.attr)
            if isinstance(sub, ast.Call):
                fn = sub.func
                if isinstance(fn, ast.Name):
                    called.add(fn.id)
                elif isinstance(fn, ast.Attribute):
                    called.add(fn.attr)

        missing_names = spec["names"] - names
        missing_attrs = spec["attrs"] - attrs
        missing_calls = spec["calls"] - called
        if missing_names or missing_attrs or missing_calls:
            problems.append(
                f"{gate}: predicate no longer references "
                f"{sorted(missing_names | missing_attrs | missing_calls)} ({spec['why']})")
            continue

        loaded = {n.id for n in ast.walk(predicate)
                  if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        if spec["names"] - loaded:
            problems.append(f"{gate}: required names appear but are never read")
            continue

        # A LOAD is not a USE. An exact-head review deleted the load-bearing conjunct and kept the
        # name alive with `tracked_dirty is not None`, so every required name still "read" and both
        # batteries stayed green -- a REGRESSION against the raw-text scan this replaced, which at
        # least noticed the missing `not dirty_paths`. A name whose only appearances are
        # existence-shaped is therefore not counted as consumed.
        trivial = _trivially_used(predicate, spec["names"])
        if trivial:
            problems.append(
                f"{gate}: {sorted(trivial)} appear only in existence tests "
                f"(is/is not None, bool(x)); the load-bearing conjunct has been removed")
            continue

        # The predicate can also be left byte-identical and neutered one line earlier by rebinding
        # its inputs to an empty literal. That is invisible to any predicate-only inspection, so the
        # enclosing function is scanned for a constant rebinding of a required name.
        rebound = _constant_rebindings(tree, call, spec["names"])
        if rebound:
            problems.append(
                f"{gate}: {sorted(rebound)} rebound to a constant before the check, "
                f"which neuters it without touching the predicate")

    return problems


#: The mutations the behavioral half performs. Each returns a hollowed source that MUST STILL
#: PARSE: a mutation producing invalid Python proves nothing, because "detected" would then only
#: mean "SyntaxError". Predicate spans come from the AST, so every splice stays valid.
def _line_starts(source: str) -> list:
    starts, total = [0], 0
    for line in source.splitlines(keepends=True):
        total += len(line)
        starts.append(total)
    return starts


def _predicate_span(source: str, gate: str):
    tree = ast.parse(source)
    starts = _line_starts(source)
    for call in _rec_calls(tree):
        if call.args[0].value.split(" ", 1)[0] == gate:
            pred = _predicate_of(call)
            if pred is None:
                return None
            return (starts[pred.lineno - 1] + pred.col_offset,
                    starts[pred.end_lineno - 1] + pred.end_col_offset)
    return None


def _stmt_span(source: str, gate: str):
    """Span of the whole expression-statement wrapping a gate's rec() call."""
    tree = ast.parse(source)
    starts = _line_starts(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if (isinstance(call.func, ast.Name) and call.func.id == "rec" and call.args
                and isinstance(call.args[0], ast.Constant)
                and str(call.args[0].value).split(" ", 1)[0] == gate):
            return starts[node.lineno - 1], starts[node.end_lineno - 1] + node.end_col_offset
    return None


def mutations(source: str) -> dict:
    out = {}
    newline = chr(10)

    def replace_predicate(gate, replacement):
        span = _predicate_span(source, gate)
        if span is None:
            return None
        begin, end = span
        return source[:begin] + replacement + source[end:]

    for gate in PROTECTED_GATES:
        # Every expected string stays exactly where it was; only the predicate is hollowed.
        out["neutralize-" + gate + "-keeping-strings"] = replace_predicate(gate, "True")
        out["constant-pass-" + gate] = replace_predicate(gate, "bool(1)")
        out["noop-same-name-" + gate] = replace_predicate(gate, "(lambda *_a, **_k: True)()")

    for gate, spec in sorted(PROTECTED_GATES.items()):
        names = sorted(spec["names"])
        # D1/D7: delete the load-bearing conjunct but keep every name "read".
        trivial = " and ".join(f"({n} is not None)" for n in names)
        out["trivial-read-" + gate] = replace_predicate(gate, trivial)
        # D2/D8: leave the predicate byte-identical and rebind its inputs one line earlier.
        span = _predicate_span(source, gate)
        if span:
            begin, _ = span
            line_start = source.rfind(newline, 0, begin) + 1
            stmt_line = source.rfind(newline, 0, line_start - 1) + 1
            indent = " " * (len(source[stmt_line:]) - len(source[stmt_line:].lstrip()))
            inject = "".join(f"{indent}{n} = []{newline}" for n in names)
            out["rebind-inputs-" + gate] = source[:stmt_line] + inject + source[stmt_line:]

    span = _stmt_span(source, "GA50b")
    if span:
        begin, end = span
        line_start = source.rfind(newline, 0, begin) + 1
        indent = source[line_start:begin]
        block = source[begin:end]
        body = newline.join(
            (indent + "    " + ln.strip()) if ln.strip() else "" for ln in block.splitlines())
        out["unreachable-GA50b"] = (source[:line_start] + indent + "if False:" + newline
                                    + body + source[end:])

    span = _stmt_span(source, "GA04k")
    if span:
        begin, end = span
        out["removed-from-inventory-GA04k"] = source[:begin] + source[end:]

    span = _stmt_span(source, "GA47f")
    if span:
        begin, end = span
        block = source[begin:end]
        indent = block[:len(block) - len(block.lstrip())]
        # A genuine DUPLICATE: the real gate is gone and two trivial calls share its id, so a
        # reader grepping for the id still finds it -- twice.
        dup = (indent + 'rec("GA47f verified-half-is-bounded", True,' + newline
               + indent + '    "duplicate one")' + newline
               + indent + 'rec("GA47f verified-half-is-bounded", True,' + newline
               + indent + '    "duplicate two")')
        out["duplicate-id-replacing-GA47f"] = source[:begin] + dup + source[end:]

    return out


# --------------------------------------------------------------------------- evidence scoping
def evidence_scope(evaluator_source: str) -> dict:
    """Map each control id to the evidence artifact FILENAMES its own probe reads.

    Derived from the evaluator's AST, so it is a property of the CODE and identical on every
    machine -- unlike asking "which artifact happens to move this control here", which needs the
    artifact to be present and therefore differs per checkout.

    Why this exists: bounding a machine-local promotion on "the promoter is *a* known artifact" is
    the count escape one level down. A review promoted the production database adapter while naming
    the MIGRATION artifact as its promoter and the guard accepted it. A promoter must be an artifact
    that actually gates THAT control.

    Fails CLOSED: a control whose probe cannot be resolved gets an empty set, which forbids
    promotion rather than allowing it.
    """
    try:
        tree = ast.parse(evaluator_source)
    except SyntaxError:
        return {}

    # module-level PATH constants -> filename
    path_files = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if not (target.id.endswith("_PATH") or "EVIDENCE" in target.id):
                continue
            leaf = None
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and "." in sub.value:
                    leaf = sub.value
            if leaf:
                path_files[target.id] = leaf

    # function -> filenames it reads
    func_files = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        files = {path_files[p] for p in names & set(path_files)}
        if files:
            func_files[fn.name] = files

    # control id -> functions called in the same branch/statement group
    scope = {}
    for node in ast.walk(tree):
        ids = [n.value for n in ast.walk(node)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and n.value.startswith("ga_")]
        if len(ids) != 1:
            continue
        called = {n.func.id for n in ast.walk(node)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        files = set()
        for name in called & set(func_files):
            files |= func_files[name]
        if files:
            scope.setdefault(ids[0], set()).update(files)
    return scope
