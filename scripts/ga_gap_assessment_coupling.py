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
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            inert = (isinstance(value, ast.Constant)
                     or (isinstance(value, (ast.List, ast.Tuple, ast.Set)) and not value.elts)
                     or (isinstance(value, ast.Dict) and not value.keys))
            # AnnAssign has a single .target; a tuple target unpacks several names. Both were
            # invisible, so `dirty_paths: list = []` and `dirty_paths, _s = [], []` hollowed a gate
            # while evading this check entirely.
            targets = getattr(node, "targets", None) or [getattr(node, "target", None)]
            flat = []
            for target in targets:
                if isinstance(target, (ast.Tuple, ast.List)):
                    flat.extend(target.elts)
                elif target is not None:
                    flat.append(target)
            for target in flat:
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
def _eq_targets(test) -> set:
    """Control ids a dispatch test selects: ``check_id == "ga_x"`` or ``check_id in ("a", "b")``."""
    ids = set()
    for node in ast.walk(test):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, op, right = node.left, node.ops[0], node.comparators[0]
            if (isinstance(op, ast.Eq) and isinstance(left, ast.Name)
                    and isinstance(right, ast.Constant) and isinstance(right.value, str)
                    and right.value.startswith("ga_")):
                ids.add(right.value)
            elif (isinstance(op, ast.In) and isinstance(left, ast.Name)
                  and isinstance(right, (ast.Tuple, ast.List, ast.Set))):
                for elt in right.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).startswith("ga_"):
                        ids.add(elt.value)
    return ids


def _called_names(node) -> set:
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Name):
                out.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                out.add(fn.attr)
    return out


def evaluator_graph(evaluator_source: str) -> dict:
    """Derive the evidence-gated control graph from the evaluator's own AST.

    Returns ``{check_id: {"artifacts": [...], "conjunction": bool, "validators": [...],
    "extra_predicates": [...], "probes": [...]}}``.

    Three things the first attempt got wrong, each of which made the resolver return NOTHING:

    * DISPATCH -- ``evaluate_blockers`` is an ``if/elif`` chain, so ``ast.walk`` over a branch node
      dragged in every sibling id and the "exactly one id" selector never matched. Only ``node.test``
      is read for the id and only ``node.body`` for the calls; the rest of the chain lives in
      ``node.orelse``.
    * TRANSITIVITY -- a probe rarely touches a path constant itself. ``_migration_runner_probe`` ->
      ``_migration_evidence_valid`` -> ``_load_migration_evidence`` is two hops from
      ``MIGRATION_EVIDENCE_PATH``, so a direct-reference scan found nothing. The call graph is closed
      transitively.
    * FILENAME EXTRACTION -- taking the last dotted string in the assignment yielded ``.json`` for the
      adapter paths. The path is rebuilt from every string constant in the expression.

    Fails closed: a control that cannot be resolved is simply absent, and the caller forbids
    promotion for anything absent. Nothing here depends on which artifacts exist on this machine --
    it is a property of the code and therefore identical on every checkout.
    """
    try:
        tree = ast.parse(evaluator_source)
    except SyntaxError:
        return {}

    # Module-level string constants, so an f-string filename can be resolved.
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)                 and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = node.value.value

    def _segments(expr):
        """Path segments of a ``ROOT / "a" / "b"`` chain, in SOURCE order.

        ast.walk yields the operands of a BinOp chain outermost-first, so the first attempt read
        the filename as "output". The chain is descended explicitly instead, and an f-string
        segment such as f"{_PRODUCTION_ADAPTER_SCHEMA}.json" is resolved from the module constants
        -- without that, both production adapter paths reduced to the useless segment ".json".
        """
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return _segments(expr.left) + _segments(expr.right)
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value]
        if isinstance(expr, ast.Name):
            return [consts[expr.id]] if expr.id in consts else []
        if isinstance(expr, ast.JoinedStr):
            text = ""
            for part in expr.values:
                if isinstance(part, ast.Constant):
                    text += str(part.value)
                elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                    text += consts.get(part.value.id, "")
            return [text] if text else []
        return []

    # module-level artifact path constants -> filename (evidence artifacts only)
    path_file = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name) or not target.id.endswith("_PATH"):
                continue
            segs = _segments(node.value)
            # An evidence artifact lives under output/ and is a .json file. REGISTRY_PATH and other
            # TRACKED inputs are deliberately excluded: they are repository state, not promotion
            # evidence, and admitting one would let a tracked file authorize a promotion.
            if segs and "output" in segs and segs[-1].endswith(".json"):
                path_file[target.id] = segs[-1]

    # function -> (paths it names directly, functions it calls)
    direct, calls, func_nodes = {}, {}, {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func_nodes[fn.name] = fn
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        direct[fn.name] = {path_file[p] for p in names & set(path_file)}
        calls[fn.name] = _called_names(fn) & set(func_nodes) | _called_names(fn)

    def reachable(name, seen=None):
        seen = seen or set()
        if name in seen or name not in direct:
            return set(), set()
        seen.add(name)
        files = set(direct[name])
        fns = {name}
        for callee in calls.get(name, ()):  # transitive closure over the call graph
            if callee in direct and callee not in seen:
                sub_files, sub_fns = reachable(callee, seen)
                files |= sub_files
                fns |= sub_fns
        return files, fns

    # dispatch: control id -> probe functions
    dispatch = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        ids = _eq_targets(node.test)
        if not ids:
            continue
        called = set()
        for stmt in node.body:  # body only -- the elif chain is in orelse
            called |= _called_names(stmt)
        for cid in ids:
            dispatch.setdefault(cid, set()).update(called & set(direct))

    graph = {}
    for cid, probes in dispatch.items():
        files, fns = set(), set()
        for probe in probes:
            probe_files, probe_fns = reachable(probe)
            files |= probe_files
            fns |= probe_fns
        if not files:
            continue  # not evidence-gated; absent means promotion is forbidden
        validators = sorted(f for f in fns if direct.get(f))
        graph[cid] = {
            "artifacts": sorted(files),
            "conjunction": len(files) > 1,
            "validators": validators,
            # Functions in the probe's closure that read NO artifact: additional static predicates
            # that a valid artifact does not override (ga_migration_validity's legacy 0003 FK check).
            "extra_predicates": sorted(f for f in fns if f in direct and not direct[f]
                                       and f not in probes),
            "probes": sorted(probes),
        }
    return graph


def evidence_scope(evaluator_source: str) -> dict:
    """control id -> the evidence artifact filenames that authorize IT, and nothing else."""
    return {cid: set(spec["artifacts"]) for cid, spec in
            evaluator_graph(evaluator_source).items()}
