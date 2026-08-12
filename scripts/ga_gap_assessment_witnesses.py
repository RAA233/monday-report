"""DATA-ONLY witness recipes for the GA gap-assessment battery.

This module describes mutations. It does not perform them, does not execute anything, does not
hash anything, does not declare what changed, and does not decide whether any witness passed.

That division exists because the previous two designs failed the same way twice. First this module
both built the mutations and judged them, so canning its aggregate functions left the battery
green. Then judging moved into the guard but EXECUTION stayed here, and a ``run_witness_child``
replacement that launched no subprocess and returned a fabricated child document again left every
witness green. Moving a verdict is not the same as moving authority: whoever supplies the
execution, the bytes or the digests still holds it.

So every recipe below is a plain serialisable record -- an operation name and literal parameters.
The guard reads the original bytes, applies the operation, serialises the result, computes every
digest, derives the changed paths, launches the subprocess, parses the output and reaches the
verdict. Nothing here is trusted for any of that, and nothing here is capable of it: the module
imports nothing and defines no function beyond two pure lookups over the table below.

Expectations deliberately do NOT live here. The guard's authoritative manifest names the check
each mutation must break; a module that both describes a mutation and declares what its success
looks like can be edited on both sides at once.

WHAT THIS DOES NOT ESTABLISH. These recipes describe a finite, registered set of isolated
mutations. Independent exact-head review remains the external control against coordinated changes
to all in-repository code, manifests and expectations.
"""
from __future__ import annotations

#: The file every recipe targets. A convenience constant, not a claim: the guard derives the
#: actual changed-path set from the bytes it wrote and refuses anything outside the manifest's
#: permitted set.
WITNESS_TARGET_PATH = "scripts/ga_gap_assessment_faults_guard.py"

#: The mutation operations the guard knows how to apply. A recipe naming anything else is refused.
OP_REPLACE_FUNCTION_BODY = "replace_function_body"
OP_REPLACE_MODULE_HANDLER_BODY = "replace_module_handler_body"
OP_APPEND_LINES = "append_lines"
OP_INSERT_BEFORE_ASSIGNMENT = "insert_before_assignment"
OP_REPLACE_ASSIGNMENT_VALUE = "replace_assignment_value"
OP_DROP_ASSIGNMENT_ENTRY = "drop_assignment_entry"
OP_NO_CHANGE = "no_change"

KNOWN_OPERATIONS = (
    OP_REPLACE_FUNCTION_BODY,
    OP_REPLACE_MODULE_HANDLER_BODY,
    OP_APPEND_LINES,
    OP_INSERT_BEFORE_ASSIGNMENT,
    OP_REPLACE_ASSIGNMENT_VALUE,
    OP_DROP_ASSIGNMENT_ENTRY,
    OP_NO_CHANGE,
)

#: WT05/WT06 plant a pinned false-completeness phrase to prove the scanner finds it. This module
#: is itself scanned, so the literal is assembled from fragments -- embedding it whole would make
#: the recipe trip the very check it exists to exercise.
_PLANTED = "# " + "all heavy " + "boundaries" + " are wrapped"

#: The recipe table. Pure data: which node to change and what to put there.
WITNESS_RECIPES = (
    {"witness_id": "WT01", "operation": OP_REPLACE_FUNCTION_BODY,
     "target_selector": "audit_self_test",
     "body": ("keys = [k for k in REQUIRED_SELF_TEST_PROBES]",
              "return {k: True for k in keys}"),
     "note": "a canned NON-EMPTY dict of exactly the expected shape, built from the production pin"},
    {"witness_id": "WT02", "operation": OP_REPLACE_FUNCTION_BODY,
     "target_selector": "audit_self_test",
     "body": ('return {k: {"status": "pass"} for k in REQUIRED_SELF_TEST_PROBES}',),
     "note": "canned non-empty dict whose values are the wrong type"},
    {"witness_id": "WT03", "operation": OP_REPLACE_FUNCTION_BODY,
     "target_selector": "_copied_body_report",
     "body": ('return {"defined": 3, "duplicate_bodies": [], "constant_only_functions": [],',
              '        "unreferenced": []}'),
     "note": "canned non-empty report of exactly the right shape"},
    {"witness_id": "WT04", "operation": OP_REPLACE_FUNCTION_BODY,
     "target_selector": "_boundary_call_audit",
     "body": ('return (["PP.fake:1"], [])',),
     "note": "canned non-empty classified list with nothing unclassified"},
    {"witness_id": "WT05", "operation": OP_APPEND_LINES,
     "target_selector": "module_tail", "lines": (_PLANTED,),
     "note": "a verbatim pinned false-completeness phrase planted in a scanned source"},
    {"witness_id": "WT06", "operation": OP_INSERT_BEFORE_ASSIGNMENT,
     "target_selector": "FALSE_COMPLETENESS_PHRASES",
     "lines": ("# FALSE_COMPLETENESS_PHRASES = (", '#     "decoy",', "# )", _PLANTED),
     "note": "the raw-text bypass: a comment carrying the assignment text above the real assignment"},
    {"witness_id": "WT07", "operation": OP_REPLACE_ASSIGNMENT_VALUE,
     "target_selector": "FALSE_COMPLETENESS_PHRASES", "values": (),
     "note": "an empty pin tuple certifies nothing"},
    {"witness_id": "WT08", "operation": OP_DROP_ASSIGNMENT_ENTRY,
     "target_selector": "REQUIRED_SELF_TEST_PROBES",
     "note": "removing one required probe while updating nothing else"},
    {"witness_id": "WT09", "operation": OP_REPLACE_MODULE_HANDLER_BODY,
     "target_selector": "module_handler", "body": ("pass",),
     "note": "handler body is pass"},
    {"witness_id": "WT10", "operation": OP_REPLACE_MODULE_HANDLER_BODY,
     "target_selector": "module_handler",
     "body": ("if False:", "    emit_structured_internal_failure(_exc)", "pass"),
     "note": "emitter present but behind a provably-false branch"},
    {"witness_id": "WT11", "operation": OP_REPLACE_MODULE_HANDLER_BODY,
     "target_selector": "module_handler",
     "body": ('print("{}")', "raise SystemExit(0)"),
     "note": "handler emits output then terminates with SUCCESS"},
    {"witness_id": "WT12", "operation": OP_REPLACE_MODULE_HANDLER_BODY,
     "target_selector": "module_handler", "body": ("raise SystemExit(0)",),
     "note": "handler terminates with success and emits nothing"},
    {"witness_id": "WT13", "operation": OP_REPLACE_MODULE_HANDLER_BODY,
     "target_selector": "module_handler",
     "body": ("for _ in ():", "    emit_structured_internal_failure(_exc)",
              "raise SystemExit(1)"),
     "note": "emitter behind an empty loop -- reachable to a heuristic, never executed"},
    {"witness_id": "WT14", "operation": OP_REPLACE_FUNCTION_BODY,
     "target_selector": "rehash",
     "body": ("artifact = copy.deepcopy(artifact)",
              'artifact.pop("canonical_payload_hash", None)',
              'artifact["canonical_payload_hash"] = GEN.canonical_hash(artifact)',
              "return artifact"),
     "note": "the handler around the canonical-hash call removed"},
    {"witness_id": "WC01", "operation": OP_APPEND_LINES, "target_selector": "module_tail",
     "lines": ("def _witness_legitimate_pair(a, b):", "    return (a, b)", "", "",
               "def _witness_legitimate_mapping(x):", '    return {"k": x}', "", "",
               "_WITNESS_LEGITIMATE_USE = (_witness_legitimate_pair, _witness_legitimate_mapping)"),
     "expect_pass": True,
     "note": ("legitimate implementations returning a tuple and a dict must not be rejected -- "
              "return shape is not an authority")},
    {"witness_id": "WC02", "operation": OP_NO_CHANGE, "target_selector": "none",
     "expect_pass": True,
     "note": ("the no-op control. Without it every witness above would be satisfied by a harness "
              "that fails merely because a temporary copy was made")},
)


def recipe_ids() -> list:
    """The witness ids this module supplies recipes for. Pure data, no judgement."""
    return sorted(r["witness_id"] for r in WITNESS_RECIPES)


def recipe_for(witness_id: str):
    """The recipe record for one id, or ``None``. The guard validates it against its manifest."""
    for recipe in WITNESS_RECIPES:
        if recipe["witness_id"] == witness_id:
            return recipe
    return None
