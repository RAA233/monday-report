# Readiness contexts

A **readiness context** is one supported runtime configuration in which the GA control registry
(`evals/ga/blocker_registry.v1.json`, 28 controls) can be evaluated.

Before this contract the repository had no context concept at all. Readiness was evaluated in
whatever configuration the process happened to start in, and nothing recorded *which*
configuration produced a disposition. That made an entire class of overclaim invisible: a PASS
observed in a demo-mode run could be read as evidence about authenticated client behaviour, and a
PASS observed on the local JSON store could be read as evidence about database-enforced tenant
isolation. The contract exists to make those readings impossible to state.

The contract is defined in [`backend/app/readiness_contexts.py`](../backend/app/readiness_contexts.py)
under schema `readiness-context-inventory.v1`.

## Definition is not execution

This is the distinction the rest of the document depends on.

| | Contract definition | Context execution |
|---|---|---|
| What it produces | the four contexts, as data | real readiness dispositions |
| Status | **implemented and verified** | **not started** |
| Verified by | `audit:readiness-context-inventory`, `audit:readiness-context-inventory-faults` | nothing yet |
| Needs Docker | no | yes |
| Verdict | `FOUR_READINESS_CONTEXT_CONTRACT_ACCEPTED` | `FOUR_READINESS_CONTEXTS_NOT_ACCEPTED` |

Defining a context says what a configuration *is* and what its result *may not be read as*. It
says nothing about what any control actually evaluates to — that requires running the contexts,
which has not happened. Every `expected_*` field in the inventory is a **falsifiable prediction the
contract commits to in advance**, not an observation. Execution may contradict them; that is the
point of writing them down first.

Accordingly the runner entry points (`run_context`, `run_all_contexts`) are deliberately inert.
They validate their arguments and return a controlled result:

```text
certification = "unavailable"
accepted      = false
executed      = false
results       = []
```

They never return a simulated disposition. `audit:readiness-context-inventory-faults` mutation-tests
exactly this: a runner patched to report `certification=passed`, or one whose serialised result
contains a fabricated `PASS`, is refused.

## Why exactly four

Four is **derived, not chosen**. The implementation supports exactly two independent binary axes,
and the inventory is their Cartesian product.

**Axis 1 — client-data mode.** `readiness.client_data_mode()` maps the environment onto exactly
`"client"` or `"demo"`; every unrecognised value collapses to `"demo"`, so there is no third state.
`store._configured_client_data_mode()` mirrors it.

**Axis 2 — repository backend.** `runtime_backends.detect_active_repository_backend()` returns
exactly `LOCAL_REPOSITORY_BACKEND` (`"local_json"`) or `POSTGRES_REPOSITORY_BACKEND`
(`"postgres"`), and `store.create_store()` correspondingly builds `LocalStateStore` or
`PostgresStateStore`.

The axes are **independent**: `create_store()` selects the store class from
`requested_repository_backend()` and `database_url()` alone and never branches on the client-data
mode, while `readiness.evaluate_client_data_readiness(store)` derives the mode from the environment
and the active repository backend from the store object — the two axes separately. So all 2×2
combinations are representable and startable, and the product is four.

One asymmetry is worth stating rather than glossing: on the PostgreSQL path `create_store()`
re-raises `TenantRuntimeRoleError`, and `tenant_rls.enforce_runtime_role()` only enforces in client
mode. `client-postgres` therefore carries a runtime-role safety **precondition** that
`demo-postgres` does not. That is a precondition on starting, not a mode-dependent choice of store
class, so the axes remain independent — but "all four are startable" means *given a safe runtime
role*.

`audit:readiness-context-inventory` re-derives both axes from those real modules on every run and
requires the inventory to equal their product. The two axes are derived differently, for a reason:

- **client-data mode** is derived *dynamically* — the guard drives the real `client_data_mode()`
  across 14 inputs, including unrecognised ones, and asserts the observed range is exactly the
  declared axis;
- **repository backend** is derived *statically*, in **both halves** — reaching the PostgreSQL
  branch of `detect_active_repository_backend()` requires a live database, which a Docker-free
  guard must not start. So the guard parses the real functions and resolves **every `return`
  statement** against the live module namespace:
  - `detect_active_repository_backend()` must return exactly the two declared backend strings, and
  - `create_store()` must return exactly the two store classes `LocalStateStore` /
    `PostgresStateStore`.

  Both halves matter because readiness reads the active backend off the *store object*
  (`getattr(store, "repository_backend", …)`), so a third store class would widen the axis even
  with the detector untouched. Either derivation refuses outright if a return value cannot be
  resolved, and an implementation whose source cannot be inspected at all fails a **named gate**
  with a printed verdict rather than crashing.

If the implementation ever drops an axis value or grows a third, the product stops being four and
**the guard fails closed** rather than certifying an inventory the implementation cannot justify.
The fault battery proves both directions: it patches the implementation down to one backend, and
separately gives `detect_active_repository_backend()` a faithful third branch, and confirms refusal
in each case.

### Why the queue backend is not a third axis

`inline_worker` / `redis` is a real configuration switch, but it is recorded as a per-context
*classification*, not an axis. No accepted evidence exists for the Redis path,
`production-queue-adapter` is BLOCKED in all four contexts, and promoting an unproven adapter to an
axis would double the inventory with configurations nothing has exercised.

## The four contexts

Canonical order is load-bearing — it is part of the canonical hash.

| `context_id` | mode | backend | what a result here can prove |
|---|---|---|---|
| `demo-local` | demo | `local_json` | UI/backend consistency only |
| `demo-postgres` | demo | `postgres` | UI/backend consistency on the PostgreSQL store |
| `client-local` | client | `local_json` | authenticated client-mode enforcement, without any database |
| `client-postgres` | client | `postgres` | authenticated client-mode enforcement with RLS-enforced isolation |

Context ids are stable, lowercase, and derived **only** from the axis values, so renaming a display
name cannot silently reuse an identity. A rename is still detectable: the canonical hash is pinned
in the guard, and any edit to the inventory fails `CH06` until the pin is updated deliberately.

## Scope semantics — what a context result may not be read as

Every context carries these statements, and the guard enforces each as a gate:

- a **demo-mode** result is never evidence of authenticated client-mode behaviour. A demo-mode
  dual-backend UI run proves UI/backend consistency *only*;
- a **local-JSON** result is never evidence of database-enforced tenant isolation (RLS);
- a **PostgreSQL** result is never evidence of production database-adapter parity — the restricted
  runtime is classified `restricted_postgres_runtime_not_production_adapter`;
- valid **tenant-authorization evidence v3** satisfies the tenant-authorization control *only*. It
  never satisfies migration validity, database-adapter readiness, or queue-adapter readiness, and
  never implies `client_data_ready`.

## How expected dispositions are derived

Dispositions are produced by four documented rules, not hand-typed per context — 112 hand-written
cells would not be auditable, and a reviewer can check a rule.

1. demo mode cannot evaluate client-identity controls → `NOT_APPLICABLE`
2. local JSON cannot evaluate RLS or the migration chain → `NOT_APPLICABLE`
3. a control with an accepted artifact produced **in that context** → `PASS`
4. otherwise → `BLOCKED`

Two deliberate exclusions from rule 2 are worth stating, because the alternative would understate a
blocker: `production-database-adapter` stays **BLOCKED** (not `NOT_APPLICABLE`) in local contexts —
GA requires it regardless of which context runs, and marking it N/A would read as "this context
does not need one". `persistence-locking-transactions` also stays BLOCKED, because the local store
has its own locking mechanism and a local run genuinely *can* evaluate it; it is simply not yet
accepted here.

Rule 3 currently fires exactly once: `tenant-authorization-enforcement` in `client-postgres`, the
one control with an accepted artifact, produced in exactly that context. That prediction is
explicitly **conditional** — the accepted v3 artifact is commit-bound, so it does not carry forward
to a later tree and must be regenerated at whatever commit is executed. Every other cell across all
four contexts is `NOT_APPLICABLE` or `BLOCKED`.

All four contexts declare `production_parity=false`, `expected_client_data_ready=false`,
`expected_release_candidate_ready=false`, `expected_ga_ready=false`. **No context is ready.**

## Current blocker: environment capacity

Executing the contexts needs real PostgreSQL containers, API processes, workers and browsers. The
gate for starting that work is:

```text
free bytes      >= 40 GiB
free percentage >= 15%
```

At the time of writing the host has **22.28 GiB free of 932.9 GiB (2.39%)** — failing both
thresholds. It is not reachable by reclaiming Docker: total Docker usage is far below the shortfall,
and reaching 15% needs roughly 116 GiB more free space than exists. This is host-level cleanup,
outside the repository.

Both context guards are therefore Docker-free by construction. `audit:readiness-context-inventory-faults`
verifies this over the parsed AST of both files: neither imports a process launcher, database
driver, browser driver, or TestClient, so neither *can* start Docker even by accident.

## What the guards do and do not prove

Stated plainly, because a green guard is easy to over-read:

- the inventory guard's completeness pin catches gate **deletion**. It does not catch a gate
  *neutered in place*, nor a gate deleted together with its own pin entry. Those are caught by the
  fault battery, which pins the gate list **cross-file** and re-runs the real guard once per
  mutation — so weakening an *inventory-guard gate* silently requires editing both files in
  concert. The recursion stops there: the battery's own pins and expected-check list live in the
  battery itself and nothing pins them from a third file, so editing that one file can still narrow
  the battery. Review it as the root of trust it is;
- each mutation names the specific gate that must catch it and only counts as caught when that gate
  fails. A non-zero exit alone is not accepted, so the frozen-hash pin cannot stand in for the gate
  that is supposed to reason about the change;
- the fault battery drives the **real** guard rather than a reimplementation, and asserts this over
  its own parsed AST rather than by scanning its source for a string that appears in the assertion
  itself;
- none of this is evidence that any control actually passes in any context. Nothing has been
  executed.

## What must happen after capacity is restored

1. free host disk to ≥ 40 GiB **and** ≥ 15%;
2. regenerate tenant-authorization evidence v3 at the executed commit (the accepted artifact is
   bound to the commit that produced it and does not carry forward);
3. implement the execution runner behind the interface already defined here — one context by id,
   all contexts, reverse order, and deterministically seeded order, with an isolated input object
   per context and canonical result serialisation;
4. execute all four contexts **twice** and require identical results;
5. commission an independent review of the executed results;
6. only then may the execution verdict move off `FOUR_READINESS_CONTEXTS_NOT_ACCEPTED`.

Until every one of those is done, the execution verdict stands and the release recommendation
remains `GA_BLOCKED`.

## Commands

```bash
pnpm run audit:readiness-context-inventory
```

```bash
pnpm run audit:readiness-context-inventory-faults
```

Both are Docker-free, deterministic, and safe to run at any time.
