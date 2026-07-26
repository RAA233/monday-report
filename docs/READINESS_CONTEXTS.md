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
| Status | **implemented and verified** | **harness implemented and verified; never run** |
| Verified by | `audit:readiness-context-inventory`, `audit:readiness-context-inventory-faults` | `audit:readiness-contexts-faults` (decision logic, Docker-free); `audit:readiness-contexts` is the certifier and is capacity-gated |
| Needs Docker | no | yes, for the two PostgreSQL contexts |
| Verdict | `FOUR_READINESS_CONTEXT_CONTRACT_ACCEPTED` | `FOUR_READINESS_CONTEXTS_NOT_ACCEPTED` |

"Harness implemented, never run" is the honest middle state: the machinery exists and its decision
logic is mutation-tested, but **no context has been executed and no readiness disposition has been
produced**. See [Executing the contexts](#executing-the-contexts-the-harness) below.

Defining a context says what a configuration *is* and what its result *may not be read as*. It
says nothing about what any control actually evaluates to — that requires running the contexts,
which has not happened. Every `expected_*` field in the inventory is a **falsifiable prediction the
contract commits to in advance**, not an observation. Execution may contradict them; that is the
point of writing them down first.

Accordingly the *contract module's* own entry points (`readiness_contexts.run_context`,
`run_all_contexts`) are deliberately inert — the contract defines contexts and must never appear to
execute them. Real execution lives in a separate module, `scripts/readiness_contexts_runner.py`.
These validate their arguments and return a controlled result:

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

---

## Executing the contexts (the harness)

Defining a context and executing one are separate things, and the repository keeps them in separate
files so they cannot be confused:

| | Definition | Execution |
|---|---|---|
| Module | `backend/app/readiness_contexts.py` | `scripts/readiness_contexts_runner.py` |
| Schema | `readiness-context-inventory.v1` | `readiness-context-execution.v1` |
| Command | — | `pnpm run ga:readiness-contexts` |
| Certification | `audit:readiness-context-inventory` | `audit:readiness-contexts` |
| Non-vacuity | `audit:readiness-context-inventory-faults` | `audit:readiness-contexts-faults` |

The runner **imports** the canonical inventory. It never restates the four contexts, the axes or the
control ids — a structural check (`FS01`) parses the runner and fails if it assigns any of them.

### Two halves, split on purpose

- `evaluate_context(run_input, observations)` is **pure**: observations in, canonical result out. No
  processes, no filesystem writes, no clock.
- `collect_observations(run_input)` is the **only** process-launching path.

That split is what makes the harness testable while execution is blocked: the fault battery drives
the pure half with synthetic observations, and says so — `observations_are_synthetic: true`,
`contexts_executed: false`. Those checks are classified `predicate/unit mutation`, never as an
executed readiness context.

### The runner never accepts a disposition

Callers supply *observations* (`readiness_by_id`, `forge_report`, counters). Dispositions are
computed here by the real evaluator `ga_readiness.evaluate_blockers`. Handing the runner a
`control_dispositions` or `expected_control_dispositions` map — for instance the contract's own
predictions — is **refused**. "Static expectations reported as executed results" is therefore
structurally impossible rather than merely discouraged.

### Two fail-closed gates the evaluator itself does not provide

1. **Applicability demotion.** `evaluate_blockers` is context-*blind*: its probes read repository
   artifacts, so one accepted artifact would produce the same PASS in all four contexts — precisely
   the cross-context leakage the context concept exists to prevent. A PASS on a control the
   configuration cannot evaluate is **demoted to BLOCKED** and recorded in `demoted_controls`.
   Demotion is the fail-closed direction: it can only ever remove a claim.
2. **Axis consistency.** A local-JSON context whose observed readiness reports an active PostgreSQL
   repository is not a local context; accepting it would let the production database-adapter control
   be promoted by a run that never had a database. Such an observation is refused, as is a Redis
   queue in an inline-worker context.

### Capacity gate and unavailable semantics

Execution requires `free bytes >= 40 GiB` **and** `free percentage >= 15%`. The gate is read-only and
is evaluated *before* the observer is ever called — verified positionally on the parsed source
(`FS03`) and behaviourally by a tripwire observer that must record zero invocations (`MK02`).

Below the gate the harness emits a complete controlled summary — `certification: unavailable`,
`accepted: false`, `dispositions_produced: false`, `results: []`, `GA_BLOCKED` — and **exits
non-zero**. `--inspect` may exit zero, but only while reporting `inspection_only: true`,
`contexts_executed: false` and `accepted: false`. No simulated disposition is ever emitted.

### Deterministic output

Execution order is not load-bearing: results are always serialised in canonical inventory order, so
canonical, reverse and seeded-random runs produce a byte-identical body and the same
`canonical_result_hash`. The hash excludes only run metadata (measured capacity, per-run
fingerprints, the requested order).

### What still has to happen after capacity is restored

1. Regenerate tenant-authorization evidence v3 at the executed commit — the accepted artifact is
   commit-bound and is **stale** for any later head.
2. `pnpm run ga:readiness-contexts` twice, then `pnpm run audit:readiness-contexts`.
3. Rerun the accepted proof suites the context inputs depend on.

Until then the execution verdict stays `FOUR_READINESS_CONTEXTS_NOT_ACCEPTED`. The PostgreSQL
observer delegates to the accepted restricted-PostgreSQL foundation and, being capacity-gated, has
**not** been exercised — that is declared in the code, not glossed.

---

## Adapter registry metadata and the inventory binding

The two production-adapter controls (`production-database-adapter` / `ga_postgres_adapter` and
`production-queue-adapter` / `ga_redis_adapter`) once delegated to client-data readiness checks:
`postgres_repository` and `redis_queue`. Both are satisfiable by *disposable test infrastructure* — a
throwaway PostgreSQL over loopback, a Redis answering `PING` — so each control could report PASS on
evidence that says nothing about production. Both consumers were rewired to require a valid,
exact-head production evidence artifact.

Their **registry metadata was left describing the removed delegation**, and `evaluate_blockers` emits
`resolution_condition` verbatim as `remediation`. So each control reported BLOCKED beside
instructions that provably could not resolve it. That metadata is now corrected:

- **`description`** — states that PASS requires the evidence artifact, distinguishes the *functional*
  restricted-runtime / worker proof from the *production operations* proof this control certifies,
  and names every non-qualifying source. The queue description also states plainly that the present
  implementation is **not durable or recoverable**.
- **`policy_reference`** — points at the committed contract module and the consumer function.
- **`resolution_condition`** — names each binding the real validator enforces: full commit/tree
  binding, clean worktree, canonical hash, production parity supported by observations, every
  required proof domain with domain-appropriate provenance, and a clean secret scan.

**Neither adapter is accepted.** The metadata says what *would* satisfy the control; no such artifact
exists at any commit.

### The inventory hash was NOT rebound — and that was determined, not assumed

The natural assumption is that editing the registry changes the canonical readiness-context inventory
and forces a rebind. It does not, and the question was settled empirically before any edit: all six
fields were changed on a scratch copy and the canonical hash recomputed.

```text
inventory hash before metadata change = b9d78ad9…7d44
inventory hash after  metadata change = b9d78ad9…7d44   (identical)
```

The canonical body carries the schema/implementation/registry **versions**, the two axes, and the four
contexts — and each context's `expected_control_dispositions` is keyed by control **id** with a
disposition value. It contains no registry prose and no registry digest. Registry *identity* enters
the inventory through control ids only, which this correction does not touch.

So the accepted hash `b9d78ad9…7d44` **stands unchanged**, no rebind record is warranted, and
manufacturing one would have misrepresented the contract. What does change is the registry file's own
SHA-256, which is not pinned as a literal by any tracked guard.

### A metadata correction changes no disposition

Verified with identical hermetic readiness inputs, before and after: all 28 dispositions unchanged
and the blocking-control id set unchanged. The emitted fields that moved are exactly
`policy_reference`, `remediation` and `resolution_condition` on the two targets — `detail` comes from
the probes and did **not** move. Both adapter controls remain BLOCKED even with every readiness check
passing, and all four contexts keep their expected counts — 22/6, 24/4, 25/3, and 27 BLOCKED with the
single conditional tenant-authorization PASS.

### Two limitations worth stating

**`description` is not emitted for these two controls.** `evaluate_blockers` surfaces `description`
only through its fallback branch (`detail = f"Unresolved control: {entry['description']}"`), and both
adapters take explicit probe branches. So the non-qualifying enumeration, the durability disclosure
and the functional-vs-production distinction live in the registry as documentation for a reader of
the file — they do not reach a consumer of the evaluator's output. The operator-facing field is
`resolution_condition`, emitted verbatim as `remediation`, which is why the anti-disposable bindings
(loopback / docker-bridge / ephemeral / test / staging / development, TLS, rotation, least-privilege
identities) are stated *there* and not only in the description.

**`docs/GA_GAP_ASSESSMENT.v2.json` is regenerated and drift-guarded.** That tracked artifact
embeds every control's `resolution_condition`, so it went stale when the adapter metadata was
corrected. It is now regenerated from current sources, renamed to match its schema, and
reconciled on every run by `audit:ga-gap-assessment` against the real registry, the live
evaluator and both adapter contracts. Its expected control inventory is loaded from
`evals/ga/blocker_registry.v1.json` -- there is no second hand-authored list of the 28 and no
editable pin that could redefine them. It remains a generated STATUS REPORT:
`artifact_class=generated_status_assessment`, `is_evidence=false`.

### Still unavailable

Four-context execution remains blocked on environment capacity. Exact-head tenant-authorization
evidence v3 and both production adapter artifacts are absent or stale for this commit and **must be
regenerated before any future execution**; regenerating them is capacity-gated and was not attempted.
