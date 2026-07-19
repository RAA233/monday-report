# GA Readiness-Gate Integrity

This document specifies the truthful, registry-backed GA readiness gate. It
exists because the previous gate reported **"software blockers: 0"** while many
critical software-owned controls were unimplemented: the blocker counts were
computed by intersecting failing checks with a hand-maintained ID set, so any
gap that had **no check** contributed **zero**. The gate now derives every
count from a committed blocker registry, so a known-but-unimplemented control is
a **declared blocker** that keeps GA red.

## The readiness contradiction (before)

`ga:readiness` reported `GA_BLOCKED` with **0 software / 0 configuration / 0
evidence** blockers and only 2 infrastructure blockers (PostgreSQL, Redis) —
while RBAC, per-user identity, keyed/anti-truncation audit integrity, a
migration runner, CI, dependency scanning, backup/restore, and more were all
absent. Those gaps had no readiness check and no registry entry, so they could
never increment any blocker category. Provisioning PostgreSQL and Redis alone
would have removed the only two visible blockers and moved the command toward a
misleading near-ready result.

## Blocker registry

`evals/ga/blocker_registry.v1.json` is the committed, policy-grounded source of
truth. Each entry declares `id`, `label`, `category`, `severity`, `owner_type`,
`policy_source`, `policy_reference`, `check_id`, `resolution_condition`,
`allow_not_applicable`, `manual_review_required`, and `description`. Every entry
cites an existing policy source (tracker, readiness doc, security/operations
requirement, existing blocker, or a directly verified code deficiency); no
speculative blockers and no invented owners or approval authorities.

- **Categories:** `software`, `configuration`, `infrastructure`,
  `security_review`, `data_review_evidence`, `client_approval`.
- **Severities:** `blocker`, `high`, `medium`, `low`.
- **Owner types:** `engineering`, `security`, `platform`, `operations`,
  `data_review`, `client_organization`.

The GA gate emits exactly one check per registry entry, and a parity guard
(`check_registry_parity`) fails if any registry entry lacks a check, any check
lacks a registry entry, an ID is duplicated, a category is unknown, or a
resolution condition / policy reference is missing. The former hand-maintained
category ID sets in `ga_readiness_guard.py` are removed; **blocker counts are
derived from each check's registry `category`**, so `uncategorized` is zero
because parity rejects missing categories — not because everything was manually
partitioned.

## Disposition semantics

Each emitted check carries a `disposition`; the legacy `status`
(`pass`/`warn`/`fail`) is preserved for existing consumers.

| Disposition | Legacy status | GA gating |
| --- | --- | --- |
| `PASS` | `pass` | non-blocking |
| `FAIL` | `fail` | **blocking** |
| `BLOCKED` | `fail` | **blocking** |
| `SKIPPED` | `fail` | **blocking** |
| `NOT_APPLICABLE` | `pass` | non-blocking (only under strict rules) |
| `REVIEW_REQUIRED` | `fail` | **blocking** |

Mandatory rules, enforced and guard-tested:

- **SKIPPED never maps to PASS.** Missing evidence and missing/undeterminable
  verification are SKIPPED (blocking), never green.
- **Missing command execution never maps to PASS.** `--skip-commands` records
  `commands_skipped=true`, `full_ga_evaluation_complete=false`, and can never
  yield `GA_READY`; empty command results are not a pass.
- **BLOCKED** = a known control that is not implemented (declared until its
  resolution condition is met). **FAIL** = a control whose verification ran and
  failed. **REVIEW_REQUIRED** = a human/organizational sign-off that is not yet
  recorded through a supported mechanism.
- **NOT_APPLICABLE is tightly restricted:** permitted only when the registry
  entry sets `allow_not_applicable=true` **and** a scope justification is
  present. No v1 entry opts in, so critical controls (identity, RBAC, audit
  integrity, migration safety, backup/restore, client approval, production
  database/queue) can never be dismissed as N/A.

## No-waiver policy (v1)

No waiver can resolve a blocker in this version. No environment variable, no
static configured actor, and no unsigned file may satisfy a blocker. Verified
per-user identity and signature verification do not exist yet, so a waiver path
would only create another false-ready route. A future schema version may add
signed, expiring, authenticated-approver waivers — deferred until authenticated
identity and signature verification exist.

## Hardened checks

- **Official export gate:** no longer passes because a gating method is
  callable; the provenance-enforcing gate is unimplemented, so it is `BLOCKED`.
- **Demo seed removal:** no longer depends on an audit action the store never
  emits; detection now uses stable tenant/user identity markers.
- **Parser coverage:** requires the promoted FORGE evaluation evidence (report
  present, 65/65 required, committed manifest/expectations SHA-256 match), not
  an environment flag. A missing report is `SKIPPED`; a stale/mismatched
  manifest is `FAIL`.
- **Audit trail:** basic non-empty logging can pass its narrow readiness check,
  but keyed integrity and tail-truncation detection are registered as separate
  `BLOCKED` security-review controls; basic logging is never presented as
  enterprise tamper evidence.
- **Local AI:** runtime reachability stays a narrow check; the Phase 06
  output-validation / provenance / isolation trust boundary is a separate
  `BLOCKED` control.

## Evidence contract

`output/ga-readiness/Monday_Report_GA_READINESS.json` records
`schema_version`, `git_commit`, `git_tree`, `worktree_clean`,
`registry_version`, `registry_sha256`, `command`, `command_arguments`,
`commands_skipped`, `command_results`, `readiness_checks` (the registry-backed
GA checks), `blocker_counts`, `top_level_status`, and `payload_sha256`.

- **Canonical hash:** `payload_sha256 = SHA256(canonical_json(payload without
  payload_sha256))`, where canonical JSON is UTF-8, sorted keys, `(",",":")`
  separators, no ASCII escaping. The guard recomputes and verifies it; the hash
  field is excluded from its own input.
- **Git binding:** the exact commit and tree SHAs and whether the worktree was
  clean. A dirty worktree may produce diagnostic evidence but never `GA_READY`.
  Release-candidate commits (not yet on `main`) may be evaluated.
- **Path redaction:** absolute paths, usernames, machine names, and temp
  directories are redacted, and a fail-closed scan refuses to write evidence
  containing any machine-specific path.

## GA decision logic

The top-level `GA_READY` / `GA_BLOCKED` string is preserved for consumers.
`GA_READY` requires all of: client mode; registry/check parity; every check
`PASS` (or a strictly permitted, justified `NOT_APPLICABLE`); no `FAIL`,
`BLOCKED`, `SKIPPED`, or `REVIEW_REQUIRED`; the software commands actually ran
and passed; a clean git commit/tree binding; and a verifiable evidence hash.
No readiness status depends only on the absence of a check — the registry
enumerates all known blockers, so an unimplemented control keeps GA red.

Because verified approval identity does not exist, the client-organizational
approval blocker is `REVIEW_REQUIRED`, and many software/security controls are
`BLOCKED`. **The repository remains `GA_BLOCKED` after this change — even if
PostgreSQL and Redis are provisioned** — until those controls are resolved by
separate approved pull requests.

## Current unresolved blockers (truthful)

The gate now reports a truthful, non-zero count across categories (software,
security_review, infrastructure, configuration, data_review_evidence,
client_approval). The registry lists each with its resolution condition; see
`evals/ga/blocker_registry.v1.json`.

## Limitations and future resolution order

This increment makes the **gate** truthful; it does **not** implement the
underlying controls. The recommended resolution order is: per-user identity +
RBAC + tenant authorization (unblocks verified reviewer identity), keyed audit
integrity + tail-truncation detection, persistence/migration safety +
cross-process atomicity (Phase 04), CI + dependency scanning, structured
logging + metrics + worker heartbeat, backup/restore, formatted export
provenance, Phase 06 trust boundary, external malware scanner, and finally the
client/organizational approval mechanism. GA is not claimed; the expected
result is a more truthful `GA_BLOCKED`.
