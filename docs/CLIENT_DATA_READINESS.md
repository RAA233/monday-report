# Client Data Readiness

Monday Report must not ingest real client packages until the live `/readiness/client-data` endpoint reports `ready`.

## Required Local Services

Use the checked-in compose file for a local approval environment:

```powershell
docker compose -f docker-compose.client.yml up -d
python -m pip install -r requirements-client.txt
```

PostgreSQL is exposed at `127.0.0.1:55432`; Redis is exposed at `127.0.0.1:56379`.

If Docker Hub image pulls are unavailable but equivalent local images exist, override image names before starting services:

```powershell
$env:MONDAY_REPORT_POSTGRES_IMAGE="dd-postgres:2.42.0-pilot.local-2026-05-11"
$env:MONDAY_REPORT_REDIS_IMAGE="redis:7.2.4-alpine"
docker compose -f docker-compose.client.yml up -d
```

## Required Environment

Use protected paths outside the repository for state, uploads, and exports. Set real secrets, not the examples below:

To generate a local env file with non-committed secrets and protected local paths:

```powershell
pnpm run ga:env
```

The generated file is written to `output/ga-readiness/monday_report_ga.env`. Keep it local; it contains secrets and is ignored by Git.

```powershell
$env:MONDAY_REPORT_CLIENT_DATA_MODE="client"
$env:MONDAY_REPORT_REPOSITORY_BACKEND="postgres"
$env:DATABASE_URL="postgresql://monday_report:monday_report_local_only@127.0.0.1:55432/monday_report"
$env:MONDAY_REPORT_QUEUE_BACKEND="redis"
$env:REDIS_URL="redis://127.0.0.1:56379/0"
$env:MONDAY_REPORT_TENANT_NAME="<client tenant name>"
$env:MONDAY_REPORT_TENANT_SLUG="<client-tenant-slug>"
$env:MONDAY_REPORT_USER_EMAIL="<reviewer email>"
$env:MONDAY_REPORT_USER_FULL_NAME="<reviewer name>"
$env:MONDAY_REPORT_STATE_PATH="$env:LOCALAPPDATA\MondayReport\state\state.json"
$env:MONDAY_REPORT_STORAGE_ROOT="$env:LOCALAPPDATA\MondayReport\storage"
$env:MONDAY_REPORT_EXPORT_ROOT="$env:LOCALAPPDATA\MondayReport\exports"
$env:MONDAY_REPORT_API_KEY="<24+ random chars>"
$env:VITE_MONDAY_REPORT_API_KEY=$env:MONDAY_REPORT_API_KEY
$env:MONDAY_REPORT_SIGNING_SECRET="<32+ random chars>"
$env:MONDAY_REPORT_MALWARE_SCANNER="builtin"
$env:MONDAY_REPORT_PRODUCTION_PARSERS="true"
$env:MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST="<reviewed anonymized client fixture manifest>"
$env:MONDAY_REPORT_PARSER_EVAL_REPORT="<passing parser/OCR eval report>"
```

Startup creates only a neutral workspace. Failure records must come from uploaded evidence or explicit fixture/eval commands.

## Fixture Evidence

For a local readiness smoke, generate the 13-family anonymized engineering fixture pack and parser/OCR report:

```powershell
pnpm run fixtures:anonymized
$env:MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST="$PWD\output\golden-fixtures\anonymized\golden-fixture-manifest.json"
$env:MONDAY_REPORT_OCR_ENGINE="tesseract"
$env:MONDAY_REPORT_TESSERACT_CMD="python $PWD\output\golden-fixtures\anonymized\tools\fake_tesseract.py"
python scripts\generate_parser_fixture_eval_report.py --manifest $env:MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST --output output\parser-evals\parser_fixture_eval_report.json
$env:MONDAY_REPORT_PARSER_EVAL_REPORT="$PWD\output\parser-evals\parser_fixture_eval_report.json"
```

Generated fixtures prove only local parser coverage. For a reviewed local approval run, regenerate the same fixture set with an explicit review attestation:

```powershell
python scripts\build_anonymized_fixture_pack.py --reviewed-by "RAA local client-readiness review"
```

Production client intake should replace these generated fixtures with a reviewed anonymized client fixture manifest carrying this top-level attestation:

```json
{
  "attestation": {
    "classification": "reviewed_anonymized_client_fixture",
    "review_status": "approved",
    "reviewed_by": "Client Fixture Review Board",
    "reviewed_at": "2026-07-12T00:00:00Z",
    "contains_client_confidential_data": false
  }
}
```

After replacing the generated pack, run a new parser/OCR eval report from that reviewed fixture set.

## Approval Command

Run the non-strict GA evidence command at any time to classify remaining blockers:

```powershell
pnpm run audit:ga-readiness
```

Run strict GA readiness after starting the API and applying the client-mode environment:

```powershell
pnpm run ga:readiness
```

`ga:readiness` is a truthful, registry-backed gate (see `docs/GA_READINESS_INTEGRITY.md`). It emits one check per entry in `evals/ga/blocker_registry.v1.json`, each with an explicit disposition (`PASS`/`FAIL`/`BLOCKED`/`SKIPPED`/`NOT_APPLICABLE`/`REVIEW_REQUIRED`) mapped onto the legacy `pass`/`warn`/`fail` status. `SKIPPED`, missing evidence, and missing/empty command execution never count as pass; `--skip-commands` can never yield `GA_READY`; evidence is bound to a clean git commit/tree with a canonical `payload_sha256`. A known-but-unimplemented control (RBAC, keyed audit integrity, migration runner, CI, backup/restore, client approval, etc.) is a declared `BLOCKED`/`REVIEW_REQUIRED` entry, so blocker counts are truthful and the gate stays `GA_BLOCKED` even with PostgreSQL and Redis provisioned. No waiver, environment variable, static configured actor, or unsigned file can resolve a blocker in this version.

Run the final client-data approval command after strict readiness is green:

```powershell
pnpm run package:client-approval
```

The approval command writes `output/client-data/Monday_Report_Client_Data_APPROVAL.md` and `.json`. A `BLOCKED` result is expected until every readiness check passes.

## Authenticated identity (foundation)

An authenticated-identity foundation (`docs/AUTHENTICATED_IDENTITY.md`,
`audit:identity-rbac`) resolves opaque per-user credentials server-side to a
request-scoped identity with default-deny RBAC on the existing roles, admin-only
provisioning/revocation, and a configured-tenant boundary. In **demo/local
mode** the shared key maps to a labelled `demo_bootstrap` administrator (existing
clients keep working); in **client mode** a resolvable credential is required and
the shared key is only a `demo_bootstrap` compatibility credential — never a
per-user identity and never a superuser bypass. This foundation **closes no GA
blocker**: `per-user-identity`, `rbac-role-separation`,
`tenant-authorization-enforcement`, and `verified-reviewer-identity` remain
declared blockers and `ga:readiness` stays `GA_BLOCKED` until resolved by
separate approved pull requests. (`verified-reviewer-identity` is since
**delivered for correction/validation outcomes** — server-derived,
permission-eligible reviewer with client fail-closed; evidence-driven
`ga_verified_reviewer_identity` — see `docs/VERIFIED_REVIEWER_ATTRIBUTION.md`;
GA stays `GA_BLOCKED` on the remaining controls.)

## Route-level RBAC (enforcement)

Built on that foundation, route-level RBAC (`docs/ROUTE_RBAC.md`,
`audit:route-rbac`) makes `backend/app/permissions.py` the single authorization
authority: 23 stable permissions and a conservative role→permission matrix (the
legacy `VIEWER` role stays unactivated) gate **every privileged read and every
mutation**. A classified route inventory (`ROUTE_ACCESS_POLICY`) covers all 48
routes; `route_policy_fully_enforced()` proves each `permission_required` route
carries its declared guard; the two download routes are public
**signed-capability** endpoints (resource-bound, expiring, GET-only, token
verified **first**); permission is checked **before** any resource lookup (no
existence leak). The **detailed** `/readiness/client-data` report (blocker ids,
dispositions, remediation, mode, paths) is `permission_required("view_runtime_
status")` — only minimal `/health` is public — and readiness detail no longer
embeds absolute paths. Every denial writes a redacted audit event
(permission/route/method). This is **route-level** authorization only — it does
**not** implement multi-tenant resource authorization, verified reviewer workflow,
or keyed audit integrity. The `rbac-role-separation` GA control is now
**evidence-driven PASS** (its resolution condition is met; the blocker registry is
unchanged, only the evaluator probe became evidence-based); the separate per-user
identity deployment, tenant-authorization, verified-reviewer, and audit-integrity
controls remain BLOCKED, so `ga:readiness` stays `GA_BLOCKED`.

## Tenant resource authorization (API layer)

A further increment (`docs/TENANT_AUTHORIZATION.md`, `audit:tenant-authorization`)
closes an API-layer IDOR gap: after the permission gate, every resource route
compares the looked-up resource's `tenant_id` to the tenant resolved from the
authenticated request, hiding cross-tenant resources behind an existence-hiding
404; lists/aggregates are tenant-filtered; and signed capabilities bind the owning
tenant. The `tenant-authorization-enforcement` GA control stays **BLOCKED** with an
evidence-driven probe (the API-layer half is implemented; its resolution also
requires **Postgres RLS** over the normalized store, which is out of scope), so
`ga:readiness` stays `GA_BLOCKED` and the blocker registry is not weakened.

## Audit-chain integrity (versioned HMAC)

A versioned, keyed HMAC-SHA256 audit foundation (`docs/AUDIT_INTEGRITY.md`,
`audit:audit-keyed-integrity`) replaces the forgeable unkeyed SHA-256 chain: v2
events are sealed with a managed key (id + version, rotation-aware), verification
selects each event's recorded key, legacy events are never re-signed or presented
as keyed, and in **client mode a request write fails closed (503) without a valid
key** and never writes an unkeyed event. `audit-keyed-integrity` becomes
PASS-capable only on runtime evidence (a v2 event round-trips under HMAC and a
public-SHA forgery of the same payload is rejected). This increment adds **no
external anchor**, so `audit-tail-truncation-detection` stays **BLOCKED**,
`ga:readiness` stays `GA_BLOCKED`, and the blocker registry is unchanged.
