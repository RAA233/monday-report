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

Run the final client-data approval command after strict readiness is green:

```powershell
pnpm run package:client-approval
```

The approval command writes `output/client-data/Monday_Report_Client_Data_APPROVAL.md` and `.json`. A `BLOCKED` result is expected until every readiness check passes.
