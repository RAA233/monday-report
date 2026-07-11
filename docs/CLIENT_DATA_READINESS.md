# Client Data Readiness

Monday Report must not ingest real client packages until the live `/readiness/client-data` endpoint reports `ready`.

## Required Local Services

Use the checked-in compose file for a local approval environment:

```powershell
docker compose -f docker-compose.client.yml up -d
python -m pip install -r requirements-client.txt
```

PostgreSQL is exposed at `127.0.0.1:55432`; Redis is exposed at `127.0.0.1:56379`.

## Required Environment

Use protected paths outside the repository for state, uploads, and exports. Set real secrets, not the examples below:

```powershell
$env:MONDAY_REPORT_CLIENT_DATA_MODE="client"
$env:MONDAY_REPORT_REPOSITORY_BACKEND="postgres"
$env:DATABASE_URL="postgresql://monday_report:monday_report_local_only@127.0.0.1:55432/monday_report"
$env:MONDAY_REPORT_QUEUE_BACKEND="redis"
$env:REDIS_URL="redis://127.0.0.1:56379/0"
$env:MONDAY_REPORT_DISABLE_DEMO_SEED="true"
$env:MONDAY_REPORT_STATE_PATH="$env:LOCALAPPDATA\MondayReport\state\state.json"
$env:MONDAY_REPORT_STORAGE_ROOT="$env:LOCALAPPDATA\MondayReport\storage"
$env:MONDAY_REPORT_EXPORT_ROOT="$env:LOCALAPPDATA\MondayReport\exports"
$env:MONDAY_REPORT_API_KEY="<24+ random chars>"
$env:MONDAY_REPORT_SIGNING_SECRET="<32+ random chars>"
$env:MONDAY_REPORT_MALWARE_SCANNER="builtin"
$env:MONDAY_REPORT_PRODUCTION_PARSERS="true"
$env:MONDAY_REPORT_GOLDEN_FIXTURE_MANIFEST="<anonymized client fixture manifest>"
$env:MONDAY_REPORT_PARSER_EVAL_REPORT="<passing parser/OCR eval report>"
```

## Approval Command

Run this after starting the API:

```powershell
pnpm run package:client-approval
```

The command writes `output/client-data/Monday_Report_Client_Data_APPROVAL.md` and `.json`. A `BLOCKED` result is expected until every readiness check passes.
