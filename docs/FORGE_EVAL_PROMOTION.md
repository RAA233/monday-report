# FORGE Corpus Evaluation Promotion

This document defines the reviewed FORGE ground-truth evaluation set, its
licensing posture, its promotion semantics, and its honest current status.

## Corpus source and local convention

- **Source**: daily drilling and completion reports for Utah FORGE well
  16A(78)-32 (a publicly funded geothermal research well). The corpus is
  obtained separately by each operator of this repository.
- **Local convention**: the raw corpus lives in a `16A(78)-32_Daily_Reports/`
  directory at the repository root, with `drilling/` and `completion/`
  subdirectories. The directory is git-ignored (`*_Daily_Reports/`). The
  location can be overridden with `MONDAY_REPORT_FORGE_CORPUS_ROOT`.
- **Contents observed locally**: 184 single-page PDFs (163 drilling,
  22 completion) plus one spreadsheet. No multi-page report exists in the
  corpus, so the multi-page selection axis is recorded as not available.

## Licensing and attribution

The local corpus folder contains **no license, notice, README, source-URL, or
attribution file**. Redistribution permission therefore **cannot be confirmed
locally**, and this repository does not assert that redistribution is
permitted. Consequences, applied deliberately:

- Raw PDFs remain local and untracked; none are committed.
- No page images, logos, or long report prose are committed.
- Committed evaluation files carry only minimal technical facts needed for
  ground-truth checking: the well and rig identifiers, numeric depths,
  pressures, angles, counts, section-marker booleans, and SHA-256 hashes.
- Personnel names and phone numbers that appear on report pages are excluded.
- This unresolved licensing limitation stands until an authoritative license
  or usage statement for the report files is confirmed and recorded here.

## Selection method

`evals/forge/manifest.v1.json` pins a **fixed, reviewed, stratified selection**
(`selection_method: reviewed_stratified_fixed_set`) of five documents chosen
for extractor coverage — not the first N files alphabetically:

| document_id | family | variant | why |
| --- | --- | --- | --- |
| forge-drilling-early | drilling | surface-hole-table-heavy | tables, bare-unit mud values, casing no-fabrication |
| forge-drilling-coring | drilling | coring-narrative-heavy | narrative, positive explicit-unit hydraulics target |
| forge-drilling-late | drilling | tangent-drilling-labeled-survey | positive survey target, separate MD/TVD scalars |
| forge-completion-early | completion | completion-wash-ream | completion template, classification, time log |
| forge-completion-late | completion | completion-rig-release-final | final-report template, laydown narrative stress |

Every document is pinned by corpus-relative path (no absolute paths, drive
letters, usernames, or machine names), full SHA-256, and page count. Changing
the selection requires editing and re-reviewing the committed manifest;
`scripts/build_forge_eval_manifest.py` verifies the committed selection against
the local corpus and never regenerates it.

## Expectations format

`evals/forge/expectations.v1.json` holds manually reviewed ground truth. Each
check carries: document id + SHA, page, extractor, stable check id, a narrow
check type (`equals`, `approximately_equals`, `contains_row`, `row_count`,
`absent`, `source_state`, `evidence_present`), expected value or explicit
absence, units and tolerances for numeric checks, a `required` flag, and
review metadata (`review_status`, `reviewed_source_page`, `review_note`).
No executable expressions are allowed. Optional (informational) checks are
explicitly marked `required: false` and can never mask a required failure.

Expected values state what is **true on the page** within documented v1
extractor scope. Where the page contains data outside that scope (split table
cells, bare-unit values, unlabeled narrative surveys), the reviewed ground
truth is an explicit **absence** check proving no row was fabricated. Reviewed
ground truth is never rewritten to match incorrect extractor output.

## Evaluation method

Two distinct gates:

1. **`pnpm run audit:forge-eval-spec`** (portable, wired into `audit:all`):
   validates manifest/expectations schemas, unique IDs, SHA formats, page
   ranges, check types, tolerances, bidirectional coverage, absence of
   absolute paths / copied prose / secrets, and proves the validator rejects
   malformed specs and that optional checks cannot mask required failures.
   Runs without the corpus; a failure here is a real software failure.
2. **`pnpm run audit:forge-evals`** (corpus-backed): verifies pinned hashes
   and page counts, then pushes each real PDF through the supported upload
   route into an isolated temporary workspace, runs the real worker entry
   point (`backend.app.worker.run_once`), reads the resulting parser profile
   and report-draft API response, and evaluates every reviewed expectation.
   It also proves recommendation/Benchmarking isolation (no failure records,
   validation tasks, anomaly events, reports, or benchmark measurements are
   created) and that user demo state is untouched. It emits
   `output/forge-evals/forge_eval_report.json` (generated, git-ignored, free
   of absolute paths).

### Skip semantics

When the corpus is absent, `audit:forge-evals` reports **SKIPPED** — never
PASS. A skipped run is not a completed FORGE evaluation and cannot mark
promotion complete. `audit:all` includes only the portable spec gate, so a
green `audit:all` never implies corpus-backed promotion.

### Promotion semantics

Promotion is complete only when the spec gate passes, every pinned hash
matches, every selected document is processed through the real pipeline,
**every required reviewed expectation passes**, no recommendation or
Benchmarking state changes, and the generated report records zero failed
required checks. Exact pass semantics — no aggregate accuracy threshold.

## Current status: promotion BLOCKED by recorded parser defects

The evaluation set is authored and the corpus-backed run executes end-to-end
(5/5 documents through upload → worker → profile → draft). The reviewed
ground truth currently records **11 required failures across four known
extraction defects**, so promotion is honestly blocked pending a separate
parser-fix PR (parser behavior is deliberately unchanged in the
evaluation-promotion increment):

- **D1 — well-name truncation** (5 docs): the scalar capture stops before
  `[`, extracting `FORGE 16A` instead of the page value `FORGE 16A [78]-32`.
- **D2 — casing narrative overmatch** (3 docs): operational narrative is
  misread as casing strings, including inch-fraction bit/pipe sizes misread
  as casing OD (`12 1/4"` bit → `4 in`; `3 1/2"` drill pipe → `2 in`) and
  tripping depths misread as shoe depths.
- **D3 — labeled-survey misparse** (1 doc): a dot-thousands survey depth is
  read as a decimal (9.5 ft instead of 9,524 ft) and the `AZM` azimuth value
  is dropped.
- **D4 — completion misclassification** (2 docs): daily completion reports
  are affirmatively classified `daily_drilling_report` although the generic
  `pdf_report` class is the correct in-taxonomy answer.

54 of 65 required checks pass, covering scalar fields, the positive
explicit-unit hydraulics observation (standpipe pressure 2,770 psi with page
provenance), survey row-count and evidence, honest absences (timeline,
surveys, hydraulics, report number, completion TVD), draft source states, and
isolation. Two informational checks (report-number capture under the `RPT
NUM` label) are marked non-required and fail as documented future scope.

Fixing D1–D4 must happen in a separate parser-fix PR; the expectations stay
as reviewed ground truth and the evaluation is rerun after the fix.

## Reproducibility

Deterministic inputs (SHA-pinned PDFs), deterministic extraction, exact or
toleranced comparisons, and isolated temporary state make repeated runs
produce equivalent results. The report embeds the SHA-256 of the committed
manifest and expectations files it evaluated.

## Limitations

- Ground truth covers page 1 of five single-page documents — meaningful
  extractor coverage, not corpus-wide accuracy measurement.
- Licensing for the report files is unconfirmed locally (see above).
- The evaluation asserts deterministic v1 extractor scope; it does not
  evaluate OCR, local-AI extraction, or multi-page behavior.

## Not a client-readiness substitute

FORGE evaluation evidence does **not** replace anonymized-client readiness
evidence, the client-data readiness gate, GA readiness, or any client or
production approval process. It is extraction-quality evidence only.
