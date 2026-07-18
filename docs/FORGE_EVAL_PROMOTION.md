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

## Current status: PROMOTED — real corpus-backed result 65/65 required

The evaluation set first ran as a blocked baseline: the initial real-corpus
run recorded 11 required failures across four extraction defects (D1
well-name bracket truncation, D2 casing rows fabricated from bit/pipe/BHA/
tripping narrative including inch-fraction sizes misread as OD, D3 a
dot-thousands survey depth read as 9.5 ft instead of 9,524 ft with the `AZM`
azimuth dropped, D4 daily completion reports classified
`daily_drilling_report` instead of the generic `pdf_report`).

A separate parser-fix PR then resolved D1–D4 with **general parser rules
only** — no FORGE filename or document-ID special case, and the committed
manifest and expectations were **not modified** (byte-identical SHA-256
before and after):

- **D1**: the well-name capture accepts bracketed pad codes, `#`, and `&`,
  stops before an adjacent same-line `Label:` boundary, and trims only
  demonstrably unmatched trailing delimiters (balanced bracket suffixes are
  preserved byte-correct).
- **D2**: casing rows now require positive casing context (casing/liner
  label, noun adjacency, casing verbs, shoe/set association, or
  planned/proposed casing wording); bit, PDC, nozzle, drill-pipe, HWDP, BHA,
  hole-opener, pipe-handling, and casing-readiness narrative is rejected;
  mixed-fraction diameters parse as complete sizes (`12 1/4"` → 12.25 in,
  `9 5/8"` → 9.625 in) and a fraction denominator can never re-match as a
  standalone diameter; depths become shoe depths only with explicit
  shoe/set/landed/planned association or casing-labelled context.
- **D3**: `AZM`/`AZ` azimuth labels and table headers parse explicitly; a
  dot-grouped labelled MD token is promoted to a thousands reading only with
  same-record corroboration — an explicitly foot-marked MD paired with a
  same-record feet-basis TVD that the decimal reading would impossibly
  undercut (the inline path additionally requires an explicit TVD foot
  marker); ambiguous multi-dot tokens are skipped, never guessed and never
  crash extraction; legitimate decimal depths, inclination, azimuth, and DLS
  values are never reinterpreted, and no global MD/TVD conflict rule exists
  (different-datum reports stay untouched).
- **D4**: completion detection uses positive heading evidence in the
  first-page header region only; explicit DDR headings always win, the veto
  applies only to the generic marker-score fallback, incidental completion
  narrative never downgrades a drilling report, and filenames are never
  consulted.

The rerun corpus-backed evaluation now passes **65/65 required checks**
(5/5 documents through the real upload → worker → profile → draft pipeline,
zero required failures, recommendation/Benchmarking isolation clean, demo
state untouched). The two informational checks (report-number capture under
the `RPT NUM` label) remain non-required, unchanged, and still failing as
documented future scope — they do not gate promotion.

These general rules are permanently pinned by the portable
`audit:parser-regression` guard (wired into `audit:all`), which encodes one
synthetic regression vector per failed FORGE expectation class plus general
positive/negative vectors, so the defect classes stay CI-visible on machines
without the corpus.

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
