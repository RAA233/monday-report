# Hydraulics Observation Extraction Specification

Parser: `deterministic_hydraulics` · Version: `v1` · Module: `backend/app/store.py`
(`_extract_hydraulics_observations`) · Guard: `pnpm run audit:hydraulics-extraction`

> **Boundary statement.** Hydraulics observations are **source extraction only** —
> informational, review-required drafting evidence. They perform **no hydraulic
> calculation** (no ECD derivation, pressure-loss, HHP/HSI, surge/swab, nozzle TFA, pump
> or hole-cleaning optimization) and **never create, trigger, clear, or reprioritize**
> the recommended-only Hydraulics / Torque & Drag `DiagnosticAction`s, nor populate any
> Benchmarking measurement or threshold. Extracted values are non-authoritative and must
> be reviewed against source evidence before any engineering use.

## Supported measurements and canonical units

| Measurement | Labels recognized | Canonical unit | Explicit conversions |
|---|---|---|---|
| `flow_rate` | flow rate, flow, pump output | `gpm` | L/min ÷ 3.785411784 |
| `standpipe_pressure` | standpipe pressure, SPP | `psi` | kPa × 0.1450377377 |
| `mud_weight` | mud weight/wt/density, MW | `ppg` | sg × 8.345404452 |
| `ecd` | ECD, equivalent circulating density | `ppg` | sg × 8.345404452 |
| `plastic_viscosity` | plastic viscosity, PV | `cP` | — |
| `yield_point` | yield point, YP | `lbf/100ft2` | — |
| `pump_rate` | pump rate/speed, strokes | `spm` | — |
| `nozzle_configuration` | nozzles, nozzle configuration | text-only | none — verbatim text; no numeric value, TFA, or inferred count/sizes |

**Explicit units only.** A value is emitted only when an explicitly labelled measurement
carries an explicitly recognized unit (nozzle configuration excepted, as text). Unitless
or ambiguous values — e.g. bare `MW 1.15` — are never converted, guessed, or emitted.
Every observation retains the verbatim `source_value_text` and `source_unit` beside the
normalized canonical value.

## Observation contract

Each observation carries: `measurement`, `value`/`unit` (canonical), `source_value_text`,
`source_unit`, `observation_status` (`observed` / `planned` / `unknown` — set only from
explicit source wording, never inferred), `equipment_label` (e.g. `Pump 2`),
`fluid_system_label` (e.g. `kill mud`), `context_note`, `activity_time` (normalized
`HH:MM` only when explicit and unambiguous) plus `activity_time_source_text` (verbatim),
`parser_method="deterministic_hydraulics"`, `parser_version="v1"`, `source="source"`,
`page`, `confidence`, `conflict`, `review_flag`, `review_reason`. Time is never inferred
(no timezone, date, AM/PM, or report-day association) and a missing or ambiguous time
never drops an otherwise valid observation.

## Validation and review flags

Rejected (never emitted): malformed numbers, NaN/infinity, missing/ambiguous units, and
structurally impossible negative values. There are **no engineering sanity ranges** —
finite source observations are never discarded for looking unusual. Structurally valid
but out-of-band values (documented order-of-magnitude review bands, e.g. SPP > 10,000
psi) are retained with `review_flag=true` and
`review_reason="source value requires review"` — a review prompt, not an
acceptable/unsafe judgement.

## Context-aware conflicts

The conflict key is (`measurement`, `activity_time`, `observation_status`,
`equipment_label`, `fluid_system_label`). Distinct values within the same key are all
flagged `conflict=true` with confidence clamped ≤ 0.5 — never merged or discarded.
Pump 1 vs Pump 2, active vs kill mud, and planned vs observed values are different
contexts and **never** conflict merely because their values differ.

## Behavior

Narrative lines (multiple labelled measurements per line supported) and tables with
recognized headers (units taken from the header, e.g. `Flow (gpm)`, time column
honored) both parse; exact repeats dedupe; deterministic ordering
(measurement, time, page); 100-row cap with recorded truncation; unsupported input
yields no rows; repeated extraction is byte-identical. Observations become page-cited
`hydraulic_observation` evidence chunks, flow through the shared
`hydraulics_rows_from_profiles` builder into both the Report Draft and
`morning_report.hydraulics_observations` (always identical), and surface in the Report
Studio "Hydraulics observations" table. No source evidence yields exactly
`hydraulics_observations = []` with `hydraulics_source = "none"` and the UI state
"No source hydraulics observations — confirm or enter from DDR" — there is no fallback.
The legacy scalar `mud_weight` draft field is unchanged.
