# Trajectory Calculation Specification — Minimum Curvature

Method: `minimum_curvature` · Version: `v1` · Module: `backend/app/trajectory.py` · Guard: `pnpm run audit:trajectory-calculation`

> **Engineering-review disclaimer.** This is a deterministic drafting aid, **not certified
> directional-survey software**. Every calculated value is emitted with
> `source = "calculated"` and `review_state = "review_required"` and must be reviewed by a
> qualified drilling engineer against the operator's survey-management system before any
> client-facing use. No survey-quality certification, anti-collision, magnetic/grid
> correction, or vertical-section computation is provided.

## Inputs

Ordered source survey stations produced by the source-only extractor
(`SurveyStation`): `measured_depth_ft` (ft), `inclination_deg` (degrees), `azimuth_deg`
(degrees), optional source `true_vertical_depth_ft` / `north_south_ft` / `east_west_ft`
(ft), `station_id`, `survey_type`, `page`, `confidence`, `conflict`.

- **Units:** feet and degrees at every module boundary. Degrees are converted to radians
  only inside the module; all trigonometry is radian-based.
- **Inclination convention:** 0° = vertical, 90° = horizontal; valid range 0–180°.
- **Azimuth convention:** degrees clockwise from North; valid range 0–360°; wrap-around is
  handled through `cos(A2 − A1)` (359° → 1° is a 2° change).
- **Sign convention:** North/South positive **north**; East/West positive **east**;
  TVD positive **down** (increasing depth).
- **Station ordering:** ascending measured depth, as guaranteed by the extractor;
  the module still re-validates and skips non-increasing MD.

## Eligibility and segmentation

A station is **calculation-eligible** only when it is not conflict-flagged, has finite
numeric MD ≥ 0, finite inclination in [0, 180], and finite azimuth in [0, 360]. Intervals
are formed only between **consecutive eligible stations of the same normalized survey
type** with strictly increasing MD.

**No bridging.** An ineligible station or ineligible interval **ends the current
segment**; a later eligible station starts a new segment. A synthetic interval is never
computed across a skipped station. Planned and actual stations (and any other explicit
`survey_type` values) are segmented independently and never mixed; stations without a
type are grouped together without inferring a type. Skip reasons are counted separately:
`conflict`, `missing_inclination`, `missing_azimuth`, `invalid_numeric`,
`zero_md_interval`, `decreasing_md`, `survey_type_boundary`, `antipodal_singularity`.

## Formulas (canonical forms)

For an interval between stations 1 and 2 with inclinations `I1, I2` and azimuths
`A1, A2` (radians) and `delta_md_ft = MD2 − MD1 > 0`:

**Dogleg angle** (canonical expression used everywhere):

```
cos(beta) = cos(I1) * cos(I2) + sin(I1) * sin(I2) * cos(A2 - A1)
beta      = acos( clamp(cos(beta), -1.0, 1.0) )
```

**Ratio factor:**

```
RF = (2 / beta) * tan(beta / 2)
```

- **Exact zero dogleg:** when `beta == 0.0` (float equality), `RF = 1`.
- **Near-zero dogleg:** when `0 < |beta| < 1e-6 rad`, the stable Maclaurin series is used:
  `RF = 1 + beta^2 / 12 + beta^4 / 120`. Continuity across the threshold is covered by a
  dedicated test vector (difference below 1e-12).
- **Near-antipodal singularity:** when `pi - beta < 1e-2 rad`, `RF` is ill-conditioned
  (`tan(beta/2) → ∞`). The interval is **not calculated**; it is skipped with reason
  `antipodal_singularity`, ends the segment, and is counted in the skip summary. It is
  never clamped into a plausible-looking trajectory.

**Interval displacements** (ft):

```
delta_tvd_ft = (delta_md_ft / 2) * (cos(I1) + cos(I2)) * RF
delta_ns_ft  = (delta_md_ft / 2) * (sin(I1)*cos(A1) + sin(I2)*cos(A2)) * RF
delta_ew_ft  = (delta_md_ft / 2) * (sin(I1)*sin(A1) + sin(I2)*sin(A2)) * RF
```

**Dogleg severity:**

```
dls_deg_per_100ft = degrees(beta) * 100 / delta_md_ft
```

(The calculated field is named `dls_deg_per_100ft`; the *source-stated* DLS keeps its
existing extractor name `dogleg_severity_dp100ft` — the distinct names reinforce the
source/calculated separation.)

## Numerical policy

- Internal precision: full IEEE-754 float64; no premature rounding.
- Output rounding (serialization only): displacements/positions 2 dp ft; dogleg 4 dp deg;
  DLS 2 dp; ratio factor 6 dp.
- Every emitted number is finite; NaN/±inf inputs skip the station (`invalid_numeric`).
- A calculation error can never surface as an API 500 — ineligible input degrades to
  skips and, when nothing is calculable, to `trajectory_source = "none"`.

## Coordinate anchoring

Anchoring is decided **independently per axis** at the first station of the first
calculated segment (the anchor station):

- Axis has a source value at the anchor station → `source_absolute`; cumulative values
  start from the stated source value.
- No source value → `relative_first_station`; cumulative values start at 0.0 **relative
  to that station** and are never presented as absolute well coordinates.
- No calculated segment at all → `none`.

Mixed references are valid (e.g. absolute TVD with relative N/S–E/W) and are labelled in
the UI. Segments after the first restart accumulation at their own first station under
the same per-axis rule; every calculated station carries its segment index. No surface
origin is ever implied unless the source stated it.

## Provenance and review

- Every interval/station result carries `source = "calculated"`,
  `method = "minimum_curvature"`, `method_version = "v1"`; the calculation summary carries
  `review_state = "review_required"`.
- `input_confidence_min` is the **lowest source-extraction confidence among the input
  stations** — it describes input quality, never the numerical accuracy or certification
  of the formula.
- Input identity is retained: interval start/end MDs, station IDs when available, source
  pages, and survey type.
- **No-overwrite policy:** source station objects are immutable inputs. Source TVD/DLS/
  N-S/E-W are never replaced, reconciled, or back-filled; calculated values live only in
  the structurally separate calculation block, and source/calculated differences are
  displayed side-by-side with the delta for review (no pass/fail engineering tolerance is
  defined in this version).
- Determinism: the pure result contains no timestamps, random values, or environment
  reads; identical inputs produce identical serialized results. Report-level
  `generated_at` is attached outside the pure result by the existing report layer.

## Limitations and non-goals (v1)

No vertical section (requires a reference azimuth the source does not provide); no
interpolation between stations; no anti-collision, target optimization, magnetic/grid
corrections, or survey-quality certification; no Benchmarking auto-population
(`dogleg_severity` measurements remain manual); no formatted-export rendering beyond the
generic JSON export.

## Horizontal displacement (display field)

`horizontal_displacement_ft` on each calculated station is the **unsigned lateral
magnitude from that station's own segment anchor**:
`hypot(ns − segment_anchor_ns, ew − segment_anchor_ew)`. It is result assembly, not a new
minimum-curvature method: the deltas are the already-calculated cumulative N/S–E/W values,
so the segment anchor is exactly 0 ft by construction and **non-zero source-absolute N/E
anchors never leak a global-origin magnitude** (guard-enforced). Sign/direction is
deliberately lost (direction lives in the plan view); it is never an absolute or east/west
position, a vertical section, or a target departure. Each segment (including each
planned/actual sequence) has its own independent anchor.

## Vertical-profile visualization

The Report Studio vertical profile (`src/components/TrajectoryVerticalProfile.tsx`)
renders **one panel per explicit calculation segment** — segments are never overlaid on a
shared TVD axis, so incompatible TVD references cannot be visually compared. Axes:
horizontal = `horizontal_displacement_ft` from the segment anchor (zero at the anchor,
positive right, magnitude only); vertical = calculated TVD in ft **increasing downward**.
Equal ft scale with letterboxing; no interpolation; zero-lateral segments render as a
vertical TVD progression with an explanatory note rather than being suppressed. The
review-required and not-certified labels apply unchanged.

## Plan-view visualization

The Report Studio plan view (`src/components/TrajectoryPlanView.tsx`) is a pure display
of the calculated stations above — it performs **no additional calculation or
interpolation**. It renders one path per calculation segment (never bridging skipped
stations or survey-type boundaries), uses equal ft scale with north up and east right,
labels relative coordinates explicitly, and suppresses the plot only when the lateral
extent is below the 0.01 ft display precision (an honest degenerate state, not an
engineering threshold). The review-required and not-certified labels apply to the
visualization exactly as they do to the underlying calculation.

## Worked test vectors (enforced by `scripts/trajectory_calculation_guard.py`)

**Primary worked example** (inputs, not just outputs):

```
Station 1: MD 3500 ft, inclination 15°, azimuth 20°
Station 2: MD 3600 ft, inclination 25°, azimuth 45°
```

High-precision expectations (computed independently from the formulas above; the widely
published rounded values 27.22 / 19.45 / 94.01 ft fall inside these tolerances):

```
cos(beta) = cos15°·cos25° + sin15°·sin25°·cos25° = 0.974560   → beta = 0.226053 rad (12.9518°)
RF        = (2/0.226053)·tan(0.113026)            = 1.004290   (±0.0005)
delta_ns  = 50·(sin15°·cos20° + sin25°·cos45°)·RF = 27.219 ft  (±0.05)
delta_ew  = 50·(sin15°·sin20° + sin25°·sin45°)·RF = 19.451 ft  (±0.05)
delta_tvd = 50·(cos15° + cos25°)·RF               = 94.013 ft  (±0.05)
dls       = 12.9518 °/100 ft                       (±0.01)
```

Additional enforced vectors: vertical well; constant inclination/azimuth; exact zero
dogleg; near-zero below/above the 1e-6 rad series threshold plus continuity across it;
azimuth wrap 359°→1°; true 180° azimuth separation at moderate inclination (β = 60°);
near-antipodal safe failure; zero MD interval; decreasing MD; missing
inclination/azimuth; NaN/inf inputs; same-MD conflict; conflict and missing-angle
stations between valid stations (no bridging); interleaved planned/actual separation;
source-TVD anchor; relative anchor; mixed anchors; source N/E anchors; source-vs-
calculated disagreement without overwrite; repeat-call determinism; 200-station bounded
set; empty input; single station; all-ineligible input; all-outputs-finite sweep.
