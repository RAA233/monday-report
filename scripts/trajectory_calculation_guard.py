"""Behavioral guard for the pure minimum-curvature trajectory module.

Enforces the worked test vectors and numerical policy documented in
docs/TRAJECTORY_CALCULATION.md against backend/app/trajectory.py. Pure-module
coverage only; report-draft/JSON integration is covered by report_draft_guard
and pdf_parser_guard.
"""
from __future__ import annotations

import copy
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.trajectory import (  # noqa: E402
    ANTIPODAL_TOLERANCE_RAD,
    METHOD,
    METHOD_VERSION,
    ZERO_DOGLEG_SERIES_THRESHOLD_RAD,
    calculate_minimum_curvature_interval,
    calculate_trajectory,
    dogleg_angle_rad,
    ratio_factor,
)


def station(md, inc=None, azi=None, **extra):
    row = {"measured_depth_ft": md, "inclination_deg": inc, "azimuth_deg": azi}
    row.update(extra)
    return row


def walk_numbers(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from walk_numbers(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_numbers(item)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield float(value)


def main() -> int:
    checks: list[dict[str, object]] = []

    def check(name: str, ok: bool, detail: object) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # --- Primary worked example (full inputs; high-precision expectations) ---
    worked = calculate_minimum_curvature_interval(3500.0, 15.0, 20.0, 3600.0, 25.0, 45.0)
    check(
        "Worked example (MD 3500/15/20 -> 3600/25/45) matches published minimum-curvature results",
        worked is not None
        and abs(worked["dogleg_rad"] - 0.226053) < 1e-3
        and abs(worked["ratio_factor"] - 1.004290) < 5e-4
        and abs(worked["delta_ns_ft"] - 27.219) < 0.05
        and abs(worked["delta_ew_ft"] - 19.451) < 0.05
        and abs(worked["delta_tvd_ft"] - 94.013) < 0.05
        and abs(worked["dls_deg_per_100ft"] - 12.9518) < 0.02,
        worked,
    )

    # --- 1. Vertical well ---
    vertical = calculate_trajectory([station(0, 0, 0), station(1000, 0, 0), station(2000, 0, 0)])
    check(
        "Vertical well: delta TVD equals delta MD with zero N/E and zero DLS",
        vertical["interval_count"] == 2
        and all(item["delta_tvd_ft"] == 1000.0 for item in vertical["intervals"])
        and all(item["delta_ns_ft"] == 0.0 and item["delta_ew_ft"] == 0.0 for item in vertical["intervals"])
        and all(item["dls_deg_per_100ft"] == 0.0 for item in vertical["intervals"])
        and [item["tvd_ft"] for item in vertical["stations"]] == [0.0, 1000.0, 2000.0],
        vertical["intervals"],
    )

    # --- 2. Constant inclination/azimuth (balanced-tangential equality) ---
    constant = calculate_trajectory([station(1000, 30, 60), station(1500, 30, 60)])
    interval = constant["intervals"][0] if constant["intervals"] else {}
    check(
        "Constant angle: RF=1 and displacements match tangential closed form",
        constant["interval_count"] == 1
        and interval.get("ratio_factor") == 1.0
        and abs(interval.get("delta_tvd_ft", 0) - 433.01) < 0.01
        and abs(interval.get("delta_ns_ft", 0) - 125.0) < 0.01
        and abs(interval.get("delta_ew_ft", 0) - 216.51) < 0.01,
        interval,
    )

    # --- 3-6. Zero and near-zero dogleg policy ---
    check("Exact zero dogleg returns RF exactly 1.0", ratio_factor(0.0) == 1.0, ratio_factor(0.0))
    below = ratio_factor(5e-7)
    check(
        "Near-zero below series threshold is stable and ~1",
        math.isfinite(below) and 1.0 <= below < 1.0 + 1e-9,
        below,
    )
    above = ratio_factor(2e-6)
    check(
        "Near-zero above threshold via closed form is stable and ~1",
        math.isfinite(above) and 1.0 <= above < 1.0 + 1e-9,
        above,
    )
    lo = ratio_factor(0.999e-6)
    hi = ratio_factor(1.001e-6)
    check(
        f"RF continuity across the {ZERO_DOGLEG_SERIES_THRESHOLD_RAD} rad threshold",
        abs(lo - hi) < 1e-12,
        {"below": lo, "above": hi},
    )

    # --- 7. Azimuth wrap 359 -> 1 degrees ---
    wrap = dogleg_angle_rad(10, 359, 10, 1)
    check(
        "Azimuth wrap 359->1 deg is a ~2 deg turn at inclination 10",
        abs(wrap - 0.006063) < 3e-4,
        wrap,
    )

    # --- 8. True 180 deg azimuth separation at moderate inclination ---
    opposed = dogleg_angle_rad(30, 0, 30, 180)
    check(
        "180 deg azimuth separation at 30 deg inclination gives beta = 60 deg",
        abs(opposed - math.pi / 3.0) < 1e-9,
        opposed,
    )

    # --- 9. Near-antipodal singularity fails safely ---
    singular_interval = calculate_minimum_curvature_interval(1000, 90, 0, 1100, 90, 179.9)
    singular_result = calculate_trajectory([station(1000, 90, 0), station(1100, 90, 179.9)])
    check(
        "Near-antipodal interval is skipped, counted, and never produces values",
        singular_interval is None
        and singular_result["interval_count"] == 0
        and singular_result["skips"]["antipodal_singularity"] == 1
        and all(math.isfinite(number) for number in walk_numbers(singular_result)),
        singular_result["skips"],
    )

    # --- 10-11. Zero and decreasing MD intervals ---
    zero_md = calculate_trajectory([station(1000, 10, 100), station(1000, 12, 105)])
    check(
        "Zero MD interval is skipped and never divides by zero",
        zero_md["interval_count"] == 0 and zero_md["skips"]["zero_md_interval"] == 1,
        zero_md["skips"],
    )
    decreasing = calculate_trajectory([station(2000, 10, 100), station(1500, 12, 100)])
    check(
        "Decreasing MD is skipped, not recalculated",
        decreasing["interval_count"] == 0 and decreasing["skips"]["decreasing_md"] == 1,
        decreasing["skips"],
    )

    # --- 12-16. Ineligible stations ---
    missing_inc = calculate_trajectory([station(1000, None, 100), station(1500, 12, 100)])
    check(
        "Missing inclination is counted and excluded",
        missing_inc["skips"]["missing_inclination"] == 1 and missing_inc["interval_count"] == 0,
        missing_inc["skips"],
    )
    missing_azi = calculate_trajectory([station(1000, 10, None), station(1500, 12, 100)])
    check(
        "Missing azimuth is counted and excluded",
        missing_azi["skips"]["missing_azimuth"] == 1 and missing_azi["interval_count"] == 0,
        missing_azi["skips"],
    )
    nan_input = calculate_trajectory([station(1000, float("nan"), 100), station(1500, 12, 100)])
    check(
        "NaN input is invalid_numeric, never propagated",
        nan_input["skips"]["invalid_numeric"] == 1
        and all(math.isfinite(number) for number in walk_numbers(nan_input)),
        nan_input["skips"],
    )
    inf_input = calculate_trajectory([station(float("inf"), 10, 100), station(1500, 12, 100)])
    check(
        "Infinite input is invalid_numeric",
        inf_input["skips"]["invalid_numeric"] == 1,
        inf_input["skips"],
    )
    conflict_station = calculate_trajectory([station(1000, 10, 100, conflict=True), station(1500, 12, 100)])
    check(
        "Conflict-flagged station is excluded with its own skip reason",
        conflict_station["skips"]["conflict"] == 1 and conflict_station["interval_count"] == 0,
        conflict_station["skips"],
    )

    # --- 17-18. No bridging across ineligible stations ---
    bridged_conflict = calculate_trajectory(
        [station(1000, 10, 100), station(1500, 11, 101, conflict=True), station(2000, 12, 102)]
    )
    check(
        "A conflict station between valid stations is never bridged",
        bridged_conflict["interval_count"] == 0
        and bridged_conflict["skips"]["conflict"] == 1
        and bridged_conflict["segment_count"] == 0,
        bridged_conflict,
    )
    bridged_missing = calculate_trajectory(
        [station(1000, 10, 100), station(1500, 11, None), station(2000, 12, 102)]
    )
    check(
        "A missing-angle station between valid stations is never bridged",
        bridged_missing["interval_count"] == 0 and bridged_missing["skips"]["missing_azimuth"] == 1,
        bridged_missing,
    )

    # --- 19. Planned and actual sequences stay separate ---
    mixed_types = calculate_trajectory(
        [
            station(1000, 10, 100, survey_type="actual"),
            station(1200, 11, 101, survey_type="planned"),
            station(1500, 12, 102, survey_type="actual"),
            station(1700, 13, 103, survey_type="planned"),
        ]
    )
    interval_types = sorted((item["survey_type"], item["md_start_ft"], item["md_end_ft"]) for item in mixed_types["intervals"])
    check(
        "Interleaved planned/actual stations calculate as separate sequences",
        mixed_types["interval_count"] == 2
        and interval_types == [("actual", 1000.0, 1500.0), ("planned", 1200.0, 1700.0)]
        and mixed_types["skips"]["survey_type_boundary"] == 3,
        mixed_types["intervals"],
    )

    # --- 20-23. Coordinate anchoring ---
    anchored = calculate_trajectory(
        [station(1000, 10, 100, true_vertical_depth_ft=950.0), station(1500, 12, 102)]
    )
    check(
        "Source TVD anchors absolute TVD while N/E stay relative (mixed reference)",
        anchored["coordinate_reference"]
        == {"tvd": "source_absolute", "north_south": "relative_first_station", "east_west": "relative_first_station"}
        and anchored["anchor"]["tvd_ft"] == 950.0
        and anchored["stations"][0]["tvd_ft"] == 950.0
        and anchored["stations"][1]["tvd_ft"] > 950.0,
        anchored["coordinate_reference"],
    )
    relative = calculate_trajectory([station(1000, 10, 100), station(1500, 12, 102)])
    check(
        "No source anchor yields relative coordinates starting at zero",
        relative["coordinate_reference"]["tvd"] == "relative_first_station"
        and relative["stations"][0]["tvd_ft"] == 0.0
        and relative["stations"][0]["north_south_ft"] == 0.0,
        relative["coordinate_reference"],
    )
    ne_anchored = calculate_trajectory(
        [
            station(1000, 10, 100, true_vertical_depth_ft=950.0, north_south_ft=100.0, east_west_ft=-50.0),
            station(1500, 12, 102),
        ]
    )
    check(
        "Source N/S and E/W anchors are honoured independently",
        ne_anchored["coordinate_reference"]
        == {"tvd": "source_absolute", "north_south": "source_absolute", "east_west": "source_absolute"}
        and ne_anchored["stations"][0]["north_south_ft"] == 100.0
        and ne_anchored["stations"][0]["east_west_ft"] == -50.0,
        ne_anchored["anchor"],
    )

    # --- 24. Source values are never overwritten ---
    disagreement_input = [
        station(1000, 10, 100, true_vertical_depth_ft=950.0, dogleg_severity_dp100ft=1.0),
        station(1500, 12, 102, true_vertical_depth_ft=1500.0, dogleg_severity_dp100ft=2.5),
    ]
    frozen = copy.deepcopy(disagreement_input)
    disagreement = calculate_trajectory(disagreement_input)
    calculated_tvd = disagreement["stations"][1]["tvd_ft"]
    check(
        "Source/calculated TVD disagreement never mutates the source stations",
        disagreement_input == frozen
        and abs(calculated_tvd - 1500.0) > 1.0
        and disagreement_input[1]["true_vertical_depth_ft"] == 1500.0,
        {"calculated_tvd": calculated_tvd, "source_tvd": 1500.0},
    )

    # --- 25. Determinism (pure result contains no timestamps) ---
    sample = [
        station(1000, 10, 100, true_vertical_depth_ft=950.0, confidence=0.8, page=1, station_id="S-1"),
        station(1500, 12, 102, confidence=0.7, page=2, station_id="S-2"),
        station(2000, 14, 104, confidence=0.9, page=2, station_id="S-3"),
    ]
    first_pass = json.dumps(calculate_trajectory(copy.deepcopy(sample)), sort_keys=True)
    second_pass = json.dumps(calculate_trajectory(copy.deepcopy(sample)), sort_keys=True)
    check(
        "Repeated calculation is deterministic and timestamp-free",
        first_pass == second_pass and "generated_at" not in first_pass,
        len(first_pass),
    )

    # --- 26 + 30. Bounded 200-station set, all outputs finite ---
    large = calculate_trajectory(
        [station(1000 + 50 * i, 20 + 0.01 * i, 100 + 0.05 * i, confidence=0.8, page=1) for i in range(200)]
    )
    check(
        "200-station set completes with 199 finite intervals",
        large["interval_count"] == 199
        and large["segment_count"] == 1
        and all(math.isfinite(number) for number in walk_numbers(large)),
        {"intervals": large["interval_count"], "segments": large["segment_count"]},
    )

    # --- 27-29. Empty, single, all-ineligible ---
    empty = calculate_trajectory([])
    check(
        "No stations yields an explicit none-reference empty result",
        empty["interval_count"] == 0
        and empty["anchor"] is None
        and empty["coordinate_reference"] == {"tvd": "none", "north_south": "none", "east_west": "none"},
        empty,
    )
    single = calculate_trajectory([station(1000, 10, 100)])
    check(
        "A single station yields no intervals but counts as eligible",
        single["interval_count"] == 0 and single["eligible_station_count"] == 1,
        single,
    )
    ineligible = calculate_trajectory([station(1000, 10, 100, conflict=True), station(1500, 11, 101, conflict=True)])
    check(
        "All-ineligible input yields zero intervals with counted skips",
        ineligible["interval_count"] == 0 and ineligible["skips"]["conflict"] == 2,
        ineligible["skips"],
    )

    # --- Provenance constants ---
    provenance = calculate_trajectory(sample)
    check(
        "Every calculated result carries method, version, and calculated provenance",
        provenance["method"] == METHOD == "minimum_curvature"
        and provenance["method_version"] == METHOD_VERSION == "v1"
        and all(item["source"] == "calculated" for item in provenance["intervals"])
        and all(item["source"] == "calculated" for item in provenance["stations"])
        and provenance["input_confidence_min"] == 0.7
        and provenance["intervals"][0]["source_pages"] == [1, 2]
        and provenance["intervals"][0]["start_station_id"] == "S-1",
        {"confidence_min": provenance["input_confidence_min"]},
    )
    check(
        "Antipodal tolerance is the documented guard band",
        ANTIPODAL_TOLERANCE_RAD == 1e-2,
        ANTIPODAL_TOLERANCE_RAD,
    )

    failed = [item for item in checks if not item["ok"]]
    for item in checks:
        status = "PASS" if item["ok"] else "FAIL"
        print(f"{status}: {item['name']} - {item['detail']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
