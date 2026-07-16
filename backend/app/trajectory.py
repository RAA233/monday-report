"""Pure minimum-curvature trajectory calculations.

Deterministic, dependency-free implementation of the industry-standard minimum
curvature method over source-derived survey stations. See
``docs/TRAJECTORY_CALCULATION.md`` for the canonical formulas, unit and
coordinate conventions, numerical policy, and worked test vectors enforced by
``scripts/trajectory_calculation_guard.py``.

Purity contract: no FastAPI/store/database/filesystem/network access, no
environment variables, no timestamps, no randomness, no global mutable state.
Identical inputs always produce identical serialized results. Source station
dicts are treated as immutable inputs and are never modified. This module is a
drafting aid, not certified directional-survey software; every result carries
``source="calculated"`` and requires engineering review.
"""
from __future__ import annotations

import math

METHOD = "minimum_curvature"
METHOD_VERSION = "v1"

# Below this dogleg angle the closed form (2/beta)*tan(beta/2) is replaced by
# its stable Maclaurin series; continuity across the boundary is test-enforced.
ZERO_DOGLEG_SERIES_THRESHOLD_RAD = 1e-6
# Within this distance of pi the ratio factor is ill-conditioned; the interval
# is skipped as an antipodal singularity rather than clamped into a plausible
# but unsupported trajectory.
ANTIPODAL_TOLERANCE_RAD = 1e-2

SKIP_REASONS = (
    "conflict",
    "missing_inclination",
    "missing_azimuth",
    "invalid_numeric",
    "zero_md_interval",
    "decreasing_md",
    "survey_type_boundary",
    "antipodal_singularity",
    "truncated",
)


def dogleg_angle_rad(inc1_deg: float, azi1_deg: float, inc2_deg: float, azi2_deg: float) -> float:
    """Dogleg angle beta in radians from the canonical dot-product form.

    cos(beta) = cos(I1)cos(I2) + sin(I1)sin(I2)cos(A2 - A1), with the acos
    argument clamped to [-1, 1] against floating-point drift.
    """
    inc1 = math.radians(inc1_deg)
    inc2 = math.radians(inc2_deg)
    delta_azi = math.radians(azi2_deg - azi1_deg)
    cos_beta = math.cos(inc1) * math.cos(inc2) + math.sin(inc1) * math.sin(inc2) * math.cos(delta_azi)
    return math.acos(max(-1.0, min(1.0, cos_beta)))


def ratio_factor(beta_rad: float) -> float:
    """Minimum-curvature ratio factor RF = (2/beta)tan(beta/2).

    Exactly zero dogleg returns 1.0; below the series threshold the stable
    expansion 1 + beta^2/12 + beta^4/120 is used. Near-antipodal angles must be
    guarded by the caller before invoking this function.
    """
    if beta_rad == 0.0:
        return 1.0
    if abs(beta_rad) < ZERO_DOGLEG_SERIES_THRESHOLD_RAD:
        beta_sq = beta_rad * beta_rad
        return 1.0 + beta_sq / 12.0 + beta_sq * beta_sq / 120.0
    return (2.0 / beta_rad) * math.tan(beta_rad / 2.0)


def calculate_minimum_curvature_interval(
    md1_ft: float,
    inc1_deg: float,
    azi1_deg: float,
    md2_ft: float,
    inc2_deg: float,
    azi2_deg: float,
) -> dict[str, float] | None:
    """Displacements over one interval, or None for an antipodal singularity.

    Callers must supply validated, strictly increasing measured depths and
    in-range angles (degrees). Returns full-precision floats; rounding is a
    serialization concern.
    """
    beta = dogleg_angle_rad(inc1_deg, azi1_deg, inc2_deg, azi2_deg)
    if math.pi - beta < ANTIPODAL_TOLERANCE_RAD:
        return None
    rf = ratio_factor(beta)
    delta_md = md2_ft - md1_ft
    inc1 = math.radians(inc1_deg)
    inc2 = math.radians(inc2_deg)
    azi1 = math.radians(azi1_deg)
    azi2 = math.radians(azi2_deg)
    half = delta_md / 2.0
    return {
        "dogleg_rad": beta,
        "dogleg_deg": math.degrees(beta),
        "ratio_factor": rf,
        "delta_tvd_ft": half * (math.cos(inc1) + math.cos(inc2)) * rf,
        "delta_ns_ft": half * (math.sin(inc1) * math.cos(azi1) + math.sin(inc2) * math.cos(azi2)) * rf,
        "delta_ew_ft": half * (math.sin(inc1) * math.sin(azi1) + math.sin(inc2) * math.sin(azi2)) * rf,
        "dls_deg_per_100ft": math.degrees(beta) * 100.0 / delta_md,
    }


def _finite(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _station_skip_reason(station: dict) -> str | None:
    """Why a station is calculation-ineligible, or None when eligible."""
    if station.get("conflict"):
        return "conflict"
    md = _finite(station.get("measured_depth_ft"))
    inclination = station.get("inclination_deg")
    azimuth = station.get("azimuth_deg")
    if inclination is None:
        return "missing_inclination"
    if azimuth is None:
        return "missing_azimuth"
    inc = _finite(inclination)
    azi = _finite(azimuth)
    if md is None or inc is None or azi is None or md < 0 or not (0.0 <= inc <= 180.0) or not (0.0 <= azi <= 360.0):
        return "invalid_numeric"
    return None


def _round(value: float, digits: int) -> float:
    return round(value, digits)


def calculate_trajectory(stations: list[dict]) -> dict:
    """Segmented minimum-curvature trajectory over ordered source stations.

    Stations are grouped by normalized survey type (absent types grouped
    together, never inferred). Within a group, intervals join consecutive
    eligible stations with strictly increasing MD; any ineligible station or
    interval ends the segment — ineligible stations are never bridged.
    Coordinate anchoring is per-axis at each segment's first station:
    ``source_absolute`` when the source stated the value, else
    ``relative_first_station``. Input dicts are never modified.
    """
    skips: dict[str, int] = {reason: 0 for reason in SKIP_REASONS}
    intervals: list[dict] = []
    calc_stations: list[dict] = []
    eligible_count = 0
    segment_count = 0
    confidence_values: list[float] = []
    top_reference: dict[str, str] | None = None
    top_anchor: dict[str, object] | None = None

    groups: dict[object, list[dict]] = {}
    group_order: list[object] = []
    previous_type: object = None
    for index, station in enumerate(stations):
        survey_type = station.get("survey_type")
        normalized = str(survey_type).strip().lower() if isinstance(survey_type, str) and survey_type.strip() else None
        if index > 0 and normalized != previous_type:
            skips["survey_type_boundary"] += 1
        previous_type = normalized
        if normalized not in groups:
            groups[normalized] = []
            group_order.append(normalized)
        groups[normalized].append(station)

    for group_key in group_order:
        segment: list[dict] = []
        for station in groups[group_key]:
            reason = _station_skip_reason(station)
            if reason is not None:
                skips[reason] += 1
                segment_count, top_reference, top_anchor = _flush_segment(
                    segment, group_key, intervals, calc_stations, segment_count,
                    confidence_values, top_reference, top_anchor,
                )
                segment = []
                continue
            eligible_count += 1
            if segment:
                previous_md = float(segment[-1]["measured_depth_ft"])
                current_md = float(station["measured_depth_ft"])
                if current_md == previous_md:
                    skips["zero_md_interval"] += 1
                    segment_count, top_reference, top_anchor = _flush_segment(
                        segment, group_key, intervals, calc_stations, segment_count,
                        confidence_values, top_reference, top_anchor,
                    )
                    segment = [station]
                    continue
                if current_md < previous_md:
                    skips["decreasing_md"] += 1
                    segment_count, top_reference, top_anchor = _flush_segment(
                        segment, group_key, intervals, calc_stations, segment_count,
                        confidence_values, top_reference, top_anchor,
                    )
                    segment = [station]
                    continue
                interval = calculate_minimum_curvature_interval(
                    previous_md,
                    float(segment[-1]["inclination_deg"]),
                    float(segment[-1]["azimuth_deg"]),
                    current_md,
                    float(station["inclination_deg"]),
                    float(station["azimuth_deg"]),
                )
                if interval is None:
                    skips["antipodal_singularity"] += 1
                    segment_count, top_reference, top_anchor = _flush_segment(
                        segment, group_key, intervals, calc_stations, segment_count,
                        confidence_values, top_reference, top_anchor,
                    )
                    segment = [station]
                    continue
            segment.append(station)
        segment_count, top_reference, top_anchor = _flush_segment(
            segment, group_key, intervals, calc_stations, segment_count,
            confidence_values, top_reference, top_anchor,
        )

    return {
        "method": METHOD,
        "method_version": METHOD_VERSION,
        "coordinate_reference": top_reference or {"tvd": "none", "north_south": "none", "east_west": "none"},
        "anchor": top_anchor,
        "source_station_count": len(stations),
        "eligible_station_count": eligible_count,
        "segment_count": segment_count,
        "interval_count": len(intervals),
        "intervals": intervals,
        "stations": calc_stations,
        "skips": skips,
        "input_confidence_min": min(confidence_values) if confidence_values else None,
    }


def _flush_segment(
    segment: list[dict],
    group_key: object,
    intervals: list[dict],
    calc_stations: list[dict],
    segment_count: int,
    confidence_values: list[float],
    top_reference: dict[str, str] | None,
    top_anchor: dict[str, object] | None,
) -> tuple[int, dict[str, str] | None, dict[str, object] | None]:
    """Emit intervals and cumulative positions for one contiguous segment."""
    if len(segment) < 2:
        return segment_count, top_reference, top_anchor
    segment_count += 1
    segment_index = segment_count

    first = segment[0]
    anchor_tvd = _finite(first.get("true_vertical_depth_ft"))
    anchor_ns = _finite(first.get("north_south_ft"))
    anchor_ew = _finite(first.get("east_west_ft"))
    reference = {
        "tvd": "source_absolute" if anchor_tvd is not None else "relative_first_station",
        "north_south": "source_absolute" if anchor_ns is not None else "relative_first_station",
        "east_west": "source_absolute" if anchor_ew is not None else "relative_first_station",
    }
    anchor = {
        "measured_depth_ft": _round(float(first["measured_depth_ft"]), 2),
        "tvd_ft": _round(anchor_tvd, 2) if anchor_tvd is not None else None,
        "north_south_ft": _round(anchor_ns, 2) if anchor_ns is not None else None,
        "east_west_ft": _round(anchor_ew, 2) if anchor_ew is not None else None,
        "source_page": first.get("page") if isinstance(first.get("page"), int) else None,
    }
    if top_reference is None:
        top_reference = reference
        top_anchor = anchor

    tvd = anchor_tvd if anchor_tvd is not None else 0.0
    ns = anchor_ns if anchor_ns is not None else 0.0
    ew = anchor_ew if anchor_ew is not None else 0.0

    def confidence_of(station: dict) -> float | None:
        return _finite(station.get("confidence"))

    def station_entry(station: dict, tvd_value: float, ns_value: float, ew_value: float) -> dict:
        return {
            "measured_depth_ft": _round(float(station["measured_depth_ft"]), 2),
            "tvd_ft": _round(tvd_value, 2),
            "north_south_ft": _round(ns_value, 2),
            "east_west_ft": _round(ew_value, 2),
            "source_station_id": str(station["station_id"]) if station.get("station_id") else None,
            "source_page": station.get("page") if isinstance(station.get("page"), int) else None,
            "segment": segment_index,
            # Explicit survey-type identity so consumers never infer it from
            # array order or interval joins (additive; no math change).
            "survey_type": group_key if isinstance(group_key, str) else None,
            "coordinate_reference": dict(reference),
            "source": "calculated",
        }

    calc_stations.append(station_entry(first, tvd, ns, ew))
    first_confidence = confidence_of(first)
    if first_confidence is not None:
        confidence_values.append(first_confidence)

    for start, end in zip(segment, segment[1:]):
        result = calculate_minimum_curvature_interval(
            float(start["measured_depth_ft"]),
            float(start["inclination_deg"]),
            float(start["azimuth_deg"]),
            float(end["measured_depth_ft"]),
            float(end["inclination_deg"]),
            float(end["azimuth_deg"]),
        )
        # Antipodal pairs were excluded during segmentation; a None here would
        # indicate a segmentation defect, so fail loudly in tests via KeyError
        # rather than fabricating a value.
        assert result is not None
        pair_confidences = [value for value in (confidence_of(start), confidence_of(end)) if value is not None]
        end_confidence = confidence_of(end)
        if end_confidence is not None:
            confidence_values.append(end_confidence)
        tvd += result["delta_tvd_ft"]
        ns += result["delta_ns_ft"]
        ew += result["delta_ew_ft"]
        pages = sorted(
            {
                station.get("page")
                for station in (start, end)
                if isinstance(station.get("page"), int)
            }
        )
        intervals.append(
            {
                "md_start_ft": _round(float(start["measured_depth_ft"]), 2),
                "md_end_ft": _round(float(end["measured_depth_ft"]), 2),
                "start_station_id": str(start["station_id"]) if start.get("station_id") else None,
                "end_station_id": str(end["station_id"]) if end.get("station_id") else None,
                "survey_type": group_key if isinstance(group_key, str) else None,
                "segment": segment_index,
                "dogleg_deg": _round(result["dogleg_deg"], 4),
                "dls_deg_per_100ft": _round(result["dls_deg_per_100ft"], 2),
                "ratio_factor": _round(result["ratio_factor"], 6),
                "delta_tvd_ft": _round(result["delta_tvd_ft"], 2),
                "delta_ns_ft": _round(result["delta_ns_ft"], 2),
                "delta_ew_ft": _round(result["delta_ew_ft"], 2),
                "source_pages": pages,
                "input_confidence_min": min(pair_confidences) if pair_confidences else None,
                "source": "calculated",
                "method": METHOD,
                "method_version": METHOD_VERSION,
            }
        )
        calc_stations.append(station_entry(end, tvd, ns, ew))

    return segment_count, top_reference, top_anchor
