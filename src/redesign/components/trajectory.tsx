import type { JSX } from "react";
import type {
  ApiCalculatedTrajectoryStation,
  ApiTrajectoryCalculation
} from "../../lib/api";
import {
  DISPLAY_EPSILON_FT,
  formatFt,
  niceTickStep,
  tickValues
} from "../../lib/trajectoryGeometry";

/**
 * Calculated-trajectory figures for the redesigned Well view.
 *
 * Same display rules as the v1 components these replace (equal ft scale on both
 * axes, letterboxed rather than stretched; paths never bridged across skipped
 * stations or survey-type boundaries; every figure discloses its coordinate
 * reference), reimplemented against the redesign's blueprint styling. All values
 * come from the backend's minimum-curvature calculation — nothing is computed
 * here beyond mapping feet to pixels — and every caption repeats the calculation's
 * own review-required framing. Not certified survey computation.
 */

interface FigureSegment {
  segment: number;
  surveyType: string | null;
  stations: ApiCalculatedTrajectoryStation[];
}

function groupSegments(
  stations: ApiCalculatedTrajectoryStation[],
  usable: (station: ApiCalculatedTrajectoryStation) => boolean
): FigureSegment[] {
  const segments: FigureSegment[] = [];
  for (const station of stations) {
    if (!usable(station)) continue;
    const existing = segments.find((item) => item.segment === station.segment);
    if (existing) {
      existing.stations.push(station);
    } else {
      segments.push({
        segment: station.segment,
        surveyType: station.survey_type ?? null,
        stations: [station]
      });
    }
  }
  return segments;
}

const PLAN_SIZE = 360;
const PLAN_PADDING = 44;

export function TrajectoryPlan({ trajectory }: { trajectory: ApiTrajectoryCalculation }): JSX.Element {
  const segments = groupSegments(
    trajectory.stations,
    (station) => Number.isFinite(station.north_south_ft) && Number.isFinite(station.east_west_ft)
  );
  const displayable = segments.flatMap((item) => item.stations);
  const drawable = segments.filter((item) => item.stations.length >= 2);

  const eastValues = displayable.map((station) => station.east_west_ft);
  const northValues = displayable.map((station) => station.north_south_ft);
  const spanEast = eastValues.length ? Math.max(...eastValues) - Math.min(...eastValues) : 0;
  const spanNorth = northValues.length ? Math.max(...northValues) - Math.min(...northValues) : 0;
  const lateralExtent = Math.max(spanEast, spanNorth);

  const nsRelative = trajectory.coordinate_reference.north_south === "relative_first_station";
  const ewRelative = trajectory.coordinate_reference.east_west === "relative_first_station";
  const referenceNote =
    nsRelative || ewRelative
      ? `${nsRelative && ewRelative ? "N/S and E/W" : nsRelative ? "N/S" : "E/W"} relative to the first calculated station — not absolute well coordinates`
      : "N/S and E/W from source-stated anchor values";

  if (drawable.length === 0 || lateralExtent <= DISPLAY_EPSILON_FT) {
    return (
      <p className="text-muted" role="note" style={{ fontSize: 12, margin: 0 }}>
        Plan-view lateral extent is effectively zero; review the calculated station table.{" "}
        {`(${displayable.length} calculated station(s), extent ${lateralExtent.toFixed(2)} ft.)`}
      </p>
    );
  }

  const minEast = Math.min(...eastValues);
  const maxEast = Math.max(...eastValues);
  const minNorth = Math.min(...northValues);
  const maxNorth = Math.max(...northValues);
  const inner = PLAN_SIZE - 2 * PLAN_PADDING;
  const scale = inner / Math.max(spanEast, spanNorth, DISPLAY_EPSILON_FT);
  const offsetX = PLAN_PADDING + (inner - spanEast * scale) / 2;
  const offsetY = PLAN_PADDING + (inner - spanNorth * scale) / 2;
  const toX = (east: number): number => offsetX + (east - minEast) * scale;
  const toY = (north: number): number => offsetY + (maxNorth - north) * scale;

  const tickStep = niceTickStep(Math.max(spanEast, spanNorth));
  const eastTicks = tickValues(minEast, maxEast, tickStep);
  const northTicks = tickValues(minNorth, maxNorth, tickStep);
  const anchorStation = drawable[0].stations[0];
  const typeLabels = Array.from(new Set(segments.map((item) => item.surveyType ?? "untyped")));

  const description =
    `Calculated plan view, minimum curvature ${trajectory.method_version}, review required: ` +
    `${displayable.length} calculated station(s) across ${trajectory.segment_count} segment(s); ` +
    `east/west span ${spanEast.toFixed(1)} ft, north/south span ${spanNorth.toFixed(1)} ft; ${referenceNote}. ` +
    "Paths never connect across skipped stations or survey-type boundaries.";

  return (
    <figure className="mr-plan-figure">
      <figcaption className="mr-plan-caption">
        Plan view (E/W vs N/S) · Calculated · minimum curvature {trajectory.method_version} · review
        required
      </figcaption>
      <p className="text-muted mr-plan-note" role="note">
        {referenceNote}. North is up, east is right, equal ft scale. Gaps mark skipped or
        conflicting stations — paths are never bridged. Not certified survey computation.
      </p>
      <svg
        className="mr-plan-svg"
        viewBox={`0 0 ${PLAN_SIZE} ${PLAN_SIZE}`}
        role="img"
        aria-label={`Calculated trajectory plan view, ${drawable.length} path segment(s), review required`}
      >
        <title>Calculated trajectory plan view (minimum curvature {trajectory.method_version})</title>
        <desc>{description}</desc>
        <rect className="mr-plan-frame" x="1" y="1" width={PLAN_SIZE - 2} height={PLAN_SIZE - 2} />
        {eastTicks.map((tick) => (
          <g key={`et-${tick}`}>
            <line
              className="mr-plan-grid"
              x1={toX(tick)}
              y1={PLAN_PADDING - 6}
              x2={toX(tick)}
              y2={PLAN_SIZE - PLAN_PADDING + 6}
            />
            <text className="mr-plan-tick" x={toX(tick)} y={PLAN_SIZE - PLAN_PADDING + 20} textAnchor="middle">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        {northTicks.map((tick) => (
          <g key={`nt-${tick}`}>
            <line
              className="mr-plan-grid"
              x1={PLAN_PADDING - 6}
              y1={toY(tick)}
              x2={PLAN_SIZE - PLAN_PADDING + 6}
              y2={toY(tick)}
            />
            <text className="mr-plan-tick" x={PLAN_PADDING - 10} y={toY(tick) + 3} textAnchor="end">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        <text className="mr-plan-axis" x={PLAN_SIZE / 2} y={PLAN_SIZE - 8} textAnchor="middle">
          East/West (ft) — east right
        </text>
        <text
          className="mr-plan-axis"
          x={12}
          y={PLAN_SIZE / 2}
          textAnchor="middle"
          transform={`rotate(-90 12 ${PLAN_SIZE / 2})`}
        >
          North/South (ft) — north up
        </text>
        {drawable.map((segment) => (
          <polyline
            key={`seg-${segment.segment}`}
            className={`mr-plan-path ${segment.surveyType === "planned" ? "is-planned" : "is-actual"}`}
            data-segment={segment.segment}
            points={segment.stations
              .map(
                (station) =>
                  `${toX(station.east_west_ft).toFixed(2)},${toY(station.north_south_ft).toFixed(2)}`
              )
              .join(" ")}
          />
        ))}
        {drawable.flatMap((segment) =>
          segment.stations.map((station, index) =>
            segment.surveyType === "planned" ? (
              <rect
                key={`marker-${segment.segment}-${index}`}
                className="mr-plan-marker is-planned"
                x={toX(station.east_west_ft) - 3}
                y={toY(station.north_south_ft) - 3}
                width={6}
                height={6}
              />
            ) : (
              <circle
                key={`marker-${segment.segment}-${index}`}
                className="mr-plan-marker is-actual"
                cx={toX(station.east_west_ft)}
                cy={toY(station.north_south_ft)}
                r={3.2}
              />
            )
          )
        )}
        <g>
          <rect
            className="mr-plan-anchor"
            x={toX(anchorStation.east_west_ft) - 5}
            y={toY(anchorStation.north_south_ft) - 5}
            width={10}
            height={10}
          />
          <text
            className="mr-plan-anchor-label"
            x={toX(anchorStation.east_west_ft) + 8}
            y={toY(anchorStation.north_south_ft) - 8}
          >
            anchor · MD {formatFt(anchorStation.measured_depth_ft)} ft
          </text>
        </g>
      </svg>
      <ul className="mr-plan-legend" aria-label="Plan view legend">
        {typeLabels.map((label) => (
          <li key={label}>
            <span
              className={`mr-plan-swatch ${label === "planned" ? "is-planned" : "is-actual"}`}
              aria-hidden="true"
            />
            {label === "untyped" ? "survey path" : `${label} path`}
            {label === "planned" ? " (dashed, square markers)" : " (solid, round markers)"}
          </li>
        ))}
        <li>
          <span className="mr-plan-swatch is-anchor" aria-hidden="true" />
          anchor station
        </li>
      </ul>
    </figure>
  );
}

const PROFILE_W = 300;
const PROFILE_H = 300;
const PROFILE_PADDING = 46;

export function TrajectoryProfile({
  trajectory
}: {
  trajectory: ApiTrajectoryCalculation;
}): JSX.Element | null {
  const segments = groupSegments(
    trajectory.stations,
    (station) =>
      Number.isFinite(station.tvd_ft) && Number.isFinite(station.horizontal_displacement_ft)
  );
  const drawable = segments.filter((item) => item.stations.length >= 2);
  if (drawable.length === 0) return null;

  const tvdReference = trajectory.coordinate_reference.tvd;
  const tvdReferenceLabel =
    tvdReference === "source_absolute"
      ? "TVD source-anchored absolute"
      : tvdReference === "relative_first_station"
        ? "TVD relative to first calculated station"
        : "TVD reference unavailable";
  const lateralRelative =
    trajectory.coordinate_reference.north_south === "relative_first_station" ||
    trajectory.coordinate_reference.east_west === "relative_first_station";

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <p className="mr-plan-caption" style={{ margin: 0 }}>
        Vertical trajectory profile (HD vs TVD) · Calculated · minimum curvature{" "}
        {trajectory.method_version} · review required
      </p>
      <p className="text-muted mr-plan-note" role="note">
        Horizontal displacement is calculated from this segment's first calculated station — an
        unsigned magnitude, never an absolute or east/west position (direction is shown in the plan
        view). {tvdReferenceLabel}.{" "}
        {lateralRelative
          ? "Underlying N/S and E/W coordinates are relative — not absolute well coordinates. "
          : ""}
        Calculated TVD increases downward. One panel per calculation segment — paths are never
        bridged. Not certified survey computation.
      </p>
      <div className="mr-profile-grid">
        {drawable.map((segment) => (
          <ProfilePanel
            key={`profile-${segment.segment}`}
            segment={segment}
            methodVersion={trajectory.method_version}
            tvdReferenceLabel={tvdReferenceLabel}
          />
        ))}
      </div>
    </div>
  );
}

function ProfilePanel({
  segment,
  methodVersion,
  tvdReferenceLabel
}: {
  segment: FigureSegment;
  methodVersion: string;
  tvdReferenceLabel: string;
}): JSX.Element {
  const hdValues = segment.stations.map((station) => station.horizontal_displacement_ft);
  const tvdValues = segment.stations.map((station) => station.tvd_ft);
  const maxHd = Math.max(...hdValues);
  const minTvd = Math.min(...tvdValues);
  const maxTvd = Math.max(...tvdValues);
  const spanTvd = maxTvd - minTvd;
  const zeroLateral = maxHd <= DISPLAY_EPSILON_FT;

  const innerW = PROFILE_W - 2 * PROFILE_PADDING;
  const innerH = PROFILE_H - 2 * PROFILE_PADDING;
  const scale = Math.min(
    innerW / Math.max(maxHd, DISPLAY_EPSILON_FT),
    innerH / Math.max(spanTvd, DISPLAY_EPSILON_FT)
  );
  const toX = (hd: number): number => PROFILE_PADDING + hd * scale;
  const toY = (tvd: number): number => PROFILE_PADDING + (tvd - minTvd) * scale;

  const hdTicks = tickValues(0, maxHd, niceTickStep(Math.max(maxHd, DISPLAY_EPSILON_FT)));
  const tvdTicks = tickValues(minTvd, maxTvd, niceTickStep(Math.max(spanTvd, DISPLAY_EPSILON_FT)));
  const anchor = segment.stations[0];
  const typeLabel = segment.surveyType ?? "untyped";
  const planned = segment.surveyType === "planned";
  const description =
    `Segment ${segment.segment} (${typeLabel}) vertical profile, minimum curvature ${methodVersion}, review required: ` +
    `${segment.stations.length} calculated station(s); horizontal displacement from the segment anchor 0 to ${maxHd.toFixed(1)} ft; ` +
    `calculated TVD ${minTvd.toFixed(1)} to ${maxTvd.toFixed(1)} ft increasing downward; ${tvdReferenceLabel}.`;

  return (
    <figure className="mr-plan-figure">
      <figcaption className="mr-plan-caption">
        Segment {segment.segment} · {typeLabel} path · {segment.stations.length} station(s)
      </figcaption>
      {zeroLateral ? (
        <p className="text-muted mr-plan-note" role="note">
          Horizontal displacement is effectively zero; this profile represents calculated TVD
          progression.
        </p>
      ) : null}
      <svg
        className="mr-plan-svg"
        viewBox={`0 0 ${PROFILE_W} ${PROFILE_H}`}
        role="img"
        aria-label={`Segment ${segment.segment} calculated vertical profile, review required`}
        data-segment={segment.segment}
      >
        <title>
          Segment {segment.segment} vertical profile (minimum curvature {methodVersion})
        </title>
        <desc>{description}</desc>
        <rect className="mr-plan-frame" x="1" y="1" width={PROFILE_W - 2} height={PROFILE_H - 2} />
        {hdTicks.map((tick) => (
          <g key={`hdt-${tick}`}>
            <line
              className="mr-plan-grid"
              x1={toX(tick)}
              y1={PROFILE_PADDING - 6}
              x2={toX(tick)}
              y2={PROFILE_H - PROFILE_PADDING + 6}
            />
            <text className="mr-plan-tick" x={toX(tick)} y={PROFILE_H - PROFILE_PADDING + 20} textAnchor="middle">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        {tvdTicks.map((tick) => (
          <g key={`tvt-${tick}`}>
            <line
              className="mr-plan-grid"
              x1={PROFILE_PADDING - 6}
              y1={toY(tick)}
              x2={PROFILE_W - PROFILE_PADDING + 6}
              y2={toY(tick)}
            />
            <text className="mr-plan-tick" x={PROFILE_PADDING - 10} y={toY(tick) + 3} textAnchor="end">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        <text className="mr-plan-axis" x={PROFILE_W / 2} y={PROFILE_H - 8} textAnchor="middle">
          HD from segment anchor (ft)
        </text>
        <text
          className="mr-plan-axis"
          x={12}
          y={PROFILE_H / 2}
          textAnchor="middle"
          transform={`rotate(-90 12 ${PROFILE_H / 2})`}
        >
          Calculated TVD (ft) — increasing downward
        </text>
        <polyline
          className={`mr-plan-path ${planned ? "is-planned" : "is-actual"}`}
          data-segment={segment.segment}
          points={segment.stations
            .map(
              (station) =>
                `${toX(station.horizontal_displacement_ft).toFixed(2)},${toY(station.tvd_ft).toFixed(2)}`
            )
            .join(" ")}
        />
        {segment.stations.map((station, index) =>
          planned ? (
            <rect
              key={`pm-${index}`}
              className="mr-plan-marker is-planned"
              x={toX(station.horizontal_displacement_ft) - 3}
              y={toY(station.tvd_ft) - 3}
              width={6}
              height={6}
            />
          ) : (
            <circle
              key={`pm-${index}`}
              className="mr-plan-marker is-actual"
              cx={toX(station.horizontal_displacement_ft)}
              cy={toY(station.tvd_ft)}
              r={3.2}
            />
          )
        )}
        <rect
          className="mr-plan-anchor"
          x={toX(anchor.horizontal_displacement_ft) - 5}
          y={toY(anchor.tvd_ft) - 5}
          width={10}
          height={10}
        />
        <text
          className="mr-plan-anchor-label"
          x={toX(anchor.horizontal_displacement_ft) + 8}
          y={toY(anchor.tvd_ft) - 8}
        >
          anchor · MD {formatFt(anchor.measured_depth_ft)} ft
        </text>
      </svg>
    </figure>
  );
}
