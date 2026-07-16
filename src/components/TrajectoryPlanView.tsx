import type { JSX } from "react";
import type {
  ApiCalculatedTrajectoryStation,
  ApiTrajectoryCalculation
} from "../lib/api";
import { DISPLAY_EPSILON_FT, formatFt, niceTickStep, tickValues } from "../lib/trajectoryGeometry";

interface TrajectoryPlanViewProps {
  trajectory: ApiTrajectoryCalculation;
}

interface PlanSegment {
  segment: number;
  surveyType: string | null;
  stations: ApiCalculatedTrajectoryStation[];
}

const VIEW_SIZE = 360;
const PADDING = 44;

export function TrajectoryPlanView({ trajectory }: TrajectoryPlanViewProps): JSX.Element {
  const displayable = trajectory.stations.filter(
    (station) => Number.isFinite(station.north_south_ft) && Number.isFinite(station.east_west_ft)
  );
  const segments: PlanSegment[] = [];
  for (const station of displayable) {
    const existing = segments.find((item) => item.segment === station.segment);
    if (existing) {
      existing.stations.push(station);
    } else {
      segments.push({ segment: station.segment, surveyType: station.survey_type ?? null, stations: [station] });
    }
  }
  const drawableSegments = segments.filter((item) => item.stations.length >= 2);

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

  if (drawableSegments.length === 0 || lateralExtent <= DISPLAY_EPSILON_FT) {
    return (
      <p className="trajectory-plan-note" role="note">
        Plan-view lateral extent is effectively zero; review the calculated station table.
        {" "}
        {`(${displayable.length} calculated station(s), extent ${lateralExtent.toFixed(2)} ft.)`}
      </p>
    );
  }

  const minEast = Math.min(...eastValues);
  const maxEast = Math.max(...eastValues);
  const minNorth = Math.min(...northValues);
  const maxNorth = Math.max(...northValues);
  // Equal spatial scale on both axes (one ft E/W = one ft N/S); the shorter
  // span is letterboxed by centring rather than stretched.
  const drawable = VIEW_SIZE - 2 * PADDING;
  const scale = drawable / Math.max(spanEast, spanNorth, DISPLAY_EPSILON_FT);
  const offsetX = PADDING + (drawable - spanEast * scale) / 2;
  const offsetY = PADDING + (drawable - spanNorth * scale) / 2;
  const toX = (east: number): number => offsetX + (east - minEast) * scale;
  const toY = (north: number): number => offsetY + (maxNorth - north) * scale;

  const tickStep = niceTickStep(Math.max(spanEast, spanNorth));
  const eastTicks = tickValues(minEast, maxEast, tickStep);
  const northTicks = tickValues(minNorth, maxNorth, tickStep);
  const anchorStation = drawableSegments[0].stations[0];
  const typeLabels = Array.from(
    new Set(segments.map((item) => item.surveyType ?? "untyped"))
  );

  const description =
    `Calculated plan view, minimum curvature ${trajectory.method_version}, review required: ` +
    `${displayable.length} calculated station(s) across ${trajectory.segment_count} segment(s); ` +
    `east/west span ${spanEast.toFixed(1)} ft, north/south span ${spanNorth.toFixed(1)} ft; ${referenceNote}. ` +
    "Paths never connect across skipped stations or survey-type boundaries.";

  return (
    <figure className="trajectory-plan-figure">
      <figcaption className="trajectory-plan-caption">
        Plan view (E/W vs N/S) · Calculated · minimum curvature {trajectory.method_version} · review required
      </figcaption>
      <p className="trajectory-plan-note" role="note">
        {referenceNote}. North is up, east is right, equal ft scale. Gaps mark skipped or
        conflicting stations — paths are never bridged. Not certified survey computation.
      </p>
      <svg
        className="trajectory-plan-view"
        viewBox={`0 0 ${VIEW_SIZE} ${VIEW_SIZE}`}
        role="img"
        aria-label={`Calculated trajectory plan view, ${drawableSegments.length} path segment(s), review required`}
      >
        <title>Calculated trajectory plan view (minimum curvature {trajectory.method_version})</title>
        <desc>{description}</desc>
        <rect className="plan-frame" x="1" y="1" width={VIEW_SIZE - 2} height={VIEW_SIZE - 2} />
        {eastTicks.map((tick) => (
          <g key={`et-${tick}`}>
            <line className="plan-grid" x1={toX(tick)} y1={PADDING - 6} x2={toX(tick)} y2={VIEW_SIZE - PADDING + 6} />
            <text className="plan-tick-label" x={toX(tick)} y={VIEW_SIZE - PADDING + 20} textAnchor="middle">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        {northTicks.map((tick) => (
          <g key={`nt-${tick}`}>
            <line className="plan-grid" x1={PADDING - 6} y1={toY(tick)} x2={VIEW_SIZE - PADDING + 6} y2={toY(tick)} />
            <text className="plan-tick-label" x={PADDING - 10} y={toY(tick) + 3} textAnchor="end">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        <text className="plan-axis-label" x={VIEW_SIZE / 2} y={VIEW_SIZE - 8} textAnchor="middle">
          East/West (ft) — east right
        </text>
        <text
          className="plan-axis-label"
          x={12}
          y={VIEW_SIZE / 2}
          textAnchor="middle"
          transform={`rotate(-90 12 ${VIEW_SIZE / 2})`}
        >
          North/South (ft) — north up
        </text>
        {drawableSegments.map((segment) => (
          <polyline
            key={`seg-${segment.segment}`}
            className={`plan-path ${segment.surveyType === "planned" ? "is-planned" : "is-actual"}`}
            data-segment={segment.segment}
            points={segment.stations.map((station) => `${toX(station.east_west_ft).toFixed(2)},${toY(station.north_south_ft).toFixed(2)}`).join(" ")}
          />
        ))}
        {drawableSegments.flatMap((segment) =>
          segment.stations.map((station, index) => (
            <g key={`marker-${segment.segment}-${index}`}>
              {segment.surveyType === "planned" ? (
                <rect
                  className="plan-marker is-planned"
                  x={toX(station.east_west_ft) - 3}
                  y={toY(station.north_south_ft) - 3}
                  width={6}
                  height={6}
                />
              ) : (
                <circle
                  className="plan-marker is-actual"
                  cx={toX(station.east_west_ft)}
                  cy={toY(station.north_south_ft)}
                  r={3.2}
                />
              )}
            </g>
          ))
        )}
        <g>
          <rect
            className="plan-anchor"
            x={toX(anchorStation.east_west_ft) - 5}
            y={toY(anchorStation.north_south_ft) - 5}
            width={10}
            height={10}
          />
          <text
            className="plan-anchor-label"
            x={toX(anchorStation.east_west_ft) + 8}
            y={toY(anchorStation.north_south_ft) - 8}
          >
            anchor · MD {formatFt(anchorStation.measured_depth_ft)} ft
          </text>
        </g>
      </svg>
      <ul className="trajectory-plan-legend" aria-label="Plan view legend">
        {typeLabels.map((label) => (
          <li key={label}>
            <span className={`legend-swatch ${label === "planned" ? "is-planned" : "is-actual"}`} aria-hidden="true" />
            {label === "untyped" ? "survey path" : `${label} path`}
            {label === "planned" ? " (dashed, square markers)" : " (solid, round markers)"}
          </li>
        ))}
        <li>
          <span className="legend-swatch is-anchor" aria-hidden="true" />
          anchor station
        </li>
      </ul>
    </figure>
  );
}
