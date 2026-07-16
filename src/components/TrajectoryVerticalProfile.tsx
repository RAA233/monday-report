import type { JSX } from "react";
import type {
  ApiCalculatedTrajectoryStation,
  ApiTrajectoryCalculation
} from "../lib/api";
import { DISPLAY_EPSILON_FT, formatFt, niceTickStep, tickValues } from "../lib/trajectoryGeometry";

interface TrajectoryVerticalProfileProps {
  trajectory: ApiTrajectoryCalculation;
}

interface ProfileSegment {
  segment: number;
  surveyType: string | null;
  stations: ApiCalculatedTrajectoryStation[];
}

const PANEL_WIDTH = 300;
const PANEL_HEIGHT = 300;
const PADDING = 46;

export function TrajectoryVerticalProfile({ trajectory }: TrajectoryVerticalProfileProps): JSX.Element | null {
  const displayable = trajectory.stations.filter(
    (station) =>
      Number.isFinite(station.tvd_ft) && Number.isFinite(station.horizontal_displacement_ft)
  );
  const segments: ProfileSegment[] = [];
  for (const station of displayable) {
    const existing = segments.find((item) => item.segment === station.segment);
    if (existing) {
      existing.stations.push(station);
    } else {
      segments.push({ segment: station.segment, surveyType: station.survey_type ?? null, stations: [station] });
    }
  }
  const drawableSegments = segments.filter((item) => item.stations.length >= 2);
  if (drawableSegments.length === 0) {
    return null;
  }

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
    <div className="trajectory-profile-block">
      <p className="trajectory-plan-caption">
        Vertical trajectory profile (HD vs TVD) · Calculated · minimum curvature {trajectory.method_version} · review required
      </p>
      <p className="trajectory-plan-note" role="note">
        Horizontal displacement is calculated from this segment’s first calculated station —
        an unsigned magnitude, never an absolute or east/west position (direction is shown in
        the plan view). {tvdReferenceLabel}.{" "}
        {lateralRelative ? "Underlying N/S and E/W coordinates are relative — not absolute well coordinates. " : ""}
        Calculated TVD increases downward. One panel per calculation segment — paths are never
        bridged. Not certified survey computation.
      </p>
      <div className="trajectory-profile-grid">
        {drawableSegments.map((segment) => (
          <SegmentProfilePanel
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

function SegmentProfilePanel({
  segment,
  methodVersion,
  tvdReferenceLabel
}: {
  segment: ProfileSegment;
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

  // Equal ft-per-pixel on both axes, letterboxed: the larger span sets the
  // scale and the smaller span simply uses less of the panel. Geometry is
  // never stretched to fill the box; numeric extents are always labelled.
  const drawableW = PANEL_WIDTH - 2 * PADDING;
  const drawableH = PANEL_HEIGHT - 2 * PADDING;
  const scale = Math.min(
    drawableW / Math.max(maxHd, DISPLAY_EPSILON_FT),
    drawableH / Math.max(spanTvd, DISPLAY_EPSILON_FT)
  );
  const toX = (hd: number): number => PADDING + hd * scale;
  const toY = (tvd: number): number => PADDING + (tvd - minTvd) * scale;

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
    <figure className="trajectory-profile-panel">
      <figcaption>
        Segment {segment.segment} · {typeLabel} path · {segment.stations.length} station(s)
      </figcaption>
      {zeroLateral && (
        <p className="trajectory-plan-note" role="note">
          Horizontal displacement is effectively zero; this profile represents calculated TVD progression.
        </p>
      )}
      <svg
        className="trajectory-vertical-profile"
        viewBox={`0 0 ${PANEL_WIDTH} ${PANEL_HEIGHT}`}
        role="img"
        aria-label={`Segment ${segment.segment} calculated vertical profile, review required`}
        data-segment={segment.segment}
      >
        <title>Segment {segment.segment} vertical profile (minimum curvature {methodVersion})</title>
        <desc>{description}</desc>
        <rect className="plan-frame" x="1" y="1" width={PANEL_WIDTH - 2} height={PANEL_HEIGHT - 2} />
        {hdTicks.map((tick) => (
          <g key={`hdt-${tick}`}>
            <line className="plan-grid" x1={toX(tick)} y1={PADDING - 6} x2={toX(tick)} y2={PANEL_HEIGHT - PADDING + 6} />
            <text className="plan-tick-label" x={toX(tick)} y={PANEL_HEIGHT - PADDING + 20} textAnchor="middle">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        {tvdTicks.map((tick) => (
          <g key={`tvt-${tick}`}>
            <line className="plan-grid" x1={PADDING - 6} y1={toY(tick)} x2={PANEL_WIDTH - PADDING + 6} y2={toY(tick)} />
            <text className="plan-tick-label" x={PADDING - 10} y={toY(tick) + 3} textAnchor="end">
              {formatFt(tick)}
            </text>
          </g>
        ))}
        <text className="plan-axis-label" x={PANEL_WIDTH / 2} y={PANEL_HEIGHT - 8} textAnchor="middle">
          HD from segment anchor (ft)
        </text>
        <text
          className="plan-axis-label"
          x={12}
          y={PANEL_HEIGHT / 2}
          textAnchor="middle"
          transform={`rotate(-90 12 ${PANEL_HEIGHT / 2})`}
        >
          Calculated TVD (ft) — increasing downward
        </text>
        <polyline
          className={`plan-path ${planned ? "is-planned" : "is-actual"}`}
          data-segment={segment.segment}
          points={segment.stations
            .map((station) => `${toX(station.horizontal_displacement_ft).toFixed(2)},${toY(station.tvd_ft).toFixed(2)}`)
            .join(" ")}
        />
        {segment.stations.map((station, index) =>
          planned ? (
            <rect
              key={`pm-${index}`}
              className="plan-marker is-planned"
              x={toX(station.horizontal_displacement_ft) - 3}
              y={toY(station.tvd_ft) - 3}
              width={6}
              height={6}
            />
          ) : (
            <circle
              key={`pm-${index}`}
              className="plan-marker is-actual"
              cx={toX(station.horizontal_displacement_ft)}
              cy={toY(station.tvd_ft)}
              r={3.2}
            />
          )
        )}
        <rect
          className="plan-anchor"
          x={toX(anchor.horizontal_displacement_ft) - 5}
          y={toY(anchor.tvd_ft) - 5}
          width={10}
          height={10}
        />
        <text className="plan-anchor-label" x={toX(anchor.horizontal_displacement_ft) + 8} y={toY(anchor.tvd_ft) - 8}>
          anchor · MD {formatFt(anchor.measured_depth_ft)} ft
        </text>
      </svg>
    </figure>
  );
}
