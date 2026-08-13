import type { JSX } from "react";
import type { ApiCasingString } from "../../lib/api";

/**
 * Casing depth schematic, drawn from the draft's own casing rows.
 *
 * Every rectangle is one casing string between its top and shoe depth. Provenance
 * is carried in the LINE ITSELF, not colour alone: a solid outline is a
 * source-derived row, a dashed outline is a labelled reference value — the same
 * distinction the table beside this figure spells out per row, so the figure can
 * never claim more than its rows do. Strings without a usable shoe depth are
 * listed as undrawable rather than silently dropped.
 */
const VIEW_W = 360;
const VIEW_H = 360;
const TOP_Y = 36;
const AXIS_H = 280;

export function CasingSchematic({
  casing,
  currentMdFt
}: {
  casing: ApiCasingString[];
  currentMdFt: number | null;
}): JSX.Element {
  const drawable = casing.filter(
    (row) => typeof row.shoe_ft === "number" && Number.isFinite(row.shoe_ft) && row.shoe_ft > 0
  );
  const undrawable = casing.filter((row) => !drawable.includes(row));
  const maxDepth = Math.max(
    currentMdFt ?? 0,
    ...drawable.map((row) => row.shoe_ft as number),
    1000
  );
  const toY = (depthFt: number): number => TOP_Y + (Math.max(0, depthFt) / maxDepth) * AXIS_H;

  const description =
    `Casing depth schematic: ${drawable.length} drawable string(s) to ${Math.round(maxDepth).toLocaleString()} ft. ` +
    drawable
      .map(
        (row) =>
          `${row.name} ${row.od ?? "OD not stated"} from ${Math.round(row.top_ft ?? 0)} to ${Math.round(
            row.shoe_ft ?? 0
          )} ft (${row.source === "source" ? "source-derived" : "reference value"})`
      )
      .join("; ") +
    (currentMdFt ? `. Current MD marker at ${Math.round(currentMdFt).toLocaleString()} ft.` : ".");

  return (
    <div style={{ display: "grid", gap: 6 }}>
      <svg
        className="mr-plan-svg mr-casing-svg"
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        role="img"
        aria-label="Casing depth schematic"
      >
        <title>Casing depth schematic</title>
        <desc>{description}</desc>
        <rect className="mr-plan-frame" x="1" y="1" width={VIEW_W - 2} height={VIEW_H - 2} />
        <line className="mr-casing-axis" x1={44} y1={TOP_Y} x2={44} y2={TOP_Y + AXIS_H} />
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => {
          const y = TOP_Y + tick * AXIS_H;
          return (
            <g key={tick}>
              <line className="mr-plan-grid" x1={36} y1={y} x2={VIEW_W - 38} y2={y} />
              <text className="mr-plan-tick" x={50} y={y - 4}>
                {Math.round(maxDepth * tick).toLocaleString()} ft
              </text>
            </g>
          );
        })}
        {drawable.map((row, index) => {
          const top = toY(row.top_ft ?? 0);
          const shoe = toY(Math.max(row.shoe_ft as number, (row.top_ft ?? 0) + 100));
          const width = Math.max(44, 170 - index * 28);
          const x = 178 - width / 2;
          return (
            <g key={`${row.name}-${index}`}>
              <rect
                className={`mr-casing-string ${row.source === "source" ? "is-source" : "is-reference"}`}
                x={x}
                y={top}
                width={width}
                height={Math.max(18, shoe - top)}
              />
              <text className="mr-plan-tick" x={266} y={Math.min(shoe, TOP_Y + AXIS_H + 6)}>
                {row.name}
              </text>
              <text
                className="mr-plan-tick"
                x={266}
                y={Math.min(shoe + 13, TOP_Y + AXIS_H + 19)}
              >
                {[row.od, row.status].filter(Boolean).join(" / ") || "—"}
              </text>
            </g>
          );
        })}
        {currentMdFt !== null && currentMdFt > 0 ? (
          <g>
            <line
              className="mr-casing-md"
              x1={68}
              x2={VIEW_W - 54}
              y1={toY(currentMdFt)}
              y2={toY(currentMdFt)}
            />
            <text className="mr-plan-anchor-label" x={188} y={toY(currentMdFt) - 4}>
              Current MD
            </text>
          </g>
        ) : null}
      </svg>
      <ul className="mr-plan-legend" aria-label="Casing schematic legend">
        <li>
          <span className="mr-plan-swatch is-actual" aria-hidden="true" />
          source-derived string (solid)
        </li>
        <li>
          <span className="mr-plan-swatch is-planned" aria-hidden="true" />
          reference value (dashed) — confirm from DDR
        </li>
      </ul>
      {undrawable.length > 0 ? (
        <p className="text-muted" style={{ fontSize: 11.5, margin: 0 }}>
          {undrawable.length} casing row(s) carry no usable shoe depth and are listed in the table
          only: {undrawable.map((row) => row.name).join(", ")}.
        </p>
      ) : null}
    </div>
  );
}
