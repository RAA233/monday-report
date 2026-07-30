import type { CSSProperties, ReactNode } from "react";

/**
 * Shared objects from the design handoff.
 *
 * The blueprint rule: framed objects are square (radius 0), transparent, hairline
 * bordered, and carry four "+" corner registration marks. That frame appears on
 * every card, panel, figure and empty state, so it lives here once.
 *
 * Status is never colour-alone — every status carries a word, and critical
 * additionally inverts to a solid accent-900 fill.
 */

/** Blueprint frame with its four corner registration marks. */
export function Frame({
  as: Tag = "div",
  children,
  style,
  ...rest
}: {
  as?: "div" | "section" | "article" | "aside" | "figure" | "form" | "main";
  children?: ReactNode;
  style?: CSSProperties;
} & Omit<React.HTMLAttributes<HTMLElement>, "style" | "children">) {
  return (
    <Tag className="blueprint" style={style} {...rest}>
      <i className="corner tl" />
      <i className="corner tr" />
      <i className="corner bl" />
      <i className="corner br" />
      {children}
    </Tag>
  );
}

/** The "MR" brand mark: a blueprint square with the monogram. */
export function BrandMark({ size = 34, fontSize = 14 }: { size?: number; fontSize?: number }) {
  return (
    <span
      className="blueprint"
      aria-hidden="true"
      style={{
        display: "grid",
        placeItems: "center",
        width: size,
        height: size,
        flex: "none",
        fontFamily: "var(--font-heading)",
        fontWeight: "var(--font-heading-weight)" as CSSProperties["fontWeight"],
        fontSize
      }}
    >
      <i className="corner tl" />
      <i className="corner tr" />
      <i className="corner bl" />
      <i className="corner br" />
      MR
    </span>
  );
}

export type TagTone = "accent" | "neutral" | "outline" | "critical";

/** Status tag. `critical` inverts to a solid fill so it never reads by hue alone. */
export function Tag({
  tone = "neutral",
  children,
  style
}: {
  tone?: TagTone;
  children: ReactNode;
  style?: CSSProperties;
}) {
  const toneClass =
    tone === "critical"
      ? "tag tag-critical"
      : tone === "accent"
        ? "tag tag-accent"
        : tone === "outline"
          ? "tag tag-outline"
          : "tag tag-neutral";
  return (
    <span className={toneClass} style={style}>
      {children}
    </span>
  );
}

/** Kicker + condensed uppercase H1 + optional lede. One H1 per page. */
export function PageHeader({
  kicker,
  title,
  lede,
  actions
}: {
  kicker?: string;
  title: string;
  lede?: string;
  actions?: ReactNode;
}) {
  return (
    <div
      data-pagehead=""
      style={{
        display: "flex",
        alignItems: "end",
        justifyContent: "space-between",
        gap: 16,
        flexWrap: "wrap"
      }}
    >
      <div>
        {kicker ? <span className="mr-kicker">{kicker}</span> : null}
        {/* tabIndex -1 so the route-change hook can move focus here without
            making the heading a tab stop. */}
        <h1 className="mr-title" tabIndex={-1}>
          {title}
        </h1>
        {lede ? (
          <p className="text-muted mr-lede">{lede}</p>
        ) : null}
      </div>
      {actions ? <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>{actions}</div> : null}
    </div>
  );
}

export interface CellSpec {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  /** Renders a check (met) or a dashed ring (gap) beside the label. */
  ok?: boolean;
}

/** Hairline cell grid — the handoff's primary way of showing facts and readiness. */
export function Cells({
  items,
  min = 150,
  label,
  style
}: {
  items: CellSpec[];
  min?: number;
  label?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      className="mr-cells"
      // role=group so the aria-label is actually exposed: a name on a plain <div>
      // with no role is dropped by assistive technology.
      {...(label ? { role: "group", "aria-label": label } : {})}
      style={{ gridTemplateColumns: `repeat(auto-fit, minmax(min(${min}px, 100%), 1fr))`, ...style }}
    >
      {items.map((item) => (
        <div className="mr-cell" key={item.label}>
          <span
            className="mr-cell-label"
            style={{ display: "flex", alignItems: "center", gap: 6 }}
          >
            {item.ok === true ? <CheckGlyph /> : null}
            {item.ok === false ? <GapGlyph /> : null}
            {item.label}
          </span>
          <strong className="mr-cell-value">{item.value}</strong>
          {item.detail ? <span className="mr-cell-detail">{item.detail}</span> : null}
        </div>
      ))}
    </div>
  );
}

function CheckGlyph() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" strokeWidth={2.2} aria-hidden="true">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

function GapGlyph() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--color-neutral-600)" strokeWidth={2} aria-hidden="true">
      <circle cx="12" cy="12" r="9" strokeDasharray="3 3" />
    </svg>
  );
}

/**
 * Grid-table. `role="table"` with an explicit column template, horizontally
 * scrollable inside its own container so the page never overflows sideways.
 */
export function GridTable({
  columns,
  template,
  label,
  minWidth = 720,
  children
}: {
  columns: string[];
  template: string;
  label: string;
  minWidth?: number;
  children: ReactNode;
}) {
  return (
    <div className="mr-scroll-x">
      <div role="table" aria-label={label} style={{ minWidth }}>
        <div role="row" className="mr-table-head" style={{ gridTemplateColumns: template }}>
          {columns.map((column, index) => (
            <span
              role="columnheader"
              key={`${column}-${index}`}
              aria-label={column === "" ? "Actions" : undefined}
            >
              {column}
            </span>
          ))}
        </div>
        {children}
      </div>
    </div>
  );
}

export function GridRow({ template, children }: { template: string; children: ReactNode }) {
  return (
    <div role="row" className="mr-table-row" style={{ gridTemplateColumns: template }}>
      {children}
    </div>
  );
}

export function GridCell({ children, style }: { children?: ReactNode; style?: CSSProperties }) {
  return (
    <span role="cell" style={style}>
      {children}
    </span>
  );
}

/** Layout-preserving skeleton. The pulse is disabled under reduced motion. */
export function Skeleton({ rows = 3, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div data-skeleton="" role="status" aria-live="polite" style={{ display: "grid", gap: 8 }}>
      <span className="mr-visually-hidden">{label}</span>
      {Array.from({ length: rows }, (_, index) => (
        <div className="mr-skeleton-row" key={index} />
      ))}
    </div>
  );
}

/** Empty state — states what is absent and offers the action that resolves it. */
export function EmptyState({
  title,
  body,
  action
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <Frame
      style={{
        display: "grid",
        placeItems: "center",
        gap: 10,
        padding: "56px 20px",
        textAlign: "center"
      }}
    >
      <strong
        style={{
          fontFamily: "var(--font-heading)",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          fontSize: 17
        }}
      >
        {title}
      </strong>
      <p className="text-muted" style={{ fontSize: 13, margin: 0, maxWidth: "46ch" }}>
        {body}
      </p>
      {action}
    </Frame>
  );
}

/**
 * Error state. Clear language, a retry, and no raw backend detail beyond the
 * short message the API client already sanitised.
 */
export function ErrorState({
  title,
  message,
  onRetry
}: {
  title: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <Frame role="alert" style={{ display: "grid", gap: 6, padding: 20 }}>
      <strong
        style={{
          fontFamily: "var(--font-heading)",
          textTransform: "uppercase",
          letterSpacing: "0.04em"
        }}
      >
        {title}
      </strong>
      <span style={{ fontSize: 13 }}>{message}</span>
      {onRetry ? (
        <button type="button" className="btn btn-secondary" style={{ justifySelf: "start" }} onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </Frame>
  );
}

/**
 * Segmented control — always a native radiogroup.
 *
 * An earlier version accepted role="tablist" and put role="tab" on the <label>
 * wrapping each radio. That is an invalid ARIA composition: a tab may not contain
 * a focusable widget, and the tablist had no tabpanel, no roving tabindex, and no
 * arrow-key handling of its own. Native radios already give arrow-key selection,
 * correct checked-state announcement, and label association, so the tab variant is
 * gone rather than half-implemented.
 */
export function SegControl<T extends string>({
  name,
  label,
  options,
  value,
  onChange
}: {
  name: string;
  label: string;
  options: Array<{ id: T; label: string }>;
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="seg" role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <label className="seg-opt" key={option.id}>
          <input
            type="radio"
            name={name}
            checked={option.id === value}
            onChange={() => onChange(option.id)}
          />
          {option.label}
        </label>
      ))}
    </div>
  );
}

/** Status line with an icon-free word so meaning survives without colour. */
export function StatusLine({
  tone = "neutral",
  children
}: {
  tone?: "neutral" | "alert";
  children: ReactNode;
}) {
  return (
    <span
      role="status"
      style={{
        fontSize: 12.5,
        fontFamily: "var(--font-heading)",
        color: tone === "alert" ? "var(--color-accent-800)" : "var(--color-neutral-700)"
      }}
    >
      {children}
    </span>
  );
}
