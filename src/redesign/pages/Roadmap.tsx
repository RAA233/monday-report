import {
  capabilitySignals,
  releaseGates,
  roadmapExecutionBoard,
  roadmapLanes,
  roadmapRisks,
  type RoadmapStatus
} from "../../data/productRoadmap";
import { Cells, Frame, GridCell, GridRow, GridTable, PageHeader, Tag } from "../components/primitives";

/**
 * Product roadmap — ported from the v1 interface on the owner's instruction.
 *
 * Everything on this page is the COMMITTED narrative record in
 * `src/data/productRoadmap.ts`: lanes, gates, risks and signals describe the
 * program as checked in, not a live workspace read, and the page says so. No
 * API request is issued here and no claim depends on one.
 */
const GATE_TEMPLATE = "0.4fr 1.2fr 0.7fr 1.3fr 1.4fr";

function statusTone(status: RoadmapStatus): "accent" | "neutral" | "outline" {
  if (status === "complete") return "accent";
  if (status === "active" || status === "watch") return "neutral";
  return "outline";
}

export function Roadmap() {
  const itemCount = roadmapLanes.reduce((total, lane) => total + lane.items.length, 0);
  const activeCount = roadmapLanes.reduce(
    (total, lane) => total + lane.items.filter((item) => item.status === "active").length,
    0
  );
  const queuedCount = roadmapLanes.reduce(
    (total, lane) => total + lane.items.filter((item) => item.status === "queued").length,
    0
  );
  const completeCount = roadmapLanes.reduce(
    (total, lane) => total + lane.items.filter((item) => item.status === "complete").length,
    0
  );

  return (
    <>
      <PageHeader
        kicker="Program"
        title="Product roadmap"
        lede="The delivery path for Monday Report as checked into the repository. Everything on this page is the committed narrative record in src/data/productRoadmap.ts — it describes the program, not live workspace data, and this page issues no API read."
        actions={<Tag tone="outline">Committed record</Tag>}
      />

      <Cells
        label="Committed roadmap summary"
        min={140}
        items={[
          { label: "Roadmap items", value: String(itemCount), detail: "Tracked work packages" },
          { label: "Complete", value: String(completeCount), detail: "Accepted in the record" },
          { label: "Active build", value: String(activeCount), detail: "In execution" },
          { label: "Queued next", value: String(queuedCount), detail: "Ready for phase pull" }
        ]}
      />

      <Frame as="section" aria-label="Capability signals" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Capability signals
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(220px,100%),1fr))",
            gap: 14
          }}
        >
          {capabilitySignals.map((signal) => (
            <article
              key={signal.id}
              style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 6, alignContent: "start" }}
            >
              <span className="text-muted" style={{ fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase" }}>
                {signal.label}
              </span>
              <strong style={{ fontFamily: "var(--font-heading)", fontSize: 16 }}>{signal.value}</strong>
              <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.5, margin: 0 }}>{signal.detail}</p>
            </article>
          ))}
        </div>
      </Frame>

      <Frame as="section" aria-label="Roadmap execution board" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Next controlled moves
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(260px,100%),1fr))",
            gap: 14
          }}
        >
          {roadmapExecutionBoard.map((item) => (
            <article
              key={item.id}
              style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 6, alignContent: "start" }}
            >
              <span className="text-muted" style={{ fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase" }}>
                {item.label}
              </span>
              <strong style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>{item.value}</strong>
              <p style={{ fontSize: 12.5, lineHeight: 1.5, margin: 0 }}>{item.detail}</p>
              <code style={{ fontSize: 11.5, overflowWrap: "anywhere" }}>{item.command}</code>
            </article>
          ))}
        </div>
      </Frame>

      <Frame as="section" aria-label="Delivery lanes" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Delivery lanes
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(300px,100%),1fr))",
            gap: 14,
            alignItems: "start"
          }}
        >
          {roadmapLanes.map((lane) => (
            <article
              key={lane.id}
              style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 10, alignContent: "start" }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap" }}>
                <div>
                  <strong style={{ fontFamily: "var(--font-heading)", fontSize: 15 }}>{lane.label}</strong>
                  <p className="text-muted" style={{ fontSize: 12, margin: "2px 0 0" }}>{lane.intent}</p>
                </div>
                <Tag tone={statusTone(lane.status)}>{lane.status.replace(/_/g, " ")}</Tag>
              </div>
              {lane.items.map((item) => (
                <div
                  key={item.id}
                  style={{ borderInlineStart: "2px solid var(--color-divider)", paddingInlineStart: 12, display: "grid", gap: 4 }}
                >
                  <span style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                    <strong style={{ fontSize: 13 }}>{item.title}</strong>
                    <Tag tone={statusTone(item.status)}>{item.status}</Tag>
                  </span>
                  <span className="text-muted" style={{ fontSize: 11.5 }}>
                    Owner: {item.owner} · Gate: {item.gate}
                  </span>
                  <span style={{ fontSize: 12, lineHeight: 1.5 }}>{item.evidence}</span>
                  <span className="text-muted" style={{ fontSize: 11.5 }}>{item.next}</span>
                </div>
              ))}
            </article>
          ))}
        </div>
      </Frame>

      <Frame as="section" aria-label="Release train" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Release train
        </h2>
        <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "80ch" }}>
          Gate statuses describe the committed record's account of each gate, not a run this page
          performed.
        </p>
        <GridTable
          label="Release gates"
          columns={["#", "Gate", "Status", "Command", "Recorded evidence"]}
          template={GATE_TEMPLATE}
          minWidth={760}
        >
          {releaseGates.map((gate, index) => (
            <GridRow template={GATE_TEMPLATE} key={gate.id}>
              <GridCell>{index + 1}</GridCell>
              <GridCell>{gate.label}</GridCell>
              <GridCell>
                <Tag tone={statusTone(gate.status)}>{gate.status}</Tag>
              </GridCell>
              <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                <code style={{ fontSize: 11.5 }}>{gate.command}</code>
              </GridCell>
              <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>{gate.evidence}</GridCell>
            </GridRow>
          ))}
        </GridTable>
      </Frame>

      <Frame as="section" aria-label="Roadmap risk controls" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Risk controls
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(280px,100%),1fr))",
            gap: 14
          }}
        >
          {roadmapRisks.map((risk) => (
            <article
              key={risk.id}
              style={{ border: "1px solid var(--color-divider)", padding: "12px 14px", display: "grid", gap: 6, alignContent: "start" }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap" }}>
                <strong style={{ fontFamily: "var(--font-heading)", fontSize: 13.5 }}>{risk.risk}</strong>
                <Tag tone={risk.severity === "high" ? "critical" : risk.severity === "medium" ? "neutral" : "outline"}>
                  {risk.severity}
                </Tag>
              </div>
              <p style={{ fontSize: 12.5, lineHeight: 1.5, margin: 0 }}>{risk.control}</p>
              <span className="text-muted" style={{ fontSize: 11.5 }}>{risk.owner}</span>
            </article>
          ))}
        </div>
      </Frame>
    </>
  );
}
