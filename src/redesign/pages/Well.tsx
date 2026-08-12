import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { getReportDraft, type ApiReportDraft } from "../../lib/api";
import { CasingSchematic } from "../components/CasingSchematic";
import { TrajectoryPlan, TrajectoryProfile } from "../components/trajectory";
import {
  Cells,
  EmptyState,
  ErrorState,
  Frame,
  GridCell,
  GridRow,
  GridTable,
  PageHeader,
  StatusLine,
  Tag,
  useRetryPresence
} from "../components/primitives";
import { apiUnreadReason, errorText, useWorkspace } from "../lib/workspace";

/**
 * Well schematics.
 *
 * Everything on this page comes from ONE explicit read: `GET
 * /workspaces/{id}/report-draft`, the same evidence payload the Studio drafts
 * from. That endpoint calls `store.audit("report_draft.generate")` — it WRITES an
 * audit event — so this page NEVER fetches it on mount or navigation. The
 * schematic, tables and trajectory figures render only after the operator asks
 * for the evidence, and the button says what asking records.
 *
 * Provenance is never collapsed: casing rows tag source vs reference, survey
 * stations carry their page/confidence or a conflict flag, and the trajectory
 * figures repeat the backend's own review-required framing.
 */
const CASING_TEMPLATE = "1.3fr 0.7fr 0.7fr 0.7fr 0.9fr 120px";
const SURVEY_TEMPLATE = "0.9fr 0.8fr 0.6fr 0.6fr 0.8fr 0.8fr 0.8fr 140px";

function ft(value: number | null | undefined): string {
  return value == null ? "—" : Math.round(value).toLocaleString();
}

function deg(value: number | null | undefined): string {
  return value == null ? "—" : `${value.toFixed(1)}°`;
}

function conf(value: number | null | undefined): string {
  return value == null ? "" : ` · ${Math.round(value * 100)}%`;
}

export function Well() {
  const { activeWorkspace, apiStatus, can } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;
  const workspaceIdRef = useRef(workspaceId);
  workspaceIdRef.current = workspaceId;
  const canRead = can("view_reports");

  const [draft, setDraft] = useState<ApiReportDraft | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [message, setMessage] = useState("");
  const loadInFlight = useRef<string | null>(null);

  const loadEvidence = useCallback(async () => {
    if (!workspaceId) {
      setState("error");
      setMessage("No workspace is selected, so there is no well evidence to load.");
      return;
    }
    // aria-disabled keeps the button focusable while loading, so the handler is
    // what makes it inert: a second Enter must not append a second
    // report_draft.generate audit event for one operator intent.
    if (loadInFlight.current === workspaceId) return;
    const askedFor = workspaceId;
    loadInFlight.current = askedFor;
    setState("loading");
    setMessage("Reading the workspace's parsed evidence…");
    try {
      const next = await getReportDraft(askedFor);
      if (askedFor !== workspaceIdRef.current) return;
      setDraft(next);
      setState("ready");
      setMessage(
        `Evidence loaded from ${next.source_document_count} document(s) and ${next.citation_count} citation(s). The read was recorded in the audit chain.`
      );
    } catch (caught) {
      if (askedFor !== workspaceIdRef.current) return;
      setState("error");
      setMessage(`The well evidence was not loaded. ${errorText(caught)}`);
    } finally {
      if (loadInFlight.current === askedFor) loadInFlight.current = null;
    }
  }, [workspaceId]);

  // The loaded evidence is workspace-scoped; a workspace change drops it rather
  // than rendering workspace A's well under workspace B's name. Same rule as the
  // Studio: only a REAL change (both ids present and different) resets.
  const previousWorkspaceIdRef = useRef<string | null>(workspaceId);
  useEffect(() => {
    const previous = previousWorkspaceIdRef.current;
    previousWorkspaceIdRef.current = workspaceId;
    if (previous === null || workspaceId === null || previous === workspaceId) return;
    setDraft(null);
    setState("idle");
    setMessage("");
  }, [workspaceId]);

  const retry = useRetryPresence(state);
  const casing = draft?.casing_strings ?? [];
  const casingSourceRows = casing.filter((row) => row.source === "source").length;
  const stations = draft?.survey_stations ?? [];
  const trajectory = draft?.trajectory ?? null;

  return (
    <>
      <PageHeader
        kicker={`Well evidence · ${activeWorkspace?.name ?? "no workspace"}`}
        title="Well schematics"
        lede="The casing program, directional survey and calculated trajectory from this workspace's parsed evidence — the same payload the Report Studio drafts from. Loading it is an audited action (the backend records report_draft.generate), so nothing is fetched until you ask."
        actions={
          <>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void loadEvidence()}
              disabled={apiStatus !== "connected" || !canRead}
              aria-disabled={state === "loading" || undefined}
            >
              {state === "loading" ? "Loading evidence…" : "Load well evidence"}
            </button>
            <Link className="btn btn-secondary" to="/app/studio">
              Report Studio
            </Link>
          </>
        }
      />

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          flexWrap: "wrap",
          border: "1px solid var(--color-divider)",
          padding: "10px 14px"
        }}
      >
        <StatusLine tone={state === "error" ? "alert" : "neutral"}>
          {state === "error"
            ? "The evidence was not loaded — see the message below."
            : message ||
              "Loading pulls this workspace's parsed evidence and is recorded in the audit chain, so it runs only when you ask for it."}
        </StatusLine>
      </div>

      {apiStatus !== "connected" && apiStatus !== "checking" ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          {apiUnreadReason(apiStatus)}, so no well evidence can be read here.
        </p>
      ) : null}

      {apiStatus === "connected" && !canRead ? (
        <ErrorState
          title="Well evidence not visible to this session"
          message="This session lacks the view_reports permission, which GET /workspaces/{id}/report-draft requires, so the well evidence cannot be read here. This is not a statement that the workspace holds no evidence — ask a workspace admin for report access."
        />
      ) : null}

      {retry.show ? (
        <ErrorState
          title="Well evidence not loaded"
          message={retry.retrying ? "The evidence is being read again." : message}
          onRetry={() => void loadEvidence()}
          retrying={retry.retrying}
        />
      ) : null}

      {state === "idle" && apiStatus === "connected" && canRead ? (
        <EmptyState
          title="No evidence loaded yet"
          body="Nothing on this page reflects workspace data until you load it. Loading reads the workspace's parsed evidence through the draft endpoint, which appends one report_draft.generate event to the audit chain."
          action={
            <button type="button" className="btn btn-primary" onClick={() => void loadEvidence()}>
              Load well evidence
            </button>
          }
        />
      ) : null}

      {draft ? (
        <>
          <Cells
            label="Well header from the loaded evidence"
            min={110}
            items={[
              { label: "Well", value: draft.well || "—" },
              { label: "Rig", value: draft.rig || "—" },
              { label: "Hole", value: draft.hole_size || "—" },
              { label: "MD", value: draft.md_ft || "—" },
              { label: "TVD", value: draft.tvd_ft || "—" },
              { label: "Mud", value: draft.mud_weight || "—" },
              {
                label: "Casing",
                value: casing.length === 0 ? "None" : `${casing.length} strings`,
                detail:
                  casing.length === 0
                    ? "No casing rows in the evidence"
                    : casingSourceRows === casing.length
                      ? "All rows from source evidence"
                      : casingSourceRows === 0
                        ? "All rows are labelled reference values, not evidence"
                        : `${casingSourceRows} of ${casing.length} rows from source; the rest are labelled reference`,
                ok: casing.length > 0 && casingSourceRows === casing.length
              },
              {
                label: "Survey",
                value: draft.survey_source === "source" ? `${stations.length} stations` : "None",
                detail:
                  draft.trajectory_source === "calculated"
                    ? "Calculated · minimum curvature · review required · not certified"
                    : "No trajectory calculated",
                ok: draft.survey_source === "source"
              }
            ]}
          />

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(min(420px,100%),1fr))",
              gap: 24,
              alignItems: "start"
            }}
          >
            <Frame as="section" aria-label="Casing schematic" style={{ padding: 18, display: "grid", gap: 12 }}>
              <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
                Casing schematic
              </h2>
              {casing.length > 0 ? (
                <>
                  <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
                    {casingSourceRows === casing.length
                      ? "Casing strings derived from source evidence — the table shows page and confidence per row."
                      : casingSourceRows === 0
                        ? "Every casing row is a labelled reference value, not extracted evidence — confirm from the DDR before relying on this figure."
                        : `${casingSourceRows} of ${casing.length} rows are source-derived; dashed strings are labelled reference values.`}
                  </p>
                  <CasingSchematic
                    casing={casing}
                    currentMdFt={(() => {
                      const parsed = Number.parseFloat((draft.md_ft || "").replace(/[^\d.]/g, ""));
                      return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
                    })()}
                  />
                </>
              ) : (
                <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                  The loaded evidence carries no casing rows, so there is nothing to draw.
                </p>
              )}
            </Frame>

            <Frame as="section" aria-label="Casing program" style={{ padding: 18, display: "grid", gap: 12 }}>
              <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
                Casing program
              </h2>
              {casing.length > 0 ? (
                <GridTable
                  label="Casing strings"
                  columns={["String", "OD", "Top", "Shoe", "Status", "Evidence"]}
                  template={CASING_TEMPLATE}
                  minWidth={520}
                >
                  {casing.map((row, index) => (
                    <GridRow template={CASING_TEMPLATE} key={`${row.name}-${index}`}>
                      <GridCell>{row.name}</GridCell>
                      <GridCell>{row.od ?? "—"}</GridCell>
                      <GridCell>{ft(row.top_ft)}</GridCell>
                      <GridCell>{ft(row.shoe_ft)}</GridCell>
                      <GridCell>{row.status ?? "—"}</GridCell>
                      <GridCell>
                        <Tag tone={row.source === "source" ? "accent" : "outline"}>
                          {row.source === "source"
                            ? `p. ${row.page ?? "—"}${conf(row.confidence)}`
                            : "reference"}
                        </Tag>
                      </GridCell>
                    </GridRow>
                  ))}
                </GridTable>
              ) : (
                <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                  No casing rows in the loaded evidence.
                </p>
              )}
            </Frame>
          </div>

          <Frame as="section" aria-label="Directional survey" style={{ padding: 18, display: "grid", gap: 12 }}>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
              Directional survey
            </h2>
            {stations.length > 0 ? (
              <>
                <p className="text-muted" style={{ fontSize: 12, margin: 0 }}>
                  Survey stations extracted from source evidence — source values are never overwritten
                  by calculations. Calculated columns come from the backend's minimum-curvature run and
                  are review-required, not certified.
                </p>
                <GridTable
                  label="Survey stations"
                  columns={["Station", "MD", "Inc", "Azi", "TVD source", "TVD calc", "Type", "Evidence"]}
                  template={SURVEY_TEMPLATE}
                  minWidth={640}
                >
                  {stations.map((station, index) => {
                    const calculated = trajectory?.stations.find((candidate) =>
                      station.station_id != null && candidate.source_station_id != null
                        ? candidate.source_station_id === station.station_id
                        : Math.abs(candidate.measured_depth_ft - station.measured_depth_ft) < 0.01
                    );
                    const tvdRelative =
                      calculated?.coordinate_reference.tvd === "relative_first_station";
                    return (
                      <GridRow
                        template={SURVEY_TEMPLATE}
                        key={`${station.station_id ?? station.measured_depth_ft}-${index}`}
                      >
                        <GridCell>{station.station_id || `#${index + 1}`}</GridCell>
                        <GridCell>{ft(station.measured_depth_ft)}</GridCell>
                        <GridCell>{deg(station.inclination_deg)}</GridCell>
                        <GridCell>{deg(station.azimuth_deg)}</GridCell>
                        <GridCell>{ft(station.true_vertical_depth_ft)}</GridCell>
                        <GridCell>
                          {calculated
                            ? tvdRelative
                              ? `+${ft(calculated.tvd_ft)} rel.`
                              : ft(calculated.tvd_ft)
                            : "—"}
                        </GridCell>
                        <GridCell>{station.survey_type || "—"}</GridCell>
                        <GridCell>
                          {station.conflict ? (
                            <Tag tone="critical">conflict — review</Tag>
                          ) : (
                            <Tag tone="accent">{`p. ${station.page ?? "—"}${conf(station.confidence)}`}</Tag>
                          )}
                        </GridCell>
                      </GridRow>
                    );
                  })}
                </GridTable>
                {trajectory &&
                (trajectory.stations ?? []).some(
                  (candidate) => candidate.coordinate_reference.tvd === "relative_first_station"
                ) ? (
                  <p className="text-muted" style={{ fontSize: 11.5, margin: 0 }}>
                    Rows marked "rel." are offsets from the first station of their own calculated
                    segment, not absolute well coordinates: that segment began without a source TVD to
                    anchor to.
                  </p>
                ) : null}
              </>
            ) : (
              <p className="text-muted" style={{ fontSize: 13, margin: 0 }}>
                The loaded evidence carries no source survey stations, so no survey or trajectory is
                shown.
              </p>
            )}
          </Frame>

          {trajectory && trajectory.stations.length > 0 ? (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit,minmax(min(380px,100%),1fr))",
                gap: 24,
                alignItems: "start"
              }}
            >
              <Frame as="section" aria-label="Trajectory plan view" style={{ padding: 18 }}>
                <TrajectoryPlan trajectory={trajectory} />
              </Frame>
              <Frame as="section" aria-label="Trajectory vertical profile" style={{ padding: 18 }}>
                <TrajectoryProfile trajectory={trajectory} />
              </Frame>
            </div>
          ) : null}
        </>
      ) : null}
    </>
  );
}
