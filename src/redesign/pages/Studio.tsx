import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getReportDraft, type ApiReportDraft } from "../../lib/api";
import {
  reportFormatVariants,
  reportVariantSchemaVersion,
  type FormatVariantId
} from "../../data/reportVariantSchemas";
import { formatSourceCitation } from "../../lib/citationFormat";
import {
  Cells,
  ErrorState,
  Frame,
  PageHeader,
  SegControl,
  Skeleton,
  StatusLine,
  Tag,
  type CellSpec
} from "../components/primitives";
import { exportGateMessage, gateIsClear, gateIsClosed, gateLabel, useWorkspace } from "../lib/workspace";

/**
 * Report Studio.
 *
 * The five format variants come from `src/data/reportVariantSchemas.ts` — the
 * committed source of truth for MR-SCHEMA-1 — so the Studio cannot drift from the
 * schema the backend and the v1 interface share.
 *
 * The editor holds local edits only. This is deliberate and disclosed on screen:
 * the API records changes as field corrections against a target, and inventing a
 * "save draft" call that does not exist would be worse than saying so. A local edit
 * never rewrites the recorded source value.
 *
 * Per-FIELD provenance marking is not implemented: `ApiReportDraft` returns the
 * header/narrative fields as bare strings with no per-field source, so the editor
 * cannot mark them without inventing provenance. Provenance IS shown where the
 * payload carries it — the casing, survey and hydraulics rows tag `source` vs
 * `reference` and their conflict/review flags, and the readiness board reports the
 * source of each evidence class.
 */
interface FormState {
  reportDate: string;
  reportNo: string;
  well: string;
  rig: string;
  operator: string;
  phase: string;
  holeSize: string;
  mdFt: string;
  tvdFt: string;
  /**
   * As-drilled dogleg severity. Operator-entered and session-local: `ApiReportDraft`
   * carries no `dls` field, so this is never populated from evidence and never
   * presented as sourced. Preserved across a re-draft of the SAME workspace, and
   * cleared with the rest of the form when the workspace changes.
   */
  dls: string;
  mudWeight: string;
  presentOps: string;
  nextOps: string;
  safety: string;
  risks: string;
}

const EMPTY_FORM: FormState = {
  reportDate: "",
  reportNo: "",
  well: "",
  rig: "",
  operator: "",
  phase: "",
  holeSize: "",
  mdFt: "",
  tvdFt: "",
  dls: "",
  mudWeight: "",
  presentOps: "",
  nextOps: "",
  safety: "",
  risks: ""
};

/** Column templates for the preview sheet's evidence tables. */
const CASING_TEMPLATE = "1.3fr 0.7fr 0.7fr 0.7fr auto";
const SURVEY_TEMPLATE = "0.8fr 0.6fr 0.6fr 0.9fr 0.9fr auto";
const HYDRAULICS_TEMPLATE = "1fr 0.8fr 1.4fr auto";

/** Feet with a thousands separator, or an em dash when absent. */
function ft(value: number | null | undefined): string {
  return value == null ? "—" : Math.round(value).toLocaleString();
}

/** Degrees to one decimal, or an em dash when absent. */
function deg(value: number | null | undefined): string {
  return value == null ? "—" : `${value.toFixed(1)}°`;
}

/** " · 86%" for a present confidence, empty otherwise — never a fabricated number. */
function conf(value: number | null | undefined): string {
  return value == null ? "" : ` · ${Math.round(value * 100)}%`;
}

function formFromDraft(draft: ApiReportDraft, previous: FormState): FormState {
  return {
    reportDate: draft.report_date,
    reportNo: draft.report_no,
    well: draft.well,
    rig: draft.rig,
    operator: draft.operator,
    phase: draft.phase,
    holeSize: draft.hole_size,
    mdFt: draft.md_ft,
    tvdFt: draft.tvd_ft,
    // Not in the payload — preserve whatever the operator typed.
    dls: previous.dls,
    mudWeight: draft.mud_weight,
    presentOps: draft.present_ops,
    nextOps: draft.next_ops,
    safety: draft.safety,
    risks: draft.risks
  };
}

/** Percentage of the issue-critical fields that currently carry text. */
const COMPLETENESS_FIELDS: Array<keyof FormState> = [
  "reportDate",
  "reportNo",
  "well",
  "rig",
  "operator",
  "phase",
  "holeSize",
  "mdFt",
  "tvdFt",
  "mudWeight",
  "presentOps",
  "nextOps",
  "safety",
  "risks"
];

export function Studio() {
  const { reportId } = useParams();
  const navigate = useNavigate();
  const { activeWorkspace, gate, readOnly, can, apiStatus } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;
  const workspaceIdRef = useRef(workspaceId);
  workspaceIdRef.current = workspaceId;
  const canEdit = can("generate_reports") || can("record_field_corrections");

  const [variant, setVariant] = useState<FormatVariantId>("ddr");
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [draft, setDraft] = useState<ApiReportDraft | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [message, setMessage] = useState(
    "Source draft pulls parsed workspace evidence into this editable report."
  );
  const [editedKeys, setEditedKeys] = useState<Set<keyof FormState>>(new Set());

  const activeVariant = useMemo(
    () => reportFormatVariants.find((item) => item.id === variant) ?? reportFormatVariants[0],
    [variant]
  );

  const sourceDraft = useCallback(async () => {
    if (!workspaceId) {
      setState("error");
      setMessage("No workspace is selected, so there is no evidence to draft from.");
      return;
    }
    const askedFor = workspaceId;
    setState("loading");
    setMessage("Building a source-backed draft from parsed documents, citations, and validation tasks…");
    try {
      const next = await getReportDraft(askedFor);
      // A draft is workspace-scoped evidence. If the operator switched workspaces
      // while this was in flight, dropping it is the only correct outcome —
      // otherwise workspace A's well, citations and readiness render under B.
      if (askedFor !== workspaceIdRef.current) return;
      setDraft(next);
      setForm((previous) => formFromDraft(next, previous));
      setEditedKeys(new Set());
      setState("ready");
      setMessage(
        `Source-backed draft ready from ${next.source_document_count} document(s), ${next.source_chunk_count} chunk(s), and ${next.citation_count} citation(s).`
      );
    } catch (caught) {
      if (askedFor !== workspaceIdRef.current) return;
      setState("error");
      setMessage(
        caught instanceof Error && caught.message
          ? `The draft was not built. ${caught.message}`
          : "The draft was not built. The workspace API did not answer."
      );
    }
  }, [workspaceId]);

  // ONE effect for the workspace-scoped view: clear the previous workspace's draft
  // AND its form, then load. Two separate effects meant the clear ran after the
  // loader had already set "loading", cancelling the skeleton; and clearing only
  // `draft` left the previous workspace's well, rig and operator text on screen
  // under the new workspace's name.
  useEffect(() => {
    setDraft(null);
    setForm(EMPTY_FORM);
    setEditedKeys(new Set());
    if (workspaceId && apiStatus === "connected") {
      void sourceDraft();
    } else {
      setState("idle");
      setMessage("Source draft pulls parsed workspace evidence into this editable report.");
    }
  }, [workspaceId, apiStatus, sourceDraft]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setEditedKeys((current) => new Set(current).add(key));
  }

  // The gate is the backend's own report for this workspace, never re-derived.
  const gateBlocked = gateIsClosed(gate);
  const gateKnown = gate.state === "ready";
  const gateText = gateLabel(gate);

  /**
   * Issue readiness board — the handoff's six cells (Format, Source, Draft,
   * Completeness, Validation, Issue), computed live from the form AND the queue.
   * `form` is a dependency on purpose: the board is named for issue readiness, so
   * emptying a required section must change it on the next keystroke.
   */
  const readiness: CellSpec[] = useMemo(() => {
    const filled = COMPLETENESS_FIELDS.filter((key) => form[key].trim().length > 0).length;
    const completeness = Math.round((filled / COMPLETENESS_FIELDS.length) * 100);
    const narrativeReady =
      form.presentOps.trim().length > 0 && form.nextOps.trim().length > 0 && form.safety.trim().length > 0;
    const gateKnownAndClear = gateIsClear(gate);
    const issueReady = narrativeReady && completeness === 100 && gateKnownAndClear;

    return [
      {
        label: "Format",
        value: activeVariant.shortLabel,
        detail: `${activeVariant.label} · ${reportVariantSchemaVersion}`,
        ok: true
      },
      {
        label: "Source",
        value: draft ? `${draft.source_document_count} docs` : "Not loaded",
        detail: draft
          ? `${draft.source_chunk_count} chunk(s) · ${draft.citation_count} citation(s)`
          : "Build a source-backed draft",
        ok: Boolean(draft && draft.source_document_count > 0)
      },
      {
        label: "Draft",
        value: narrativeReady ? "Ready" : "Gaps",
        detail: narrativeReady
          ? "Operations, plan and safety all carry text"
          : "Present operations, next 24 hr and safety are required",
        ok: narrativeReady
      },
      {
        label: "Completeness",
        value: `${completeness}%`,
        detail: `${filled} of ${COMPLETENESS_FIELDS.length} report fields`,
        ok: completeness === 100
      },
      {
        label: "Validation",
        value: gateText,
        detail: !gateKnown
          ? "The backend gate could not be read — not a claim that it is clear"
          : gateBlocked
            ? "Export blocked until resolved"
            : "No open tasks for this workspace",
        ok: gateKnownAndClear
      },
      {
        label: "Issue",
        value: issueReady ? "Ready" : "Gated",
        detail: issueReady
          ? "Draft text complete and the gate is clear"
          : !gateKnownAndClear
            ? "Held by the validation gate"
            : "Held by incomplete draft fields",
        ok: issueReady
      }
    ];
  }, [activeVariant, draft, form, gate, gateBlocked, gateKnown, gateText]);

  /** Second row: what the loaded evidence actually contains. */
  const evidenceCells: CellSpec[] = useMemo(() => {
    if (!draft) return [];
    return [
      {
        label: "Casing",
        value: draft.schematic_source === "source" ? `${draft.casing_strings?.length ?? 0} strings` : "Reference",
        detail:
          draft.schematic_source === "source"
            ? "From source evidence"
            : "Labelled reference values, not evidence",
        ok: draft.schematic_source === "source"
      },
      {
        label: "Survey",
        value: draft.survey_source === "source" ? `${draft.survey_stations?.length ?? 0} stations` : "None",
        detail:
          draft.trajectory_source === "calculated"
            ? "Calculated · minimum curvature · review required · not certified"
            : "No trajectory calculated",
        ok: draft.survey_source === "source"
      },
      {
        label: "Hydraulics",
        value:
          draft.hydraulics_source === "source" ? `${draft.hydraulics_observations?.length ?? 0} obs` : "None",
        detail: draft.hydraulics_source === "source" ? "Extracted from source" : "No observations found",
        ok: draft.hydraulics_source === "source"
      },
      {
        label: "Failures",
        value: String(draft.failure_count),
        detail: `${draft.open_validation_tasks} open validation task(s) on this draft`,
        ok: draft.failure_count === 0 || draft.open_validation_tasks === 0
      }
    ];
  }, [draft]);

  return (
    <>
      {/* The draft is WORKSPACE-scoped: GET /workspaces/{id}/report-draft. Naming a
          report id here implied the Studio was showing that report's stored
          content, which it never reads. The report id (when the route carries one)
          is disclosed below as the issue target instead. */}
      <PageHeader
        kicker={`Report Studio · ${activeWorkspace?.name ?? "no workspace"} · ${reportVariantSchemaVersion}`}
        title={`${activeVariant.label} draft`}
        actions={
          <>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void sourceDraft()}
              disabled={state === "loading" || apiStatus !== "connected"}
            >
              {state === "loading" ? "Building draft…" : "Build source-backed draft"}
            </button>
            <Link className="btn btn-secondary" to="/app/exports">
              Exports
            </Link>
            <Link className="btn btn-secondary" to="/app/well">
              Well schematics
            </Link>
          </>
        }
      />

      {reportId ? (
        <p className="text-muted" style={{ fontSize: 12.5, margin: 0 }}>
          Issue target: report <code title={reportId}>{reportId}</code>. This draft is built from the
          workspace's parsed evidence, not from that report's stored content — the report is where an
          export is issued.
        </p>
      ) : null}

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
        <span
          style={{
            fontSize: 10.5,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            color: "var(--color-neutral-700)"
          }}
        >
          Format
        </span>
        <SegControl<FormatVariantId>
          name="mr-variant"
          label="Report format variants"
          value={variant}
          onChange={setVariant}
          options={reportFormatVariants.map((item) => ({ id: item.id, label: item.shortLabel }))}
        />
        <span style={{ fontSize: 13 }}>
          <strong style={{ fontFamily: "var(--font-heading)" }}>{activeVariant.label}</strong>{" "}
          <span className="text-muted">— {activeVariant.scope}</span>
        </span>
        <span style={{ marginInlineStart: "auto" }}>
          <StatusLine tone={state === "error" ? "alert" : "neutral"}>{message}</StatusLine>
        </span>
      </div>

      <Cells items={readiness} label="Issue readiness board" />

      {evidenceCells.length > 0 ? <Cells items={evidenceCells} label="Loaded evidence" /> : null}

      {state === "loading" && !draft ? <Skeleton rows={4} label="Building the draft" /> : null}

      {state === "error" ? (
        <ErrorState title="Draft not built" message={message} onRetry={() => void sourceDraft()} />
      ) : null}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(min(430px,100%),1fr))",
          gap: 24,
          alignItems: "start"
        }}
      >
        <Frame
          as="form"
          aria-label={`${activeVariant.label} editor`}
          style={{ padding: 18, display: "grid", gap: 14 }}
          onSubmit={(event) => event.preventDefault()}
        >
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            Report inputs
          </h2>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
              gap: 10
            }}
          >
            <Field id="st-date" label="Date" type="date" value={form.reportDate} onChange={(v) => update("reportDate", v)} disabled={readOnly} />
            <Field id="st-no" label="Report no." value={form.reportNo} onChange={(v) => update("reportNo", v)} disabled={readOnly} />
            <Field id="st-well" label="Well" value={form.well} onChange={(v) => update("well", v)} disabled={readOnly} />
            <Field id="st-rig" label="Rig" value={form.rig} onChange={(v) => update("rig", v)} disabled={readOnly} />
            <Field id="st-op" label="Operator" value={form.operator} onChange={(v) => update("operator", v)} disabled={readOnly} />
            <Field id="st-phase" label="Phase" value={form.phase} onChange={(v) => update("phase", v)} disabled={readOnly} />
            <Field id="st-hole" label="Hole size" value={form.holeSize} onChange={(v) => update("holeSize", v)} disabled={readOnly} />
            <Field id="st-md" label="MD ft" value={form.mdFt} onChange={(v) => update("mdFt", v)} disabled={readOnly} inputMode="decimal" />
            <Field id="st-tvd" label="TVD ft" value={form.tvdFt} onChange={(v) => update("tvdFt", v)} disabled={readOnly} inputMode="decimal" />
            <Field
              id="st-dls"
              label="As-drilled DLS"
              value={form.dls}
              onChange={(v) => update("dls", v)}
              disabled={readOnly}
              placeholder="1.3 deg/100 ft"
              hint="Operator-entered — the draft payload carries no DLS value."
            />
            <Field id="st-mud" label="Mud weight" value={form.mudWeight} onChange={(v) => update("mudWeight", v)} disabled={readOnly} />
          </div>

          <TextField id="st-present" label="Present operations" rows={3} value={form.presentOps} onChange={(v) => update("presentOps", v)} disabled={readOnly} />
          <TextField id="st-next" label="Next 24 hr plan" rows={3} value={form.nextOps} onChange={(v) => update("nextOps", v)} disabled={readOnly} />
          <TextField id="st-safety" label="Safety and well-control notes" rows={2} value={form.safety} onChange={(v) => update("safety", v)} disabled={readOnly} />
          <TextField id="st-risks" label="Risks and AI watchlist" rows={2} value={form.risks} onChange={(v) => update("risks", v)} disabled={readOnly} />

          {readOnly ? (
            <p
              className="text-muted"
              style={{ fontSize: 12, margin: 0, border: "1px solid var(--color-divider)", padding: "8px 10px" }}
            >
              Read-only: the workspace API is unreachable, so no edit can be recorded.
            </p>
          ) : (
            <p
              className="text-muted"
              style={{ fontSize: 12, margin: 0, border: "1px solid var(--color-divider)", padding: "8px 10px" }}
            >
              Edits here stay in this browser session. {editedKeys.size > 0 ? `${editedKeys.size} field(s) changed locally. ` : ""}
              Recording a change against the report requires a field correction with a written reason,
              which carries reviewer attribution into the audit chain — the recorded source value is
              never overwritten.
              {!canEdit ? (
                <>
                  {" "}
                  This session holds neither <strong>generate_reports</strong> nor{" "}
                  <strong>record_field_corrections</strong>, so a correction could not be recorded even
                  with a reason.
                </>
              ) : null}
            </p>
          )}
        </Frame>

        <Frame as="aside" aria-label="Report preview" style={{ padding: 0, overflow: "hidden" }}>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              justifyContent: "space-between",
              gap: 12,
              padding: "16px 18px",
              borderBlockEnd: "1px solid var(--color-text)"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span
                aria-hidden="true"
                style={{
                  display: "grid",
                  placeItems: "center",
                  width: 30,
                  height: 30,
                  background: "var(--color-accent-900)",
                  color: "var(--color-bg)",
                  fontFamily: "var(--font-heading)",
                  fontSize: 12
                }}
              >
                MR
              </span>
              <div>
                <span
                  style={{
                    display: "block",
                    fontSize: 10,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    color: "var(--color-accent-700)"
                  }}
                >
                  Monday Report
                </span>
                <strong
                  style={{
                    fontFamily: "var(--font-heading)",
                    fontSize: 19,
                    textTransform: "uppercase",
                    letterSpacing: "0.02em"
                  }}
                >
                  {activeVariant.label} report
                </strong>
              </div>
            </div>
            <Tag tone="accent">{activeVariant.shortLabel} · draft</Tag>
          </div>

          <div
            style={{
              display: "flex",
              gap: 14,
              flexWrap: "wrap",
              padding: "8px 18px",
              borderBlockEnd: "1px solid var(--color-divider)",
              fontSize: 12,
              color: "var(--color-neutral-700)"
            }}
          >
            <span>{form.reportDate || "No date"}</span>
            <span>{form.reportNo || "No report number"}</span>
            <span>{form.phase || activeVariant.phase}</span>
          </div>

          {/* minmax(0,1fr): an implicit grid column is sized to its widest child's
              max-content, so the evidence tables (min-width 380-460px) pushed this
              column past the card, where overflow:hidden then CLIPPED the content
              instead of letting the tables scroll inside themselves. */}
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 16, padding: "16px 18px" }}>
            <Cells
              min={110}
              label="Report header values"
              items={[
                { label: "Well", value: form.well || "—" },
                { label: "Rig", value: form.rig || "—" },
                { label: "Hole", value: form.holeSize || "—" },
                { label: "MD", value: form.mdFt || "—" },
                { label: "TVD", value: form.tvdFt || "—" },
                { label: "DLS", value: form.dls || "—" },
                { label: "Mud", value: form.mudWeight || "—" }
              ]}
            />

            <PreviewSection title="Present operations" body={form.presentOps} />
            <PreviewSection title="Next 24 hr plan" body={form.nextOps} />
            <PreviewSection title="Safety and well control" body={form.safety} />
            <PreviewSection title="Risks and watchlist" body={form.risks} />

            {draft && draft.activity_timeline && draft.activity_timeline.length > 0 ? (
              <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                <strong
                  style={{
                    display: "block",
                    fontSize: 11,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase"
                  }}
                >
                  24 hr timeline
                </strong>
                <div
                  style={{
                    display: "grid",
                    gap: 3,
                    marginTop: 5,
                    fontSize: 12,
                    color: "var(--color-neutral-700)"
                  }}
                >
                  {draft.activity_timeline.map((segment, index) => (
                    <span key={`${segment.time}-${index}`} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                      <strong style={{ fontFamily: "var(--font-heading)", minWidth: 92 }}>{segment.time}</strong>
                      <span style={{ minWidth: 0 }}>
                        {segment.activity}
                        {segment.source === "reference" ? (
                          <Tag tone="outline" style={{ marginInlineStart: 6 }}>
                            reference
                          </Tag>
                        ) : null}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
              <strong
                style={{ display: "block", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}
              >
                Issue gate
              </strong>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
                <Tag tone={gateIsClear(gate) ? "accent" : "critical"}>
                  Validation · {gateKnown ? (gateBlocked ? `${gate.openTasks} open` : "clear") : gateText.toLowerCase()}
                </Tag>
                <Tag tone={gateIsClear(gate) ? "accent" : "neutral"}>
                  Export · {gateIsClear(gate) ? "available" : gateBlocked ? "gated" : "gate not read"}
                </Tag>
                <Tag tone="outline">{reportVariantSchemaVersion}</Tag>
              </div>
              {gateBlocked ? (
                <p role="status" style={{ fontSize: 12, margin: "8px 0 0", color: "var(--color-accent-800)" }}>
                  {exportGateMessage(gate.state === "ready" ? gate.openTasks : 0)}{" "}
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ minHeight: 0, padding: "0 4px", fontSize: 12 }}
                    onClick={() => navigate("/app/validation")}
                  >
                    Open validation
                  </button>
                </p>
              ) : null}
            </div>

            {/* Casing list. The handoff's preview sheet carries the casing program;
                the mini deviated-schematic SVG ports with the Stage 2 generators. */}
            {draft && draft.casing_strings && draft.casing_strings.length > 0 ? (
              <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                {/* Wraps at narrow widths: as one non-wrapping row the link
                    overflowed the card at 390px. */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                    gap: 8,
                    flexWrap: "wrap"
                  }}
                >
                  <strong
                    style={{ fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}
                  >
                    Casing program
                  </strong>
                  <Link
                    className="btn btn-ghost"
                    to="/app/well"
                    style={{ minHeight: 0, padding: "0 4px", fontSize: 11.5, whiteSpace: "normal", textAlign: "start" }}
                  >
                    Open full well schematics →
                  </Link>
                </div>
                <div className="mr-scroll-x" style={{ marginTop: 6 }}>
                  <div role="table" aria-label="Casing strings" style={{ minWidth: 380 }}>
                    <div role="row" className="mr-table-head" style={{ gridTemplateColumns: CASING_TEMPLATE }}>
                      <span role="columnheader">String</span>
                      <span role="columnheader">OD</span>
                      <span role="columnheader">Top</span>
                      <span role="columnheader">Shoe</span>
                      <span role="columnheader">Evidence</span>
                    </div>
                    {draft.casing_strings.map((string, index) => (
                      <div
                        role="row"
                        className="mr-table-row"
                        key={`${string.name}-${index}`}
                        style={{ gridTemplateColumns: CASING_TEMPLATE, fontSize: 11.5 }}
                      >
                        <span role="cell">{string.name}</span>
                        <span role="cell">{string.od ?? "—"}</span>
                        <span role="cell">{ft(string.top_ft)}</span>
                        <span role="cell">{ft(string.shoe_ft)}</span>
                        <span role="cell">
                          <Tag tone={string.source === "source" ? "accent" : "outline"}>
                            {string.source === "source"
                              ? `p. ${string.page ?? "—"}${conf(string.confidence)}`
                              : "reference"}
                          </Tag>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}

            {/* Survey source-vs-calculated table with conflict tags. */}
            {draft && draft.survey_stations && draft.survey_stations.length > 0 ? (
              <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                <strong style={{ display: "block", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  Survey — source vs calculated
                </strong>
                <div className="mr-scroll-x" style={{ marginTop: 6 }}>
                  <div role="table" aria-label="Survey stations" style={{ minWidth: 460 }}>
                    <div role="row" className="mr-table-head" style={{ gridTemplateColumns: SURVEY_TEMPLATE }}>
                      <span role="columnheader">MD</span>
                      <span role="columnheader">Inc</span>
                      <span role="columnheader">Azi</span>
                      <span role="columnheader">TVD source</span>
                      <span role="columnheader">TVD calc</span>
                      <span role="columnheader">Evidence</span>
                    </div>
                    {draft.survey_stations.map((station, index) => {
                      const calculated = draft.trajectory?.stations.find(
                        (candidate) => candidate.measured_depth_ft === station.measured_depth_ft
                      );
                      return (
                        <div
                          role="row"
                          className="mr-table-row"
                          key={`${station.station_id ?? station.measured_depth_ft}-${index}`}
                          style={{ gridTemplateColumns: SURVEY_TEMPLATE, fontSize: 11.5 }}
                        >
                          <span role="cell">{ft(station.measured_depth_ft)}</span>
                          <span role="cell">{deg(station.inclination_deg)}</span>
                          <span role="cell">{deg(station.azimuth_deg)}</span>
                          <span role="cell">{ft(station.true_vertical_depth_ft)}</span>
                          <span role="cell">{calculated ? ft(calculated.tvd_ft) : "—"}</span>
                          <span role="cell">
                            {station.conflict ? (
                              <Tag tone="critical">conflict — review</Tag>
                            ) : (
                              <Tag tone="accent">{`p. ${station.page ?? "—"}${conf(station.confidence)}`}</Tag>
                            )}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                {draft.trajectory_source === "calculated" ? (
                  <p className="text-muted" style={{ fontSize: 11, margin: "6px 0 0" }}>
                    Calculated · minimum curvature · review required · not certified.
                  </p>
                ) : null}
              </div>
            ) : null}

            {/* Hydraulics observations with their review flags. */}
            {draft && draft.hydraulics_observations && draft.hydraulics_observations.length > 0 ? (
              <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                <strong style={{ display: "block", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  Hydraulics observations
                </strong>
                <div className="mr-scroll-x" style={{ marginTop: 6 }}>
                  <div role="table" aria-label="Hydraulics observations" style={{ minWidth: 420 }}>
                    <div role="row" className="mr-table-head" style={{ gridTemplateColumns: HYDRAULICS_TEMPLATE }}>
                      <span role="columnheader">Measurement</span>
                      <span role="columnheader">Value</span>
                      <span role="columnheader">Source text</span>
                      <span role="columnheader">Status</span>
                    </div>
                    {draft.hydraulics_observations.map((observation, index) => (
                      <div
                        role="row"
                        className="mr-table-row"
                        key={`${observation.measurement}-${index}`}
                        style={{ gridTemplateColumns: HYDRAULICS_TEMPLATE, fontSize: 11.5 }}
                      >
                        <span role="cell">{observation.measurement.replace(/_/g, " ")}</span>
                        <span role="cell">
                          {observation.value ?? "—"}
                          {observation.unit ? ` ${observation.unit}` : ""}
                        </span>
                        <span role="cell" style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                          {observation.source_value_text}
                        </span>
                        <span role="cell">
                          {observation.conflict || observation.review_flag ? (
                            <Tag tone="critical">{observation.conflict ? "conflict" : "review"}</Tag>
                          ) : (
                            <Tag tone="outline">{observation.observation_status}</Tag>
                          )}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}

            {draft && draft.citations.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }} role="group" aria-label="Draft citations">
                <strong
                  style={{ fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}
                >
                  Citations
                </strong>
                {draft.citations.slice(0, 6).map((citation) => (
                  <span
                    key={citation.id}
                    style={{
                      border: "1px solid var(--color-divider)",
                      padding: "6px 9px",
                      fontSize: 11.5,
                      lineHeight: 1.45,
                      color: "var(--color-neutral-700)"
                    }}
                  >
                    {formatSourceCitation(citation.locator_type, citation.locator)} ·{" "}
                    {Math.round(citation.confidence * 100)}% confidence
                  </span>
                ))}
                {draft.citations.length > 6 ? (
                  <span className="text-muted" style={{ fontSize: 11.5 }}>
                    {draft.citations.length - 6} further citation(s) attached to this draft.
                  </span>
                ) : null}
              </div>
            ) : null}

            {draft && draft.confidence_notes.length > 0 ? (
              <ul
                className="text-muted"
                style={{ fontSize: 11.5, lineHeight: 1.5, margin: 0, paddingInlineStart: 18 }}
              >
                {draft.confidence_notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            ) : null}
          </div>
        </Frame>
      </div>

      <p className="text-muted" style={{ fontSize: 12.5, margin: 0, maxWidth: "80ch" }}>
        Required sections for {activeVariant.label}: {activeVariant.requiredSections.join(", ")}.
      </p>
    </>
  );
}

function PreviewSection({ title, body }: { title: string; body: string }) {
  return (
    <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
      <strong style={{ display: "block", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}>
        {title}
      </strong>
      <p
        style={{
          margin: "4px 0 0",
          fontSize: 12,
          lineHeight: 1.5,
          color: "var(--color-neutral-700)",
          whiteSpace: "pre-wrap"
        }}
      >
        {body || "Not drafted yet."}
      </p>
    </div>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  disabled,
  type = "text",
  inputMode,
  placeholder,
  hint
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
  type?: string;
  inputMode?: "decimal" | "text";
  placeholder?: string;
  hint?: string;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        type={type}
        inputMode={inputMode}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        aria-describedby={hintId}
      />
      {hint ? (
        <span id={hintId} className="text-muted" style={{ fontSize: 11, lineHeight: 1.4 }}>
          {hint}
        </span>
      ) : null}
    </div>
  );
}

function TextField({
  id,
  label,
  rows,
  value,
  onChange,
  disabled
}: {
  id: string;
  label: string;
  rows: number;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        className="input"
        rows={rows}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
    </div>
  );
}
