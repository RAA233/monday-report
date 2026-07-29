import { useCallback, useEffect, useMemo, useState } from "react";
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
import { exportGateMessage, useWorkspace } from "../lib/workspace";

/**
 * Report Studio.
 *
 * The five format variants come from `src/data/reportVariantSchemas.ts` — the
 * committed source of truth for MR-SCHEMA-1 — so the Studio cannot drift from the
 * schema the backend and the v1 interface share.
 *
 * The editor holds local edits only. This is deliberate and disclosed on screen:
 * the API records changes as field corrections against a target, and inventing a
 * "save draft" call that does not exist would be worse than saying so. Values that
 * arrived from evidence are marked, and a local edit never rewrites the recorded
 * source value.
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
  mudWeight: "",
  presentOps: "",
  nextOps: "",
  safety: "",
  risks: ""
};

function formFromDraft(draft: ApiReportDraft): FormState {
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
    mudWeight: draft.mud_weight,
    presentOps: draft.present_ops,
    nextOps: draft.next_ops,
    safety: draft.safety,
    risks: draft.risks
  };
}

export function Studio() {
  const { reportId } = useParams();
  const navigate = useNavigate();
  const { activeWorkspace, openValidationTasks, readOnly, apiStatus } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;

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
    setState("loading");
    setMessage("Building a source-backed draft from parsed documents, citations, and validation tasks…");
    try {
      const next = await getReportDraft(workspaceId);
      setDraft(next);
      setForm(formFromDraft(next));
      setEditedKeys(new Set());
      setState("ready");
      setMessage(
        `Source-backed draft ready from ${next.source_document_count} document(s), ${next.source_chunk_count} chunk(s), and ${next.citation_count} citation(s).`
      );
    } catch (caught) {
      setState("error");
      setMessage(
        caught instanceof Error && caught.message
          ? `The draft was not built. ${caught.message}`
          : "The draft was not built. The workspace API did not answer."
      );
    }
  }, [workspaceId]);

  // Entering the Studio through a report loads that workspace's draft immediately;
  // the fields are otherwise empty rather than pre-filled with plausible values.
  useEffect(() => {
    if (workspaceId && apiStatus === "connected") void sourceDraft();
  }, [workspaceId, apiStatus, sourceDraft]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setEditedKeys((current) => new Set(current).add(key));
  }

  const readiness: CellSpec[] = useMemo(() => {
    if (!draft) {
      return [
        { label: "Evidence", value: "Not loaded", detail: "Build a source-backed draft", ok: false },
        { label: "Citations", value: "—", detail: "Attached once the draft is built", ok: false },
        {
          label: "Validation gate",
          value: openValidationTasks === 0 ? "Clear" : `${openValidationTasks} open`,
          detail: openValidationTasks === 0 ? "No open tasks" : "Export blocked",
          ok: openValidationTasks === 0
        },
        { label: "Schematic", value: "—", detail: "Requires casing evidence", ok: false },
        { label: "Survey", value: "—", detail: "Requires survey stations", ok: false },
        { label: "Hydraulics", value: "—", detail: "Requires hydraulics observations", ok: false }
      ];
    }
    return [
      {
        label: "Evidence",
        value: `${draft.source_document_count} docs`,
        detail: `${draft.source_chunk_count} chunks parsed`,
        ok: draft.source_document_count > 0
      },
      {
        label: "Citations",
        value: String(draft.citation_count),
        detail: `${draft.failure_count} failure record(s)`,
        ok: draft.citation_count > 0
      },
      {
        label: "Validation gate",
        value: draft.validation_gate === "clear" ? "Clear" : "Review required",
        detail: `${draft.open_validation_tasks} open task(s)`,
        ok: draft.validation_gate === "clear"
      },
      {
        label: "Schematic",
        value: draft.schematic_source === "source" ? "From source" : "Reference",
        detail:
          draft.schematic_source === "source"
            ? `${draft.casing_strings?.length ?? 0} casing string(s)`
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
          draft.hydraulics_source === "source"
            ? `${draft.hydraulics_observations?.length ?? 0} obs`
            : "None",
        detail: draft.hydraulics_source === "source" ? "Extracted from source" : "No observations found",
        ok: draft.hydraulics_source === "source"
      }
    ];
  }, [draft, openValidationTasks]);

  const gateBlocked = openValidationTasks > 0;

  return (
    <>
      <PageHeader
        kicker={`Report Studio${reportId ? ` · ${reportId}` : ""} · ${reportVariantSchemaVersion}`}
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
            color: "var(--color-neutral-600)"
          }}
        >
          Format
        </span>
        <SegControl<FormatVariantId>
          name="mr-variant"
          label="Report format variants"
          role="tablist"
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
              {apiStatus === "connected"
                ? "Read-only session: this role has no report-edit permission. Ask a workspace admin for engineer access."
                : "Read-only: the workspace API is unreachable, so no edit can be recorded."}
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

          <div style={{ display: "grid", gap: 16, padding: "16px 18px" }}>
            <Cells
              min={110}
              label="Report header values"
              items={[
                { label: "Well", value: form.well || "—" },
                { label: "Rig", value: form.rig || "—" },
                { label: "Hole", value: form.holeSize || "—" },
                { label: "MD", value: form.mdFt || "—" },
                { label: "TVD", value: form.tvdFt || "—" },
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
                <Tag tone={gateBlocked ? "critical" : "accent"}>
                  Validation · {gateBlocked ? `${openValidationTasks} open` : "clear"}
                </Tag>
                <Tag tone={gateBlocked ? "neutral" : "accent"}>
                  Export · {gateBlocked ? "gated" : "available"}
                </Tag>
                <Tag tone="outline">{reportVariantSchemaVersion}</Tag>
              </div>
              {gateBlocked ? (
                <p role="status" style={{ fontSize: 12, margin: "8px 0 0", color: "var(--color-accent-800)" }}>
                  {exportGateMessage(openValidationTasks)}{" "}
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

            {draft && draft.citations.length > 0 ? (
              <div style={{ display: "grid", gap: 6 }} aria-label="Draft citations">
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
  inputMode
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
  type?: string;
  inputMode?: "decimal" | "text";
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        type={type}
        inputMode={inputMode}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
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
