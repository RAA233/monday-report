import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  getReportDraft,
  type ApiReportDraft,
  type ApiTrajectoryCoordinateReference
} from "../../lib/api";
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
  type CellSpec,
  useRetryPresence
} from "../components/primitives";
import {
  apiUnreadReason,
  errorText,
  exportGateMessage,
  gateIsClear,
  gateIsClosed,
  gateLabel,
  useWorkspace,
  type GateState
} from "../lib/workspace";

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
// The trailing evidence column is a definite width, not `auto`: each row is its own
// grid container, so an `auto` track sizes to that row's own tag and the header drifts
// out of alignment with the cells.
const CASING_TEMPLATE = "1.3fr 0.7fr 0.7fr 0.7fr 104px";
/**
 * Is the calculated TVD an OFFSET rather than a depth?
 *
 * `backend/app/trajectory.py` anchors the accumulation to a source station's TVD when
 * one exists and otherwise starts from 0.0, recording which it did in
 * `coordinate_reference.tvd`. `backend/app/schemas.py` is explicit that
 * `relative_first_station` values "must never be presented as absolute well
 * coordinates" - so the column has to say which kind of number it is holding.
 */
function tvdIsRelative(reference: ApiTrajectoryCoordinateReference): boolean {
  return reference.tvd === "relative_first_station";
}

const SURVEY_TEMPLATE = "0.8fr 0.6fr 0.6fr 0.9fr 0.9fr 128px";
const HYDRAULICS_TEMPLATE = "1fr 0.8fr 1.4fr 96px";

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
  // Read inside sourceDraft, which must not re-create on every keystroke.
  const editedKeysRef = useRef(editedKeys);
  editedKeysRef.current = editedKeys;
  const formRef = useRef(form);
  formRef.current = form;

  const activeVariant = useMemo(
    () => reportFormatVariants.find((item) => item.id === variant) ?? reportFormatVariants[0],
    [variant]
  );

  const sourceDraft = useCallback(async () => {
    // The no-workspace precondition runs FIRST. The in-flight dedup below compares
    // `draftInFlight.current` (initially null) against `workspaceId`; with no workspace
    // BOTH are null, so `null === null` returned early and swallowed the click — the
    // primary action became a silent no-op and the blocking message just below it was
    // unreachable. A blocked click must always announce, so this precondition owns
    // that, and the dedup guard is only meaningful once a real workspace exists.
    if (!workspaceId) {
      setState("error");
      setMessage(
        "No workspace is selected, so there is no evidence to draft from. Choose a workspace in the top bar to draft from its parsed evidence."
      );
      return;
    }
    // The button stays focusable while drafting (aria-disabled, not `disabled`), so the
    // handler is what makes it inert. Without this a second Enter would append a second
    // report_draft.generate to the audit chain for one operator intent.
    if (draftInFlight.current === workspaceId) return;
    const askedFor = workspaceId;
    draftInFlight.current = askedFor;
    setState("loading");
    setMessage("Building a source-backed draft from parsed documents, citations, and validation tasks…");
    try {
      const next = await getReportDraft(askedFor);
      // A draft is workspace-scoped evidence. If the operator switched workspaces
      // while this was in flight, dropping it is the only correct outcome —
      // otherwise workspace A's well, citations and readiness render under B.
      if (askedFor !== workspaceIdRef.current) return;
      setDraft(next);
      // Locally edited fields are PRESERVED. Overwriting them silently discarded
      // work the same panel was counting ("N field(s) changed locally").
      //
      // Computed from a ref BEFORE the update, never by pushing into a closure from
      // inside a state updater: React runs the updater during the following render,
      // so `kept.length` read here was always 0 and the disclosure never printed.
      const previous = formRef.current;
      // EVERY key the operator touched is restored from `previous`, including one they
      // deliberately CLEARED. Filtering on `.trim().length > 0` treated a clear as "no
      // edit", so the draft's value was written straight back over it while the panel
      // below still counted the field as changed locally - the operator was told an
      // edit was held that had just been reverted.
      //
      // Three states are kept distinct: a key absent from `editedKeys` is NOT LOADED and
      // takes the backend value; a key present with text is an operator VALUE; a key
      // present with "" is EMPTY BY CHOICE. No truthiness fallback anywhere.
      const edited = [...editedKeysRef.current];
      const drafted = formFromDraft(next, previous);
      for (const key of edited) drafted[key] = previous[key];
      const clearedCount = edited.filter((key) => previous[key].trim().length === 0).length;
      const keptCount = edited.length - clearedCount;
      setForm(drafted);
      setState("ready");
      setMessage(
        `Source-backed draft ready from ${next.source_document_count} document(s), ${next.source_chunk_count} chunk(s), and ${next.citation_count} citation(s).` +
          (keptCount > 0 ? ` ${keptCount} locally edited field(s) were kept.` : "") +
          (clearedCount > 0
            ? ` ${clearedCount} field(s) you cleared were left empty rather than re-drafted.`
            : "")
      );
    } catch (caught) {
      if (askedFor !== workspaceIdRef.current) return;
      setState("error");
      setMessage(`The draft was not built. ${errorText(caught)}`);
    } finally {
      // Release only OUR request. A later draft for a different workspace may already
      // own the flag; clearing it unconditionally would let a second request through
      // while the first is still running.
      if (draftInFlight.current === askedFor) draftInFlight.current = null;
    }
  }, [workspaceId]);

  // Clear the workspace-scoped view when the workspace changes, and DO NOT auto-load.
  //
  // `GET /workspaces/{id}/report-draft` calls store.audit("report_draft.generate"),
  // so fetching it on mount would append an audit event claiming a draft was
  // generated every time someone merely navigated here -- a write on a hash-chained
  // trust surface caused by navigation. Drafting is an explicit action, which is
  // also what the handoff specifies ("Source draft" is a button).
  //
  // Reset ONLY on a real workspace change - both ids present and different. It used to
  // key on `apiStatus` too, which was harmless while the fields were inert but became a
  // silent wipe the moment they went live: `retry()` is the one affordance the degraded
  // shell offers, and it moves apiStatus offline -> checking, so clicking "Retry
  // connection" after typing a report discarded every character with no prompt and no
  // undo - even when the retry then failed. The null -> first-workspace resolution is
  // not a change either: it is the same workspace becoming known.
  // Which WORKSPACE has a draft in flight, not merely "one exists". A bare boolean
  // made the guard outlive its request: it blocked the button for whatever workspace
  // the operator had switched to, and the primary action became a silent no-op.
  const draftInFlight = useRef<string | null>(null);
  const previousWorkspaceIdRef = useRef<string | null>(workspaceId);
  useEffect(() => {
    const previous = previousWorkspaceIdRef.current;
    previousWorkspaceIdRef.current = workspaceId;
    if (previous === null || workspaceId === null || previous === workspaceId) return;
    setDraft(null);
    setForm(EMPTY_FORM);
    setEditedKeys(new Set());
    setState("idle");
    // The message belongs to the workspace that produced it. Without this, a successful
    // draft's "ready from N document(s), N chunk(s), N citation(s)" survived the switch
    // and was read as the NEW workspace's state - three wrong numbers stated as fact,
    // directly above a readiness board that said "Not loaded". A failed draft stranded
    // its error in neutral tone, and an in-flight one stranded "Building..." forever,
    // because both resolution paths drop a response for a workspace already left.
    setMessage("");
    // A draft belongs to one workspace, and so does the report the route names. Dropping
    // the id keeps the "Issue target" line and the Exports link from carrying a report
    // that belongs to the workspace the operator just left.
    if (reportId) navigate("/app/studio", { replace: true });
  }, [workspaceId, reportId, navigate]);

  // The idle message depends on connectivity but must never touch the form.
  useEffect(() => {
    setMessage((current) =>
      current === "" || current.startsWith("Source draft pulls") || current.startsWith("Build a source-backed draft")
        ? workspaceId && apiStatus === "connected"
          ? "Build a source-backed draft to pull this workspace's parsed evidence into the report. Drafting is recorded in the report integrity record, so it runs only when you ask for it."
          : "Source draft pulls parsed workspace evidence into this editable report."
        : current
    );
  }, [workspaceId, apiStatus]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setEditedKeys((current) => new Set(current).add(key));
  }

  /**
   * The gate this screen reports. Two backend sources, never a client re-derivation:
   *
   *  1. `gate` — the provider's reconstruction of `_open_validation_tasks_for_workspace`
   *     from read-only endpoints. Live, but needs `view_validation_queue`, which
   *     MANAGER and ENGINEER do not hold.
   *  2. `draft.open_validation_tasks` — the backend's OWN count for this workspace,
   *     via the identical predicate, returned by `GET /workspaces/{id}/report-draft`
   *     (which needs only `view_reports`).
   *
   * (2) is used only as a fallback, and only once a draft exists: that route audits a
   * write, so it is never called on navigation — but when the operator has asked for
   * the draft, the write has already happened and refusing to read its number while
   * printing it two rows below was simply contradictory.
   */
  const draftGateSource = gate.state !== "ready" ? draft : null;
  const gateFromDraft = draftGateSource !== null;
  const boardGate: GateState = draftGateSource
    ? {
        state: "ready",
        openTasks: draftGateSource.open_validation_tasks,
        clear: draftGateSource.open_validation_tasks === 0
      }
    : gate;
  const gateBlocked = gateIsClosed(boardGate);
  const gateKnown = boardGate.state === "ready";
  const gateText = gateLabel(boardGate);

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
    const gateKnownAndClear = gateIsClear(boardGate);
    // Evidence is a precondition for issuance: without it, "Ready" would mean a
    // fully typed but wholly unsourced report.
    const evidenceReady = Boolean(draft && draft.source_document_count > 0 && draft.citation_count > 0);
    const issueReady = evidenceReady && narrativeReady && completeness === 100 && gateKnownAndClear;

    return [
      {
        // No check glyph: the selector picks which MR-SCHEMA-1 variant's required
        // sections apply, but the draft payload is not variant-specific, so this
        // cell reports a selection -- it is not a satisfied requirement.
        label: "Format",
        value: activeVariant.shortLabel,
        detail: `${activeVariant.label} · ${activeVariant.requiredSections.length} required sections`
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
        // "Could not be read" is reserved for a read that FAILED. While it is still
        // in flight the cell says so instead.
        detail:
          boardGate.state === "loading"
            ? "Reading the gate from the backend"
            : !gateKnown
              ? "The backend gate could not be read — not a claim that it is clear"
              : gateFromDraft
                ? "The backend's own count for this workspace, from the draft you built"
                : gateBlocked
                  ? "Export blocked until resolved"
                  : "No open tasks for this workspace",
        ok: gateKnownAndClear
      },
      {
        label: "Issue",
        value: issueReady ? "Ready" : "Gated",
        detail: issueReady
          ? "Evidence loaded, draft text complete, and the gate is clear"
          : !evidenceReady
            ? "Held by missing source evidence -- build a source-backed draft"
            : gateBlocked
              ? "Held by the validation gate"
              : !gateKnownAndClear
                ? "Held open until the gate is read — the backend decides on export"
                : "Held by incomplete draft fields",
        ok: issueReady
      }
    ];
  }, [activeVariant, boardGate, draft, form, gateBlocked, gateFromDraft, gateKnown, gateText]);

  /** Second row: what the loaded evidence actually contains. */
  const evidenceCells: CellSpec[] = useMemo(() => {
    if (!draft) return [];
    const casingRows = draft.casing_strings ?? [];
    const casingSourceRows = casingRows.filter((row) => row.source === "source").length;
    return [
      {
        // Derived from the ROWS, not from draft.schematic_source: that flag also
        // covers the activity timeline, so it can read "source" while every casing
        // row is a labelled reference value.
        label: "Casing",
        value: casingRows.length === 0 ? "None" : `${casingRows.length} strings`,
        detail:
          casingRows.length === 0
            ? "No casing rows in the draft"
            : casingSourceRows === casingRows.length
              ? "All rows from source evidence"
              : casingSourceRows === 0
                ? "All rows are labelled reference values, not evidence"
                : `${casingSourceRows} of ${casingRows.length} rows from source; the rest are labelled reference`,
        ok: casingRows.length > 0 && casingSourceRows === casingRows.length
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

  const draftRetry = useRetryPresence(state);

  return (
    <>
      {/* The draft is WORKSPACE-scoped: GET /workspaces/{id}/report-draft. Naming a
          report id here implied the Studio was showing that report's stored
          content, which it never reads. The report id (when the route carries one)
          is disclosed below as the issue target instead. */}
      <PageHeader
        kicker={`Report Studio · ${activeWorkspace?.name ?? "no workspace"} · Standard report format`}
        title={`${activeVariant.label} draft`}
        actions={
          <>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void sourceDraft()}
              disabled={apiStatus !== "connected"}
              aria-disabled={state === "loading" || undefined}
            >
              {state === "loading" ? "Building draft…" : "Build source-backed draft"}
            </button>
            {/* Carries the report id so Exports issues THIS report rather than
                whichever happens to be newest. */}
            <Link
              className="btn btn-secondary"
              to={reportId ? `/app/exports?report=${encodeURIComponent(reportId)}` : "/app/exports"}
            >
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
          export is issued, and the Exports button below carries this id.
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
        {/* On the error path the `role="alert"` card below owns the message. Repeating
            it in this `role="status"` line printed the same sentence twice and had two
            live regions announce it twice. */}
        <span style={{ marginInlineStart: "auto" }}>
          <StatusLine tone={state === "error" ? "alert" : "neutral"}>
            {state === "error" ? "The draft was not built — see the message below." : message}
          </StatusLine>
        </span>
      </div>

      <Cells items={readiness} label="Issue readiness board" />

      {evidenceCells.length > 0 ? <Cells items={evidenceCells} label="Loaded evidence" /> : null}

      {state === "loading" && !draft && !draftRetry.show ? (
        <Skeleton rows={4} label="Building the draft" />
      ) : null}

      {draftRetry.show ? (
        <ErrorState
          title="Draft not built"
          message={draftRetry.retrying ? "The draft is being built again." : message}
          onRetry={() => void sourceDraft()}
          retrying={draftRetry.retrying}
        />
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
            <Field id="st-date" label="Date" type="date" value={form.reportDate} onChange={(v) => update("reportDate", v)} />
            <Field id="st-no" label="Report no." value={form.reportNo} onChange={(v) => update("reportNo", v)} />
            <Field id="st-well" label="Well" value={form.well} onChange={(v) => update("well", v)} />
            <Field id="st-rig" label="Rig" value={form.rig} onChange={(v) => update("rig", v)} />
            <Field id="st-op" label="Operator" value={form.operator} onChange={(v) => update("operator", v)} />
            <Field id="st-phase" label="Phase" value={form.phase} onChange={(v) => update("phase", v)} />
            <Field id="st-hole" label="Hole size" value={form.holeSize} onChange={(v) => update("holeSize", v)} />
            <Field id="st-md" label="MD ft" value={form.mdFt} onChange={(v) => update("mdFt", v)} inputMode="decimal" />
            <Field id="st-tvd" label="TVD ft" value={form.tvdFt} onChange={(v) => update("tvdFt", v)} inputMode="decimal" />
            <Field
              id="st-dls"
              label="As-drilled DLS"
              value={form.dls}
              onChange={(v) => update("dls", v)}
             
              placeholder="1.3 deg/100 ft"
              hint="Operator-entered — the draft payload carries no DLS value."
            />
            <Field id="st-mud" label="Mud weight" value={form.mudWeight} onChange={(v) => update("mudWeight", v)} />
          </div>

          <TextField id="st-present" label="Present operations" rows={3} value={form.presentOps} onChange={(v) => update("presentOps", v)} />
          <TextField id="st-next" label="Next 24 hr plan" rows={3} value={form.nextOps} onChange={(v) => update("nextOps", v)} />
          <TextField id="st-safety" label="Safety and well-control notes" rows={2} value={form.safety} onChange={(v) => update("safety", v)} />
          <TextField id="st-risks" label="Risks and AI watchlist" rows={2} value={form.risks} onChange={(v) => update("risks", v)} />

          {readOnly ? (
            <p
              className="text-muted"
              style={{ fontSize: 12, margin: 0, border: "1px solid var(--color-divider)", padding: "8px 10px" }}
            >
              {`${apiUnreadReason(apiStatus) ?? "No workspace session is resolved"}, so a
              source-backed draft cannot be rebuilt right now. These fields stay editable:
              they are local to this browser session in every state, and nothing typed
              here is recorded against the report either way.`}
            </p>
          ) : (
            <p
              className="text-muted"
              style={{ fontSize: 12, margin: 0, border: "1px solid var(--color-divider)", padding: "8px 10px" }}
            >
              Edits here stay in this browser session. {editedKeys.size > 0 ? `${editedKeys.size} field(s) changed locally. ` : ""}
              Recording a change against the report requires a field correction with a written reason,
              which carries reviewer attribution into the report integrity record — the recorded source value is
              never overwritten.
              {!canEdit ? (
                <>
                  {" "}
                  This session can neither <strong>generate reports</strong> nor{" "}
                  <strong>record field corrections</strong>, so a correction could not be recorded even
                  with a reason.
                </>
              ) : null}
            </p>
          )}
        </Frame>

        {/* No `overflow: hidden` here: `Frame` is the blueprint wrapper and draws its
            four registration marks at -6px, so clipping the box cut them in half. The
            wide tables inside scroll in their own `.mr-scroll-x` containers. */}
        <Frame as="aside" aria-label="Report preview" style={{ padding: 0 }}>
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

            {/* Executive summary: the handoff's preview sheet leads with it, and
                the draft payload already carries the computed lines. */}
            {draft && draft.evidence_summary.length > 0 ? (
              <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                <strong
                  style={{ display: "block", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase" }}
                >
                  Executive summary
                </strong>
                <ul
                  style={{
                    margin: "5px 0 0",
                    paddingInlineStart: 18,
                    fontSize: 12,
                    lineHeight: 1.5,
                    color: "var(--color-neutral-700)"
                  }}
                >
                  {draft.evidence_summary.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
                <span className="text-muted" style={{ fontSize: 10.5 }}>
                  Computed from the parsed evidence, not written by hand.
                </span>
              </div>
            ) : null}

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
                {/* `critical` is reserved for a gate the backend reported CLOSED. An
                    unread gate is neutral here, matching the Export chip beside it and
                    the Exports banner — the two chips used to disagree on the same row. */}
                <Tag tone={gateIsClear(boardGate) ? "accent" : gateBlocked ? "critical" : "neutral"}>
                  Validation ·{" "}
                  {gateKnown
                    ? gateBlocked
                      ? `${boardGate.state === "ready" ? boardGate.openTasks : 0} open`
                      : "clear"
                    : gateText.toLowerCase()}
                </Tag>
                <Tag tone={gateIsClear(boardGate) ? "accent" : "neutral"}>
                  Export · {gateIsClear(boardGate) ? "available" : gateBlocked ? "gated" : "gate not read"}
                </Tag>
                <Tag tone="outline">Standard report format</Tag>
              </div>
              {gateBlocked ? (
                <p role="status" style={{ fontSize: 12, margin: "8px 0 0", color: "var(--color-accent-800)" }}>
                  {exportGateMessage(boardGate.state === "ready" ? boardGate.openTasks : 0)}{" "}
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
                the drawn schematic lives on the Well schematics view. */}
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
                    Open in Well schematics →
                  </Link>
                </div>
                <div
                  className="mr-scroll-x"
                  style={{ marginTop: 6 }}
                  // Focusable: the Evidence column sits past the right edge at narrow
                  // widths and every cell inside is a non-focusable span, so without
                  // this a keyboard-only user cannot scroll to it.
                  tabIndex={0}
                  role="region"
                  aria-label="Casing strings, scrollable"
                >
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
                <div
                  className="mr-scroll-x"
                  style={{ marginTop: 6 }}
                  tabIndex={0}
                  role="region"
                  aria-label="Survey stations, scrollable"
                >
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
                      // Join on the id the payload carries for exactly this purpose.
                      // Depth equality is the fallback and must be tolerant: the
                      // backend rounds the CALCULATED station's MD to 2 dp while the
                      // source station keeps the raw parsed float, so `===` missed
                      // every station quoted to three decimals and printed "—" for a
                      // value that exists.
                      const calculated = draft.trajectory?.stations.find((candidate) =>
                        station.station_id != null && candidate.source_station_id != null
                          ? candidate.source_station_id === station.station_id
                          : Math.abs(candidate.measured_depth_ft - station.measured_depth_ft) < 0.01
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
                          <span role="cell">
                            {calculated
                              ? tvdIsRelative(calculated.coordinate_reference)
                                ? `+${ft(calculated.tvd_ft)} rel.`
                                : ft(calculated.tvd_ft)
                              : "—"}
                          </span>
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
                    {(draft.trajectory?.stations ?? []).some((candidate) =>
                      tvdIsRelative(candidate.coordinate_reference)
                    )
                      ? " Rows marked “rel.” are offsets from the first station of their own calculated segment, not absolute well coordinates: that segment began without a source TVD to anchor to."
                      : null}
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
                <div
                  className="mr-scroll-x"
                  style={{ marginTop: 6 }}
                  tabIndex={0}
                  role="region"
                  aria-label="Hydraulics observations, scrollable"
                >
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

      {/* Reviewed schema variants — the committed MR-SCHEMA-1 coverage board.
          Every figure is read from `src/data/reportVariantSchemas.ts`, the same
          module the selector above renders from, so this board cannot drift from
          the schema the backend and the guards pin. */}
      <Frame as="section" aria-label="Reviewed schema variants" style={{ padding: 18, display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <div>
            <span className="mr-kicker">Reviewed schema variants</span>
            <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: "2px 0 0" }}>
              Extraction and drafting targets
            </h2>
          </div>
          <Tag tone="accent">Standard report format</Tag>
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(190px,100%),1fr))",
            gap: 10
          }}
        >
          {reportFormatVariants.map((variant) => (
            <article
              key={variant.id}
              aria-current={variant.id === activeVariant.id ? "true" : undefined}
              style={{
                border:
                  variant.id === activeVariant.id
                    ? "1px solid var(--color-accent-700)"
                    : "1px solid var(--color-divider)",
                padding: "10px 12px",
                display: "grid",
                gap: 4,
                alignContent: "start"
              }}
            >
              <span
                style={{
                  fontSize: 10,
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  color: "var(--color-accent-700)"
                }}
              >
                {variant.shortLabel}
              </span>
              <strong style={{ fontFamily: "var(--font-heading)", fontSize: 14.5 }}>{variant.label}</strong>
              <code style={{ fontSize: 11 }}>{variant.schemaId}</code>
              <span className="text-muted" style={{ fontSize: 11.5 }}>
                {variant.extractionMarkers.length} markers · {variant.draftingChecks.length} checks ·{" "}
                {variant.outputSections.length} outputs
              </span>
            </article>
          ))}
        </div>
        <p className="text-muted" style={{ fontSize: 11.5, margin: 0, maxWidth: "80ch" }}>
          Marker, check and output counts are read from the committed schema module, never a
          hand-typed figure.
        </p>
      </Frame>
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
  /** Optional: the editor is local-only and no longer keys this on connectivity. */
  disabled?: boolean;
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
  /** Optional: see Field. */
  disabled?: boolean;
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
