import { Link } from "react-router-dom";

/**
 * Public product page.
 *
 * A recreation of the handoff landing design. The copy is the approved final copy;
 * the only substantive change is the product-preview caption, which now says the
 * preview is an illustration using demo-workspace values. This page is not
 * connected to the API, so describing it as "drawn from the demo workspace" would
 * have asserted a provenance it does not have.
 *
 * No certification, compliance, or production-acceptance claim appears anywhere on
 * this page — the trust section states that explicitly.
 */

const CTA_LABEL = "Open the app";

const PREVIEW_META = [
  { label: "Well", value: "FORGE 16A(78)-32" },
  { label: "Rig", value: "Frontier Rig 16" },
  { label: "Hole", value: "12.25 in" },
  { label: "MD / TVD", value: "8,620 / 7,980 ft" },
  { label: "Mud", value: "10.2 ppg" },
  { label: "DLS", value: "2.1°/100 ft" }
];

const STATS = [
  { value: "5", label: "Report variants — DDR, BHA, mud, survey, directional" },
  { value: "6", label: "Pipeline stages modelled — upload, parse, extraction and validation each audited" },
  { value: "5", label: "Export formats, checksummed and validation-gated" },
  { value: "1:1", label: "Extracted records to source citations — drafted narrative is labelled, never passed off as evidence" }
];

const CAPABILITIES = [
  {
    title: "Structured Monday reporting",
    body:
      "Weekly Monday reports and daily morning reports on a reviewed schema — five variants, period tracking, and a recorded status: a report opens as a draft, or directly as review when the workspace already has open validation tasks; a refused export also moves one to review, and a completed export marks it exported.",
    tags: ["MR-SCHEMA-1", "5 variants"]
  },
  {
    title: "Source-cited drafting",
    body:
      "The Studio drafts sections from parsed workspace evidence. Casing rows carry their locator, confidence and a source-vs-reference label; survey stations carry locator, confidence and a conflict flag; hydraulics observations carry their source text and a review flag. The drafted header and narrative fields carry the draft's own citation list rather than per-field provenance, and a recorded source value is never overwritten.",
    tags: ["Citations", "Confidence"]
  },
  {
    title: "Benchmarking",
    body:
      "Daily drilling rate against approved operator and market benchmarks, with severity-tiered anomaly rules and recommended-only diagnostics that require a reason to dismiss.",
    tags: ["ft/day", "Anomaly rules"]
  },
  {
    title: "Validation workflow",
    body:
      "A high-severity extracted failure, a file that needed OCR before its text could be read, and a Critical benchmark anomaly each queue for human review. Decisions carry server-derived reviewer attribution into the record; verified-reviewer attribution requires a session authenticated with a per-user credential.",
    tags: ["Human-in-the-loop", "Reviewer attribution"]
  },
  {
    title: "Tenant isolation",
    body:
      "Every table, endpoint, and workspace is tenant-scoped, and the schema is written for row-level security. One tenant's evidence never leaks into another's answers.",
    tags: ["Tenant-scoped", "RLS-ready"]
  },
  {
    title: "Audited exports",
    body:
      "Official PDF, XLSX, HTML, JSON, and CSV exports are blocked while an open failure- or anomaly-targeted validation task exists for the workspace — then checksummed and served by expiring signed URL.",
    tags: ["SHA-256", "Signed URLs"]
  }
];

const WORKFLOW = [
  {
    num: "01",
    title: "Import the evidence",
    body:
      "ZIPs, folders, PDFs, spreadsheets, emails, and scans register into one audited batch — hashed, malware-checked, and OCR-routed with folder lineage preserved.",
    surface: "Upload"
  },
  {
    num: "02",
    title: "Extract and cite",
    body:
      "The pipeline parses each file into chunks and cites them. Every extracted record carries its source file, the locator the parser recorded for that chunk (a page for PDFs, a chunk index otherwise) and a confidence. Extraction itself is a deterministic keyword rule in this increment, not a model: it recognises one failure pattern, so treat the extracted set as a demonstration rather than full coverage.",
    surface: "Pipeline"
  },
  {
    num: "03",
    title: "Draft the report",
    body:
      "The Studio assembles the report variant you need, pulling a source-backed draft with the casing program, survey stations, and hydraulics observations.",
    surface: "Report Studio"
  },
  {
    num: "04",
    title: "Validate",
    body:
      "Three sources raise a review task: a high-severity extracted failure, a file that needed OCR, and a Critical benchmark anomaly. The issue gate counts the open failure and anomaly tasks — and holds the report until those are clear.",
    surface: "Validation"
  },
  {
    num: "05",
    title: "Export with the audit chain",
    body:
      "Reports export in five formats once the validation gate is clear — checksummed, signed-URL served, and written into the hash-chained audit log.",
    surface: "Exports"
  }
];

const TRUST = [
  {
    title: "Tenant-scoped behavior",
    body:
      "Requests resolve to one tenant; workspaces, uploads, failures, reports, and audit events all carry the tenant ID end to end."
  },
  {
    title: "Audit-chain visibility",
    body:
      "Every action appends to a hash-chained audit log — keyed with HMAC when a signing key is configured — and the app shows the chain's sealed, legacy, or broken state instead of hiding it."
  },
  {
    title: "Local-first AI",
    body:
      "Classification, extraction and drafting are deterministic and run fully offline — no request leaves the tenant. A local model runtime (Ollama or LM Studio) is detected and its status reported, but it does not yet perform the analysis. Hosted fallback stays policy-controlled per tenant and off by default. No training by default."
  },
  {
    title: "Controlled evidence and exports",
    body:
      "Uploads are size-limited, malware-scanned, hashed, and lineage-tracked. Exports are validation-gated, checksummed, and fetched only through expiring signed URLs."
  }
];

const SHELL_WIDTH = {
  maxWidth: 1200,
  marginInline: "auto",
  paddingInline: "clamp(20px,5vw,72px)"
} as const;

const SECTION_KICKER = {
  display: "block",
  margin: 0,
  fontSize: 13,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  fontWeight: 600,
  color: "var(--color-accent-700)",
  marginBottom: 12
} as const;

const RULE = { height: 1, border: 0, background: "var(--color-divider)" } as const;

const BODY_TEXT = "color-mix(in srgb, var(--color-text) 78%, transparent)";

export function Landing() {
  return (
    <div style={{ minHeight: "100vh", background: "var(--color-bg)", color: "var(--color-text)" }}>
      <nav
        className="nav"
        aria-label="Primary"
        style={{
          paddingInline:
            "max(clamp(20px,5vw,72px), calc((100% - 1200px) / 2 + clamp(20px,5vw,72px)))",
          flexWrap: "wrap"
        }}
      >
        <span className="nav-brand">Monday Report</span>
        <a href="#capabilities">Capabilities</a>
        <a href="#workflow">Workflow</a>
        <a href="#security">Security</a>
        <Link className="btn btn-primary" to="/app" style={{ textDecoration: "none" }}>
          {CTA_LABEL}
        </Link>
      </nav>

      {/* Single main landmark for the whole page body; the nav and footer sit
          outside it so "skip to content" and landmark navigation behave. */}
      <main>
      <div style={SHELL_WIDTH}>
        <section
          aria-label="Monday Report"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(420px,100%),1fr))",
            gap: "48px clamp(24px,4vw,72px)",
            alignItems: "center",
            paddingBlock: "clamp(48px,7vw,96px) clamp(48px,6vw,72px)"
          }}
        >
          <div>
            <h1
              tabIndex={-1}
              data-page-heading=""
              style={{
                fontFamily: "var(--font-heading)",
                fontWeight: "var(--font-heading-weight)" as never,
                fontSize: "clamp(44px,6.4vw,88px)",
                lineHeight: 1.04,
                letterSpacing: "0.01em",
                textTransform: "uppercase",
                margin: "0 -0.052em 0"
              }}
            >
              <span style={{ display: "block" }}>Rig evidence in.</span>
              <span style={{ display: "block" }}>Audited reports out.</span>
            </h1>
            <p style={{ fontSize: 16, lineHeight: 1.55, maxWidth: "56ch", margin: "28px 0 0" }}>
              Monday Report drafts morning and Monday drilling reports for rig teams and operator HQ —
              from the paperwork the rig already produces. A local-first, deterministic engine
              extracts and cites the evidence, people validate it, and official exports stay gated
              behind the audit chain.
            </p>
            <div style={{ display: "flex", gap: "var(--space-3)", flexWrap: "wrap", marginTop: 28 }}>
              <Link className="btn btn-primary" to="/app" style={{ textDecoration: "none" }}>
                {CTA_LABEL}
              </Link>
              <a className="btn btn-ghost" href="#workflow" style={{ textDecoration: "none" }}>
                See the workflow
              </a>
            </div>
            <p className="text-muted" style={{ fontSize: 12, margin: "16px 0 0" }}>
              Demo workspace, demo data. No client data is stored.
            </p>
          </div>

          <figure
            className="blueprint"
            style={{ margin: 0, padding: "var(--space-4)", background: "transparent" }}
          >
            <i className="corner tl" />
            <i className="corner tr" />
            <i className="corner bl" />
            <i className="corner br" />
            <div
              role="group"
              aria-label="Product preview: an illustrated morning drilling report"
              style={{ display: "grid", gap: "var(--space-3)" }}
            >
              <header
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  justifyContent: "space-between",
                  gap: "var(--space-3)",
                  borderBottom: "1px solid var(--color-text)",
                  paddingBottom: "var(--space-2)"
                }}
              >
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
                    Report Studio — source-backed draft
                  </span>
                  <strong
                    style={{
                      fontFamily: "var(--font-heading)",
                      fontWeight: "var(--font-heading-weight)" as never,
                      fontSize: 22,
                      textTransform: "uppercase",
                      letterSpacing: "0.02em"
                    }}
                  >
                    Morning Drilling Report
                  </strong>
                </div>
                <span className="tag tag-accent">DDR · draft</span>
              </header>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3,minmax(0,1fr))",
                  gap: 1,
                  background: "var(--color-divider)",
                  border: "1px solid var(--color-divider)"
                }}
              >
                {PREVIEW_META.map((meta) => (
                  <div key={meta.label} style={{ background: "var(--color-bg)", padding: "8px 10px" }}>
                    <span
                      style={{
                        display: "block",
                        fontSize: 9,
                        letterSpacing: "0.08em",
                        textTransform: "uppercase",
                        color: "var(--color-neutral-700)"
                      }}
                    >
                      {meta.label}
                    </span>
                    <strong
                      style={{
                        display: "block",
                        fontFamily: "var(--font-heading)",
                        fontWeight: "var(--font-heading-weight)" as never,
                        fontSize: 15,
                        marginTop: 2
                      }}
                    >
                      {meta.value}
                    </strong>
                  </div>
                ))}
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(0,1.4fr) minmax(96px,0.6fr)",
                  gap: "var(--space-3)"
                }}
              >
                <div style={{ display: "grid", gap: "var(--space-2)", alignContent: "start" }}>
                  <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                    <strong
                      style={{
                        display: "block",
                        fontSize: 11,
                        letterSpacing: "0.06em",
                        textTransform: "uppercase"
                      }}
                    >
                      Present operations
                    </strong>
                    <p
                      style={{
                        margin: "4px 0 0",
                        fontSize: 12,
                        lineHeight: 1.5,
                        color: "var(--color-neutral-700)"
                      }}
                    >
                      Drilling ahead 12.25 in section at 8,620 ft MD; hole cleaning and directional
                      response monitored.
                    </p>
                    {/* Draft-LEVEL, not per-field: `ApiReportDraft` returns the narrative
                        as a bare string with no page or confidence of its own, which the
                        capability card above and the Studio both state. Row-level page and
                        confidence appear on the casing/survey/hydraulics rows, which do
                        carry them. */}
                    <span className="tag tag-neutral" style={{ marginTop: 6 }}>
                      Drafted narrative · cited at draft level
                    </span>
                  </div>

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
                      {[
                        ["00:00–06:00", "Drill ahead, maintain hole cleaning."],
                        ["06:00–12:00", "Survey, circulate bottoms up."],
                        ["12:00–18:00", "Condition mud, update BHA record."]
                      ].map(([span, text]) => (
                        <span key={span} style={{ display: "flex", gap: 8 }}>
                          <strong style={{ fontFamily: "var(--font-heading)", minWidth: 74 }}>{span}</strong>{" "}
                          {text}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div style={{ border: "1px solid var(--color-divider)", padding: "9px 10px" }}>
                    <strong
                      style={{
                        display: "block",
                        fontSize: 11,
                        letterSpacing: "0.06em",
                        textTransform: "uppercase"
                      }}
                    >
                      Issue gate
                    </strong>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
                      <span className="tag tag-neutral">Validation · 2 open</span>
                      <span className="tag tag-neutral">Export · gated</span>
                      <span className="tag tag-accent">Audit · sealed</span>
                    </div>
                  </div>
                </div>

                <figure
                  style={{
                    margin: 0,
                    border: "1px solid var(--color-divider)",
                    background: "var(--color-bg)"
                  }}
                >
                  <svg
                    viewBox="0 0 250 560"
                    role="img"
                    aria-label="Casing and directional schematic"
                    style={{ display: "block", width: "100%", height: "100%" }}
                  >
                    <line x1="24" y1="92" x2="226" y2="92" stroke="var(--color-neutral-300)" strokeWidth="1" />
                    <line x1="24" y1="190" x2="226" y2="190" stroke="var(--color-neutral-300)" strokeWidth="1" />
                    <line x1="24" y1="350" x2="226" y2="350" stroke="var(--color-neutral-300)" strokeWidth="1" />
                    <path d="M110 52 L110 158" fill="none" stroke="var(--color-accent-700)" strokeWidth="4.5" strokeLinecap="round" />
                    <path d="M92 52 L92 282" fill="none" stroke="var(--color-accent-700)" strokeWidth="4.5" strokeLinecap="round" />
                    <path d="M128 52 L128 422" fill="none" stroke="var(--color-accent-700)" strokeWidth="4.5" strokeLinecap="round" />
                    <path
                      d="M110 52 C110 184 116 284 138 360 C158 430 190 470 226 492"
                      fill="none"
                      stroke="var(--color-accent)"
                      strokeWidth="4"
                      strokeLinecap="round"
                    />
                    <path d="M176 446 L236 446 L236 528 L176 528 Z" fill="none" stroke="var(--color-text)" strokeWidth="2" strokeLinejoin="round" />
                    <path d="M30 422 L222 422" fill="none" stroke="var(--color-text)" strokeWidth="1.5" strokeDasharray="6 6" />
                    {/* No <text> here. These are viewBox units, and this figure's rendered
                        scale falls to about 0.38 at the narrow breakpoint, which put the
                        labels at 3.8-6.0 CSS px - while `role="img"` hid the same words
                        from assistive technology, so they were unreadable AND unannounced.
                        The wording lives in the figcaption below, as real text at a real
                        size that a screen reader also reaches. */}
                  </svg>
                </figure>
              </div>
            </div>
            <figcaption style={{ marginTop: "var(--space-2)" }}>
              An illustration of the draft the Studio produces, using demo-workspace values: a
              casing and directional schematic with the 13 3/8 in and 9 5/8 in shoes, current depth
              MD 8,620 ft, and the target box. Not live data and not a real survey computation.
            </figcaption>
          </figure>
        </section>
      </div>

      <section
        aria-label="Monday Report, by the numbers"
        style={{ background: "var(--color-accent-900)", color: "var(--color-bg)", paddingBlock: 60 }}
      >
        <div style={SHELL_WIDTH}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(min(180px,100%),1fr))",
              justifyContent: "space-between",
              gap: "36px 24px"
            }}
          >
            {STATS.map((stat) => (
              <div key={stat.label}>
                <p
                  style={{
                    fontFamily: "var(--font-heading)",
                    fontWeight: "var(--font-heading-weight)" as never,
                    fontSize: "clamp(36px,3.8vw,56px)",
                    lineHeight: 1,
                    color: "var(--color-bg)",
                    margin: "0 -0.036em 0"
                  }}
                >
                  {stat.value}
                </p>
                <p
                  style={{
                    fontSize: 13,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    fontWeight: 600,
                    color: "color-mix(in srgb, var(--color-bg) 55%, transparent)",
                    margin: "12px 0 0"
                  }}
                >
                  {stat.label}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div style={SHELL_WIDTH}>
        <section id="capabilities" aria-label="Capabilities" style={{ paddingBlock: "72px 60px" }}>
          <h2 style={SECTION_KICKER}>What the system does</h2>
          <hr style={{ ...RULE, margin: "0 0 32px" }} />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(min(300px,100%),1fr))",
              gap: "clamp(20px,3vw,40px)"
            }}
          >
            {CAPABILITIES.map((capability) => (
              <div className="blueprint" key={capability.title} style={{ padding: 24 }}>
                <i className="corner tl" />
                <i className="corner tr" />
                <i className="corner bl" />
                <i className="corner br" />
                <h3
                  style={{
                    fontSize: 21,
                    lineHeight: 1.15,
                    letterSpacing: "0.02em",
                    textTransform: "uppercase",
                    margin: 0
                  }}
                >
                  {capability.title}
                </h3>
                <p style={{ fontSize: 15, lineHeight: 1.55, margin: "14px 0 0", color: BODY_TEXT }}>
                  {capability.body}
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 14 }}>
                  {capability.tags.map((tag) => (
                    <span className="tag tag-neutral" key={tag}>
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section id="workflow" aria-label="Workflow" style={{ paddingBlock: "24px 72px" }}>
          <h2 style={SECTION_KICKER}>How a report gets issued</h2>
          <hr style={{ ...RULE, margin: "0 0 8px" }} />
          <div style={{ display: "grid" }}>
            {WORKFLOW.map((step) => (
              <div
                key={step.num}
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(64px,auto) minmax(0,1fr) auto",
                  gap: "16px clamp(16px,3vw,48px)",
                  alignItems: "baseline",
                  paddingBlock: 22,
                  borderBottom: "1px solid var(--color-divider)"
                }}
              >
                <span
                  style={{
                    fontFamily: "var(--font-heading)",
                    fontWeight: "var(--font-heading-weight)" as never,
                    fontSize: "clamp(32px,3vw,44px)",
                    lineHeight: 1,
                    color: "var(--color-accent)"
                  }}
                >
                  {step.num}
                </span>
                <div>
                  <h3 style={{ fontSize: 20, letterSpacing: "0.02em", textTransform: "uppercase", margin: 0 }}>
                    {step.title}
                  </h3>
                  <p
                    style={{
                      fontSize: 15,
                      lineHeight: 1.55,
                      margin: "8px 0 0",
                      maxWidth: "64ch",
                      color: BODY_TEXT
                    }}
                  >
                    {step.body}
                  </p>
                </div>
                <span className="tag tag-outline" style={{ justifySelf: "end" }}>
                  {step.surface}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section id="security" aria-label="Security" style={{ paddingBlock: "0 72px" }}>
          <h2 style={SECTION_KICKER}>Trust, as enforced by the code</h2>
          <hr style={{ ...RULE, margin: "0 0 32px" }} />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(min(280px,100%),1fr))",
              gap: "clamp(20px,3vw,40px)"
            }}
          >
            {TRUST.map((item) => (
              <div
                key={item.title}
                style={{ borderInlineStart: "1px solid var(--color-divider)", paddingInlineStart: 20 }}
              >
                <h3 style={{ fontSize: 19, letterSpacing: "0.02em", textTransform: "uppercase", margin: 0 }}>
                  {item.title}
                </h3>
                <p style={{ fontSize: 14, lineHeight: 1.55, margin: "10px 0 0", color: BODY_TEXT }}>
                  {item.body}
                </p>
              </div>
            ))}
          </div>
          <p className="text-muted" style={{ fontSize: 13, margin: "32px 0 0", maxWidth: "70ch" }}>
            No certification, compliance, or production-acceptance claims are made here. Everything
            above is behavior the repository itself enforces and audits.
          </p>
        </section>

        <section aria-label="Open the demo workspace" style={{ paddingBlock: "0 48px" }}>
          <h2 style={SECTION_KICKER}>The next Monday</h2>
          <hr style={{ ...RULE, margin: "0 0 28px" }} />
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 24,
              alignItems: "end",
              justifyContent: "space-between"
            }}
          >
            <div>
              <h3 style={{ fontSize: 26, letterSpacing: "0.02em", textTransform: "uppercase", margin: 0 }}>
                Open the demo workspace
              </h3>
              <p
                style={{
                  fontSize: 15,
                  lineHeight: 1.55,
                  margin: "10px 0 0",
                  maxWidth: "56ch",
                  color: BODY_TEXT
                }}
              >
                This increment runs on demo data: draft a DDR from parsed evidence, clear the
                validation queue, and issue a checksummed, gated export. Well schematics, upload,
                benchmarking, the failure explorer, the audit-chain view and settings arrive in the
                next increment and say so on their own pages.
              </p>
            </div>
            <Link className="btn btn-primary" to="/app" style={{ textDecoration: "none" }}>
              {CTA_LABEL}
            </Link>
          </div>
        </section>
      </div>
      </main>

      <div style={SHELL_WIDTH}>
        <footer
          style={{
            display: "grid",
            gap: 16,
            paddingBlock: "40px 48px",
            borderTop: "1px solid var(--color-divider)",
            fontSize: 13,
            lineHeight: 1.55,
            color: "color-mix(in srgb, var(--color-text) 70%, transparent)"
          }}
        >
          <div style={{ display: "flex", flexWrap: "wrap", gap: "12px 28px", alignItems: "baseline" }}>
            <span
              style={{
                fontFamily: "var(--font-heading)",
                fontWeight: "var(--font-heading-weight)" as never,
                fontSize: 16,
                color: "var(--color-text)"
              }}
            >
              Monday Report
            </span>
            <a href="#capabilities" style={{ color: "inherit" }}>
              Capabilities
            </a>
            <a href="#workflow" style={{ color: "inherit" }}>
              Workflow
            </a>
            <a href="#security" style={{ color: "inherit" }}>
              Security
            </a>
            <Link to="/app" style={{ color: "inherit" }}>
              Open the app
            </Link>
          </div>
          <span>
            Tenant-scoped drilling-report drafting on a local-first, deterministic engine. This
            preview runs on demo
            data only — no client data is stored, and official exports remain gated behind validation
            and the audit chain.
          </span>
        </footer>
      </div>
    </div>
  );
}
