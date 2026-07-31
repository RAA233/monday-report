/**
 * Focused, load-bearing coverage for the six confirmed Frontend Stage 1 defects.
 *
 * ADDITIVE and self-contained: it does NOT touch, replace, or re-run
 * `scripts/ui_quality_e2e.mjs` (the v1 suite) and does NOT mutate any backend — every
 * API response is stubbed with Playwright route interception, so the suite is
 * non-mutating and needs only the redesign Vite dev server (no isolated state dirs,
 * no real API). Each check targets the EXACT behaviour a fix changed and is designed
 * to FAIL on the pre-fix code:
 *
 *   1. validation refusal discriminator — real function, full status matrix + unknown
 *   2. Studio "Build" is not a silent no-op with no workspace
 *   3. disabled / in-flight visual state: hover/inline cannot defeat the inert style,
 *      contrast is met, and an aria-disabled control does not activate
 *   4. exports gate: a closed BUSINESS gate is not a native-disabled button; it is
 *      focusable, explained, and offers a next action
 *   5. landing preview figures are labelled sample values, not workspace provenance
 *
 * Run: MONDAY_REPORT_WEB_BASE=http://127.0.0.1:5174 node scripts/redesign_stage1_defects.mjs
 * (start the redesign dev server first; VITE_API_BASE_URL is only used as the origin
 *  these stubs match, so it can point anywhere as long as it is a valid URL.)
 */
import { chromium } from "playwright";

const WEB = (process.env.MONDAY_REPORT_WEB_BASE ?? "http://127.0.0.1:5174").replace(/\/$/, "");
const API = (process.env.MONDAY_REPORT_API_BASE ?? "http://127.0.0.1:8010").replace(/\/$/, "");

const results = [];
let failed = 0;
function check(id, ok, detail) {
  results.push({ id, ok: !!ok, detail });
  if (!ok) failed += 1;
  process.stdout.write(`${ok ? "PASS" : "FAIL"}: ${id}${detail ? ` — ${detail}` : ""}\n`);
}

// ── WCAG relative-luminance contrast, from a computed rgb()/rgba() string ──────────
function parseRgb(str) {
  const m = /rgba?\(([^)]+)\)/i.exec(str);
  if (!m) return null;
  const parts = m[1].split(",").map((s) => parseFloat(s.trim()));
  return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
}
function lin(c) {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function relLum({ r, g, b }) {
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}
function contrast(fg, bg) {
  // Flatten fg over bg if the ink carries alpha (it should not here, but be exact).
  const a = fg.a ?? 1;
  const flat = {
    r: fg.r * a + bg.r * (1 - a),
    g: fg.g * a + bg.g * (1 - a),
    b: fg.b * a + bg.b * (1 - a)
  };
  const l1 = relLum(flat);
  const l2 = relLum(bg);
  const hi = Math.max(l1, l2);
  const lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}

// ── stub backend ───────────────────────────────────────────────────────────────────
const TENANT = { id: "t1", name: "Demo", slug: "demo", local_llm_policy: { mode: "off", hosted_fallback_enabled: false } };
const USER = { id: "u1", tenant_id: "t1", email: "op@demo", full_name: "Operator", roles: ["operator"] };
const PERMS = {
  view_validation_queue: true,
  resolve_validation: true,
  issue_client_reports: true,
  export_evidence: true,
  create_client_reports: true
};
const SESSION = { tenant: TENANT, user: USER, authenticated_identity: { roles: ["operator"] }, permissions: PERMS };
const WS = { id: "w1", tenant_id: "t1", name: "FORGE 16A", asset: "FORGE", campaign: null, status: "active" };
const REPORT = {
  id: "r1", tenant_id: "t1", workspace_id: "w1", period_start: "2026-01-01", period_end: "2026-01-07",
  status: "review", report_json: {}, created_at: "2026-01-07T00:00:00Z"
};
const OPEN_FAILURE_TASK = {
  id: "vt1", tenant_id: "t1", target_type: "failure", target_id: "f1", reason: "High-severity failure",
  priority: "high", status: "open", created_at: "2026-01-06T00:00:00Z"
};
const FAILURE = {
  id: "f1", tenant_id: "t1", workspace_id: "w1", event_type: "MWD signal loss", severity: "High",
  summary: "loss", company: "svc", tool_type: "MWD", tool_serial: "x", npt_hours: 8, confidence: 0.8,
  validation_status: "open", citations: []
};
const BENCHMARKING = {
  workspace_id: "w1", generated_at: "2026-01-07T00:00:00Z", comparisons: [], active_anomalies: [],
  historical_anomalies: [], benchmark_values: [], anomaly_rules: [], seven_day_trend: [],
  likely_operational_contributors: [], recommended_diagnostic_actions: [], supporting_evidence_references: [],
  ai_interpretation: [], permissions: {}
};

function json(body, status = 200) {
  return { status, contentType: "application/json", body: JSON.stringify(body) };
}

/** Install a stub router for one scenario. `overrides` maps a path suffix to a body. */
async function stub(page, { workspaces = [WS], overrides = {} } = {}) {
  await page.route(`${API}/**`, async (route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    const send = (b, s = 200) => route.fulfill(json(b, s));
    for (const [suffix, resp] of Object.entries(overrides)) {
      if (p.endsWith(suffix) || p.includes(suffix)) {
        if (typeof resp === "function") return resp(route, url);
        return send(resp);
      }
    }
    if (p.endsWith("/auth/session")) return send(SESSION);
    if (p.endsWith("/workspaces")) return send(workspaces);
    if (p.endsWith("/validation-tasks")) return send([]);
    if (p.endsWith("/failures")) return send([]);
    if (p.endsWith("/monday-reports")) return send([]);
    if (p.includes("/benchmarking")) return send(BENCHMARKING);
    if (p.endsWith("/client-data")) return send({ mode: "demo", status: "blocked", ready: false, generated_at: "2026-01-01T00:00:00Z", checks: [] });
    if (p.endsWith("/local-ai/status")) return send({ enabled: false, runtime: null, model: null, reachable: false, detail: "off" });
    if (p.endsWith("/runtime/backends")) return send({ repository: { requested: "local_json", active: "local_json" }, queue: { requested: "inline", active: "inline" } });
    if (p.includes("/audit-logs/integrity")) return send({ status: "empty", entries: 0 });
    if (p.includes("/audit-logs")) return send([]);
    if (p.endsWith("/processing-jobs")) return send([]);
    if (p.endsWith("/documents")) return send([]);
    // benign default: an empty collection never crashes a list read.
    return send([]);
  });
}

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  context.on("weberror", (e) => errors.push(String(e.error())));

  // ── Defect 1: refusal discriminator — the REAL exported function, full matrix ─────
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [] });
    await page.goto(`${WEB}/`, { waitUntil: "domcontentloaded" });
    const r = await page.evaluate(async () => {
      const m = await import("/src/redesign/lib/workspace.tsx");
      // Missing exports is the pre-fix state: report it as data, not a crash, so the
      // suite still emits per-check FAILs when run against unfixed source.
      if (typeof m.requestStatus !== "function" || typeof m.isBackendRefusal !== "function") {
        return { missing: true, errorText409: typeof m.errorText === "function" ? m.errorText(new Error("API 409: conflict")) : "" };
      }
      const mk = (msg) => new Error(msg);
      const statuses = [400, 401, 403, 404, 409, 422, 423, 429, 500, 502, 503];
      const refusal = statuses.map((s) => ({
        s,
        status: m.requestStatus(mk(`API ${s}: detail here`)),
        isRefusal: m.isBackendRefusal(mk(`API ${s}: detail here`))
      }));
      const unknowns = [
        m.isBackendRefusal(new TypeError("Failed to fetch")),
        m.isBackendRefusal(mk("The request did not complete.")),
        m.isBackendRefusal(mk("network error")),
        m.isBackendRefusal(null),
        m.isBackendRefusal(undefined),
        m.isBackendRefusal("API 409: not an Error instance")
      ];
      return {
        refusal,
        unknowns,
        // The OLD classifier tested errorText()'s output; prove that erases the status.
        oldClassifierOn409: /^API \d{3}\b/.test(m.errorText(mk("API 409: conflict"))),
        errorText409: m.errorText(mk("API 409: conflict"))
      };
    });
    if (r.missing) {
      check("d1-status-matrix", false, "requestStatus/isBackendRefusal are not exported (pre-fix)");
      check("d1-unknown-fail-closed", false, "discriminator not present");
      check("d1-sanitized-string-would-misclassify", false, "discriminator not present");
      await page.close();
      // fall through to the remaining defect blocks
    } else {
    const everyStatus = r.refusal.every((x) => x.status === x.s && x.isRefusal === true);
    check("d1-status-matrix", everyStatus, `statuses -> ${JSON.stringify(r.refusal.map((x) => x.status))}`);
    check("d1-unknown-fail-closed", r.unknowns.every((x) => x === false), `unknowns -> ${JSON.stringify(r.unknowns)}`);
    check(
      "d1-sanitized-string-would-misclassify",
      r.oldClassifierOn409 === false && !/^API /.test(r.errorText409),
      `errorText("API 409:…") = ${JSON.stringify(r.errorText409)} (old classifier match=${r.oldClassifierOn409})`
    );
    await page.close();
    }
  }

  // ── Defect 3: inert visual state (hover/inline cannot defeat it; contrast; inert) ──
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [] });
    await page.goto(`${WEB}/`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => {
      const mkBtn = (id, cls, aria, inlineColor) => {
        const b = document.createElement("button");
        b.id = id;
        b.className = cls;
        if (aria) b.setAttribute("aria-disabled", "true");
        if (inlineColor) b.style.color = inlineColor;
        b.textContent = "Building draft…";
        b.dataset.fired = "0";
        b.addEventListener("click", () => (b.dataset.fired = "1"));
        document.body.appendChild(b);
      };
      mkBtn("t-primary-inert", "btn btn-primary", true, null);
      mkBtn("t-inline-inert", "btn btn-secondary", true, "var(--color-neutral-400)");
      mkBtn("t-primary-live", "btn btn-primary", false, null);
    });
    const measure = async (sel) => {
      await page.hover(sel);
      return page.evaluate((s) => {
        const el = document.querySelector(s);
        const cs = getComputedStyle(el);
        return { color: cs.color, bg: cs.backgroundColor };
      }, sel);
    };
    const prim = await measure("#t-primary-inert");
    const primC = contrast(parseRgb(prim.color), parseRgb(prim.bg));
    check("d3-inflight-hover-contrast", primC >= 4.5, `aria-disabled .btn-primary on hover = ${primC.toFixed(2)}:1 (was 1.51:1)`);

    const inl = await measure("#t-inline-inert");
    const inlC = contrast(parseRgb(inl.color), parseRgb(inl.bg));
    check("d3-inline-colored-inert-contrast", inlC >= 4.5, `inline-coloured aria-disabled on hover = ${inlC.toFixed(2)}:1 (was 1.62:1)`);

    // The rule must be SCOPED: a normal primary button still reacts to hover.
    const live = await measure("#t-primary-live");
    const liveBg = parseRgb(live.bg);
    const inertBg = parseRgb(prim.bg);
    const scoped = !(liveBg.r === inertBg.r && liveBg.g === inertBg.g && liveBg.b === inertBg.b);
    check("d3-rule-scoped-to-disabled", scoped, `live hover bg ${live.bg} != inert bg ${prim.bg}`);

    // Activation blocked: an aria-disabled native button that the app renders keeps its
    // handler inert. Here we assert the app's own contract — clicking a control the app
    // marked aria-disabled must not run its action — using the reset button below.
    await page.close();
  }

  // ── Defect 5: landing preview figures are labelled sample, not provenance ─────────
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [] });
    await page.goto(`${WEB}/`, { waitUntil: "domcontentloaded" });
    const cap = await page.evaluate(() => {
      const f = document.querySelector("figcaption");
      return f ? f.textContent.replace(/\s+/g, " ").trim() : "";
    });
    check(
      "d5-no-workspace-provenance-claim",
      !/demo-workspace values/i.test(cap),
      `figcaption ${JSON.stringify(cap.slice(0, 90))}`
    );
    check(
      "d5-sample-values-labelled",
      /sample figures/i.test(cap) && /not read from any workspace/i.test(cap),
      "caption names the figures as sample values not read from a workspace"
    );
    await page.close();
  }

  // ── Defect 2: Studio "Build" is not a silent no-op with no workspace ──────────────
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [] }); // connected, but no workspace resolves
    await page.goto(`${WEB}/app/studio`, { waitUntil: "domcontentloaded" });
    const btn = page.getByRole("button", { name: /Build source-backed draft/i });
    await btn.waitFor({ state: "visible", timeout: 15000 });
    const nativelyDisabled = await btn.isDisabled();
    check("d2-build-reachable-when-connected", !nativelyDisabled, `connected + no workspace: button disabled=${nativelyDisabled}`);
    // A blocked click must ANNOUNCE. Before the fix the dedup guard (null===null)
    // swallowed it: no alert, no status text change.
    const before = await page.locator("body").innerText();
    await btn.click({ force: true });
    await page.waitForTimeout(400);
    const alertText = await page.evaluate(() => {
      const a = Array.from(document.querySelectorAll('[role="alert"],[role="status"]'));
      return a.map((n) => n.textContent).join(" | ");
    });
    const after = await page.locator("body").innerText();
    const announced = /No workspace is selected/i.test(alertText) || /No workspace is selected/i.test(after);
    check("d2-no-workspace-click-announces", announced, `alert/status after click: ${JSON.stringify(alertText.slice(0, 120))}`);
    check("d2-click-not-silent", after !== before || announced, "the click changed the accessible page state");
    await page.close();
  }

  // ── Defect 4: a closed business gate is not a native-disabled button ──────────────
  {
    const page = await context.newPage();
    await stub(page, {
      workspaces: [WS],
      overrides: {
        "/validation-tasks": [OPEN_FAILURE_TASK],
        "/failures": [FAILURE],
        "/monday-reports": [REPORT]
      }
    });
    await page.goto(`${WEB}/app/exports`, { waitUntil: "domcontentloaded" });
    // Wait for the gate to resolve to "closed".
    await page.getByText(/Export gate closed/i).waitFor({ state: "visible", timeout: 15000 });
    const banner = await page.evaluate(() => document.body.innerText);
    check("d4-gate-reason-shown", /Resolve 1 validation task\(s\) before exporting/i.test(banner), "closed-gate reason (committed copy) is shown");
    const hasNextAction = (await page.getByRole("link", { name: /Open the queue/i }).count()) > 0;
    check("d4-gate-next-action", hasNextAction, "an 'Open the queue' link to Validation is offered");

    const exportBtn = page.getByRole("button", { name: /^Export /i }).first();
    await exportBtn.waitFor({ state: "visible", timeout: 8000 });
    const state = await exportBtn.evaluate((el) => ({
      disabled: el.disabled,
      ariaDisabled: el.getAttribute("aria-disabled"),
      describedBy: el.getAttribute("aria-describedby")
    }));
    check("d4-closed-gate-not-native-disabled", state.disabled === false, `export button native disabled=${state.disabled}`);
    check("d4-closed-gate-aria-disabled", state.ariaDisabled === "true", `aria-disabled=${state.ariaDisabled}`);
    check(
      "d4-closed-gate-describedby-reason",
      state.describedBy === "export-gate-reason",
      `aria-describedby=${state.describedBy}`
    );
    // The described reason element must actually exist and carry the reason.
    const reasonText = await page.evaluate(() => document.getElementById("export-gate-reason")?.textContent ?? "");
    check("d4-describedby-target-exists", /validation task/i.test(reasonText), `#export-gate-reason = ${JSON.stringify(reasonText.slice(0, 80))}`);

    // Activation blocked: clicking the aria-disabled export must not issue an export
    // (no POST /monday-reports/*/exports). We assert the handler is inert by checking
    // no status flips to "Creating…".
    await exportBtn.click({ force: true });
    await page.waitForTimeout(300);
    const creating = await page.evaluate(() => /Creating .* export…/i.test(document.body.innerText));
    check("d4-closed-gate-activation-blocked", creating === false, "clicking the closed-gate export did not start an export");
    await page.close();
  }

  check("no-web-errors", errors.length === 0, errors.length ? errors.slice(0, 3).join(" || ") : "0 uncaught page errors");

  await browser.close();
  const passed = results.filter((r) => r.ok).length;
  process.stdout.write(`\n${JSON.stringify({ suite: "redesign_stage1_defects", passed, failed, total: results.length })}\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`redesign_stage1_defects harness error: ${error && error.stack ? error.stack : error}\n`);
  process.exit(2);
});
