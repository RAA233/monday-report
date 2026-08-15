// Shared canonical browser scenario inventory for the dual-backend UI certification.
//
// Drives a REAL Chrome (Playwright) against the REAL built frontend + REAL external API for ONE backend
// (local/file OR restricted PostgreSQL). The SAME scenario ids run against both backends; the Python
// orchestrator (dual_backend_ui_guard.py) launches each backend, runs this once per backend, attaches
// the database/state postconditions, and compares the two result sets.
//
// The frontend under test is the CANONICAL redesign entry: the public landing at `/`, the application
// shell under `/app`, a real router, and sidebar navigation links. Scenarios enter at `/app` and use
// the sidebar (aside[aria-label="Primary"]) exactly as an operator would.
//
// Emits a single JSON object on stdout: { backend, fatal, scenarios[], counters{}, console_errors[],
// network_errors[] }. Business responses come only from the real API — no mocks, no interception.
//
// Env: DBUI_WEB_BASE, DBUI_API_BASE, DBUI_BACKEND, DBUI_EXPECT_TENANT, DBUI_UPLOAD_FIXTURE, DBUI_DOWNLOAD_DIR
import { chromium } from "playwright";

const web = process.env.DBUI_WEB_BASE;
const backend = process.env.DBUI_BACKEND || "unknown";
const expectTenant = process.env.DBUI_EXPECT_TENANT || "";
const uploadFixture = process.env.DBUI_UPLOAD_FIXTURE || "";

const scenarios = [];
const consoleErrors = [];
const networkErrors = [];
const counters = {
  console_error_count: 0, uncaught_exception_count: 0, failed_business_request_count: 0,
  normal_HTTP_423_count: 0, normal_HTTP_500_count: 0, normal_HTTP_503_count: 0,
};
// expected/classified negatives that must NOT count as failures (none expected in the demo happy path)
const CLASSIFIED_OK = [];

function scenario(id, fields) {
  scenarios.push({ check_id: id, backend, ...fields });
}

// Per-scenario error scoping: snapshot error counts before, diff after.
function mark() { return { c: consoleErrors.length, n: networkErrors.length, e: counters.uncaught_exception_count }; }
function since(m) {
  return {
    console_result: consoleErrors.length === m.c ? "clean" : consoleErrors.slice(m.c).slice(0, 4).join(" | "),
    network_result: networkErrors.length === m.n ? "clean" : networkErrors.slice(m.n).slice(0, 4).join(" | "),
    uncaught: counters.uncaught_exception_count - m.e,
  };
}

const browser = await chromium.launch({ channel: "chrome", headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  acceptDownloads: true,
});
const page = await context.newPage();
page.on("pageerror", (e) => { counters.uncaught_exception_count += 1; consoleErrors.push(`pageerror: ${e.message}`); });
page.on("console", (m) => {
  if (m.type() === "error" && !/Failed to load resource/i.test(m.text())) {
    counters.console_error_count += 1;
    consoleErrors.push(`console: ${m.text()}`);
  }
});
page.on("response", (r) => {
  const s = r.status();
  if (s < 400) return;
  const url = r.url();
  if (/favicon|\.ico|\.png|\.svg|\.woff/i.test(url)) return;
  if (s === 423) counters.normal_HTTP_423_count += 1;
  else if (s === 500) counters.normal_HTTP_500_count += 1;
  else if (s === 503) counters.normal_HTTP_503_count += 1;
  const classified = CLASSIFIED_OK.some((c) => url.includes(c));
  if (!classified) {
    counters.failed_business_request_count += 1;
    networkErrors.push(`HTTP ${s}: ${url}`);
  }
});

async function openFresh() {
  // `/app` is the shell entry (Ask). `/` is the public landing and issues no
  // authenticated read, so it proves nothing about the backend under test.
  await page.goto(`${web}/app`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.locator("[data-shell]").waitFor({ state: "visible", timeout: 20000 });
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
}
async function nav(label) {
  // The primary rail is a set of router LINKS, named by their accessible name
  // (which folds in the validation badge when present, hence the regex).
  await page
    .locator('aside[aria-label="Primary"]')
    .getByRole("link", { name: new RegExp(`^${label}`) })
    .first()
    .click();
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
}
async function visible(pattern, timeout = 20000) {
  try { await page.getByText(pattern).first().waitFor({ state: "visible", timeout }); return true; }
  catch { return false; }
}
async function headingIs(pattern, timeout = 20000) {
  // POLLS until an h1 matching the pattern is visible: after a client-side route
  // transition the OLD view's h1 is still mounted for a beat (and views that issue
  // no request on mount reach networkidle before rendering), so a single read of
  // the first h1 raced the router and failed views that render perfectly.
  try {
    await page
      .locator("h1")
      .filter({ hasText: pattern })
      .first()
      .waitFor({ state: "visible", timeout });
    return true;
  } catch {
    return false;
  }
}

let fatal = null;
try {
  // UI01 — bootstrap: real session/workspaces load; the topbar chip reads "API connected"
  {
    const m = mark();
    await openFresh();
    const connected = await visible(/API connected/i);
    const askHome = await headingIs(/^Ask Monday Report$/i);
    const noFallback = (await page.getByText(/local fallback/i).count()) === 0;
    scenario("UI01-bootstrap", {
      description: "app boots against the real external API: the shell renders, the connectivity chip reads API connected, and no local-fallback claim appears",
      page: "ask", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "API connected + Ask Monday Report", expected_http_status: "200",
      db_postcondition: "n/a (read path)", ...since(m),
      result: connected && askHome && noFallback ? "PASS" : "FAIL",
    });
  }
  // UI02 — tenant presentation: the expected tenant renders (identity from the real API session)
  {
    const m = mark();
    await openFresh();
    let tenantOk = true;
    if (expectTenant) tenantOk = (await page.getByText(expectTenant, { exact: false }).count()) >= 1;
    scenario("UI02-tenant-presentation", {
      description: "the sidebar tenant card renders the expected tenant identity from the real API session",
      page: "ask", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: `tenant '${expectTenant}' visible`, expected_http_status: "200",
      db_postcondition: "n/a (read path)", ...since(m),
      result: tenantOk ? "PASS" : "FAIL",
    });
  }
  // UI03 — navigation across the real views, through the sidebar links
  {
    const views = [
      ["Monday reports", /^Monday reports$/i],
      // Fresh load: the Studio h1 is "<active variant label> draft" and DDR is the default.
      ["Report Studio", /^Daily drilling draft$/i],
      ["Well schematics", /^Well schematics$/i],
      ["Upload", /^Upload rig reports$/i],
      ["Benchmarking", /^Benchmarking$/i],
      ["Validation", /^Validation queue$/i],
      ["Failures", /^Failure explorer$/i],
      ["Report integrity", /^Report integrity$/i],
      ["Exports", /^Exports$/i],
      ["Settings", /^Settings$/i],
      ["Tracker", /^Project tracker$/i],
      ["Roadmap", /^Product roadmap$/i],
    ];
    let allOk = true; const detail = [];
    const m = mark();
    for (const [label, title] of views) {
      await openFresh();
      await nav(label);
      const ok = await headingIs(title);
      if (!ok) { allOk = false; detail.push(`${label}:missing`); }
    }
    scenario("UI03-navigation", {
      description: "every primary view renders its own h1 against the real API, reached through the sidebar",
      page: "all-views", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "each view heading visible", expected_http_status: "200",
      db_postcondition: "n/a (read path)", views_checked: views.length, detail: detail.join(",") || "all-visible",
      ...since(m), result: allOk ? "PASS" : "FAIL",
    });
  }
  // UI04 — upload mutation: the audited direct-upload intake on /app/upload
  {
    const m = mark();
    await openFresh();
    await nav("Upload");
    await headingIs(/^Upload rig reports$/i);
    let uploadOk = false, detail = "";
    try {
      await page.getByLabel("Select report files to upload").setInputFiles(uploadFixture);
      // Rendered only after POST /uploads/direct succeeds: "Stored, hashed (sha256 …), audited, and queued".
      uploadOk = await visible(/Stored, hashed/i, 25000);
      const refused = await page.getByText(/uploads refused|Outcome partly unknown/i).count();
      if (refused > 0) { uploadOk = false; detail = "upload refused or outcome unknown"; }
    } catch (e) { detail = `upload-error:${e.message}`; }
    scenario("UI04-upload-mutation", {
      description: "uploading a file via /app/upload stores+hashes+audits it through the real API (POST /uploads/direct)",
      page: "upload", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Stored, hashed, audited, and queued", expected_http_status: "201",
      db_postcondition: "PENDING(python: uploaded_file row + parsed_document after worker)",
      detail, ...since(m), result: uploadOk ? "PASS" : "FAIL",
    });
  }
  // UI05 — benchmarking measurement mutation (real API)
  {
    const m = mark();
    await openFresh();
    await nav("Benchmarking");
    await headingIs(/^Benchmarking$/i);
    let benchOk = false, detail = "";
    try {
      // The record form renders once the gated benchmarking read resolves — WAIT for
      // it rather than sampling `count()` the instant the route mounts.
      const ftInput = page.locator("#bm-value");
      await ftInput.waitFor({ state: "visible", timeout: 20000 });
      await ftInput.fill("540");
      const src = page.locator("#bm-source");
      if (await src.count()) await src.fill("dual-backend-ui synthetic");
      await page.getByRole("button", { name: /Record measurement/i }).click();
      // Mutation-ONLY confirmation: this sentence is set only after a successful
      // createBenchmarkMeasurement API call ("...anomaly rules were evaluated...").
      benchOk = await visible(/anomaly rules were evaluated/i, 20000);
      if (!benchOk && (await page.getByText(/Not recorded|Outcome unknown/i).count()) > 0) {
        detail = "the record was refused or its outcome unknown";
      }
    } catch (e) { detail = `bench-error:${e.message}`; }
    scenario("UI05-benchmarking-mutation", {
      description: "recording a benchmark measurement via the UI persists through the real API",
      page: "benchmarking", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Measurement recorded", expected_http_status: "200",
      db_postcondition: "PENDING(python: benchmark measurement recorded)",
      detail, ...since(m), result: benchOk ? "PASS" : "FAIL",
    });
  }
  // UI06 — chat: a real API-backed answer on the Ask home
  {
    const m = mark();
    await openFresh();
    let chatOk = false, detail = "";
    try {
      await page.getByLabel("Ask the analyst").fill("Summarize the current rig evidence and risks.");
      await page.getByRole("button", { name: "Ask", exact: true }).click();
      const answered = await page
        .locator('article[aria-label="Monday Report answer"]')
        .first()
        .waitFor({ state: "visible", timeout: 25000 })
        .then(() => true)
        .catch(() => false);
      const refusal = (await page.getByText(/was not processed/i).count()) > 0;
      chatOk = answered && !refusal;
      if (!answered) detail = "no answer turn rendered";
      else if (refusal) detail = "the answer turn carries a refusal classification";
    } catch (e) { detail = `chat-error:${e.message}`; }
    scenario("UI06-chat-real-answer", {
      description: "Ask returns a real API-backed answer turn (POST /chat), not a refusal classification",
      page: "ask", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "an answer turn with no refusal", expected_http_status: "200",
      db_postcondition: "n/a (read/derive path)", detail, ...since(m),
      result: chatOk ? "PASS" : "FAIL",
    });
  }
  // UI07 — report studio source draft (real API getReportDraft; the route audits the draft)
  {
    const m = mark();
    await openFresh();
    await nav("Report Studio");
    await headingIs(/draft$/i);
    let draftOk = false, detail = "";
    try {
      await page.getByRole("button", { name: /Build source-backed draft/i }).click();
      draftOk = await visible(/Source-backed draft ready/i, 20000);
      if (!draftOk) detail = "source draft not ready";
    } catch (e) { detail = `draft-error:${e.message}`; }
    scenario("UI07-report-draft", {
      description: "Report Studio pulls a source-backed draft from the real API",
      page: "studio", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Source-backed draft ready", expected_http_status: "200",
      db_postcondition: "n/a (read path; the backend audits report_draft.generate)", detail, ...since(m),
      result: draftOk ? "PASS" : "FAIL",
    });
  }
  // UI08 — Monday-report creation (real API mutation reachable by a fixed selector)
  {
    const m = mark();
    await openFresh();
    await nav("Monday reports");
    await headingIs(/^Monday reports$/i);
    let createOk = false, detail = "";
    try {
      // `.first()`: the control renders in the page header AND beside the empty
      // state, and both are the same handler.
      await page.getByRole("button", { name: /New Monday report/i }).first().click();
      // Mutation-ONLY confirmation: the success toast body reads
      // "<id> opened as a <status> for <period> and appended to the audit chain."
      // — set only after a successful createMondayReport API call. The failure
      // toast ("Not created") cannot match this.
      createOk = await visible(/opened as a (draft|review)/i, 20000);
      if (!createOk) detail = "no creation confirmation rendered";
    } catch (e) { detail = `create-error:${e.message}`; }
    scenario("UI08-report-create-mutation", {
      description: "creating a Monday report via the UI persists through the real API (POST /monday-reports)",
      page: "reports", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Report created", expected_http_status: "201",
      db_postcondition: "PENDING(python: monday report row present)",
      detail, ...since(m), result: createOk ? "PASS" : "FAIL",
    });
  }
  // UI09 — validation queue renders (read path in THIS run: the redesign's decision
  // buttons DO call the real validation API, but the demo queue is empty while the
  // browser runs — the worker that raises a task runs after the scenarios — so the
  // transition path is exercised by scripts/ui_redesign_e2e.mjs, not here)
  {
    const m = mark();
    await openFresh();
    await nav("Validation");
    const queueOk = await headingIs(/^Validation queue$/i);
    scenario("UI09-validation-queue-render", {
      description: "the Validation view renders the queue from the real API (decision controls are real API "
        + "mutations in this frontend; they are exercised with a seeded task by scripts/ui_redesign_e2e.mjs)",
      page: "validation", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Validation queue visible", expected_http_status: "200",
      db_postcondition: "n/a (read path in this run)", ...since(m),
      result: queueOk ? "PASS" : "FAIL",
    });
  }
  // UI10 — whole-run browser integrity (no console errors / uncaught exceptions / failed business reqs)
  scenario("UI10-browser-integrity", {
    description: "no console errors, no uncaught exceptions, no failed business requests, no 423/500/503",
    page: "all", actor_classification: "demo_bootstrap", tenant_classification: "primary",
    expected_ui_state: "all counters zero", expected_http_status: "none >=400",
    db_postcondition: "n/a", console_result: counters.console_error_count === 0 ? "clean" : `${counters.console_error_count} errors`,
    network_result: counters.failed_business_request_count === 0 ? "clean" : `${counters.failed_business_request_count} failed`,
    result: (counters.console_error_count === 0 && counters.uncaught_exception_count === 0
      && counters.failed_business_request_count === 0 && counters.normal_HTTP_423_count === 0
      && counters.normal_HTTP_500_count === 0 && counters.normal_HTTP_503_count === 0) ? "PASS" : "FAIL",
  });
} catch (e) {
  fatal = `${e && e.name}: ${e && e.message}`;
} finally {
  await context.close();
  await browser.close();
}

process.stdout.write(JSON.stringify({ backend, fatal, scenarios, counters, console_errors: consoleErrors, network_errors: networkErrors }, null, 2));
process.exit(0);
