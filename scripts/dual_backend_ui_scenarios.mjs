// Shared canonical browser scenario inventory for the dual-backend UI certification.
//
// Drives a REAL Chrome (Playwright) against the REAL built frontend + REAL external API for ONE backend
// (local/file OR restricted PostgreSQL). The SAME scenario ids run against both backends; the Python
// orchestrator (dual_backend_ui_guard.py) launches each backend, runs this once per backend, attaches
// the database/state postconditions, and compares the two result sets.
//
// Emits a single JSON object on stdout: { backend, fatal, scenarios[], counters{}, console_errors[],
// network_errors[] }. Business responses come only from the real API — no mocks, no route interception.
//
// Env: DBUI_WEB_BASE, DBUI_API_BASE, DBUI_BACKEND, DBUI_EXPECT_TENANT, DBUI_UPLOAD_FIXTURE, DBUI_DOWNLOAD_DIR
import fs from "node:fs/promises";
import path from "node:path";
import { chromium } from "playwright";

const web = process.env.DBUI_WEB_BASE;
const backend = process.env.DBUI_BACKEND || "unknown";
const expectTenant = process.env.DBUI_EXPECT_TENANT || "";
const uploadFixture = process.env.DBUI_UPLOAD_FIXTURE || "";
const downloadDir = process.env.DBUI_DOWNLOAD_DIR || "";

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
  await page.goto(web, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.locator(".app-shell").waitFor({ state: "visible", timeout: 20000 });
  await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
}
async function nav(label) {
  await page.getByLabel("Primary", { exact: true }).getByRole("button", { name: label, exact: true }).click();
}
async function visible(pattern, timeout = 20000) {
  try { await page.getByText(pattern).first().waitFor({ state: "visible", timeout }); return true; }
  catch { return false; }
}

let fatal = null;
try {
  // UI01 — bootstrap: real session/workspaces load, "API connected" (not local fallback)
  {
    const m = mark();
    await openFresh();
    const connected = await visible(/API connected/i);
    const landing = await visible(/Advanced drilling reports without visual noise/i);
    const noFallback = (await page.getByText(/local fallback/i).count()) === 0;
    scenario("UI01-bootstrap", {
      description: "app boots against the real external API and shows API-connected (no local fallback)",
      page: "client-home", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "API connected + client landing", expected_http_status: "200",
      db_postcondition: "n/a (read path)", ...since(m),
      result: connected && landing && noFallback ? "PASS" : "FAIL",
    });
  }
  // UI02 — tenant presentation: the expected tenant renders (identity from the real API session)
  {
    const m = mark();
    await openFresh();
    let tenantOk = true;
    if (expectTenant) tenantOk = (await page.getByText(expectTenant, { exact: false }).count()) >= 1;
    scenario("UI02-tenant-presentation", {
      description: "the sidebar renders the expected tenant identity from the real API session",
      page: "client-home", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: `tenant '${expectTenant}' visible`, expected_http_status: "200",
      db_postcondition: "n/a (read path)", ...since(m),
      result: tenantOk ? "PASS" : "FAIL",
    });
  }
  // UI03 — navigation across the real views
  {
    const views = [
      ["Report Studio", /Technical daily-report command console/i],
      ["Benchmarking", /Market Benchmark/i],
      ["Upload", /Upload rig reports/i],
      ["Dashboard", /Monday Report intelligence/i],
      ["Validation", /Validation queue/i],
      ["Tracker", /Project tracker/i],
      ["Roadmap", /Product roadmap/i],
      ["Architecture", /Local AI-first architecture/i],
    ];
    let allOk = true; const detail = [];
    const m = mark();
    for (const [label, title] of views) {
      await openFresh();
      await nav(label);
      const ok = await visible(title);
      if (!ok) { allOk = false; detail.push(`${label}:missing`); }
    }
    scenario("UI03-navigation", {
      description: "every primary view renders its heading against the real API",
      page: "all-views", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "each view heading visible", expected_http_status: "200",
      db_postcondition: "n/a (read path)", views_checked: views.length, detail: detail.join(",") || "all-visible",
      ...since(m), result: allOk ? "PASS" : "FAIL",
    });
  }
  // UI04 — upload mutation (the one always-present real-API mutation reachable by a fixed selector)
  {
    const m = mark();
    await openFresh();
    await nav("Upload");
    await visible(/Upload rig reports/i);
    let uploadOk = false, detail = "";
    try {
      await page.locator('input[type="file"]').first().setInputFiles(uploadFixture);
      uploadOk = await visible(/Stored, hashed, and audited/i, 25000);
      const failed = await page.getByText(/backend upload audit failed/i).count();
      if (failed > 0) { uploadOk = false; detail = "backend upload audit failed"; }
    } catch (e) { detail = `upload-error:${e.message}`; }
    scenario("UI04-upload-mutation", {
      description: "uploading a file via the UI stores+hashes+audits it through the real API",
      page: "upload", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Stored, hashed, and audited", expected_http_status: "201",
      db_postcondition: "PENDING(python: uploaded_file row + parsed_document after worker)",
      detail, ...since(m), result: uploadOk ? "PASS" : "FAIL",
    });
  }
  // UI05 — benchmarking measurement mutation (real API)
  {
    const m = mark();
    await openFresh();
    await nav("Benchmarking");
    await visible(/Market Benchmark/i);
    let benchOk = false, detail = "";
    try {
      const ftInput = page.getByLabel(/feet.*day|ft.*day/i).first();
      const hasInput = await ftInput.count();
      if (hasInput) {
        await ftInput.fill("540");
        const src = page.getByLabel(/source|dataset/i).first();
        if (await src.count()) await src.fill("dual-backend-ui synthetic");
        await page.getByRole("button", { name: /Record measurement/i }).click();
        // mutation-ONLY confirmation (BenchmarkingModule sets this string only after a successful
        // recordMeasurement API call); static page labels must not be able to satisfy this.
        benchOk = await visible(/Measurement recorded, anomaly rules evaluated/i, 20000);
      } else {
        detail = "no ft/day input exposed"; benchOk = false;
      }
    } catch (e) { detail = `bench-error:${e.message}`; }
    scenario("UI05-benchmarking-mutation", {
      description: "recording a benchmark measurement via the UI persists through the real API",
      page: "benchmarking", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "measurement recorded + variance rendered", expected_http_status: "200",
      db_postcondition: "PENDING(python: benchmark measurement recorded)",
      detail, ...since(m), result: benchOk ? "PASS" : "FAIL",
    });
  }
  // UI06 — chat: a real API-backed answer (source-backed), not the local fallback
  {
    const m = mark();
    await openFresh();
    await nav("Local AI Chat");
    await visible(/Ask Monday Report first/i);
    let chatOk = false, detail = "";
    try {
      await page.getByPlaceholder(/Ask about failures/i).fill("Summarize the current rig evidence and risks.");
      await page.getByRole("button", { name: /Send question/i }).click();
      const sourceBacked = await visible(/Source-backed response/i, 25000);
      chatOk = sourceBacked;
      if (!sourceBacked) detail = "no source-backed (real-API) answer rendered";
    } catch (e) { detail = `chat-error:${e.message}`; }
    scenario("UI06-chat-real-answer", {
      description: "chat returns a real API-backed source answer (not the offline local fallback)",
      page: "chat", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Source-backed response", expected_http_status: "200",
      db_postcondition: "n/a (read/derive path)", detail, ...since(m),
      result: chatOk ? "PASS" : "FAIL",
    });
  }
  // UI07 — report studio source draft (real API getReportDraft)
  {
    const m = mark();
    await openFresh();
    await nav("Report Studio");
    await visible(/Technical daily-report command console/i);
    let draftOk = false, detail = "";
    try {
      await page.getByRole("button", { name: /Source draft/i }).click();
      draftOk = await visible(/Source-backed draft ready/i, 20000);
      if (!draftOk) detail = "source draft not ready";
    } catch (e) { detail = `draft-error:${e.message}`; }
    scenario("UI07-report-draft", {
      description: "Report Studio pulls a source-backed draft from the real API",
      page: "report-studio", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Source-backed draft ready", expected_http_status: "200",
      db_postcondition: "n/a (read path)", detail, ...since(m),
      result: draftOk ? "PASS" : "FAIL",
    });
  }
  // UI08 — client-side draft download (the one real browser-download event the UI exposes)
  {
    const m = mark();
    await openFresh();
    await nav("Report Studio");
    await visible(/Technical daily-report command console/i);
    let dlOk = false, dlName = "", dlSize = 0, detail = "";
    try {
      const [download] = await Promise.all([
        page.waitForEvent("download", { timeout: 15000 }),
        page.getByRole("button", { name: /Export draft/i }).click(),
      ]);
      dlName = download.suggestedFilename();
      const saveTo = path.join(downloadDir, `${backend}-${dlName}`);
      await download.saveAs(saveTo);
      const st = await fs.stat(saveTo);
      dlSize = st.size;
      dlOk = dlSize > 0 && /\.md$/i.test(dlName);
    } catch (e) { detail = `download-error:${e.message}`; }
    scenario("UI08-draft-download", {
      description: "the Report Studio 'Export draft' control produces a real, nonempty Markdown browser download",
      page: "report-studio", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "browser download of a .md file", expected_http_status: "n/a (client blob)",
      db_postcondition: "n/a (client-side blob)", download_name: dlName, download_size: dlSize,
      detail, ...since(m), result: dlOk ? "PASS" : "FAIL",
    });
  }
  // UI09 — validation queue renders (read-only; buttons are local-state-only per the UI inventory)
  {
    const m = mark();
    await openFresh();
    await nav("Validation");
    const queueOk = await visible(/Validation queue/i);
    scenario("UI09-validation-queue-render", {
      description: "the Validation view renders the queue from the real API (transition buttons are UI-local; "
        + "real approve/reject/reopen is an API-only contract — see the guard's api_only_contracts)",
      page: "validation", actor_classification: "demo_bootstrap", tenant_classification: "primary",
      expected_ui_state: "Validation queue visible", expected_http_status: "200",
      db_postcondition: "n/a (read path; UI does not mutate validation state)", ...since(m),
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
