#!/usr/bin/env node
/**
 * Redesign route and state coverage (additive).
 *
 * This is a NEW suite for the redesigned frontend on its own Vite entry. It does
 * not replace and does not touch `scripts/ui_quality_e2e.mjs`, which continues to
 * assert against the v1 application on its own entry.
 *
 * What it proves, against a real browser and the real built/served redesign:
 *   - the public landing page renders its committed copy and disclosures
 *   - every Stage 1 route renders its own heading
 *   - deep-route refresh works (a full document load of /app/reports stays there)
 *   - /app/chat redirects to /app, and an unknown /app path renders in-shell
 *   - reserved Stage 2 routes declare themselves unimplemented
 *   - the export gate shows the exact committed copy while a task is open, and
 *     resolving the task unlocks it
 *   - no page scrolls horizontally at 390 / 768 / 1440 / 1728
 *   - dir="rtl" flips the shell without a second stylesheet
 *   - the mobile breakpoint gives 44px navigation targets
 *   - zero blocking console errors and zero failed same-origin requests
 *
 * Usage:
 *   node scripts/ui_redesign_e2e.mjs
 *
 * Environment:
 *   MONDAY_REPORT_WEB_BASE   default http://127.0.0.1:5174
 *   MONDAY_REPORT_API_BASE   default http://127.0.0.1:8000
 *   MONDAY_REPORT_API_KEY    API key the served frontend was built/run with
 *   MONDAY_REPORT_SHOT_DIR   optional; write screenshots here (never committed)
 *   MONDAY_REPORT_STATE_PATH, MONDAY_REPORT_STORAGE_ROOT, MONDAY_REPORT_EXPORT_ROOT
 *                            the same state pointers the running API uses — needed
 *                            because the gate assertions seed demo evidence and then
 *                            drain the queue with the out-of-process worker
 *   PYTHON                   optional interpreter override (default "python")
 *
 * The web and API servers must already be running. This script starts and stops no
 * server; it does run `python -m backend.app.worker` once when it needs to raise a
 * validation task, which is the product's own processing path.
 */
import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";

const WEB = (process.env.MONDAY_REPORT_WEB_BASE ?? "http://127.0.0.1:5174").replace(/\/$/, "");
const API = (process.env.MONDAY_REPORT_API_BASE ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const API_KEY = process.env.MONDAY_REPORT_API_KEY ?? "";
const SHOT_DIR = process.env.MONDAY_REPORT_SHOT_DIR ?? "";

/** The committed export-gate copy. Must match the backend-enforced wording. */
const gateCopy = (count) =>
  `Resolve ${count} validation task(s) before exporting an official Monday Report.`;

const VIEWPORTS = [
  { name: "mobile", width: 390, height: 812 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "desktop", width: 1440, height: 900 },
  { name: "wide", width: 1728, height: 1080 }
];

const STAGE1_ROUTES = [
  // The hero h1 is two block spans, so innerText joins them with a space.
  { path: "/", heading: "Rig evidence in. Audited reports out.", label: "landing" },
  { path: "/app/signin", heading: "Sign in to the workspace", label: "signin" },
  { path: "/app", heading: "Ask Monday Report", label: "ask" },
  { path: "/app/reports", heading: "Monday reports", label: "reports" },
  // The Studio h1 is "<variant label> draft" and the variant is user-selectable, so
  // the assertion is the shape. `heading: null` used to reduce this check to "some
  // page with one h1", which NotFound and PendingStage also satisfy — deleting the
  // Studio route kept the suite green.
  { path: "/app/studio", headingPattern: /draft$/i, label: "studio" },
  { path: "/app/validation", heading: "Validation queue", label: "validation" },
  { path: "/app/exports", heading: "Exports", label: "exports" }
];

const STAGE2_ROUTES = ["/app/well", "/app/upload", "/app/benchmarking", "/app/failures", "/app/audit", "/app/settings"];

const results = [];
let failed = 0;

function check(id, ok, detail) {
  results.push({ id, status: ok ? "pass" : "fail", detail });
  if (!ok) failed += 1;
}

async function apiJson(pathname, init = {}) {
  const response = await fetch(`${API}${pathname}`, {
    ...init,
    headers: {
      "X-Monday-Report-Key": API_KEY,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers ?? {})
    }
  });
  if (!response.ok) {
    throw new Error(`${init.method ?? "GET"} ${pathname} -> ${response.status}`);
  }
  return response.json();
}

/**
 * Demo evidence used only to raise a real validation task.
 *
 * The deterministic extractor keys on MWD + signal loss, so this text produces one
 * High-severity failure record and one open validation task through the product's
 * own intake → parse → extract path. Every value here is invented demo data; it is
 * not client data.
 *
 * It IS persistent: the upload, the parsed document, the failure record and the
 * resolved task all remain in the target workspace after the run, and each run adds
 * another set. That is why the gate flow refuses to run against a stack that already
 * holds open validation tasks it did not create (see runGateFlow).
 */
const DEMO_DDR = [
  "DAILY DRILLING REPORT - DEMO DATA ONLY",
  "Well: DEMO 1-A   Rig: Demo Rig 1   Operator: Monday Report Demo",
  "Report date: 2026-01-01   Report no: DEMO-DDR-SMOKE",
  "Hole size: 12.25 in   MD: 8620 ft   TVD: 7980 ft   Mud weight: 10.2 ppg",
  "",
  "24 HR OPERATIONS SUMMARY",
  "04:30-09:15 MWD signal loss while drilling ahead; no pulse telemetry received.",
  "Pulled out of hole and replaced the MWD probe.",
  "npt_hours: 14.5",
  "09:15-24:00 Resumed drilling ahead after tool replacement."
].join("\n");

/**
 * Raise one real open validation task, so the gate assertions exercise the product
 * rather than a stub. Returns the open-task list after seeding.
 *
 * Jobs are drained by the out-of-process worker — there is no HTTP route that
 * processes a queue — so the worker is invoked directly. It inherits this process's
 * environment, which must therefore carry the same MONDAY_REPORT_* state pointers
 * the running API uses.
 */
const isOpen = (task) => task.status === "open" || task.status === "conflict";

/**
 * Poll the API until the SEEDED tasks have left the open set.
 *
 * Scoped to the ids this run created, not the tenant-wide count: an unrelated task
 * opening mid-run would otherwise stall the wait and be reported as "the decision
 * did not land", which is a different and misleading claim. Returns what it saw so
 * a failure can say so.
 */
async function waitForSeededResolved(seededIds, wantRemaining, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let remaining = -1;
  let openIds = [];
  while (Date.now() < deadline) {
    const open = (await apiJson("/validation-tasks")).filter(isOpen);
    openIds = open.map((task) => task.id);
    remaining = openIds.filter((id) => seededIds.has(id)).length;
    if (remaining === wantRemaining) return { ok: true, remaining, openIds };
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return { ok: false, remaining, openIds };
}

async function seedOpenValidationTask(workspaceId) {
  const form = new FormData();
  form.append("workspace_id", workspaceId);
  form.append("file_name", "demo_ddr_smoke.txt");
  form.append("source_type", "files");
  form.append("file", new Blob([DEMO_DDR], { type: "text/plain" }), "demo_ddr_smoke.txt");

  const response = await fetch(`${API}/uploads/direct`, {
    method: "POST",
    headers: {
      "X-Monday-Report-Key": API_KEY,
      "Idempotency-Key": `ui-redesign-smoke-${Date.now()}`
    },
    body: form
  });
  if (!response.ok) throw new Error(`POST /uploads/direct -> ${response.status}`);

  const worker = spawnSync(process.env.PYTHON ?? "python", ["-m", "backend.app.worker"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: process.env
  });
  if (worker.status !== 0) {
    throw new Error(`worker exited ${worker.status}: ${(worker.stderr || worker.stdout || "").slice(0, 300)}`);
  }

  const tasks = await apiJson("/validation-tasks");
  return tasks.filter(isOpen);
}

/**
 * Ensure a Monday report exists, so the gated Export button is actually rendered
 * and its disabled state is a real assertion rather than a silent skip.
 */
async function ensureReport(workspaceId, mutated) {
  const existing = await apiJson(`/monday-reports?workspace_id=${encodeURIComponent(workspaceId)}`);
  if (existing.length > 0) return existing;
  if (mutated) mutated.value = true;
  const now = new Date();
  const monday = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - ((now.getUTCDay() + 6) % 7))
  );
  const sunday = new Date(monday);
  sunday.setUTCDate(monday.getUTCDate() + 6);
  await apiJson("/monday-reports", {
    method: "POST",
    headers: { "Idempotency-Key": `ui-redesign-smoke-report-${Date.now()}` },
    body: JSON.stringify({
      workspace_id: workspaceId,
      period_start: monday.toISOString().slice(0, 10),
      period_end: sunday.toISOString().slice(0, 10)
    })
  });
  return apiJson(`/monday-reports?workspace_id=${encodeURIComponent(workspaceId)}`);
}

/** Layout invariant: the document itself must never scroll sideways. */
async function assertNoHorizontalScroll(page, label) {
  const overflow = await page.evaluate(() => {
    const de = document.documentElement;
    // Rendered-content proof: a blank document has no overflow either, so these 24
    // checks would otherwise be the largest vacuous block in the suite.
    const rendered = {
      elements: document.querySelectorAll("body *").length,
      text: (document.body.innerText || "").trim().length,
      headings: document.querySelectorAll("h1").length
    };
    const offenders = [];
    const vw = de.clientWidth;
    for (const el of document.querySelectorAll("body *")) {
      const rect = el.getBoundingClientRect();
      if (rect.right > vw + 1 && getComputedStyle(el).position !== "fixed") {
        offenders.push(`${el.tagName.toLowerCase()}.${String(el.className || "").slice(0, 30)}`);
        if (offenders.length >= 4) break;
      }
    }
    return { scrollWidth: de.scrollWidth, clientWidth: de.clientWidth, offenders, rendered };
  });
  const painted = overflow.rendered.elements >= 10 && overflow.rendered.text >= 40;
  const noOverflow = overflow.scrollWidth <= overflow.clientWidth + 1;
  check(
    `no-horizontal-scroll:${label}`,
    painted && noOverflow,
    !painted
      ? `nothing rendered to measure (${overflow.rendered.elements} elements, ${overflow.rendered.text} chars) — the check would have passed vacuously`
      : noOverflow
        ? `${overflow.clientWidth}px viewport, ${overflow.rendered.elements} elements painted, no page-level overflow`
        : `scrollWidth ${overflow.scrollWidth} > clientWidth ${overflow.clientWidth}; first offenders: ${overflow.offenders.join(", ") || "none in-flow"}`
  );
}

async function shoot(page, name) {
  if (!SHOT_DIR) return;
  await mkdir(SHOT_DIR, { recursive: true });
  await page.screenshot({ path: path.join(SHOT_DIR, `${name}.png`), fullPage: true });
}

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

  const consoleErrors = [];
  const thirdPartyErrors = [];
  const failedRequests = [];
  const isThirdParty = (url) => Boolean(url) && !url.startsWith(WEB) && !url.startsWith(API) && url !== "";
  context.on("console", (message) => {
    if (message.type() !== "error") return;
    const url = message.location().url ?? "";
    // Third-party failures (the design system's Google Fonts @import, blocked
    // offline or by a CSP) are not defects in this application. They are recorded
    // separately so the run still discloses them.
    if (isThirdParty(url)) {
      thirdPartyErrors.push(`${url}: ${message.text()}`);
      return;
    }
    consoleErrors.push(`console: ${url}: ${message.text()}`);
  });
  // Uncaught exceptions and unhandled rejections arrive as weberror, NOT as console
  // messages — without this they escaped the console-error assertion entirely.
  context.on("weberror", (error) => {
    consoleErrors.push(`uncaught: ${String(error.error()).slice(0, 300)}`);
  });
  context.on("requestfailed", (request) => {
    // Only same-origin app requests matter; an offline API is a separate assertion.
    if (request.url().startsWith(WEB)) failedRequests.push(`${request.url()} ${request.failure()?.errorText}`);
  });
  // A same-origin 4xx/5xx is a real failure but never fires requestfailed. Two
  // exclusions, both non-defects: /favicon.ico (this entry ships none) and Vite's
  // transient 504 while it re-optimises a dependency on first request.
  context.on("response", (response) => {
    const url = response.url();
    if (!url.startsWith(WEB)) return;
    const status = response.status();
    if (status < 400) return;
    if (new URL(url).pathname === "/favicon.ico") return;
    if (status === 504 && url.includes("/node_modules/.vite/")) return;
    failedRequests.push(`${url} -> HTTP ${status}`);
  });

  const page = await context.newPage();

  // ── landing ───────────────────────────────────────────────────────────────
  await page.goto(`${WEB}/`, { waitUntil: "networkidle" });
  const h1 = (await page.locator("h1").first().innerText()).replace(/\s+/g, " ").trim();
  check("landing-hero", /Rig evidence in\.\s*Audited reports out\./i.test(h1), `h1 = ${JSON.stringify(h1)}`);

  const landingText = await page.locator("body").innerText();
  const found = (ok, what) => (ok ? `found: ${what}` : `MISSING: ${what}`);
  const hasDemoLine = landingText.includes("Demo workspace, demo data. No client data is stored.");
  check("landing-demo-disclosure", hasDemoLine, found(hasDemoLine, "the demo-data disclosure"));
  const hasNoClaims = landingText.includes(
    "No certification, compliance, or production-acceptance claims are made here."
  );
  check("landing-no-certification-claim", hasNoClaims, found(hasNoClaims, "the no-claims line"));
  const hasIllustration = /An illustration of the draft the Studio produces/i.test(landingText);
  check(
    "landing-preview-labelled-illustration",
    hasIllustration,
    found(hasIllustration, "the preview's illustration caption")
  );
  const anchorIds = ["capabilities", "workflow", "security"];
  const anchorsFound = [];
  for (const id of anchorIds) {
    if ((await page.locator(`#${id}`).count()) === 1) anchorsFound.push(id);
  }
  check(
    "landing-sections",
    anchorsFound.length === anchorIds.length,
    `in-page anchors present: ${anchorsFound.join(", ") || "none"}`
  );
  const stageBandValues = await page.locator("section[aria-label='Monday Report, by the numbers'] p").allInnerTexts();
  check("landing-stat-band", stageBandValues.includes("1:1"), `stat band rendered ${stageBandValues.length} lines`);
  await shoot(page, "landing-desktop");

  // Landing CTA must navigate, never silently redirect.
  await page.locator("nav a", { hasText: "Open the app" }).first().click();
  await page.waitForURL(`${WEB}/app`);
  check("landing-cta-navigates", page.url() === `${WEB}/app`, `cta landed on ${page.url()}`);

  // ── every Stage 1 route renders ───────────────────────────────────────────
  for (const route of STAGE1_ROUTES) {
    await page.goto(`${WEB}${route.path}`, { waitUntil: "networkidle" });
    const headings = await page.locator("h1").allInnerTexts();
    const one = headings.length === 1;
    const text = headings.map((value) => value.replace(/\s+/g, " ").trim()).join(" | ");
    const matches = route.headingPattern
      ? route.headingPattern.test(text)
      : text.toLowerCase().includes(route.heading.toLowerCase().replace(/\s+/g, " "));
    check(
      `route-renders:${route.label}`,
      one && matches,
      `single h1 = ${JSON.stringify(text)} (expected ${route.headingPattern ?? JSON.stringify(route.heading)})`
    );
    await shoot(page, `route-${route.label}`);
  }

  // ── deep-route refresh (a real document load, not a client transition) ────
  const deep = await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
  check("deep-route-status", deep?.status() === 200, `GET /app/reports -> ${deep?.status()}`);
  await page.reload({ waitUntil: "networkidle" });
  const afterReload = await page.locator("h1").first().innerText();
  check(
    "deep-route-refresh",
    page.url() === `${WEB}/app/reports` && /monday reports/i.test(afterReload),
    `after reload url=${page.url()} h1=${JSON.stringify(afterReload.trim())}`
  );

  // A report id containing a dot also exercises the middleware's extension test.
  const draftDeep = await page.goto(`${WEB}/app/reports/MR-2026.W31/draft`, { waitUntil: "networkidle" });
  const draftHeading = (await page.locator("h1").allInnerTexts()).join(" | ").trim();
  check(
    "deep-route-refresh:studio-param",
    draftDeep?.status() === 200 && (await page.locator("h1").count()) === 1 && /draft$/i.test(draftHeading),
    `GET /app/reports/MR-2026.W31/draft -> ${draftDeep?.status()}, h1 = ${JSON.stringify(draftHeading)}`
  );
  // NotFound renders the pathname, so "the id appears somewhere" proves nothing.
  // Assert the Studio's own issue-target disclosure, which only it renders.
  const draftBody = await page.locator("body").innerText();
  check(
    "deep-route-kicker-carries-report-id",
    /Issue target: report/i.test(draftBody) && draftBody.includes("MR-2026.W31"),
    "the Studio's issue-target line names the report id from the URL, so the Studio route matched"
  );

  // A query string must not be misclassified as an asset request.
  const queried = await page.goto(`${WEB}/app/reports?tab=all`, { waitUntil: "networkidle" });
  const queriedHeading = (await page.locator("h1").first().innerText()).trim();
  check(
    "deep-route-with-query-string",
    queried?.status() === 200 && /monday reports/i.test(queriedHeading),
    `GET /app/reports?tab=all -> ${queried?.status()}, h1 = ${JSON.stringify(queriedHeading)}`
  );

  // ── redirect and not-found ────────────────────────────────────────────────
  await page.goto(`${WEB}/app/chat`, { waitUntil: "networkidle" });
  check(
    "chat-redirects-to-ask",
    new URL(page.url()).pathname === "/app" && /ask monday report/i.test(await page.locator("h1").first().innerText()),
    `/app/chat landed on ${new URL(page.url()).pathname}`
  );

  await page.goto(`${WEB}/app/definitely-not-a-route`, { waitUntil: "networkidle" });
  const notFoundText = await page.locator("body").innerText();
  const shellPresent = (await page.locator("[data-shell]").count()) === 1;
  check(
    "unknown-route-in-shell",
    shellPresent && /this route does not exist/i.test(notFoundText),
    `not-found rendered inside the shell: ${shellPresent}`
  );

  // ── reserved Stage 2 routes must not claim completeness ───────────────────
  for (const route of STAGE2_ROUTES) {
    await page.goto(`${WEB}${route}`, { waitUntil: "networkidle" });
    const text = await page.locator("body").innerText();
    const declares = /not implemented in this increment/i.test(text) && /Redesign pending/i.test(text);
    check(
      `stage2-declared-pending:${route}`,
      declares,
      declares
        ? "route declares itself unimplemented"
        : "route does NOT declare itself unimplemented — it may read as a working surface"
    );
  }

  // ── export gate: closed with the committed copy, then unlocked ────────────
  //
  // This flow MUTATES the target stack: it uploads demo evidence and resolves the
  // validation task that evidence raises. It therefore refuses to run when the
  // stack already holds open tasks it did not create — resolving somebody else's
  // review queue (with reviewer attribution, into an append-only audit chain, and
  // unlocking official export) is not something a smoke test may do.
  // Set as soon as the flow performs its first write, so the summary reports a
  // mutation even when a later assertion fails.
  const mutated = { value: false };
  const gateChecked = await runGateFlow();

  async function runGateFlow() {
    if (!API_KEY) {
      check("export-gate-precondition", false, "not run: MONDAY_REPORT_API_KEY is not set");
      return false;
    }
    try {
      const workspaces = await apiJson("/workspaces");
      const workspaceId = workspaces[0]?.id;
      if (!workspaceId) {
        check("export-gate-precondition", false, "not run: the API reported no workspace");
        return false;
      }

      const preExisting = (await apiJson("/validation-tasks")).filter(isOpen);
      if (preExisting.length > 0) {
        check(
          "export-gate-precondition",
          false,
          `not run: ${preExisting.length} validation task(s) are already open on this stack. This flow resolves ` +
            `only tasks it raises itself, and it will not resolve pre-existing ones. Point ` +
            `MONDAY_REPORT_API_BASE at a stack with a clear queue.`
        );
        return false;
      }

      // A report must exist or Exports renders no format cards, which would make the
      // disabled-button assertion silently vanish.
      const reports = await ensureReport(workspaceId, mutated);
      check("export-gate-report-present", reports.length > 0, `${reports.length} report(s) available to export`);

      mutated.value = true;
      const open = await seedOpenValidationTask(workspaceId);
      check(
        "export-gate-seeded-real-task",
        open.length > 0,
        open.length > 0
          ? `seeded demo evidence through /uploads/direct + worker; ${open.length} open task(s)`
          : "seeding produced NO open validation task — the extractor did not fire"
      );
      if (open.length === 0) return false;
      const seededIds = new Set(open.map((task) => task.id));

      // The worker drains the WHOLE queue, so a job someone else queued before our
      // upload would also produce tasks. Confirm every open task traces to a failure
      // extracted from our own document before resolving anything.
      const failures = await apiJson("/failures");
      const ours = new Set(
        failures
          .filter((failure) =>
            (failure.citations ?? []).some((citation) =>
              JSON.stringify(citation.locator ?? {}).includes("demo_ddr_smoke.txt")
            )
          )
          .map((failure) => failure.id)
      );
      const foreign = open.filter(
        (task) => task.target_type !== "failure" || !ours.has(task.target_id)
      );
      check(
        "export-gate-seeded-tasks-are-ours",
        foreign.length === 0,
        foreign.length === 0
          ? `all ${open.length} open task(s) trace to this run's own demo document`
          : `${foreign.length} open task(s) do NOT trace to this run's document — refusing to resolve them`
      );
      if (foreign.length > 0) return false;

      await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
      const gatedText = await page.locator("body").innerText();
      check(
        "export-gate-closed-copy",
        gatedText.includes(gateCopy(open.length)),
        `gate copy for ${open.length} open task(s) present verbatim`
      );

      const exportButton = page.locator("button", { hasText: /^Export PDF$/ }).first();
      const buttonPresent = (await exportButton.count()) > 0;
      check(
        "export-disabled-while-gated",
        buttonPresent && (await exportButton.isDisabled()),
        buttonPresent
          ? "Export PDF is rendered and disabled while gated"
          : "FAILED: no Export PDF button was rendered, so the gated state could not be asserted"
      );

      // Resolve through the UI so the unlock is the product's own behaviour, and
      // resolve ONLY the tasks this run seeded.
      await page.goto(`${WEB}/app/validation`, { waitUntil: "networkidle" });
      const validate = page.locator("button", { hasText: /^Validate$/ }).first();
      check("validation-card-present", (await validate.count()) > 0, "an open task card is rendered");

      for (let i = 0; i < seededIds.size; i += 1) {
        const button = page.locator("button", { hasText: /^Validate$/ }).first();
        await button.waitFor({ state: "visible", timeout: 15000 }).catch(() => {});
        if ((await button.count()) === 0) break;
        await button.click();
        // Wait on the SERVER, not the DOM. The button's own label flips to
        // "Recording…" while the PATCH is in flight, so any DOM predicate counting
        // "Validate" buttons is satisfied before the decision has actually landed.
        const want = seededIds.size - i - 1;
        const settled = await waitForSeededResolved(seededIds, want);
        check(
          `validation-decision-landed-${i + 1}`,
          settled.ok,
          settled.ok
            ? `decision ${i + 1} landed; ${want} seeded task(s) still open`
            : `decision ${i + 1} not observed within 15s: wanted ${want} seeded task(s) open, saw ${settled.remaining}; ` +
              `open ids now = [${settled.openIds.join(", ")}], seeded = [${[...seededIds].join(", ")}]`
        );
      }

      const remaining = (await apiJson("/validation-tasks")).filter(isOpen);
      const seededStillOpen = remaining.filter((task) => seededIds.has(task.id));
      check(
        "validation-resolved-only-seeded",
        seededStillOpen.length === 0 && remaining.length === 0,
        seededStillOpen.length === 0 && remaining.length === 0
          ? `all ${seededIds.size} seeded task(s) resolved and nothing else is open`
          : `${seededIds.size - seededStillOpen.length} of ${seededIds.size} seeded task(s) resolved; ` +
            `${seededStillOpen.length} seeded and ${remaining.length - seededStillOpen.length} unrelated task(s) still open`
      );

      // Re-enter the view so the assertion reads a settled render, not whatever
      // frame the click left behind.
      await page.goto(`${WEB}/app/validation`, { waitUntil: "networkidle" });
      const clearedText = await page.locator("body").innerText();
      check(
        "validation-unlocks-gate",
        /all extracted events are resolved/i.test(clearedText),
        "the queue itself reports every event resolved after the UI decisions"
      );

      await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
      const clearGate = await page.locator("body").innerText();
      check(
        "export-gate-clear-after-validation",
        /export gate clear/i.test(clearGate) && !clearGate.includes("before exporting an official Monday Report"),
        "gate reads clear and the blocking copy is gone"
      );
      const enabledButton = page.locator("button", { hasText: /^Export PDF$/ }).first();
      check(
        "export-enabled-after-unlock",
        (await enabledButton.count()) > 0 && !(await enabledButton.isDisabled()),
        "Export PDF became enabled once the gate cleared"
      );
      return true;
    } catch (error) {
      check("export-gate-precondition", false, `not run: ${error.message}`);
      return false;
    }
  }

  // ── responsive: no page-level horizontal scroll at any viewport ───────────
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    for (const route of ["/", "/app", "/app/reports", "/app/validation", "/app/exports", "/app/studio"]) {
      await page.goto(`${WEB}${route}`, { waitUntil: "networkidle" });
      await assertNoHorizontalScroll(page, `${viewport.name}${route}`);
    }
    await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
    await shoot(page, `reports-${viewport.name}`);
  }

  // ── mobile navigation ─────────────────────────────────────────────────────
  await page.setViewportSize({ width: 390, height: 812 });
  await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
  const mobile = await page.evaluate(() => {
    const shell = document.querySelector("[data-shell]");
    const sidebar = document.querySelector("[data-sidebar]");
    const groups = document.querySelector("[data-navgroups]");
    const buttons = [...document.querySelectorAll("[data-navbtn]")];
    const label = document.querySelector("[data-navlabel]");
    const tenant = document.querySelector("[data-tenantcard]");
    return {
      columns: getComputedStyle(shell).gridTemplateColumns,
      sidebarPosition: getComputedStyle(sidebar).position,
      navOverflowX: getComputedStyle(groups).overflowX,
      minHeight: Math.min(...buttons.map((b) => Math.round(b.getBoundingClientRect().height))),
      count: buttons.length,
      labelHidden: label ? getComputedStyle(label).display === "none" : false,
      tenantHidden: tenant ? getComputedStyle(tenant).display === "none" : false
    };
  });
  check(
    "mobile-nav-single-column",
    mobile.sidebarPosition === "static" && mobile.navOverflowX === "auto",
    `sidebar ${mobile.sidebarPosition}, nav overflow-x ${mobile.navOverflowX}, columns ${mobile.columns}`
  );
  // The count is asserted too: Math.min() of an empty selector is Infinity, so a
  // missing nav used to satisfy ">= 44".
  check(
    "mobile-nav-hit-targets",
    mobile.count >= 11 && Number.isFinite(mobile.minHeight) && mobile.minHeight >= 44,
    `${mobile.count} nav targets found (expected >= 11); smallest is ${mobile.minHeight}px`
  );
  check(
    "mobile-nav-chrome-hidden",
    mobile.labelHidden && mobile.tenantHidden,
    "group labels and the tenant card hide on mobile"
  );
  await shoot(page, "reports-mobile-nav");

  // ── RTL ───────────────────────────────────────────────────────────────────
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
  const rtl = await page.evaluate(() => {
    document.documentElement.dir = "rtl";
    const sidebar = document.querySelector("[data-sidebar]");
    const rect = sidebar.getBoundingClientRect();
    const style = getComputedStyle(sidebar);
    return {
      onRight: rect.right > window.innerWidth - 5,
      borderLeft: style.borderLeftWidth,
      borderRight: style.borderRightWidth,
      scrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
    };
  });
  check(
    "rtl-flips-shell",
    rtl.onRight && rtl.borderLeft === "1px" && rtl.borderRight === "0px",
    `sidebar on the right with the divider on its inline-start (left ${rtl.borderLeft} / right ${rtl.borderRight})`
  );
  check("rtl-no-horizontal-scroll", !rtl.scrolls, "no page-level overflow under dir=rtl");
  await shoot(page, "reports-rtl");
  await page.evaluate(() => {
    document.documentElement.dir = "ltr";
  });

  // ── keyboard reachability of the primary navigation ───────────────────────
  await page.goto(`${WEB}/app`, { waitUntil: "networkidle" });
  const reached = await page.evaluate(async () => {
    const focusable = [...document.querySelectorAll("[data-navbtn], button, a[href], input, select, textarea")].filter(
      (el) => !el.hasAttribute("disabled") && el.tabIndex !== -1
    );
    return focusable.length;
  });
  check("keyboard-focusable-controls", reached > 10, `${reached} focusable controls in the shell`);

  // Focus must be driven by a REAL Tab press: :focus-visible does not match a
  // programmatic .focus(), so the previous version measured no ring at all and
  // asserted only that .focus() worked — an assertion that cannot fail.
  await page.keyboard.press("Tab");
  const ringed = await page.evaluate(() => {
    const el = document.activeElement;
    if (!el || el === document.body) return { none: true };
    const style = getComputedStyle(el);
    return {
      tag: el.tagName,
      matchesFocusVisible: el.matches(":focus-visible"),
      outlineStyle: style.outlineStyle,
      outlineWidth: parseFloat(style.outlineWidth) || 0
    };
  });
  check(
    "focus-visible-ring",
    !ringed.none && ringed.matchesFocusVisible && ringed.outlineStyle !== "none" && ringed.outlineWidth > 0,
    ringed.none
      ? "Tab moved focus nowhere"
      : `${ringed.tag} matches :focus-visible with a ${ringed.outlineStyle} ${ringed.outlineWidth}px outline`
  );

  // ── console and request hygiene ────────────────────────────────────────────
  check(
    "no-console-errors",
    consoleErrors.length === 0,
    consoleErrors.length === 0 ? "no console errors across the run" : consoleErrors.slice(0, 5).join(" ;; ")
  );
  check(
    "no-failed-app-requests",
    failedRequests.length === 0,
    failedRequests.length === 0 ? "no failed same-origin requests" : failedRequests.slice(0, 5).join(" ;; ")
  );

  await browser.close();

  // Every check id emitted by a fully-exercised run. Declared so a caller can pin
  // the suite's coverage: a check that silently disappears (deleted, or skipped by a
  // conditional branch) is reported here rather than shrinking the totals unnoticed.
  const EXPECTED_CHECK_IDS = [
    "landing-hero",
    "landing-demo-disclosure",
    "landing-no-certification-claim",
    "landing-preview-labelled-illustration",
    "landing-sections",
    "landing-stat-band",
    "landing-cta-navigates",
    ...STAGE1_ROUTES.map((route) => `route-renders:${route.label}`),
    "deep-route-status",
    "deep-route-refresh",
    "deep-route-refresh:studio-param",
    "deep-route-kicker-carries-report-id",
    "deep-route-with-query-string",
    "chat-redirects-to-ask",
    "unknown-route-in-shell",
    ...STAGE2_ROUTES.map((route) => `stage2-declared-pending:${route}`),
    "export-gate-report-present",
    "export-gate-seeded-real-task",
    "export-gate-seeded-tasks-are-ours",
    "export-gate-closed-copy",
    "export-disabled-while-gated",
    "validation-card-present",
    "validation-decision-landed-1",
    "validation-resolved-only-seeded",
    "validation-unlocks-gate",
    "export-gate-clear-after-validation",
    "export-enabled-after-unlock",
    ...VIEWPORTS.flatMap((viewport) =>
      ["/", "/app", "/app/reports", "/app/validation", "/app/exports", "/app/studio"].map(
        (route) => `no-horizontal-scroll:${viewport.name}${route}`
      )
    ),
    "mobile-nav-single-column",
    "mobile-nav-hit-targets",
    "mobile-nav-chrome-hidden",
    "rtl-flips-shell",
    "rtl-no-horizontal-scroll",
    "keyboard-focusable-controls",
    "focus-visible-ring",
    "no-console-errors",
    "no-failed-app-requests"
  ];

  const emitted = new Set(results.map((entry) => entry.id));
  const missing = EXPECTED_CHECK_IDS.filter((id) => !emitted.has(id));
  const unexpected = [...emitted].filter((id) => !EXPECTED_CHECK_IDS.includes(id));
  check(
    "coverage-complete",
    missing.length === 0 && unexpected.length === 0,
    missing.length === 0 && unexpected.length === 0
      ? `all ${EXPECTED_CHECK_IDS.length} declared checks ran and nothing undeclared appeared`
      : [
          missing.length ? `${missing.length} declared check(s) did not run: ${missing.slice(0, 8).join(", ")}` : "",
          unexpected.length ? `${unexpected.length} undeclared check id(s): ${unexpected.slice(0, 8).join(", ")}` : ""
        ]
          .filter(Boolean)
          .join(" ;; ")
  );

  const summary = {
    guard: "ui_redesign_e2e",
    claim_scope: "redesign-frontend-routes-and-states-only",
    web_base: WEB,
    api_base: API,
    export_gate_exercised: gateChecked,
    mutates_target_stack: mutated.value,
    screenshots: SHOT_DIR || null,
    expected_check_count: EXPECTED_CHECK_IDS.length + 1,
    unexpected_check_ids: unexpected,
    checked: results.length,
    passed: results.filter((entry) => entry.status === "pass").length,
    failed,
    results
  };
  const text = JSON.stringify(summary, null, 2);
  console.log(text);
  if (SHOT_DIR) {
    await mkdir(SHOT_DIR, { recursive: true });
    await writeFile(path.join(SHOT_DIR, "ui_redesign_e2e.json"), text, "utf8");
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  // Report what DID run rather than discarding it: a mid-run locator failure used
  // to throw away every result collected up to that point.
  check("suite-completed", false, `aborted: ${String(error?.message ?? error).slice(0, 400)}`);
  console.error(
    JSON.stringify(
      {
        guard: "ui_redesign_e2e",
        fatal: String(error?.stack ?? error),
        checked: results.length,
        passed: results.filter((entry) => entry.status === "pass").length,
        failed,
        results
      },
      null,
      2
    )
  );
  process.exit(1);
});
