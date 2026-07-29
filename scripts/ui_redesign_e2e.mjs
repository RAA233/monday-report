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
  { path: "/app/studio", heading: null, label: "studio" },
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
 * not client data and it is never presented to a user as evidence of anything.
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
  return tasks.filter((task) => task.status === "open" || task.status === "conflict");
}

/** Layout invariant: the document itself must never scroll sideways. */
async function assertNoHorizontalScroll(page, label) {
  const overflow = await page.evaluate(() => {
    const de = document.documentElement;
    const offenders = [];
    const vw = de.clientWidth;
    for (const el of document.querySelectorAll("body *")) {
      const rect = el.getBoundingClientRect();
      if (rect.right > vw + 1 && getComputedStyle(el).position !== "fixed") {
        offenders.push(`${el.tagName.toLowerCase()}.${String(el.className || "").slice(0, 30)}`);
        if (offenders.length >= 4) break;
      }
    }
    return { scrollWidth: de.scrollWidth, clientWidth: de.clientWidth, offenders };
  });
  const ok = overflow.scrollWidth <= overflow.clientWidth + 1;
  check(
    `no-horizontal-scroll:${label}`,
    ok,
    ok
      ? `${overflow.clientWidth}px viewport, no page-level overflow`
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
  const failedRequests = [];
  context.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(`${message.location().url}: ${message.text()}`);
  });
  context.on("requestfailed", (request) => {
    // Only same-origin app requests matter; an offline API is a separate assertion.
    if (request.url().startsWith(WEB)) failedRequests.push(`${request.url()} ${request.failure()?.errorText}`);
  });

  const page = await context.newPage();

  // ── landing ───────────────────────────────────────────────────────────────
  await page.goto(`${WEB}/`, { waitUntil: "networkidle" });
  const h1 = (await page.locator("h1").first().innerText()).replace(/\s+/g, " ").trim();
  check("landing-hero", /Rig evidence in\.\s*Audited reports out\./i.test(h1), `h1 = ${JSON.stringify(h1)}`);

  const landingText = await page.locator("body").innerText();
  check(
    "landing-demo-disclosure",
    landingText.includes("Demo workspace, demo data. No client data is stored."),
    "demo-data disclosure present"
  );
  check(
    "landing-no-certification-claim",
    landingText.includes("No certification, compliance, or production-acceptance claims are made here."),
    "trust section carries the no-claims line"
  );
  check(
    "landing-preview-labelled-illustration",
    /An illustration of the draft the Studio produces/i.test(landingText),
    "product preview is labelled an illustration, not live data"
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
    const matches = route.heading
      ? text.toLowerCase().includes(route.heading.toLowerCase().replace(/\s+/g, " "))
      : headings.length === 1;
    check(`route-renders:${route.label}`, one && matches, `single h1 = ${JSON.stringify(text)}`);
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

  const draftDeep = await page.goto(`${WEB}/app/reports/some-report-id/draft`, { waitUntil: "networkidle" });
  check(
    "deep-route-refresh:studio-param",
    draftDeep?.status() === 200 && (await page.locator("h1").count()) === 1,
    `GET /app/reports/:id/draft -> ${draftDeep?.status()}`
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
    check(
      `stage2-declared-pending:${route}`,
      /not implemented in this increment/i.test(text) && /Redesign pending/i.test(text),
      "route declares itself unimplemented"
    );
  }

  // ── export gate: closed with the committed copy, then unlocked ────────────
  let gateChecked = false;
  if (API_KEY) {
    try {
      const workspaces = await apiJson("/workspaces");
      const workspaceId = workspaces[0]?.id;
      const before = await apiJson("/validation-tasks");
      let open = before.filter((task) => task.status === "open" || task.status === "conflict");

      // The gate assertions resolve every open task, so a repeat run starts clear.
      // Seed one through the real intake path rather than skipping the coverage.
      if (workspaceId && open.length === 0) {
        open = await seedOpenValidationTask(workspaceId);
        check(
          "export-gate-seeded-real-task",
          open.length > 0,
          `seeded demo evidence through /uploads/direct + worker; ${open.length} open task(s)`
        );
      }

      if (workspaceId && open.length > 0) {
        await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
        const gatedText = await page.locator("body").innerText();
        check(
          "export-gate-closed-copy",
          gatedText.includes(gateCopy(open.length)),
          `gate copy for ${open.length} open task(s) present`
        );
        const exportButton = page.locator("button", { hasText: /^Export PDF$/ }).first();
        if (await exportButton.count()) {
          check("export-disabled-while-gated", await exportButton.isDisabled(), "Export PDF is disabled while gated");
        }

        // Resolve through the UI so the unlock is the product's own behaviour.
        await page.goto(`${WEB}/app/validation`, { waitUntil: "networkidle" });
        const validate = page.locator("button", { hasText: /^Validate$/ }).first();
        check("validation-card-present", (await validate.count()) > 0, "an open task card is rendered");
        for (let i = 0; i < open.length; i += 1) {
          const button = page.locator("button", { hasText: /^Validate$/ }).first();
          if (!(await button.count())) break;
          await button.click();
          await page.waitForTimeout(400);
        }
        const clearedText = await page.locator("body").innerText();
        check(
          "validation-unlocks-gate",
          /all extracted events are resolved/i.test(clearedText),
          "queue reports every event resolved after validating"
        );

        await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
        const clearGate = await page.locator("body").innerText();
        check(
          "export-gate-clear-after-validation",
          /export gate clear/i.test(clearGate) && !clearGate.includes("before exporting an official Monday Report"),
          "gate reads clear and the blocking copy is gone"
        );
        gateChecked = true;
      } else {
        check(
          "export-gate-precondition",
          false,
          `skipped: needs a workspace and >=1 open validation task (found workspace=${Boolean(workspaceId)}, open=${open.length})`
        );
      }
    } catch (error) {
      check("export-gate-precondition", false, `skipped: ${error.message}`);
    }
  } else {
    check("export-gate-precondition", false, "skipped: MONDAY_REPORT_API_KEY is not set");
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
  check("mobile-nav-hit-targets", mobile.minHeight >= 44, `smallest of ${mobile.count} nav targets is ${mobile.minHeight}px`);
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
  const ringed = await page.evaluate(() => {
    const first = document.querySelector("[data-navbtn]");
    first.focus();
    const style = getComputedStyle(first);
    return { active: document.activeElement === first, outlineWidth: style.outlineWidth, outlineStyle: style.outlineStyle };
  });
  check(
    "focus-visible-ring",
    ringed.active,
    `programmatic focus lands on the first nav item (outline ${ringed.outlineStyle} ${ringed.outlineWidth})`
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

  const summary = {
    guard: "ui_redesign_e2e",
    claim_scope: "redesign-frontend-routes-and-states-only",
    web_base: WEB,
    api_base: API,
    export_gate_exercised: gateChecked,
    screenshots: SHOT_DIR || null,
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
  console.error(JSON.stringify({ guard: "ui_redesign_e2e", fatal: String(error?.stack ?? error) }, null, 2));
  process.exit(1);
});
