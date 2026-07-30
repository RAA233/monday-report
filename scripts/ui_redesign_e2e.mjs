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
 *   - dir="rtl" flips the shell (sidebar on the right, logical divider) and does not
 *     introduce a horizontal scroll; it does NOT assert anything about how many
 *     stylesheets are involved
 *   - the mobile breakpoint collapses to one column, hides the nav chrome, and keeps
 *     every navigation target at least 44px tall
 *   - zero blocking console errors and zero failed same-origin requests
 *
 * Usage:
 *   node scripts/ui_redesign_e2e.mjs
 *
 * Environment (the first five are REQUIRED - the gate refuses a default):
 *   MONDAY_REPORT_WEB_BASE   the isolated web origin (never the live v1 port 5173)
 *   MONDAY_REPORT_API_BASE   the isolated API origin, explicit port, never 8000
 *   MONDAY_REPORT_API_KEY    API key the served frontend was built/run with
 *   MONDAY_REPORT_SHOT_DIR   optional; write screenshots and the JSON summary here.
 *                            A path inside the repository is REFUSED (not written to)
 *                            and the refusal is reported in the summary's `screenshots`
 *                            field, so these artifacts cannot end up committed.
 *   MONDAY_REPORT_STATE_PATH, MONDAY_REPORT_STORAGE_ROOT, MONDAY_REPORT_EXPORT_ROOT
 *                            the same state pointers the running API uses — needed
 *                            because the gate assertions seed demo evidence and then
 *                            drain the queue with the out-of-process worker
 *   PYTHON                   optional interpreter override (default "python")
 *
 * The web and API servers must already be running. This script starts and stops no
 * server; it does run `python -m backend.app.worker` once when it needs to raise a
 * validation task, which is the product's own processing path.
 *
 * Because it mutates its target, it refuses to start at all unless
 * `scripts/verification_isolation.py` certifies the environment as isolated from the
 * live runtime - the same fail-closed preflight the committed v1 suite runs.
 */
import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// fileURLToPath, not a hand-rolled pathname fix-up: `import.meta.url` is
// percent-ENCODED, so a repository path containing a space resolved to
// "…/Monday%20Report" and every real subdirectory then looked OUTSIDE it. And
// path.relative rather than a string prefix, because Windows paths are
// case-insensitive while `startsWith` is not.
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Hard verification-isolation gate (Part E): fail closed BEFORE launching a browser,
// issuing a request, or spawning the worker. This suite MUTATES its target - it creates
// a Monday report, uploads demo evidence and resolves the validation task that evidence
// raises - and without a gate its defaults (API 127.0.0.1:8000, state ./.local_data)
// point straight at the live runtime.
//
// TWO layers, because the shared preflight alone is not sufficient for a mutating suite
// and this file must not modify the shared module:
//
//   1. The repository's single Python preflight, so there is one definition of
//      "isolated" and this suite cannot drift from the frozen v1 suite.
//   2. A local re-assertion of the same substantive facts, which closes three gaps the
//      shared module leaves open for a MUTATING caller:
//        - MONDAY_REPORT_ALLOW_LIVE_TARGET=1 excuses every violation, and the PID
//          branch it cannot excuse is unreachable from the CLI entry point;
//        - the ".local_data" test is a case-sensitive substring test, so
//          ./.Local_Data (the same directory on Windows) passes;
//        - a relative root passes and materialises uploaded bytes inside the tree.
//      This layer never RELAXES the preflight; it only refuses more.
//
// It still cannot prove the already-running SERVER is isolated - that is asserted
// separately against the browser's own traffic in `assertBrowserTargetsGatedApi`,
// before the first mutation.
function refuseNotIsolated(reason, detail) {
  console.error(`FAIL: verification isolation - ${reason}`);
  if (detail) console.error(detail);
  console.error(
    "test:ui-redesign mutates its target, so it refuses to run without an explicitly isolated stack."
  );
  process.exit(2);
}

try {
  // `process.env.PYTHON`, matching the worker spawn below and this file's own
  // documented override; stdout is CAPTURED, not inherited, because stdout carries the
  // JSON summary; and a bounded timeout, so a blocking interpreter cannot hang the run.
  execFileSync(
    process.env.PYTHON ?? "python",
    [path.join(REPO_ROOT, "scripts", "verification_isolation.py"), "--context", "test-ui-redesign"],
    { stdio: ["ignore", "pipe", "pipe"], timeout: 30_000, encoding: "utf8" }
  );
} catch (error) {
  const stderr = (error && error.stderr) || "";
  const stdout = (error && error.stdout) || "";
  if (error && error.status === 2) {
    refuseNotIsolated("the repository preflight refused this environment.", `${stdout}${stderr}`);
  }
  // ENOENT / EINVAL / ETIMEDOUT are NOT isolation verdicts. Reporting them as one sent
  // an operator with a correct stack to debug variables that were already right.
  refuseNotIsolated(
    `the preflight could not be executed (${(error && (error.code || error.message)) || "unknown"}).`,
    `${stdout}${stderr}`.trim() || "Set PYTHON to a spawnable interpreter, or fix the preflight."
  );
}

{
  // Layer 2. Every one of these must hold on its own terms, regardless of any override.
  const required = [
    "MONDAY_REPORT_STATE_PATH",
    "MONDAY_REPORT_STORAGE_ROOT",
    "MONDAY_REPORT_EXPORT_ROOT",
    "MONDAY_REPORT_API_BASE",
    "MONDAY_REPORT_WEB_BASE"
  ];
  const unset = required.filter((name) => !(process.env[name] ?? "").trim());
  if (unset.length > 0) {
    refuseNotIsolated(
      `these must be set explicitly, with no default: ${unset.join(", ")}.`,
      "An override such as MONDAY_REPORT_ALLOW_LIVE_TARGET does not excuse them for a mutating suite."
    );
  }
  const liveState = path.resolve(REPO_ROOT, ".local_data");
  const insideOrEqual = (candidate, root) => {
    const rel = path.relative(root, candidate);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };
  for (const name of required.slice(0, 3)) {
    const raw = process.env[name];
    // Case-insensitive and path-resolved: a substring test passes ./.Local_Data, which
    // is the SAME directory on Windows, and passes a relative root that lands in the
    // working tree. Both are refused here.
    const resolved = path.resolve(raw);
    if (!path.isAbsolute(raw)) {
      refuseNotIsolated(`${name} must be an absolute path (got "${raw}").`);
    }
    if (insideOrEqual(resolved.toLowerCase(), liveState.toLowerCase())) {
      refuseNotIsolated(`${name} resolves inside the live state directory (${resolved}).`);
    }
    if (insideOrEqual(resolved.toLowerCase(), REPO_ROOT.toLowerCase())) {
      refuseNotIsolated(
        `${name} resolves inside the repository (${resolved}); uploaded bytes and exports must not land in the tree.`
      );
    }
  }
  const port = (value) => {
    try {
      return new URL(value).port;
    } catch {
      return "";
    }
  };
  if (port(process.env.MONDAY_REPORT_API_BASE) === "" ) {
    refuseNotIsolated(
      `MONDAY_REPORT_API_BASE must name an explicit port (got "${process.env.MONDAY_REPORT_API_BASE}").`
    );
  }
  if (port(process.env.MONDAY_REPORT_API_BASE) === "8000") {
    refuseNotIsolated("MONDAY_REPORT_API_BASE is the live API port 8000.");
  }
  if (port(process.env.MONDAY_REPORT_WEB_BASE) === "5173") {
    refuseNotIsolated("MONDAY_REPORT_WEB_BASE is the live v1 web port 5173.");
  }
}

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

/**
 * A 1x1 PNG. Uploading an image makes `_should_route_to_ocr` fire, which raises a
 * validation task whose target_type is `file` - the one task class the export gate
 * deliberately does NOT count. Seeding it is what makes the gate-scope check below
 * discriminating rather than an assertion about an empty set.
 */
const DEMO_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

async function uploadDemoFile(workspaceId, fileName, blob) {
  const form = new FormData();
  form.append("workspace_id", workspaceId);
  form.append("file_name", fileName);
  form.append("source_type", "files");
  form.append("file", blob, fileName);
  const response = await fetch(`${API}/uploads/direct`, {
    method: "POST",
    headers: {
      "X-Monday-Report-Key": API_KEY,
      "Idempotency-Key": `ui-redesign-smoke-${fileName}-${Date.now()}`
    },
    body: form
  });
  if (!response.ok) throw new Error(`POST /uploads/direct (${fileName}) -> ${response.status}`);
}

function runWorkerOnce() {
  const worker = spawnSync(process.env.PYTHON ?? "python", ["-m", "backend.app.worker"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: process.env
  });
  if (worker.status !== 0) {
    throw new Error(`worker exited ${worker.status}: ${(worker.stderr || worker.stdout || "").slice(0, 300)}`);
  }
}

/** Seed an image so the OCR route raises a `file`-targeted task. */
async function seedOcrFileTask(workspaceId) {
  const bytes = Uint8Array.from(atob(DEMO_PNG_BASE64), (c) => c.charCodeAt(0));
  await uploadDemoFile(workspaceId, "demo_scan_smoke.png", new Blob([bytes], { type: "image/png" }));
  runWorkerOnce();
  const tasks = await apiJson("/validation-tasks");
  return tasks.filter(isOpen).filter((task) => task.target_type === "file");
}

async function seedOpenValidationTask(workspaceId) {
  await uploadDemoFile(
    workspaceId,
    "demo_ddr_smoke.txt",
    new Blob([DEMO_DDR], { type: "text/plain" })
  );
  // REPO_ROOT, not process.cwd(): `-m backend.app.worker` only resolves from the
  // repository root, and the gate is deliberately cwd-independent. With cwd() a run
  // started from any other directory passed the gate, uploaded evidence, and only THEN
  // failed with ModuleNotFoundError - leaving the mutation behind.
  runWorkerOnce();
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
  // `headings` is part of the gate, not a collected-and-discarded signal: every route
  // in this loop renders exactly one h1, which route-renders already asserts.
  const painted =
    overflow.rendered.elements >= 10 && overflow.rendered.text >= 40 && overflow.rendered.headings >= 1;
  const noOverflow = overflow.scrollWidth <= overflow.clientWidth + 1;
  check(
    `no-horizontal-scroll:${label}`,
    painted && noOverflow,
    !painted
      ? `nothing rendered to measure (${overflow.rendered.elements} elements, ${overflow.rendered.text} chars, ${overflow.rendered.headings} h1) — the check would have passed vacuously`
      : noOverflow
        ? `${overflow.clientWidth}px viewport, ${overflow.rendered.elements} elements painted, no page-level overflow`
        : `scrollWidth ${overflow.scrollWidth} > clientWidth ${overflow.clientWidth}; first offenders: ${overflow.offenders.join(", ") || "none in-flow"}`
  );
}

/**
 * Screenshots and the JSON summary are working artifacts and must never land in the
 * tree. The docstring promised that; nothing enforced it. Resolving the directory and
 * refusing anything inside the repository does — and the outcome is reported in the
 * summary's `screenshots` field so a run cannot hide that it wrote somewhere
 * unexpected.
 */
function resolveShotDir() {
  if (!SHOT_DIR) return { dir: "", note: "not set: no screenshot or summary file is written" };
  const dir = path.resolve(SHOT_DIR);
  const rel = path.relative(REPO_ROOT, dir);
  const inside = rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  return inside
    ? { dir: "", note: `REFUSED ${dir}: inside the repository at ${REPO_ROOT}` }
    : { dir, note: `writing to ${dir} (outside ${REPO_ROOT})` };
}
const SHOTS = resolveShotDir();

async function shoot(page, name) {
  if (!SHOTS.dir) return;
  await mkdir(SHOTS.dir, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS.dir, `${name}.png`), fullPage: true });
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
    // A third-party console error is not a defect in this application, so it is
    // recorded separately rather than gating the run — and the summary prints the list
    // so a run cannot hide one. This frontend now makes NO third-party request at all
    // (the design system's webfont @import was removed), so the expected value is an
    // empty array; anything in it means something new reached off-origin.
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
  // Every origin the BROWSER contacts, so the served bundle's API target can be proven
  // before this suite mutates anything. The isolation gate binds MONDAY_REPORT_API_BASE,
  // which governs only this script's own fetches; the app resolves its API from the
  // build-time VITE_API_BASE_URL, and the two are independent. Without this the suite
  // could pass the gate while the browser - which performs the validation decision -
  // wrote to a completely different, possibly live, API.
  const browserOrigins = new Set();
  context.on("request", (request) => {
    try {
      const origin = new URL(request.url()).origin;
      if (origin !== new URL(WEB).origin) browserOrigins.add(origin);
    } catch {
      /* non-URL schemes (data:, blob:) are not an origin we can bind */
    }
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
  // The queue's real sources, and no claim the backend does not implement. No creation
  // path keys on ambiguity: the three ValidationTask sites are a high-severity extracted
  // failure, a file routed to OCR, and a Critical benchmark anomaly.
  const workflowNamesRealSources =
    /high-severity extracted failure/i.test(landingText) &&
    /file that needed OCR/i.test(landingText) &&
    /Critical benchmark anomaly/i.test(landingText);
  const workflowClaimsAmbiguity = /ambiguous/i.test(landingText);
  check(
    "landing-workflow-names-real-queue-sources",
    workflowNamesRealSources && !workflowClaimsAmbiguity,
    `names all three real sources: ${workflowNamesRealSources}; claims "ambiguous": ${workflowClaimsAmbiguity}` +
      (workflowClaimsAmbiguity
        ? ` — offending sentence: ${JSON.stringify((/[^.]*ambiguous[^.]*\./i.exec(landingText) ?? ["?"])[0].trim())}`
        : "")
  );
  // Every route that renders the not-implemented page must be named as pending.
  const pendingNamed = ["Well schematics", "upload", "benchmarking", "failure explorer", "audit-chain", "settings"];
  const pendingMissing = pendingNamed.filter((name) => !new RegExp(name, "i").test(landingText));
  check(
    "landing-names-every-pending-surface",
    pendingMissing.length === 0,
    pendingMissing.length === 0
      ? `all ${pendingNamed.length} pending surfaces are named in the closing copy`
      : `the closing copy omits: ${pendingMissing.join(", ")}`
  );
  // A per-field citation chip on a NARRATIVE block would assert provenance the payload
  // does not carry; the page's own capability card says so.
  const heroClaimsPerFieldNarrativeProvenance = /Present operations[\s\S]{0,400}?p\.\s*\d+\s*·\s*\d+% confidence/i.test(
    landingText
  );
  check(
    "landing-hero-no-per-field-narrative-provenance",
    !heroClaimsPerFieldNarrativeProvenance,
    heroClaimsPerFieldNarrativeProvenance
      ? "the hero preview pins a page/confidence chip to the drafted narrative, which the payload does not carry"
      : "the drafted narrative block carries no per-field page/confidence chip"
  );

  const stageBandValues = await page.locator("section[aria-label='Monday Report, by the numbers'] p").allInnerTexts();
  check("landing-stat-band", stageBandValues.includes("1:1"), `stat band rendered ${stageBandValues.length} lines`);
  await shoot(page, "landing-desktop");

  // Landing CTA must navigate, never silently redirect. The wait is caught rather
  // than awaited bare: an unhandled rejection would abort the whole suite instead of
  // failing this one check, and the assertion after it would be unreachable.
  await page.locator("nav a", { hasText: "Open the app" }).first().click();
  const ctaLanded = await page
    .waitForURL(`${WEB}/app`, { timeout: 10000 })
    .then(() => true)
    .catch(() => false);
  check(
    "landing-cta-navigates",
    ctaLanded && page.url() === `${WEB}/app`,
    `cta landed on ${page.url()} (expected ${WEB}/app)`
  );
  if (!ctaLanded) await page.goto(`${WEB}/app`, { waitUntil: "networkidle" });

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
  const targetLine = /Issue target: report/i.test(draftBody);
  const carriesId = draftBody.includes("MR-2026.W31");
  check(
    "deep-route-kicker-carries-report-id",
    targetLine && carriesId,
    `issue-target line present: ${targetLine}; body names MR-2026.W31: ${carriesId}`
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
    `exactly one [data-shell]: ${shellPresent}; body states the route does not exist: ${/this route does not exist/i.test(
      notFoundText
    )}`
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
  // ── the served bundle must target the SAME API the gate authorised ──────────
  //
  // Runs after the route sweep above (so the app has issued its probe reads) and
  // BEFORE any mutation. A mismatch means the isolation gate certified one target while
  // the browser writes to another, so the gate flow is refused rather than run.
  const apiOrigin = new URL(API).origin;
  const foreignOrigins = [...browserOrigins].filter((origin) => origin !== apiOrigin);
  const browserContactedApi = browserOrigins.has(apiOrigin);
  check(
    "browser-targets-gated-api",
    browserContactedApi && foreignOrigins.length === 0,
    !browserContactedApi
      ? `the served bundle never contacted the gated API origin ${apiOrigin}; observed [${[...browserOrigins].join(", ") || "none"}]. It was probably built with a different VITE_API_BASE_URL.`
      : foreignOrigins.length > 0
        ? `the served bundle also contacted [${foreignOrigins.join(", ")}], which the isolation gate did not authorise (gated origin ${apiOrigin})`
        : `the served bundle contacted only the gated API origin ${apiOrigin}`
  );
  const browserBoundToGatedApi = browserContactedApi && foreignOrigins.length === 0;

  const mutated = { value: false };
  // How many tasks the seed actually raised. The per-decision check ids are declared
  // from this, so a document that yields two tasks does not break the coverage pin.
  const seeded = { count: 0 };
  const gateChecked = await runGateFlow();

  async function runGateFlow() {
    if (!API_KEY) {
      check("export-gate-precondition", false, "not run: MONDAY_REPORT_API_KEY is not set");
      return false;
    }
    if (!browserBoundToGatedApi) {
      check(
        "export-gate-precondition",
        false,
        "not run: the served bundle does not target the gated API origin, so a UI-driven " +
          "mutation would land on an unauthorised stack. Rebuild the redesign entry with " +
          "VITE_API_BASE_URL set to MONDAY_REPORT_API_BASE."
      );
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

      // ── the export gate counts SOME task types, not all of them ─────────────
      //
      // Seed an OCR `file` task FIRST and prove the gate ignores it, then seed the
      // failure task and prove the gate counts that one. Without the first half the
      // "gate closed" assertion below could not distinguish "counts the right classes"
      // from "counts everything".
      const ocrTasks = await seedOcrFileTask(workspaceId);
      check(
        "ocr-file-task-seeded",
        ocrTasks.length === 1,
        ocrTasks.length === 1
          ? `one open file-targeted task raised by the OCR route (${ocrTasks[0].id})`
          : `expected exactly 1 open file-targeted task from the image upload, saw ${ocrTasks.length}`
      );
      if (ocrTasks.length !== 1) return false;

      await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
      const gateWithOnlyOcr = await page.locator("body").innerText();
      const clearWithOcrOpen =
        /export gate clear/i.test(gateWithOnlyOcr) &&
        !gateWithOnlyOcr.includes("before exporting an official Monday Report");
      check(
        "ocr-file-task-does-not-block-export",
        clearWithOcrOpen,
        clearWithOcrOpen
          ? "an open file-targeted OCR task leaves the export gate clear, matching _open_validation_tasks_for_workspace"
          : `the gate is NOT clear while the only open task is file-targeted; banner reads ${JSON.stringify(
              (/Export gate[^\n]*/i.exec(gateWithOnlyOcr) ?? ["<no gate banner>"])[0]
            )}`
      );

      const open = await seedOpenValidationTask(workspaceId);
      check(
        "export-gate-seeded-real-task",
        open.length > 0,
        open.length > 0
          ? `seeded demo evidence through /uploads/direct + worker; ${open.length} open task(s)`
          : "seeding produced NO open validation task — the extractor did not fire"
      );
      if (open.length === 0) return false;
      const ocrTaskIds = new Set(ocrTasks.map((task) => task.id));
      // Only the gate-counted tasks are resolved through the UI. The OCR file task is
      // deliberately still open here - that is what makes the "gate ignores it" check
      // above discriminating - and is cleared through the API after the flow.
      const seededIds = new Set(open.filter((task) => !ocrTaskIds.has(task.id)).map((task) => task.id));
      seeded.count = seededIds.size;

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
        (task) =>
          !ocrTaskIds.has(task.id) && (task.target_type !== "failure" || !ours.has(task.target_id))
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
      const failureTasks = open.filter((task) => !ocrTaskIds.has(task.id));
      check(
        "failure-task-blocks-export",
        failureTasks.length === 1 && open.length === 2,
        `${open.length} open task(s) total, of which ${failureTasks.length} are gate-counted ` +
          `(expected 2 and 1: one file-targeted OCR task the gate ignores plus one failure task it counts)`
      );
      // The committed copy must carry the GATE's count, not the queue's: the OCR task is
      // open at this moment and must not appear in the number.
      const wantedCopy = gateCopy(failureTasks.length);
      const copyPresent = gatedText.includes(wantedCopy);
      check(
        "export-gate-closed-copy",
        copyPresent,
        copyPresent
          ? `present verbatim: ${JSON.stringify(wantedCopy)}`
          : `MISSING ${JSON.stringify(wantedCopy)}; the page's gate sentence reads ` +
            `${JSON.stringify((/Resolve [^\n]*/.exec(gatedText) ?? ["<no 'Resolve …' sentence>"])[0])}`
      );

      const exportButton = page.locator("button", { hasText: /^Export PDF$/ }).first();
      const buttonPresent = (await exportButton.count()) > 0;
      const gatedDisabled = buttonPresent ? await exportButton.isDisabled() : false;
      check(
        "export-disabled-while-gated",
        buttonPresent && gatedDisabled,
        buttonPresent
          ? `Export PDF rendered, disabled=${gatedDisabled}`
          : "no Export PDF button was rendered, so the gated state could not be asserted"
      );

      // The OCR task has now served its purpose (gate clear with it open, gate closed
      // once the failure task exists), so clear it through the API BEFORE the UI loop.
      // Leaving it open would put a second card in the queue, where a positional click
      // could resolve the wrong task, and it is queue work the UI flow is not about.
      for (const task of ocrTasks) {
        await apiJson(`/validation-tasks/${task.id}`, {
          method: "PATCH",
          headers: { "Idempotency-Key": `ui-redesign-ocr-cleanup-${task.id}` },
          body: JSON.stringify({ status: "validated", resolution_note: "Smoke-test cleanup." })
        });
      }
      const queueAfterOcrCleanup = (await apiJson("/validation-tasks")).filter(isOpen);
      check(
        "ocr-task-cleared-before-ui-decisions",
        queueAfterOcrCleanup.length === seededIds.size &&
          queueAfterOcrCleanup.every((task) => seededIds.has(task.id)),
        `${queueAfterOcrCleanup.length} open task(s) remain before the UI decisions ` +
          `(expected exactly the ${seededIds.size} gate-counted task(s) this run seeded)`
      );

      // Resolve through the UI so the unlock is the product's own behaviour, and
      // resolve ONLY the tasks this run seeded.
      await page.goto(`${WEB}/app/validation`, { waitUntil: "networkidle" });
      const validateCount = await page.locator("button", { hasText: /^Validate$/ }).count();
      check(
        "validation-card-present",
        validateCount > 0,
        `${validateCount} open task card(s) offer a Validate control`
      );

      // The card of a landed decision leaves the DOM only after the queue reload
      // resolves, so a second iteration could otherwise re-click the same card while
      // a genuinely open task stayed untouched.
      // Counts the aria-label, which is stable: the visible text flips to
      // "Recording…" while the PATCH is in flight, so counting /^Validate$/ would
      // report the card as gone before it had actually left the queue.
      const waitForCardCount = async (want) => {
        const deadline = Date.now() + 15000;
        let seen = -1;
        while (Date.now() < deadline) {
          seen = await page.locator('button[aria-label^="Validate: "]').count();
          if (seen === want) return { ok: true, seen };
          await page.waitForTimeout(200);
        }
        return { ok: false, seen };
      };

      for (let i = 0; i < seededIds.size; i += 1) {
        if (i > 0) {
          const settledDom = await waitForCardCount(seededIds.size - i);
          check(
            `validation-card-cleared-${i}`,
            settledDom.ok,
            settledDom.ok
              ? `the resolved card left the queue; ${seededIds.size - i} card(s) remain`
              : `expected ${seededIds.size - i} Validate control(s) after decision ${i}, still see ${settledDom.seen}`
          );
        }
        // By accessible name, not by position: the name carries the card's own target,
        // so a click cannot land on a different task's card.
        const button = page.locator('button[aria-label^="Validate: "]').first();
        await button.waitFor({ state: "visible", timeout: 15000 }).catch(() => {});
        if ((await button.count()) === 0) break;
        const clickedLabel = await button.getAttribute("aria-label");
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
            ? `decision ${i + 1} landed on ${JSON.stringify(clickedLabel)}; ${want} seeded task(s) still open`
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
          ? `all ${seededIds.size} gate-counted task(s) resolved through the UI, the seeded OCR task cleared through the API, and nothing else is open`
          : `${seededIds.size - seededStillOpen.length} of ${seededIds.size} seeded task(s) resolved; ` +
            `${seededStillOpen.length} seeded and ${remaining.length - seededStillOpen.length} unrelated task(s) still open`
      );

      // Re-enter the view so the assertion reads a settled render, not whatever
      // frame the click left behind.
      await page.goto(`${WEB}/app/validation`, { waitUntil: "networkidle" });
      const clearedText = await page.locator("body").innerText();
      const queueReportsResolved = /all extracted events are resolved/i.test(clearedText);
      check(
        "validation-unlocks-gate",
        queueReportsResolved,
        queueReportsResolved
          ? "the queue itself reports every event resolved after the UI decisions"
          : `the queue does NOT report every event resolved; its state line reads ` +
            `${JSON.stringify((/(No open[^\n]*|\d+ open[^\n]*|Queue not read[^\n]*)/.exec(clearedText) ?? ["<no queue state line>"])[0])}`
      );

      await page.goto(`${WEB}/app/exports`, { waitUntil: "networkidle" });
      const clearGate = await page.locator("body").innerText();
      const readsClear = /export gate clear/i.test(clearGate);
      const blockingCopyGone = !clearGate.includes("before exporting an official Monday Report");
      check(
        "export-gate-clear-after-validation",
        readsClear && blockingCopyGone,
        `banner says "export gate clear": ${readsClear}; blocking copy gone: ${blockingCopyGone}`
      );
      const enabledButton = page.locator("button", { hasText: /^Export PDF$/ }).first();
      const enabledPresent = (await enabledButton.count()) > 0;
      const stillDisabled = enabledPresent ? await enabledButton.isDisabled() : true;
      check(
        "export-enabled-after-unlock",
        enabledPresent && !stillDisabled,
        enabledPresent
          ? `Export PDF rendered, disabled=${stillDisabled}`
          : "no Export PDF button was rendered, so the unlocked state could not be asserted"
      );
      return true;
    } catch (error) {
      // Two different facts, two different ids. Before the first write, the flow
      // genuinely did not run. After it, the stack HAS been mutated and a seeded task
      // may still be open — which blocks every later run of this suite, so it has to
      // be said out loud rather than filed under "precondition".
      if (mutated.value) {
        check(
          "export-gate-flow-aborted",
          false,
          `aborted AFTER seeding: ${error.message}. Demo evidence was uploaded and a validation task ` +
            `may still be open on ${API}; this suite refuses to resolve tasks it cannot attribute, so ` +
            `clear the queue (or point at a fresh stack) before the next run.`
        );
      } else {
        check("export-gate-precondition", false, `not run: ${error.message}`);
      }
      return false;
    }
  }

  // ── the Studio must not draft on mount (that call writes an audit event) ──
  {
    // `.catch(() => null)`, NOT `=> []`: substituting an array made both counts 0, so
    // an UNREADABLE audit log passed this check while proving nothing.
    //
    // And ANCHORED rather than counted: GET /audit-logs caps at the newest 200 tenant
    // entries, newest first, so on a busy stack two equal counts prove nothing — the
    // draft event could have entered while an older one fell off the end. The entries
    // newer than a fixed anchor are examined instead, and the check fails closed when
    // the anchor is no longer in the page.
    const readAuditPage = async () => {
      const entries = await apiJson("/audit-logs?limit=200").catch(() => null);
      return Array.isArray(entries) ? entries : null;
    };
    const before = await readAuditPage();
    const anchorId = before && before.length > 0 ? before[0].id : null;
    await page.goto(`${WEB}/app/studio`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1200);
    const after = await readAuditPage();
    const anchorIndex = after && anchorId ? after.findIndex((entry) => entry.id === anchorId) : -1;
    const newer = after && anchorIndex >= 0 ? after.slice(0, anchorIndex) : null;
    const drafted = newer ? newer.filter((entry) => entry.action === "report_draft.generate") : null;
    check(
      "studio-does-not-draft-on-mount",
      drafted !== null && drafted.length === 0,
      before === null || after === null
        ? "could not read the audit log, so nothing was verified"
        : anchorId === null
          ? "the audit log was empty before navigating, so there was no anchor to compare against"
          : anchorIndex < 0
            ? `the anchor entry ${anchorId} is no longer in the newest 200, so the window cannot be compared`
            : drafted.length === 0
              ? `${newer.length} audit event(s) were appended by navigation, none of them report_draft.generate`
              : `navigation appended ${drafted.length} report_draft.generate audit event(s)`
    );
    const studioBody = await page.locator("body").innerText();
    const explicitDrafting = /runs only when you ask for it/i.test(studioBody);
    check(
      "studio-discloses-explicit-drafting",
      explicitDrafting,
      explicitDrafting
        ? "the Studio states that drafting is an explicit, audited action"
        : "MISSING the explicit-drafting disclosure ('runs only when you ask for it') from the Studio body"
    );
  }

  // ── an operator-cleared draft field must STAY cleared ─────────────────────
  //
  // Three states must stay distinct: not loaded, empty by operator choice, and a
  // backend value. Filtering "edited" on non-empty collapsed the middle one, so a
  // re-draft silently wrote the drafted text back over a field the operator had
  // deliberately emptied - while the panel still counted it as changed locally.
  {
    await page.goto(`${WEB}/app/studio`, { waitUntil: "networkidle" });
    const build = page.locator("button", { hasText: /^Build source-backed draft$/ }).first();
    const canDraft = (await build.count()) > 0 && !(await build.isDisabled());
    if (!canDraft) {
      check("studio-cleared-field-stays-empty", false, "the draft button was not available, so nothing was proven");
    } else {
      await build.click();
      const well = page.locator("#st-well");
      // Wait for the draft to populate the field; a field that never populates would
      // make the clear-and-redraft assertion vacuous.
      const populated = await well
        .waitFor({ state: "visible", timeout: 15000 })
        .then(async () => {
          const deadline = Date.now() + 15000;
          while (Date.now() < deadline) {
            if (((await well.inputValue()) ?? "").trim().length > 0) return true;
            await page.waitForTimeout(200);
          }
          return false;
        })
        .catch(() => false);
      if (!populated) {
        check(
          "studio-cleared-field-stays-empty",
          false,
          "the draft never populated #st-well, so clearing it would prove nothing"
        );
      } else {
        const before = await well.inputValue();
        await well.fill("");
        const afterClear = await well.inputValue();
        // Re-draft: the operator's clear must survive it.
        await build.click();
        await page.waitForTimeout(1500);
        const afterRedraft = await well.inputValue();
        const body = await page.locator("body").innerText();
        const disclosed = /field\(s\) you cleared were left empty/i.test(body);
        check(
          "studio-cleared-field-stays-empty",
          afterClear === "" && afterRedraft === "" && disclosed,
          `drafted ${JSON.stringify(before)} -> cleared ${JSON.stringify(afterClear)} -> after re-draft ` +
            `${JSON.stringify(afterRedraft)} (expected ""); the run disclosed the cleared field: ${disclosed}`
        );
      }
    }
  }

  // ── profile disclosure: contained, RTL-correct, keyboard-operable ──────────
  for (const direction of ["ltr", "rtl"]) {
    for (const width of [390, 768, 1440]) {
      await page.setViewportSize({ width, height: 820 });
      await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
      await page.evaluate((dir) => {
        document.documentElement.dir = dir;
      }, direction);
      const trigger = page.locator('button[aria-controls="mr-profile-disclosure"]').first();
      await trigger.click();
      const geometry = await page.evaluate(() => {
        const panel = document.getElementById("mr-profile-disclosure");
        if (!panel) return null;
        const rect = panel.getBoundingClientRect();
        return {
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          viewport: window.innerWidth,
          docScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
        };
      });
      const contained =
        geometry !== null &&
        geometry.left >= -1 &&
        geometry.right <= geometry.viewport + 1 &&
        !geometry.docScrolls;
      check(
        `profile-panel-contained:${direction}:${width}`,
        contained,
        geometry === null
          ? "the panel did not render, so containment could not be measured"
          : `panel spans ${geometry.left}..${geometry.right} in a ${geometry.viewport}px viewport; page scrolls sideways: ${geometry.docScrolls}`
      );
      await page.keyboard.press("Escape");
    }
  }
  await page.evaluate(() => {
    document.documentElement.dir = "ltr";
  });

  {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
    const trigger = page.locator('button[aria-controls="mr-profile-disclosure"]').first();
    await trigger.click();
    const focusInside = await page.evaluate(() =>
      Boolean(document.getElementById("mr-profile-disclosure")?.contains(document.activeElement))
    );
    // Tab must not leave the open panel.
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    const stillInside = await page.evaluate(() =>
      Boolean(document.getElementById("mr-profile-disclosure")?.contains(document.activeElement))
    );
    await page.keyboard.press("Escape");
    const closedAndRestored = await page.evaluate(() => ({
      closed: document.getElementById("mr-profile-disclosure") === null,
      onTrigger: document.activeElement?.getAttribute("aria-controls") === "mr-profile-disclosure"
    }));
    check(
      "profile-panel-keyboard",
      focusInside && stillInside && closedAndRestored.closed && closedAndRestored.onTrigger,
      `focus moved into the panel: ${focusInside}; still inside after 3 Tabs: ${stillInside}; ` +
        `Escape closed it: ${closedAndRestored.closed}; focus returned to the trigger: ${closedAndRestored.onTrigger}`
    );
  }

  // ── the mobile navigation focus ring must not be clipped ───────────────────
  {
    await page.setViewportSize({ width: 390, height: 812 });
    await page.goto(`${WEB}/app/reports`, { waitUntil: "networkidle" });
    // Focus a nav item with a REAL Tab press first: :focus-visible does not match a
    // programmatic .focus(), and an unfocused element reports the UA's default
    // `medium` outline rather than the ring the design system actually paints.
    let focusedNavItem = false;
    for (let i = 0; i < 20 && !focusedNavItem; i += 1) {
      await page.keyboard.press("Tab");
      focusedNavItem = await page.evaluate(() =>
        Boolean(document.activeElement?.hasAttribute?.("data-navbtn"))
      );
    }
    const ring = await page.evaluate(() => {
      const groups = document.querySelector("[data-navgroups]");
      const btn = document.activeElement;
      if (!groups || !btn || !btn.hasAttribute("data-navbtn")) return null;
      const gs = getComputedStyle(groups);
      const bs = getComputedStyle(btn);
      const pad = {
        top: parseFloat(gs.paddingTop) || 0,
        bottom: parseFloat(gs.paddingBottom) || 0,
        left: parseFloat(gs.paddingLeft) || 0,
        right: parseFloat(gs.paddingRight) || 0
      };
      return {
        overflowX: gs.overflowX,
        matchesFocusVisible: btn.matches(":focus-visible"),
        outline: `${bs.outlineStyle} ${bs.outlineWidth} offset ${bs.outlineOffset}`,
        pad,
        // The ring reaches outlineWidth + outlineOffset beyond the border box.
        reach: (parseFloat(bs.outlineWidth) || 0) + (parseFloat(bs.outlineOffset) || 0)
      };
    });
    const clears =
      ring !== null &&
      ring.matchesFocusVisible &&
      ring.reach > 0 &&
      ring.pad.top >= ring.reach &&
      ring.pad.bottom >= ring.reach &&
      ring.pad.left >= ring.reach &&
      ring.pad.right >= ring.reach;
    check(
      "mobile-nav-focus-ring-not-clipped",
      clears,
      ring === null
        ? "Tab never reached a nav item, so the focus ring could not be measured"
        : `focused nav item matches :focus-visible: ${ring.matchesFocusVisible}, ring ${ring.outline} ` +
          `reaching ${ring.reach}px outside the button; scroll container overflow-x ${ring.overflowX} ` +
          `with padding t/b/l/r ${ring.pad.top}/${ring.pad.bottom}/${ring.pad.left}/${ring.pad.right}px`
    );
  }

  // ── 200% zoom: the reflow target, at every Stage 1 route ───────────────────
  //
  // 1440x900 at 200% is 720x450 CSS px, which is what a zoomed desktop actually is.
  for (const route of ["/", "/app", "/app/reports", "/app/validation", "/app/exports", "/app/studio"]) {
    await page.setViewportSize({ width: 720, height: 450 });
    await page.goto(`${WEB}${route}`, { waitUntil: "networkidle" });
    await assertNoHorizontalScroll(page, `zoom200${route}`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });

  // ── the API chip must not claim a local fallback this entry does not have ──
  await page.goto(`${WEB}/app`, { waitUntil: "networkidle" });
  const chipText = await page.locator("[data-chip]").first().innerText();
  check(
    "api-chip-no-false-local-fallback",
    !/local fallback/i.test(chipText),
    `API chip reads ${JSON.stringify(chipText.trim())} — it must not claim a local fallback dataset`
  );

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
    // ALL the group labels: querySelector returned the first, so two of the three
    // were never measured while the check id claimed the whole nav chrome.
    const labels = [...document.querySelectorAll("[data-navlabel]")];
    const tenant = document.querySelector("[data-tenantcard]");
    return {
      columns: getComputedStyle(shell).gridTemplateColumns,
      sidebarPosition: getComputedStyle(sidebar).position,
      navOverflowX: getComputedStyle(groups).overflowX,
      minHeight: Math.min(...buttons.map((b) => Math.round(b.getBoundingClientRect().height))),
      count: buttons.length,
      labelCount: labels.length,
      labelsHidden: labels.filter((node) => getComputedStyle(node).display === "none").length,
      tenantHidden: tenant ? getComputedStyle(tenant).display === "none" : false
    };
  });
  // The single column is now ASSERTED, not merely measured: the rule that produces it
  // (`[data-shell] { grid-template-columns: minmax(0,1fr) }`) is separate from the one
  // that unpins the sidebar, so the check was passing while its own name went unproven.
  const shellTracks = mobile.columns.trim().split(/\s+/).filter(Boolean);
  check(
    "mobile-nav-single-column",
    shellTracks.length === 1 && mobile.sidebarPosition === "static" && mobile.navOverflowX === "auto",
    `shell resolves to ${shellTracks.length} column track(s) [${mobile.columns}], sidebar ${mobile.sidebarPosition}, nav overflow-x ${mobile.navOverflowX}`
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
    mobile.labelCount === 3 && mobile.labelsHidden === mobile.labelCount && mobile.tenantHidden,
    `${mobile.labelsHidden} of ${mobile.labelCount} group labels are display:none (expected 3 of 3); tenant card display:none = ${mobile.tenantHidden}`
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
    `sidebar reaches the right edge: ${rtl.onRight}; divider left ${rtl.borderLeft} / right ${rtl.borderRight} (expected 1px / 0px)`
  );
  check(
    "rtl-no-horizontal-scroll",
    !rtl.scrolls,
    rtl.scrolls ? "the document scrolls horizontally under dir=rtl" : "no page-level overflow under dir=rtl"
  );
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
      : `${ringed.tag}: :focus-visible=${ringed.matchesFocusVisible}, outline ${ringed.outlineStyle} ${ringed.outlineWidth}px`
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

  const emitted = new Set(results.map((entry) => entry.id));

  /**
   * The gate flow's ids, which are conditional by design: the flow refuses to run on
   * a stack whose queue it did not seed. Coverage is therefore an EITHER/OR — the flow
   * ran and emitted all of these, or it refused/aborted and said so with one of the
   * refusal ids. A silent partial is neither, and still fails.
   *
   * The per-decision ids scale with the number of tasks the seed actually raised, so a
   * document that yields two tasks does not read as an undeclared check.
   */
  const GATE_FLOW_IDS = [
    "export-gate-report-present",
    "ocr-file-task-seeded",
    "ocr-file-task-does-not-block-export",
    "failure-task-blocks-export",
    "ocr-task-cleared-before-ui-decisions",
    "export-gate-seeded-real-task",
    "export-gate-seeded-tasks-are-ours",
    "export-gate-closed-copy",
    "export-disabled-while-gated",
    "validation-card-present",
    "validation-resolved-only-seeded",
    "validation-unlocks-gate",
    "export-gate-clear-after-validation",
    "export-enabled-after-unlock",
    ...Array.from({ length: seeded.count }, (_, index) => `validation-decision-landed-${index + 1}`),
    ...Array.from({ length: Math.max(0, seeded.count - 1) }, (_, index) => `validation-card-cleared-${index + 1}`)
  ];
  const GATE_REFUSAL_IDS = ["export-gate-precondition", "export-gate-flow-aborted"];
  const gateRefusals = GATE_REFUSAL_IDS.filter((id) => emitted.has(id));
  const gateFlowRan = GATE_FLOW_IDS.filter((id) => emitted.has(id));
  const gateFlowMissing = GATE_FLOW_IDS.filter((id) => !emitted.has(id));
  const gateComplete = gateRefusals.length > 0 ? true : gateFlowMissing.length === 0;

  // Every check id an unconditional run emits. Declared so a caller can pin the
  // suite's coverage: a check that silently disappears (deleted, or skipped by a
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
    "landing-workflow-names-real-queue-sources",
    "landing-names-every-pending-surface",
    "landing-hero-no-per-field-narrative-provenance",
    "browser-targets-gated-api",
    "studio-does-not-draft-on-mount",
    "studio-discloses-explicit-drafting",
    "studio-cleared-field-stays-empty",
    ...["ltr", "rtl"].flatMap((dir) =>
      [390, 768, 1440].map((width) => `profile-panel-contained:${dir}:${width}`)
    ),
    "profile-panel-keyboard",
    "mobile-nav-focus-ring-not-clipped",
    ...["/", "/app", "/app/reports", "/app/validation", "/app/exports", "/app/studio"].map(
      (route) => `no-horizontal-scroll:zoom200${route}`
    ),
    "api-chip-no-false-local-fallback",
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

  const declared = new Set([...EXPECTED_CHECK_IDS, ...GATE_FLOW_IDS, ...GATE_REFUSAL_IDS, "coverage-complete"]);
  const missing = EXPECTED_CHECK_IDS.filter((id) => !emitted.has(id));
  const unexpected = [...emitted].filter((id) => !declared.has(id));
  const complete = missing.length === 0 && unexpected.length === 0 && gateComplete;
  check(
    "coverage-complete",
    complete,
    complete
      ? `all ${EXPECTED_CHECK_IDS.length} unconditional check(s) ran, nothing undeclared appeared, and the gate flow ` +
        (gateRefusals.length > 0
          ? `declared itself not run (${gateRefusals.join(", ")})`
          : `emitted all ${GATE_FLOW_IDS.length} of its ids`)
      : [
          missing.length ? `${missing.length} declared check(s) did not run: ${missing.slice(0, 8).join(", ")}` : "",
          unexpected.length ? `${unexpected.length} undeclared check id(s): ${unexpected.slice(0, 8).join(", ")}` : "",
          gateComplete
            ? ""
            : `the gate flow neither completed nor declared itself not run: ${gateFlowRan.length} of ` +
              `${GATE_FLOW_IDS.length} ids ran, missing ${gateFlowMissing.slice(0, 8).join(", ")}`
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
    export_gate_refusals: gateRefusals,
    seeded_validation_tasks: seeded.count,
    mutates_target_stack: mutated.value,
    screenshots: SHOTS.note,
    // Recorded, not gating: a third-party console error (the design system's Google
    // Fonts @import, blocked offline or by a CSP) is not a defect in this application,
    // but the run must still disclose it rather than swallow it.
    third_party_console_errors: thirdPartyErrors,
    unconditional_check_count: EXPECTED_CHECK_IDS.length,
    gate_flow_check_ids: GATE_FLOW_IDS.length,
    unexpected_check_ids: unexpected,
    checked: results.length,
    passed: results.filter((entry) => entry.status === "pass").length,
    failed,
    results
  };
  const text = JSON.stringify(summary, null, 2);
  console.log(text);
  if (SHOTS.dir) {
    await mkdir(SHOTS.dir, { recursive: true });
    await writeFile(path.join(SHOTS.dir, "ui_redesign_e2e.json"), text, "utf8");
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
