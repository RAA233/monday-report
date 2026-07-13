import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const webBase = process.env.MONDAY_REPORT_WEB_BASE ?? "http://127.0.0.1:5173";
const screenshotDir = path.join(root, "output", "screenshots", "ui-quality");
const manifestPath = path.join(root, "output", "qa", "ui_quality_e2e_manifest.json");
const uploadFixturePath = path.join(root, "output", "qa", "ui_upload_fixture.txt");

const views = [
  { label: "Client Home", title: /Rigs and Monday Reports/i, file: "00-client-home.png" },
  { label: "Local AI Chat", title: /Ask Monday Report first/i, file: "01-chat-initial.png" },
  { label: "Report Studio", title: /Technical daily-report command console/i, file: "03-report-studio.png" },
  { label: "Upload", title: /Upload rig reports/i, file: "04-upload.png" },
  { label: "Dashboard", title: /Monday Report intelligence/i, file: "05-dashboard.png" },
  { label: "Explorer", title: /Failure explorer/i, file: "06-explorer.png" },
  { label: "Validation", title: /Validation queue/i, file: "07-validation.png" },
  { label: "Tracker", title: /Project tracker/i, file: "08-tracker.png" },
  { label: "Roadmap", title: /Product roadmap/i, file: "09-roadmap.png" },
  { label: "Architecture", title: /Local AI-first architecture/i, file: "10-architecture.png" }
];

const checks = [];
const browserErrors = [];

await fs.mkdir(screenshotDir, { recursive: true });
await fs.mkdir(path.dirname(manifestPath), { recursive: true });
await fs.writeFile(
  uploadFixturePath,
  [
    "Monday Report UI QA fixture.",
    "MWD signal loss observed at 10,342 ft MD.",
    "NPT 8.5 hr. Client-mode upload path should hash and audit this file."
  ].join("\n"),
  "utf8"
);

const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
page.on("pageerror", (error) => browserErrors.push(error.message));
page.on("console", (message) => {
  if (["error", "warning"].includes(message.type())) {
    browserErrors.push(`${message.type()}: ${message.text()}`);
  }
});

try {
  await openFresh(page);
  await expectText(page, /API connected/i, "API connected");
  await expectText(page, /Client landing/i, "Client landing visible");
  await expectText(page, /Rig MR list/i, "Rig MR list visible");
  await expectText(page, /Import coverage/i, "Import coverage visible");
  await expectText(page, /Export coverage/i, "Export coverage visible");
  await expectText(page, /ZIP archives/i, "ZIP import coverage");
  await expectText(page, /PDF reports/i, "PDF import coverage");
  await expectText(page, /JSON/i, "JSON export coverage");
  await expectText(page, /XLSX/i, "XLSX export coverage");
  await screenshot(page, "00-client-home.png", "Client Home");

  await page.getByRole("button", { name: "Local AI Chat", exact: true }).click();
  await expectText(page, /Ask Monday Report first/i, "Chat visible");
  await screenshot(page, "01-chat-initial.png", "Chat initial");

  await page.getByPlaceholder(/Ask about failures/i).fill("Generate this week's Monday Report executive summary.");
  await page.getByRole("button", { name: /Send question/i }).click();
  await expectText(page, /Draft Monday Report|extracted failure|extracted failures/i, "Chat answer");
  await expectText(page, /Risk register/i, "Chat structured risk register");
  await expectText(page, /Plan DDR/i, "Chat tool actions");
  await screenshot(page, "02-chat-answer.png", "Chat answer");

  for (const view of views.slice(2)) {
    await openFresh(page);
    await page.getByRole("button", { name: view.label, exact: true }).click();
    await expectText(page, view.title, `${view.label} visible`);

    if (view.label === "Report Studio") {
      await page.getByRole("button", { name: /Source draft/i }).click();
      await expectText(page, /Source-backed draft ready/i, "Report Studio source draft");
      await expectText(page, /Source-backed draft evidence/i, "Report Studio evidence panel");
      await expectText(page, /Client issue readiness/i, "Report Studio issue readiness");
      await expectText(page, /Normal formats/i, "Report Studio normal formats");
      await page.getByRole("button", { name: /FORGE style/i }).click();
      await page.getByRole("tab", { name: /BHA/i }).click();
      await page.getByRole("button", { name: /Apply format/i }).click();
      await expectText(page, /BHA performance report/i, "Report Studio BHA variant");
      await page.getByRole("button", { name: /AI draft/i }).click();
      await expectText(page, /FORGE 16A\(78\)-32/i, "Report Studio FORGE template");
      await expectText(page, /MR-DDR-2/i, "Report Studio format telemetry");
      await expectText(page, /Trajectory/i, "Report Studio control matrix");
    }

    if (view.label === "Roadmap") {
      await expectText(page, /Roadmap execution board/i, "Roadmap execution board");
      await expectText(page, /Next controlled moves/i, "Roadmap controlled moves");
    }

    if (view.label === "Upload") {
      await page.locator('input[type="file"]').first().setInputFiles(uploadFixturePath);
      await expectText(page, /Stored, hashed, and audited|backend upload audit failed/i, "Upload action completed");
      const failed = await page.getByText(/backend upload audit failed/i).count();
      record("Upload action", failed === 0, failed === 0 ? "Stored, hashed, and audited" : "Backend upload audit failed");
    }

    await screenshot(page, view.file, view.label);
  }
} finally {
  await browser.close();
}

record("Browser console", browserErrors.length === 0, browserErrors.length === 0 ? "No page errors" : browserErrors.slice(0, 8).join(" | "));

const failed = checks.filter((check) => !check.ok);
const manifest = {
  status: failed.length === 0 ? "pass" : "fail",
  generated_at: new Date().toISOString(),
  web_base: webBase,
  screenshot_dir: screenshotDir,
  checks,
  browser_errors: browserErrors,
  screenshots: checks.filter((check) => check.screenshot).map((check) => check.screenshot)
};
await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), "utf8");

for (const check of checks) {
  console.log(`${check.ok ? "PASS" : "FAIL"}: ${check.name} - ${check.detail}`);
}
console.log(`\nUI manifest: ${manifestPath}`);
if (failed.length > 0) {
  console.error(`UI quality E2E failed with ${failed.length} failing check(s).`);
  process.exit(1);
}
console.log("UI quality E2E passed.");

async function openFresh(activePage) {
  await activePage.goto(webBase, { waitUntil: "networkidle" });
  await activePage.reload({ waitUntil: "networkidle" });
  await activePage.locator(".app-shell").waitFor({ state: "visible", timeout: 15000 });
}

async function expectText(activePage, pattern, name) {
  await activePage.getByText(pattern).first().waitFor({ state: "visible", timeout: 20000 });
  record(name, true, "visible");
}

async function screenshot(activePage, fileName, name) {
  const target = path.join(screenshotDir, fileName);
  await activePage.screenshot({ path: target, fullPage: true });
  record(`${name} screenshot`, true, target, target);
}

function record(name, ok, detail, screenshotPath = null) {
  checks.push({ name, ok, detail, screenshot: screenshotPath });
}
