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
 * Run: MONDAY_REPORT_WEB_BASE=… MONDAY_REPORT_API_BASE=… (plus the isolated state
 *      pointers below) node scripts/redesign_stage1_defects.mjs
 * (start the redesign dev server first.)
 *
 * ISOLATION, and why this suite has the same gate as the mutating sibling suite:
 * the stubs are installed by ORIGIN MATCH, and the app resolves its API origin from the
 * build-time `VITE_API_BASE_URL` baked into the dev server — not from this process's
 * environment. If those two spellings disagree AT ALL (`localhost` vs `127.0.0.1` for
 * the very same backend), interception silently misses, requests reach the real network,
 * and a click such as Studio "Build" issues `GET /workspaces/{id}/report-draft`, which
 * the backend records as an AUDITED write on the hash-chained trust surface. So this
 * suite must never be pointed at a live stack, exactly like `ui_redesign_e2e.mjs`:
 *
 *   1. the repository's fail-closed `verification_isolation.py` preflight, plus the same
 *      local re-assertions that close its ALLOW_LIVE_TARGET / case-sensitivity /
 *      relative-root gaps for a suite that can mutate;
 *   2. `assertStubsIntercept` — proof, before any click, that interception actually
 *      engaged: a canary request is counted, and the app's own resolved origin (read
 *      from the served bundle) must equal the origin these stubs match. A spelling
 *      difference is a REFUSAL, not a silent escape;
 *   3. every route handler `fulfill`s; none calls `continue()`, so no matched request
 *      can reach a server, and an unmatched one is caught by (2).
 */
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function refuseNotIsolated(reason, detail) {
  console.error(`FAIL: verification isolation - ${reason}`);
  if (detail) console.error(detail);
  console.error(
    "redesign_stage1_defects drives a real browser whose traffic can escape its stubs, " +
      "so it refuses to run without an explicitly isolated stack."
  );
  process.exit(2);
}

// Layer 1: the repository's single definition of "isolated". Captured stdout (this
// file's own summary JSON is on stdout), bounded, and an unspawnable interpreter is
// reported as such rather than as an isolation verdict.
try {
  execFileSync(
    process.env.PYTHON ?? "python",
    [path.join(REPO_ROOT, "scripts", "verification_isolation.py"), "--context", "redesign-stage1-defects"],
    { stdio: ["ignore", "pipe", "pipe"], timeout: 30_000, encoding: "utf8" }
  );
} catch (error) {
  const stderr = (error && error.stderr) || "";
  const stdout = (error && error.stdout) || "";
  if (error && error.status === 2) {
    refuseNotIsolated("the repository preflight refused this environment.", `${stdout}${stderr}`);
  }
  refuseNotIsolated(
    `the preflight could not be executed (${(error && (error.code || error.message)) || "unknown"}).`,
    `${stdout}${stderr}`.trim() || "Set PYTHON to a spawnable interpreter, or fix the preflight."
  );
}

// Layer 2: hold regardless of any override. No default may stand in for these — a
// defaulted API base is exactly how the origin spellings drift apart.
{
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
      "An override such as MONDAY_REPORT_ALLOW_LIVE_TARGET does not excuse them."
    );
  }
  const liveState = path.resolve(REPO_ROOT, ".local_data");
  const insideOrEqual = (candidate, root) => {
    const rel = path.relative(root, candidate);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };
  for (const name of required.slice(0, 3)) {
    const raw = process.env[name];
    if (!path.isAbsolute(raw)) {
      refuseNotIsolated(`${name} must be an ABSOLUTE path (got ${JSON.stringify(raw)}).`);
    }
    const resolved = path.resolve(raw);
    // path.relative, not startsWith: Windows paths are case-insensitive.
    if (insideOrEqual(resolved, liveState) || insideOrEqual(resolved, REPO_ROOT)) {
      refuseNotIsolated(
        `${name} points inside the repository or the live .local_data (${resolved}).`,
        "Point every state pointer at a disposable directory outside the tree."
      );
    }
  }
  for (const [name, live] of [
    ["MONDAY_REPORT_API_BASE", "8000"],
    ["MONDAY_REPORT_WEB_BASE", "5173"]
  ]) {
    let parsed;
    try {
      parsed = new URL(process.env[name]);
    } catch {
      refuseNotIsolated(`${name} is not a valid URL (${JSON.stringify(process.env[name])}).`);
    }
    if (parsed.port === live) {
      refuseNotIsolated(`${name} names the LIVE port ${live} (${parsed.origin}).`);
    }
  }
}

const WEB = process.env.MONDAY_REPORT_WEB_BASE.replace(/\/$/, "");
const API = process.env.MONDAY_REPORT_API_BASE.replace(/\/$/, "");
const API_ORIGIN = new URL(API).origin;

// Counts every request the stub router actually intercepted. Zero at the point of the
// first navigation-driven read would mean the stubs are not on the app's path.
let intercepted = 0;

const results = [];
let failed = 0;
function check(id, ok, detail) {
  results.push({ id, ok: !!ok, detail });
  if (!ok) failed += 1;
  process.stdout.write(`${ok ? "PASS" : "FAIL"}: ${id}${detail ? ` — ${detail}` : ""}\n`);
}

// ── WCAG relative-luminance contrast, from a computed colour string ────────────────
// Chromium serializes computed colours in TWO forms: `rgb()/rgba()` for named/hex
// tokens, and `color(srgb r g b / a)` for anything that went through `color-mix()`
// (0..1 channels). A parser that knew only the first silently returned null for every
// wash, and the callers that did `if (!c) continue` then measured NOTHING for an entire
// class of the app's own fills. Both forms are parsed here; an UNPARSEABLE colour
// returns null and every caller treats null as a FAILURE, never a skip.
function parseRgb(str) {
  const rgb = /rgba?\(([^)]+)\)/i.exec(str);
  if (rgb) {
    const p = rgb[1].split(/[,\s/]+/).filter(Boolean).map((s) => parseFloat(s));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  }
  const srgb = /color\(\s*srgb\s+([^)]+)\)/i.exec(str);
  if (srgb) {
    const p = srgb[1].split(/[\s/]+/).filter(Boolean).map((s) => parseFloat(s));
    return { r: p[0] * 255, g: p[1] * 255, b: p[2] * 255, a: p.length > 3 ? p[3] : 1 };
  }
  return null;
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
  create_client_reports: true,
  // Without these the Ask dock/composer and Studio editor render natively DISABLED
  // under the stub session and silently drop out of the inert-contract census — the
  // exact controls two review rounds found unmeasured.
  generate_reports: true,
  record_field_corrections: true
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

/** Install a stub router for one scenario. `overrides` maps a path suffix to a body.
 *
 *  Routes are matched by PREDICATE on the parsed origin, not by a URL-pattern string:
 *  a glob compares spellings, while `new URL(...).origin` compares what the browser
 *  will actually connect to. Every branch fulfills; none continues, so a matched
 *  request can never reach a server. */
async function stub(page, { workspaces = [WS], overrides = {} } = {}) {
  await page.route(
    (url) => {
      try {
        return new URL(url).origin === API_ORIGIN;
      } catch {
        return false;
      }
    },
    async (route) => {
    intercepted += 1;
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
  }
  );
}

/** Prove, BEFORE any click can reach a handler, that the stubs are on the app's path.
 *
 *  This observes the BROWSER'S OWN TRAFFIC rather than reading a variable out of the
 *  bundle: what matters is not what the app was configured with but where it actually
 *  connects. Two independent facts, both required:
 *
 *    - every origin the page contacted is either the web origin under test or exactly
 *      the origin these stubs intercept. A `localhost` vs `127.0.0.1` spelling
 *      difference shows up here as a foreign origin and is REFUSED, which is precisely
 *      the escape route that would otherwise let a click reach a real backend;
 *    - a CANARY request issued from the page to the stubbed API origin is provably
 *      intercepted and answered by the stub, so the router is demonstrably on the
 *      request path and not merely installed. The canary is `GET /auth/session`: a
 *      read, never a mutation, so even the failure case cannot change server state.
 *
 *  Either failing is a hard refusal (exit 2), never a recorded check: a suite whose
 *  isolation is unproven must not continue to the phase where it clicks things. */
async function assertStubsIntercept(page, contactedOrigins) {
  const webOrigin = new URL(WEB).origin;
  const before = intercepted;
  const canary = await page.evaluate(async (api) => {
    try {
      const response = await fetch(`${api}/auth/session`, { headers: { accept: "application/json" } });
      return { ok: response.ok, body: (await response.text()).slice(0, 200) };
    } catch (error) {
      return { ok: false, body: `fetch failed: ${String(error)}` };
    }
  }, API);
  if (intercepted === before) {
    refuseNotIsolated(
      "the canary request to the stubbed API origin was NOT intercepted.",
      `the stub router did not see GET ${API}/auth/session (response: ${JSON.stringify(canary.body)}). ` +
        "Traffic is reaching something other than these stubs; refusing to continue."
    );
  }
  // The stub's own tenant slug proves the ANSWER came from the stub, not merely that a
  // matcher fired — a real backend would not return this fixture.
  if (!canary.ok || !canary.body.includes(`"slug":"${TENANT.slug}"`)) {
    refuseNotIsolated(
      "the canary response did not come from the stub fixture.",
      `expected the stub tenant slug ${JSON.stringify(TENANT.slug)}; got ${JSON.stringify(canary.body)}.`
    );
  }
  const foreign = [...contactedOrigins].filter((o) => o !== webOrigin && o !== API_ORIGIN);
  if (foreign.length > 0) {
    refuseNotIsolated(
      "the browser contacted an origin these stubs do not intercept.",
      `foreign origin(s): ${foreign.join(", ")}; stubs intercept ${API_ORIGIN}, page is ` +
        `${webOrigin}. Requests are escaping to a real backend — most often because the ` +
        "dev server was built with a VITE_API_BASE_URL whose host spelling differs from " +
        "MONDAY_REPORT_API_BASE. Rebuild the dev server with the identical origin."
    );
  }
}

// Every check id this suite emits on a complete run. Pinned so a structurally skipped
// block shrinks the total instead of passing silently: `coverage-complete` compares the
// emitted set against this list in both directions.
const EXPECTED_CHECK_IDS = [
  "d1-status-matrix",
  "d1-unknown-fail-closed",
  "d1-sanitized-string-would-misclassify",
  "d3-inert-contract-fill-luminance",
  "d3-inert-contract-label-ink",
  "d3-inert-contract-focus-preserved",
  "d5-no-workspace-provenance-claim",
  "d5-sample-values-labelled",
  "d6-unknown-outcome-no-direct-retry",
  "d6-unknown-outcome-announced-as-unknown",
  "d2-build-reachable-when-connected",
  "d2-no-workspace-click-announces",
  "d2-click-not-silent",
  "d4-gate-reason-shown",
  "d4-gate-next-action",
  "d4-closed-gate-not-native-disabled",
  "d4-closed-gate-aria-disabled",
  "d4-closed-gate-describedby-reason",
  "d4-describedby-target-exists",
  "d4-closed-gate-activation-blocked",
  "no-web-errors",
  "coverage-complete"
];

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  context.on("weberror", (e) => errors.push(String(e.error())));

  // Every origin the browser contacts, recorded for the isolation assertion. A request
  // that escaped the stubs shows up here as a third origin.
  const contactedOrigins = new Set();
  // Mutating API calls, counted by method+path rather than by any UI side effect, so a
  // regressed handler is caught by the request it issued and not by a transient string.
  const exportPosts = [];
  context.on("request", (request) => {
    try {
      const url = new URL(request.url());
      if (url.protocol === "http:" || url.protocol === "https:") {
        contactedOrigins.add(url.origin);
      }
      if (request.method() === "POST" && /\/monday-reports\/[^/]+\/exports\b/.test(url.pathname)) {
        exportPosts.push(`${request.method()} ${url.pathname}`);
      }
    } catch {
      /* non-URL request targets cannot reach a backend */
    }
  });

  // ── Defect 1: refusal discriminator — the REAL exported function, full matrix ─────
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [] });
    await page.goto(`${WEB}/`, { waitUntil: "domcontentloaded" });
    // Prove the stubs are on the request path — and that no traffic reached a foreign
    // origin — before anything in this suite clicks a control.
    await page.waitForTimeout(500);
    await assertStubsIntercept(page, contactedOrigins);
    const r = await page.evaluate(async () => {
      const m = await import("/src/redesign/lib/workspace.tsx");
      // Missing exports is the pre-fix state: report it as data, not a crash, so the
      // suite still emits per-check FAILs when run against unfixed source.
      if (typeof m.requestStatus !== "function" || typeof m.isBackendRefusal !== "function") {
        return { missing: true, errorText409: typeof m.errorText === "function" ? m.errorText(new Error("API 409: conflict")) : "" };
      }
      const mk = (msg) => new Error(msg);
      // 4xx PROVE the server rejected before applying. 5xx/gateway do not: a 500 can
      // follow a commit and a 502/504 can be minted by a proxy that never reached the
      // backend, so they must classify as UNKNOWN (fail closed), not as refusals.
      const proven = [400, 401, 403, 404, 409, 422, 423, 429];
      const unproven = [500, 502, 503, 504];
      const refusal = proven.map((s) => ({
        s,
        status: m.requestStatus(mk(`API ${s}: detail here`)),
        isRefusal: m.isBackendRefusal(mk(`API ${s}: detail here`))
      }));
      const serverSide = unproven.map((s) => ({
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
        serverSide,
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
    // 4xx parse AND classify as proven refusals; 5xx/gateway parse but must NOT, or the
    // operator is told "nothing was applied" about a mutation that may have landed.
    const everyStatus =
      r.refusal.every((x) => x.status === x.s && x.isRefusal === true) &&
      r.serverSide.every((x) => x.status === x.s && x.isRefusal === false);
    check(
      "d1-status-matrix",
      everyStatus,
      `4xx refusals -> ${JSON.stringify(r.refusal.map((x) => [x.s, x.isRefusal]))}; ` +
        `5xx/gateway must be unknown -> ${JSON.stringify(r.serverSide.map((x) => [x.s, x.isRefusal]))}`
    );
    check("d1-unknown-fail-closed", r.unknowns.every((x) => x === false), `unknowns -> ${JSON.stringify(r.unknowns)}`);
    check(
      "d1-sanitized-string-would-misclassify",
      r.oldClassifierOn409 === false && !/^API /.test(r.errorText409),
      `errorText("API 409:…") = ${JSON.stringify(r.errorText409)} (old classifier match=${r.oldClassifierOn409})`
    );
    await page.close();
    }
  }

  // ── Defect 3: the INERT-STATE CONTRACT, measured on the RENDERED APP ─────────────
  //
  // Earlier rounds asserted this against nodes the suite constructed itself. Synthetic
  // probes cannot fail the way the app fails: a probe whose label is a text node hides
  // the whole class where a control's label is element CHILDREN carrying their own
  // inline colours, and a probe compared against a sibling probe hides a fill that is
  // luminance-identical to that control's own live fill. So this walks the app's OWN
  // controls on the app's OWN routes, measures each one live, then marks it inert and
  // measures again, asserting NUMERIC luminance/contrast deltas — never string
  // inequality, which passes on a hue shift that no one can see.
  {
    const page = await context.newPage();
    await stub(page, { workspaces: [WS] });
    // `unparse` collects colour strings the census returned that this side could not
    // read; any entry is a FAILURE (the fill/ink assertions cannot vouch for a fill
    // they never measured). `focusRing` records controls whose :focus-visible ring is
    // absent. The census FOCUSES each control before reading the ring, because the
    // sheet only draws it under :focus-visible — reading an unfocused control's
    // outline (an earlier bug) can never fail.
    const contract = { checked: 0, inkChecked: 0, fill: [], ink: [], focus: [], unparse: [] };
    for (const route of ["/", "/app", "/app/reports", "/app/validation", "/app/exports", "/app/studio"]) {
      await page.goto(`${WEB}${route}`, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(400);
      // Gate EVERY route, not just the first: this block is the only one that visits
      // app routes in bulk, and each mount issues reads. Asserting once at the start
      // would leave the remaining routes' reads ungated on a mis-spelled origin.
      await assertStubsIntercept(page, contactedOrigins);
      const measured = await page.evaluate(async () => {
        const SELECTOR = 'button, a[href], [role="button"], input, textarea, select';
        // The EFFECTIVE background: the LAYER STACK composited, not the first
        // non-transparent string. A `color-mix(... 10%, transparent)` wash computes to
        // `color(srgb r g b / 0.1)`; returning that raw made the comparison treat a
        // 10%-opacity tint as if it were an opaque fill — a wrong number in BOTH
        // directions. Every layer is collected here and alpha-composited over the
        // first fully opaque one, so what is compared is what the eye sees.
        const readColour = (str) => {
          const rgb = /rgba?\(([^)]+)\)/i.exec(str || "");
          if (rgb) {
            const p = rgb[1].split(/[,\s/]+/).filter(Boolean).map(Number);
            return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
          }
          const srgb = /color\(\s*srgb\s+([^)]+)\)/i.exec(str || "");
          if (srgb) {
            const p = srgb[1].split(/[\s/]+/).filter(Boolean).map(Number);
            return { r: p[0] * 255, g: p[1] * 255, b: p[2] * 255, a: p.length > 3 ? p[3] : 1 };
          }
          return null;
        };
        const effectiveBg = (el) => {
          const layers = [];
          let node = el;
          while (node) {
            const c = readColour(getComputedStyle(node).backgroundColor);
            // An UNREADABLE layer is reported as-is so the node side fails on it,
            // rather than being skipped into a guess.
            if (c === null) return getComputedStyle(node).backgroundColor;
            if (c.a > 0) {
              layers.push(c);
              if (c.a >= 1) break;
            }
            node = node.parentElement;
          }
          let base = layers.length && layers[layers.length - 1].a >= 1
            ? layers.pop()
            : { r: 255, g: 255, b: 255, a: 1 };
          for (let i = layers.length - 1; i >= 0; i -= 1) {
            const top = layers[i];
            base = {
              r: top.r * top.a + base.r * (1 - top.a),
              g: top.g * top.a + base.g * (1 - top.a),
              b: top.b * top.a + base.b * (1 - top.a),
              a: 1
            };
          }
          return `rgb(${Math.round(base.r)}, ${Math.round(base.g)}, ${Math.round(base.b)})`;
        };
        const inkOf = (el) =>
          [el, ...el.querySelectorAll("*")]
            .filter((n) => Array.from(n.childNodes).some((c) => c.nodeType === 3 && c.textContent.trim()))
            .map((n) => getComputedStyle(n).color);
        const out = [];
        for (const el of Array.from(document.querySelectorAll(SELECTOR))) {
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue; // not rendered
          if (el.getAttribute("aria-disabled") === "true" || el.disabled) continue; // already inert
          const liveBg = effectiveBg(el);
          const liveInk = inkOf(el);
          el.setAttribute("aria-disabled", "true");
          const inertBg = effectiveBg(el);
          const inertInk = inkOf(el);
          // Focus the control (still focusable — that is the point of aria-disabled) and
          // read the ACTUAL :focus-visible ring, not the resting outline.
          el.focus();
          const fs = getComputedStyle(el);
          const ring = { style: fs.outlineStyle, width: fs.outlineWidth, color: fs.outlineColor };
          el.blur();
          el.removeAttribute("aria-disabled");
          out.push({
            tag: el.tagName.toLowerCase(),
            cls: (el.className?.toString() ?? "").slice(0, 40),
            liveBg,
            inertBg,
            inertInk,
            focused: el === document.activeElement, // false after blur; recorded pre-blur below
            ring
          });
        }
        return out;
      });
      for (const m of measured) {
        contract.checked += 1;
        const live = parseRgb(m.liveBg);
        const inert = parseRgb(m.inertBg);
        if (!live || !inert) {
          contract.unparse.push(`${route} ${m.tag}.${m.cls} bg ${m.liveBg} / ${m.inertBg}`);
          continue; // unparseable => already a failure; do not measure against a guess
        }
        const fillRatio = contrast(live, inert);
        if (fillRatio < 1.4) {
          contract.fill.push(`${route} ${m.tag}.${m.cls} fill ${fillRatio.toFixed(3)}:1`);
        }
        for (const [i, colour] of m.inertInk.entries()) {
          const c = parseRgb(colour);
          if (!c) {
            contract.unparse.push(`${route} ${m.tag}.${m.cls} ink#${i} ${colour}`);
            continue;
          }
          contract.inkChecked += 1;
          const inkRatio = contrast(c, inert);
          if (inkRatio < 4.5) {
            contract.ink.push(`${route} ${m.tag}.${m.cls} ink#${i} ${inkRatio.toFixed(2)}:1`);
          }
        }
        // A focusable inert control MUST show a ring: a solid outline >= 1px. `none`
        // (or 0 width) means the focus contract these controls exist to keep is gone.
        const w = parseFloat(m.ring.width);
        if (m.ring.style === "none" || !(w >= 1)) {
          contract.focus.push(`${route} ${m.tag}.${m.cls} ring=${m.ring.style}/${m.ring.width}`);
        }
      }
    }
    check(
      "d3-inert-contract-fill-luminance",
      contract.checked > 0 && contract.fill.length === 0 && contract.unparse.length === 0,
      contract.fill.length || contract.unparse.length
        ? `${contract.fill.length} below 1.4:1 (${contract.fill.slice(0, 3).join("; ")}); ${contract.unparse.length} unparseable (${contract.unparse.slice(0, 2).join("; ")})`
        : `${contract.checked} rendered control(s): every inert fill differs from its own live fill by >= 1.4:1`
    );
    check(
      "d3-inert-contract-label-ink",
      contract.inkChecked > 0 && contract.ink.length === 0 && contract.unparse.length === 0,
      contract.ink.length || contract.unparse.length || contract.inkChecked === 0
        ? `${contract.ink.length} label part(s) below 4.5:1 (${contract.ink.slice(0, 3).join("; ")}); inkChecked=${contract.inkChecked}; unparseable=${contract.unparse.length}`
        : `${contract.inkChecked} text part(s): every text-bearing part of every inert control clears 4.5:1`
    );
    check(
      "d3-inert-contract-focus-preserved",
      contract.checked > 0 && contract.focus.length === 0,
      contract.focus.length ? `${contract.focus.length} control(s) without a focus ring: ${contract.focus.slice(0, 3).join("; ")}` : `${contract.checked} inert control(s) keep a visible focus ring`
    );
    await page.close();
  }

  // ── Defect 6: mutation OUTCOME is state, not copy ─────────────────────────────────
  // An unknown outcome (5xx/gateway/disconnect) must not offer a direct re-mutation
  // (the api client mints a fresh Idempotency-Key, so a retry can land twice) and must
  // not be announced as a definite refusal. Both are proven on the RENDERED app by
  // driving Studio's draft to a 502 and reading what the alert renders.
  {
    const page = await context.newPage();
    await stub(page, {
      workspaces: [WS],
      overrides: {
        // The audited draft fetch answers 502 — an UNKNOWN outcome (a proxy that never
        // got the backend's answer), NOT a 4xx refusal.
        "/report-draft": (route) => route.fulfill({ status: 502, contentType: "text/plain", body: "Bad Gateway" })
      }
    });
    await page.goto(`${WEB}/app/studio`, { waitUntil: "domcontentloaded" });
    await assertStubsIntercept(page, contactedOrigins);
    const build = page.getByRole("button", { name: /Build source-backed draft/i });
    await build.waitFor({ state: "visible", timeout: 15000 });
    await build.click();
    // Wait for the FAILED state itself — the alert region — not for the words this
    // check is about to assert. Waiting on "outcome unknown" would make a regression
    // that says "not built" time out as a harness error instead of failing the check
    // that names the property.
    await page.locator('[role="alert"]').first().waitFor({ state: "visible", timeout: 15000 });
    const view = await page.evaluate(() => {
      const alert = document.querySelector('[role="alert"]');
      const bodyText = document.body.innerText;
      // Any control offering a DIRECT re-issue of the draft. "Reload this page" is the
      // safe re-read affordance and is allowed; a "Retry"/"Build" re-mutation is not.
      const retryish = Array.from(document.querySelectorAll("button, [role=button]")).filter((b) =>
        /^(retry|build source-backed draft|try again)$/i.test((b.textContent || "").trim())
      );
      return {
        alertText: alert ? alert.textContent : "",
        saysNotBuilt: /\bnot built\b/i.test(bodyText) && !/unknown/i.test(bodyText),
        saysUnknown: /outcome unknown/i.test(bodyText),
        saysMayHaveLanded: /may have been (applied|built)|may or may not/i.test(bodyText),
        directRetryCount: retryish.length
      };
    });
    check(
      "d6-unknown-outcome-no-direct-retry",
      view.directRetryCount === 0,
      `direct re-mutation control(s) offered on an unknown outcome: ${view.directRetryCount}`
    );
    check(
      "d6-unknown-outcome-announced-as-unknown",
      view.saysUnknown && view.saysMayHaveLanded && !view.saysNotBuilt,
      `alert=${JSON.stringify((view.alertText || "").slice(0, 90))} unknown=${view.saysUnknown} mayHaveLanded=${view.saysMayHaveLanded} notBuilt=${view.saysNotBuilt}`
    );
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
    // Re-assert isolation HERE, on an app route that has actually issued its mount
    // reads, and immediately before the first click. The landing page makes no API
    // calls, so the foreign-origin half of the gate has nothing to inspect there; this
    // is the point where an escaped request would already be visible and where the very
    // next statement could otherwise reach a real backend.
    await assertStubsIntercept(page, contactedOrigins);
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

    // Activation blocked, asserted on the REQUEST and not on transient UI text: a
    // regressed non-inert handler issues POST /monday-reports/{id}/exports/{fmt}, and
    // with an instant stub response the "Creating…" status can come and go inside any
    // fixed wait — so absence of that string proves nothing. Count the POSTs instead.
    // Same re-assertion before the click that could issue an export POST.
    await assertStubsIntercept(page, contactedOrigins);
    const postsBefore = exportPosts.length;
    await exportBtn.click({ force: true });
    await page.waitForTimeout(500);
    const issued = exportPosts.slice(postsBefore);
    check(
      "d4-closed-gate-activation-blocked",
      issued.length === 0,
      issued.length === 0
        ? "clicking the closed-gate export issued 0 export requests"
        : `clicking the closed-gate export issued ${issued.length}: ${issued.join(", ")}`
    );
    await page.close();
  }

  check("no-web-errors", errors.length === 0, errors.length ? errors.slice(0, 3).join(" || ") : "0 uncaught page errors");

  // Coverage: the emitted ids must equal EXPECTED_CHECK_IDS in BOTH directions, so a
  // structurally skipped block (or a silently renamed check) fails the run instead of
  // shrinking the total unnoticed. Duplicates fail too.
  {
    const emitted = results.map((r) => r.id).filter((id) => id !== "coverage-complete");
    const expected = EXPECTED_CHECK_IDS.filter((id) => id !== "coverage-complete");
    const missing = expected.filter((id) => !emitted.includes(id));
    const undeclared = emitted.filter((id) => !expected.includes(id));
    const duplicated = emitted.filter((id, i) => emitted.indexOf(id) !== i);
    check(
      "coverage-complete",
      missing.length === 0 && undeclared.length === 0 && duplicated.length === 0,
      missing.length || undeclared.length || duplicated.length
        ? `missing=${JSON.stringify(missing)} undeclared=${JSON.stringify(undeclared)} duplicated=${JSON.stringify(duplicated)}`
        : `all ${expected.length} declared check(s) ran exactly once`
    );
  }

  await browser.close();
  const passed = results.filter((r) => r.ok).length;
  process.stdout.write(`\n${JSON.stringify({ suite: "redesign_stage1_defects", passed, failed, total: results.length })}\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`redesign_stage1_defects harness error: ${error && error.stack ? error.stack : error}\n`);
  process.exit(2);
});
