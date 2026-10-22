#!/usr/bin/env node
/**
 * browser_check.js — tier-2 gate. Drives the real app in headless Chrome over
 * the DevTools Protocol (no puppeteer, no dependencies) and asserts on what
 * actually rendered.
 *
 *   node scripts/browser_check.js            # full gate
 *   node scripts/browser_check.js --keep     # keep the chrome profile
 *   node scripts/browser_check.js --shot-dir=artifacts
 *
 * It starts everything it needs: a loopback fixture origin (an end-of-life
 * WordPress/PHP/Apache stack and a patched one), then the real collector, then
 * Chrome. Nothing is mocked inside the app — the page fetches, detects, matches
 * and renders exactly as a user's browser does.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const argv = process.argv.slice(2);
const KEEP = argv.includes("--keep");
const SHOT_DIR = (argv.find((a) => a.startsWith("--shot-dir=")) || "").split("=")[1] || path.join(ROOT, "artifacts");
const APP_PORT = 8123;
const FIXTURE_PORT = 8124;
const APP = `http://127.0.0.1:${APP_PORT}/`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
const failures = [];
function ok(cond, label, detail) {
  if (cond) { pass++; return true; }
  fail++; failures.push(label + (detail !== undefined ? "  [" + detail + "]" : ""));
  return false;
}
const eq = (a, b, label) => ok(a === b, label, "got " + JSON.stringify(a) + " want " + JSON.stringify(b));
const atLeast = (a, n, label) => ok(typeof a === "number" && a >= n, label, "got " + a + " want >= " + n);

/* --------------------------- fixture origin --------------------------- */
const FIXTURES = {
  "/old-wp": {
    headers: {
      "Server": "Apache/2.4.29 (Ubuntu)",
      "X-Powered-By": "PHP/7.2.34",
      "Set-Cookie": "wordpress_test_cookie=WP+Cookie+check; path=/",
      "Content-Type": "text/html; charset=UTF-8",
    },
    body: '<!doctype html><html><head><meta name="generator" content="WordPress 5.0.1">' +
      '<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4"></script>' +
      '<link rel="stylesheet" href="/wp-content/themes/twentyseventeen/style.css"></head>' +
      "<body><h1>An end-of-life stack</h1></body></html>",
  },
  "/modern-wp": {
    headers: {
      "Server": "nginx/1.25.5",
      "X-Powered-By": "PHP/8.3.2",
      "Content-Type": "text/html; charset=UTF-8",
    },
    body: '<!doctype html><html><head><meta name="generator" content="WordPress 6.6.1"></head><body>ok</body></html>',
  },
  "/plain": {
    headers: { "Server": "gws", "Content-Type": "text/html; charset=UTF-8" },
    body: "<!doctype html><html><body>nothing to fingerprint here</body></html>",
  },
};

function startFixture() {
  const srv = http.createServer((req, res) => {
    const fx = FIXTURES[req.url.split("?")[0]];
    if (!fx) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("not found"); }
    res.writeHead(200, fx.headers);
    res.end(fx.body);
  });
  return new Promise((resolve) => srv.listen(FIXTURE_PORT, "127.0.0.1", () => resolve(srv)));
}

/* ------------------------------ app server ----------------------------- */
function startApp(port, extraEnv) {
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), ...(extraEnv || {}) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => { out += d.toString(); });
  child.stderr.on("data", (d) => { out += d.toString(); });
  return { child, log: () => out };
}

async function waitForServer(url, timeoutMs) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(url);
      if (r.ok) return await r.json().catch(() => ({}));
    } catch (e) { /* not up yet */ }
    if (Date.now() - t0 > timeoutMs) throw new Error("app server never became ready at " + url);
    await sleep(150);
  }
}

/* ---------------------------------- CDP --------------------------------- */
function findChrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const home = os.homedir();
  const candidates = [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    path.join(home, "AppData/Local/Google/Chrome/Application/chrome.exe"),
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  for (const tools of [path.join(home, "AppData/Local/hermes/tools"), path.join(home, ".hermes/tools")]) {
    if (!fs.existsSync(tools)) continue;
    for (const d of fs.readdirSync(tools)) {
      if (!d.startsWith("chromium")) continue;
      candidates.push(
        path.join(tools, d, "chrome-win64/chrome.exe"),
        path.join(tools, d, "chrome-linux/chrome"),
        path.join(tools, d, "chrome-mac/Chromium.app/Contents/MacOS/Chromium")
      );
    }
  }
  return candidates.find((c) => fs.existsSync(c)) || null;
}

class CDP {
  constructor(ws) {
    this.ws = ws; this.seq = 0; this.pending = new Map(); this.listeners = [];
    ws.addEventListener("message", (ev) => {
      let msg;
      try { msg = JSON.parse(typeof ev.data === "string" ? ev.data : String(ev.data)); } catch (e) { return; }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) {
        for (const l of this.listeners) l(msg);
      }
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params: params || {} }));
      setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new Error("CDP timeout: " + method)); }
      }, 40000);
    });
  }
  async eval(expression, awaitPromise) {
    const r = await this.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: !!awaitPromise, userGesture: true });
    if (r.exceptionDetails) {
      const d = r.exceptionDetails;
      throw new Error((d.exception && d.exception.description) || d.text);
    }
    return r.result.value;
  }
}

async function waitFor(fn, timeoutMs, label) {
  const t0 = Date.now();
  for (;;) {
    let v = false;
    try { v = await fn(); } catch (e) { v = false; }
    if (v) return v;
    if (Date.now() - t0 > timeoutMs) throw new Error("timed out waiting for " + label);
    await sleep(140);
  }
}

async function launch(url) {
  const chrome = findChrome();
  if (!chrome) throw new Error("no Chrome/Chromium found — set CHROME_PATH");
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ninescope-gate-"));
  const port = 9411 + (process.pid % 200);
  const child = spawn(chrome, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    "--disable-extensions", "--disable-background-networking", "--hide-scrollbars",
    "--force-device-scale-factor=1", "--window-size=1500,1100",
    "--user-data-dir=" + profile, "--remote-debugging-port=" + port,
    "about:blank",
  ], { stdio: "ignore" });

  const close = async () => {
    try { child.kill(); } catch (e) {}
    await sleep(350);
    if (!KEEP) { try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) {} }
  };

  const version = await waitFor(async () => {
    const r = await fetch("http://127.0.0.1:" + port + "/json/version");
    return r.ok ? r.json() : false;
  }, 30000, "the debugging port");

  const target = await waitFor(async () => {
    const list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    return list.find((t) => t.type === "page" && t.webSocketDebuggerUrl) || false;
  }, 15000, "a page target");

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", () => rej(new Error("could not open the CDP socket")), { once: true });
  });
  const cdp = new CDP(ws);

  const errors = [];
  cdp.on((m) => {
    if (m.method === "Runtime.exceptionThrown") {
      const d = m.params.exceptionDetails;
      errors.push("exception: " + ((d.exception && d.exception.description) || d.text));
    }
    if (m.method === "Log.entryAdded" && m.params.entry.level === "error") errors.push("console: " + m.params.entry.text);
  });
  // subscribe BEFORE navigating, or the boot-time error is the one never seen
  await cdp.send("Runtime.enable");
  await cdp.send("Log.enable");
  await cdp.send("Page.enable");
  await cdp.send("Page.navigate", { url });
  await waitFor(() => cdp.eval("document.readyState === 'complete'"), 25000, "page load");
  await waitFor(() => cdp.eval("!!(window.NineScope && window.NineScope.state.meta)"), 25000, "the dataset to load");
  await sleep(300);
  return { cdp, errors, close, version };
}

async function shot(cdp, name) {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const r = await cdp.send("Page.captureScreenshot", { format: "png" });
  const p = path.join(SHOT_DIR, name);
  fs.writeFileSync(p, Buffer.from(r.data, "base64"));
  console.log("  shot: " + path.relative(ROOT, p) + " (" + (fs.statSync(p).size / 1024).toFixed(0) + " KB)");
  return p;
}

/* --------------------------------- main -------------------------------- */
(async () => {
  let fixture, app, session, strict;
  try {
    fixture = await startFixture();
    app = startApp(APP_PORT, { NINESCOPE_ALLOW_LOOPBACK: "1" });
    await waitForServer(`http://127.0.0.1:${APP_PORT}/api/health`, 25000);
    console.log("collector + fixture origin up; launching Chrome");

    session = await launch(APP);
    const { cdp, errors } = session;

    /* ---------------- feed ---------------- */
    console.log("\n== critical feed ==");
    const title = await cdp.eval("document.title");
    ok(/NINESCOPE/i.test(title), "page title names the app", title);

    const dom0 = await cdp.eval("JSON.stringify(window.NineScope.dom())");
    const d0 = JSON.parse(dom0);
    eq(d0.tab, "feed", "default tab is the feed");
    eq(d0.cveCards, 40, "first page renders 40 rows");
    eq(d0.stats.length, 5, "stat rail has 5 cells");
    const feedCount = parseInt(String(d0.feedCount).replace(/[^\d]/g, ""), 10);
    atLeast(feedCount, 1000, "feed count is a real dataset size");
    ok(/criticals/i.test(d0.statusText), "status line reports the dataset", d0.statusText);

    // the sparkline must have actually painted something
    const painted = await cdp.eval(`(() => {
      const c = document.getElementById('spark');
      const g = c.getContext('2d');
      const d = g.getImageData(0, 0, c.width, c.height).data;
      let n = 0;
      for (let i = 3; i < d.length; i += 4) if (d[i] > 0) n++;
      return n;
    })()`);
    atLeast(painted, 500, "sparkline painted pixels");

    /* ---------------- filters ---------------- */
    console.log("\n== filters ==");
    const t1 = await cdp.eval(`(() => {
      const s = document.getElementById('minScore');
      s.value = '10'; s.dispatchEvent(new Event('change'));
      const badges = [...document.querySelectorAll('#cveList .cve .score')].map(b => b.textContent.trim());
      return JSON.stringify({ n: badges.length, all: badges.every(b => b === '10.0'), sample: badges.slice(0, 3) });
    })()`);
    const f1 = JSON.parse(t1);
    ok(f1.n > 0, "score filter 10.0 still shows rows", f1.n);
    ok(f1.all, "every visible row is exactly 10.0", f1.sample.join(","));

    const t2 = await cdp.eval(`(() => {
      const s = document.getElementById('minScore');
      s.value = '9'; s.dispatchEvent(new Event('change'));
      const q = document.getElementById('q');
      q.value = 'wordpress'; q.dispatchEvent(new Event('input'));
      return new Promise(r => setTimeout(() => {
        const cards = [...document.querySelectorAll('#cveList .cve')];
        r(JSON.stringify({
          n: cards.length,
          all: cards.every(c => /wordpress/i.test(c.textContent)),
          first: cards.length ? cards[0].querySelector('.cvid').textContent : '',
        }));
      }, 400));
    })()`, true);
    const f2 = JSON.parse(t2);
    ok(f2.n > 0, "search for 'wordpress' returns rows", f2.n);
    ok(f2.all, "every search result actually mentions wordpress");

    const t3 = await cdp.eval(`(() => {
      const q = document.getElementById('q');
      q.value = ''; q.dispatchEvent(new Event('input'));
      const k = document.getElementById('kevOnly');
      k.checked = true; k.dispatchEvent(new Event('change'));
      return new Promise(r => setTimeout(() => {
        const cards = [...document.querySelectorAll('#cveList .cve')];
        r(JSON.stringify({ n: cards.length, all: cards.every(c => !!c.querySelector('.chip.kev')) }));
      }, 400));
    })()`, true);
    const f3 = JSON.parse(t3);
    ok(f3.n > 0, "KEV filter returns rows", f3.n);
    ok(f3.all, "every KEV-filtered row carries the exploited chip");

    // reset, then open a row
    await cdp.eval(`(() => {
      const k = document.getElementById('kevOnly');
      k.checked = false; k.dispatchEvent(new Event('change'));
      return true;
    })()`);
    await sleep(300);
    const opened = await cdp.eval(`(() => {
      const c = document.querySelector('#cveList .cve');
      c.click();
      const det = c.querySelector('.cvedetail');
      const link = det.querySelector('a[href*="nvd.nist.gov"]');
      return JSON.stringify({
        open: c.classList.contains('open'),
        visible: det.getBoundingClientRect().height > 0,
        link: link ? link.getAttribute('href') : '',
        vector: (det.querySelector('.vec') || {}).textContent || '',
      });
    })()`);
    const op = JSON.parse(opened);
    ok(op.open && op.visible, "clicking a row reveals its detail panel", JSON.stringify(op));
    ok(/nvd\.nist\.gov/.test(op.link), "detail links to the NVD record", op.link);

    await shot(cdp, "feed.png");

    /* ---------------- scanner ---------------- */
    console.log("\n== scanner ==");
    await cdp.eval(`window.NineScope.setTab('scan')`);
    eq(await cdp.eval(`document.getElementById('tab-scan').classList.contains('hide')`), false, "scan tab visible after switch");
    eq(await cdp.eval(`document.getElementById('tab-feed').classList.contains('hide')`), true, "feed tab hidden after switch");

    const oldScan = await cdp.eval(`window.NineScope.scan('http://127.0.0.1:${FIXTURE_PORT}/old-wp').then(r => JSON.stringify(r))`, true);
    const so = JSON.parse(oldScan);
    atLeast(so.summary.exposedModules, 3, "EOL fixture exposes 3 modules", JSON.stringify(so.summary));
    atLeast(so.summary.totalCves, 10, "EOL fixture matches many critical CVEs", so.summary.totalCves);
    atLeast(so.summary.kevExposures, 1, "EOL fixture includes an actively exploited CVE", so.summary.kevExposures);
    ok(so.summary.worst >= 9.0 && so.summary.worst <= 10, "worst score is a real CVSS value", so.summary.worst);
    const names = so.modules.map((m) => m.name);
    ok(names.indexOf("WordPress") >= 0, "WordPress identified in the fixture", names.join(","));
    ok(names.indexOf("PHP") >= 0, "PHP identified in the fixture", names.join(","));
    const php = so.modules.find((m) => m.name === "PHP");
    eq(php.version, "7.2.34", "PHP version read from X-Powered-By");
    ok(php.fixedIn.length > 0, "a fixed-in version is reported", JSON.stringify(php.fixedIn));
    // the recommended target must be the HIGHEST boundary, never the lowest
    for (const m of so.modules.filter((x) => x.cves.length)) {
      ok(!!m.recommendedFix, "exposed module carries a recommended fix", m.name);
      eq(m.recommendedFix, m.fixedIn[m.fixedIn.length - 1], "recommended fix is the highest boundary (" + m.name + ")");
      const below = m.fixedIn.filter((f) => f !== m.recommendedFix);
      ok(below.every((f) => f < m.recommendedFix || f.length <= m.recommendedFix.length),
        "no recommended fix is below a sibling boundary (" + m.name + ")", JSON.stringify(m.fixedIn));
    }
    ok(so.modules.every((m) => m.confidence >= 35), "no sub-threshold detection reached the UI",
      so.modules.map((m) => m.confidence).join(","));
    ok(so.modules.every((m) => m.cves.every((c) => c.score >= 9)), "every reported CVE clears the 9.0 floor");

    // rendered reality, not state
    const rendered = JSON.parse(await cdp.eval(`JSON.stringify({
      stats: [...document.querySelectorAll('#scanResults .stat b')].map(b => b.textContent.trim()),
      attnRows: document.querySelectorAll('#scanResults .attn .row').length,
      techCards: document.querySelectorAll('#scanResults .tech').length,
      exposedCards: document.querySelectorAll('#scanResults .tech.hit').length,
      kevChips: document.querySelectorAll('#scanResults .chip.kev').length,
      fixes: [...document.querySelectorAll('#scanResults .mfix b')].map(b => b.textContent.trim()),
      nvdLinks: document.querySelectorAll('#scanResults a[href*="nvd.nist.gov"]').length,
      msg: (document.getElementById('scanMsg') || {}).textContent || '',
    })`));
    eq(rendered.attnRows, so.summary.exposedModules, "one attention row per exposed module");
    atLeast(rendered.techCards, 3, "stack cards rendered", rendered.techCards);
    atLeast(rendered.exposedCards, 3, "exposed modules are visually flagged", rendered.exposedCards);
    atLeast(rendered.kevChips, 1, "KEV chip rendered for an exploited CVE", rendered.kevChips);
    atLeast(rendered.fixes.length, 1, "fixed-in versions rendered", JSON.stringify(rendered.fixes));
    atLeast(rendered.nvdLinks, 1, "CVE links rendered", rendered.nvdLinks);
    ok(/\b3 modules exposed\b/.test(rendered.msg), "summary line reports the exposure count", rendered.msg.slice(0, 120));
    eq(rendered.stats[0], String(so.summary.exposedModules), "rendered exposed count matches state");
    await shot(cdp, "scan-eol.png");

    // a patched modern stack
    const modScan = JSON.parse(await cdp.eval(`window.NineScope.scan('http://127.0.0.1:${FIXTURE_PORT}/modern-wp').then(r => JSON.stringify(r))`, true));
    ok(modScan.summary.technologies >= 3, "modern fixture detects its stack", modScan.summary.technologies);
    const wp = modScan.modules.find((m) => m.name === "WordPress");
    eq(wp.status, "clear", "current WordPress version is clear against the index", wp.status);
    eq(modScan.modules.find((m) => m.name === "nginx").status, "untracked", "product with no criticals on record is 'untracked', not 'clear'");

    // a site with nothing to fingerprint must report nothing, not an all-clear
    const plainScan = JSON.parse(await cdp.eval(`window.NineScope.scan('http://127.0.0.1:${FIXTURE_PORT}/plain').then(r => JSON.stringify(r))`, true));
    eq(plainScan.summary.technologies, 0, "blank fixture yields zero technologies");
    const plainMsg = await cdp.eval(`document.getElementById('scanMsg').textContent`);
    ok(/0 technologies/.test(plainMsg), "blank fixture reports zero technologies in the UI", String(plainMsg).slice(0, 100));

    // SSRF guard: the collector must refuse cloud metadata and non-http schemes.
    // Checked harness-side so the deliberate 4xx responses do not pollute the
    // page's own console-error assertion.
    const ssrfTargets = {
      "metadata": "http://169.254.169.254/latest/meta-data/",
      "file": "file:///etc/passwd",
      "private": "http://10.0.0.1/",
      "localhost-name": "http://localhost:" + APP_PORT + "/api/health",
    };
    const ssrf = {};
    for (const [k, u] of Object.entries(ssrfTargets)) {
      const r = await fetch(`http://127.0.0.1:${APP_PORT}/api/scan?url=` + encodeURIComponent(u));
      ssrf[k] = r.status;
    }
    eq(ssrf.metadata, 400, "metadata endpoint refused");
    eq(ssrf.file, 400, "file:// scheme refused");
    eq(ssrf.private, 400, "private range refused");

    // The gate's own collector runs with the loopback hatch open (it has to, to
    // scan the fixture origin). That must not stand in for the DEFAULT posture:
    // start a second collector with no hatch and prove it refuses loopback
    // targets, by literal address and by name.
    strict = startApp(APP_PORT + 2, {});
    await waitForServer(`http://127.0.0.1:${APP_PORT + 2}/api/health`, 25000);
    const strictOut = {};
    for (const [k, u] of Object.entries({
      "loopback-ip": `http://127.0.0.1:${FIXTURE_PORT}/plain`,
      "loopback-name": `http://localhost:${FIXTURE_PORT}/plain`,
      "metadata": "http://169.254.169.254/latest/meta-data/",
    })) {
      const r = await fetch(`http://127.0.0.1:${APP_PORT + 2}/api/scan?url=` + encodeURIComponent(u));
      strictOut[k] = r.status;
    }
    eq(strictOut["loopback-ip"], 400, "default posture refuses a loopback IP");
    eq(strictOut["loopback-name"], 400, "default posture refuses a name resolving to loopback (DNS-rebinding guard)");
    eq(strictOut.metadata, 400, "default posture refuses cloud metadata");
    strict.child.kill();

    /* ---------------- responsive ---------------- */
    console.log("\n== responsive ==");
    for (const [w, h] of [[320, 568], [390, 844], [1024, 768], [1500, 1100]]) {
      await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: w < 500 });
      await sleep(250);
      const probe = JSON.parse(await cdp.eval(`(() => {
        const iw = window.innerWidth;
        const bad = [];
        for (const el of document.querySelectorAll('.wrap, .stat, .cve, .panel, .attn .row, .tech, nav.tabs')) {
          const r = el.getBoundingClientRect();
          if (r.width > 0 && (r.right > iw + 1 || r.left < -1)) bad.push(el.className + ':' + Math.round(r.left) + '..' + Math.round(r.right));
        }
        return JSON.stringify({ iw, ih: window.innerHeight, overflow: bad.slice(0, 4), n: bad.length,
          scroll: document.documentElement.scrollWidth - window.innerWidth });
      })()`));
      eq(probe.iw, w, `viewport really is ${w}px`);
      eq(probe.n, 0, `no element overflows at ${w}px`, probe.overflow.join(" | "));
      ok(probe.scroll <= 1, `no horizontal scroll at ${w}px`, probe.scroll);
    }
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 320, height: 568, deviceScaleFactor: 1, mobile: true });
    await sleep(300);
    await shot(cdp, "scan-320.png");
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1500, height: 1100, deviceScaleFactor: 1, mobile: false });
    await sleep(200);

    /* ---------------- methodology + console ---------------- */
    console.log("\n== methodology tab ==");
    await cdp.eval(`window.NineScope.setTab('method')`);
    await sleep(200);
    const src = await cdp.eval(`document.getElementById('sources').textContent.replace(/\\s+/g,' ').slice(0,400)`);
    ok(/NVD/i.test(src) && /CISA/i.test(src), "provenance panel names both sources", src.slice(0, 80));
    ok(await cdp.eval(`document.querySelectorAll('#sources .srcrow').length >= 3`), "provenance lists sources and build info");
    await shot(cdp, "methodology.png");

    console.log("\n== console ==");
    if (errors.length) for (const e of errors.slice(0, 6)) console.log("  \x1b[31m!\x1b[0m " + String(e).split("\n")[0]);
    eq(errors.length, 0, "zero exceptions / console errors for the whole session", errors.length + " captured");

    console.log("\n" + "-".repeat(62));
    if (fail) {
      console.log(`\x1b[31mRED\x1b[0m — ${pass} passed, ${fail} failed`);
      for (const f of failures) console.log("  \x1b[31m✗\x1b[0m " + f);
      process.exitCode = 1;
    } else {
      console.log(`\x1b[32mGREEN\x1b[0m — ${pass} browser assertions passed`);
      console.log("  feed rows 40 · EOL fixture: " + so.summary.exposedModules + " exposed / " + so.summary.totalCves +
        " CVEs / " + rendered.kevChips + " KEV chips · 320→1500px clean");
    }
  } catch (e) {
    console.log("\x1b[31mharness error:\x1b[0m " + (e && e.stack ? e.stack.split("\n").slice(0, 4).join("\n  ") : e));
    if (app) console.log("server log:\n" + app.log().split("\n").slice(-8).join("\n"));
    process.exitCode = 1;
  } finally {
    if (session) await session.close();
    if (app) { try { app.child.kill(); } catch (e) {} }
    if (strict) { try { strict.child.kill(); } catch (e) {} }
    if (fixture) { try { fixture.close(); } catch (e) {} }
    setTimeout(() => process.exit(process.exitCode || 0), 250);
  }
})();
