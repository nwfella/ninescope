#!/usr/bin/env node
/**
 * live_check.js — tier-2 gate against a DEPLOYED url.
 *
 * A successful push is not a successful deploy, and matching hashes only prove
 * the bytes are right — not that the served page boots. This loads the live
 * URL in headless Chrome and asserts the app actually rendered from the
 * network copy of the dataset.
 *
 *   node scripts/live_check.js --url=https://nwfella.github.io/ninescope/
 *
 * Exit 0 = the served artifact rendered with zero console errors.
 * Exit 1 = a real defect, or the page was intercepted before it ever ran
 *          (an empty document.title with none of the app's DOM is the
 *          signature of a security agent rewriting the response — that is a
 *          local interception, not a broken deploy).
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const argv = process.argv.slice(2);
const flag = (n, d) => {
  const hit = argv.find((a) => a.startsWith("--" + n + "="));
  return hit ? hit.slice(n.length + 3) : d;
};
const URL_ = flag("url", "https://nwfella.github.io/ninescope/");
const SHOT = flag("shot", path.join(ROOT, "artifacts", "live.png"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let pass = 0, fail = 0;
const failures = [];
const ok = (c, label, detail) => {
  if (c) { pass++; return true; }
  fail++; failures.push(label + (detail !== undefined ? "  [" + detail + "]" : ""));
  return false;
};

function findChrome() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const home = os.homedir();
  const c = [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    path.join(home, "AppData/Local/Google/Chrome/Application/chrome.exe"),
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  for (const tools of [path.join(home, "AppData/Local/hermes/tools")]) {
    if (!fs.existsSync(tools)) continue;
    for (const d of fs.readdirSync(tools)) {
      if (d.startsWith("chromium")) c.push(path.join(tools, d, "chrome-win64/chrome.exe"), path.join(tools, d, "chrome-linux/chrome"));
    }
  }
  return c.find((p) => fs.existsSync(p)) || null;
}

class CDP {
  constructor(ws) {
    this.ws = ws; this.seq = 0; this.pending = new Map(); this.listeners = [];
    ws.addEventListener("message", (ev) => {
      let m; try { m = JSON.parse(typeof ev.data === "string" ? ev.data : String(ev.data)); } catch (e) { return; }
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id); this.pending.delete(m.id);
        m.error ? reject(new Error(m.error.message)) : resolve(m.result);
      } else if (m.method) for (const l of this.listeners) l(m);
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params) {
    const id = ++this.seq;
    return new Promise((res, rej) => {
      this.pending.set(id, { resolve: res, reject: rej });
      this.ws.send(JSON.stringify({ id, method, params: params || {} }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); rej(new Error("CDP timeout: " + method)); } }, 40000);
    });
  }
  async eval(expr, awaitPromise) {
    const r = await this.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: !!awaitPromise, userGesture: true });
    if (r.exceptionDetails) throw new Error((r.exceptionDetails.exception && r.exceptionDetails.exception.description) || r.exceptionDetails.text);
    return r.result.value;
  }
}

(async () => {
  let child, profile;
  try {
    const chrome = findChrome();
    if (!chrome) throw new Error("no Chrome found — set CHROME_PATH");
    profile = fs.mkdtempSync(path.join(os.tmpdir(), "ninescope-live-"));
    const port = 9711 + (process.pid % 200);
    child = spawn(chrome, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
      "--disable-extensions", "--hide-scrollbars", "--force-device-scale-factor=1",
      "--window-size=1500,1100", "--user-data-dir=" + profile, "--remote-debugging-port=" + port,
      "about:blank"], { stdio: "ignore" });

    let version, target;
    for (let i = 0; i < 200 && !version; i++) {
      try { const r = await fetch(`http://127.0.0.1:${port}/json/version`); if (r.ok) version = await r.json(); } catch (e) {}
      if (!version) await sleep(150);
    }
    if (!version) throw new Error("chrome never opened its debugging port");
    for (let i = 0; i < 100 && !target; i++) {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      target = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (!target) await sleep(150);
    }
    if (!target) throw new Error("no page target");

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.addEventListener("open", res, { once: true }); ws.addEventListener("error", () => rej(new Error("cdp socket failed")), { once: true }); });
    const cdp = new CDP(ws);

    const errors = [];
    cdp.on((m) => {
      if (m.method === "Runtime.exceptionThrown") errors.push("exception: " + ((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text));
      if (m.method === "Log.entryAdded" && m.params.entry.level === "error") errors.push("console: " + m.params.entry.text);
    });
    await cdp.send("Runtime.enable");
    await cdp.send("Log.enable");
    await cdp.send("Page.enable");
    console.log(version.Browser + " → " + URL_);
    await cdp.send("Page.navigate", { url: URL_ });

    // wait for the app to boot from the network copy of the dataset
    let booted = false;
    for (let i = 0; i < 120; i++) {
      try {
        if (await cdp.eval("!!(window.NineScope && window.NineScope.state.meta)")) { booted = true; break; }
      } catch (e) {}
      await sleep(250);
    }
    const title = await cdp.eval("document.title");
    ok(/NINESCOPE/i.test(title), "served page has the app title", JSON.stringify(title));
    ok(booted, "app booted and loaded the dataset over the network");
    if (!booted) {
      const bodyLen = await cdp.eval("document.body ? document.body.innerHTML.length : -1");
      console.log("  body html length: " + bodyLen + (bodyLen < 2000 ? "  ← looks intercepted, not broken" : ""));
    }

    const d = JSON.parse(await cdp.eval("JSON.stringify(window.NineScope.dom())"));
    ok(d.cveCards === 40, "40 rows rendered from the served data", d.cveCards);
    ok(parseInt(String(d.feedCount).replace(/[^\d]/g, ""), 10) >= 1000, "feed count populated", d.feedCount);
    ok(d.stats.length === 5, "stat rail rendered", d.stats.join("|"));
    ok(/criticals/i.test(d.statusText), "status line reports the dataset", d.statusText);
    ok(await cdp.eval("document.querySelectorAll('#sources .srcrow').length >= 3"), "provenance panel populated");

    const painted = await cdp.eval(`(() => {
      const c = document.getElementById('spark'); const g = c.getContext('2d');
      const px = g.getImageData(0, 0, c.width, c.height).data;
      let n = 0; for (let i = 3; i < px.length; i += 4) if (px[i] > 0) n++;
      return n;
    })()`);
    ok(painted > 500, "sparkline painted on the live page", painted);

    fs.mkdirSync(path.dirname(SHOT), { recursive: true });
    const r = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(SHOT, Buffer.from(r.data, "base64"));
    console.log("  shot: " + path.relative(ROOT, SHOT));

    for (const e of errors.slice(0, 5)) console.log("  \x1b[31m!\x1b[0m " + e.split("\n")[0]);
    ok(errors.length === 0, "zero console errors on the served page", errors.length + " captured");

    console.log(fail ? `\x1b[31mRED\x1b[0m — ${pass} passed, ${fail} failed`
      : `\x1b[32mGREEN\x1b[0m — ${pass} live assertions passed on the deployed artifact`);
    for (const f of failures) console.log("  \x1b[31m✗\x1b[0m " + f);
    process.exitCode = fail ? 1 : 0;
  } catch (e) {
    console.log("\x1b[31mharness error:\x1b[0m " + (e && e.message ? e.message : e));
    process.exitCode = 1;
  } finally {
    try { if (child) child.kill(); } catch (e) {}
    await sleep(300);
    try { if (profile) fs.rmSync(profile, { recursive: true, force: true }); } catch (e) {}
    setTimeout(() => process.exit(process.exitCode || 0), 200);
  }
})();
