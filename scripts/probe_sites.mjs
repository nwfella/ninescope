#!/usr/bin/env node
/**
 * probe_sites.mjs — exercise the real fingerprint engine against real responses.
 *
 * Loads the app's CORE block from public/index.html (the same code the page
 * runs), fetches each URL with a browser-like UA, and prints what was detected.
 * This is how fixtures for the browser gate get chosen: a target is only used
 * in a test if its signature is measurably there.
 *
 *   node scripts/probe_sites.mjs https://wordpress.org https://www.drupal.org
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTML = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");
const CS = HTML.indexOf("/* CORE-START */"), CE = HTML.indexOf("/* CORE-END */");
const CORE_SRC = HTML.slice(CS + "/* CORE-START */".length, CE);
const Core = new Function(CORE_SRC + "\nreturn Core;")();
const IDX = JSON.parse(fs.readFileSync(path.join(ROOT, "public", "data", "index.json"), "utf8"));

const args = process.argv.slice(2);
const targets = args.length ? args : [
  "https://wordpress.org", "https://www.drupal.org", "https://www.php.net",
  "https://www.joomla.org", "https://www.apache.org", "https://nginx.org",
  "https://www.magentocommerce.com", "https://www.codeigniter.com",
];
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

for (const url of targets) {
  process.stdout.write(`\n=== ${url}\n`);
  let res, body = "";
  try {
    res = await fetch(url, {
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(20_000),
    });
    body = (await res.text()).slice(0, 2 * 1024 * 1024);
  } catch (e) {
    console.log(`  FETCH FAILED: ${e.message}`);
    continue;
  }
  const headers = {};
  for (const [k, v] of res.headers) headers[k] = v;
  const stack = Core.detect({ headers, html: body, finalUrl: res.url || url });
  const { modules, summary } = Core.matchVulns(stack, IDX.products);
  console.log(`  HTTP ${res.status} · ${(body.length / 1024).toFixed(1)} KB · ${summary.technologies} tech · ${summary.exposedModules} exposed · ${summary.totalCves} CVEs`);
  for (const m of modules) {
    console.log(`   ${m.status === "exposed" ? "!!" : "  "} ${m.name.padEnd(24)} ${(m.version || "-").padEnd(10)} ${String(m.confidence).padStart(3)}%  ${m.status.padEnd(11)} ${m.cves.length ? m.cves.length + " cves" : ""}  [${m.evidence.slice(0, 60)}]`);
  }
}
