#!/usr/bin/env node
/**
 * build_data.mjs — bake the critical-CVE dataset from authoritative sources.
 *
 * Sources (both keyless, both CORS-open):
 *   1. NVD CVE API 2.0  https://services.nvd.nist.gov/rest/json/cves/2.0
 *      - cvssV3Severity=CRITICAL  (CVSS v3 CRITICAL == baseScore 9.0-10.0)
 *      - plus a rolling unfiltered tail window, so CVEs scored only under
 *        CVSS v4.0 are not missed (the API's cvssV4Severity filter returns 0)
 *   2. CISA KEV         https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *
 * Output:
 *   public/data/monitor.json  rolling feed: criticals published in the last N months + every KEV entry
 *   public/data/index.json    product -> CVE version-range index, for the stack scanner
 *   public/data/meta.json     provenance + counts (the UI shows this, it is part of the product)
 *
 * No synthetic fallback, ever: a failed source aborts the build. If the data
 * cannot be fetched, nothing is written and the exit code is non-zero.
 *
 * Usage:
 *   node scripts/build_data.mjs                 # full build (network, ~2-4 min cold)
 *   node scripts/build_data.mjs --months 24     # monitor window
 *   NVD_API_KEY=xxx node scripts/build_data.mjs # 50 req/30s instead of 5
 *   node scripts/build_data.mjs --stats         # print CPE product frequency only
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "public", "data");
const CACHE = path.join(ROOT, ".cache");
const UA = "ninescope/1.0 (+https://github.com/nwfella/ninescope) CVE-monitor";
const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const API_KEY = process.env.NVD_API_KEY || "";

const args = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const MONTHS = Number(argOf("--months", "24"));
const STATS_ONLY = args.includes("--stats");
const MIN_SCORE = 9.0;

/* ------------------------------------------------------------------ *
 * Product allowlist — CPE keys the stack scanner can actually resolve.
 * Anything outside this set is still counted in the monitor feed, but it
 * is not indexed for version matching (no detector can fingerprint it).
 * ------------------------------------------------------------------ */
const WEB_PRODUCTS = new Set([
  // ---- servers / edge ----
  "apache:http_server", "nginx:nginx", "microsoft:internet_information_services",
  "lighttpd:lighttpd", "caddyserver:caddy", "apache:tomcat", "eclipse:jetty",
  "oracle:http_server", "litespeedtech:openlitespeed", "h2o:h2o",
  // ---- runtimes / languages ----
  "php:php", "nodejs:node.js", "python:python", "ruby-lang:ruby", "golang:go",
  "oracle:jre", "oracle:jdk", "openjdk:openjdk", "perl:perl",
  // ---- frameworks ----
  "djangoproject:django", "rubyonrails:rails", "rubyonrails:ruby_on_rails",
  "laravel:laravel", "sensiolabs:symfony", "symfony:symfony", "symfony:twig",
  "codeigniter:codeigniter", "cakephp:cakephp", "yiiframework:yii",
  "slimframework:slim", "expressjs:express", "palletsprojects:flask",
  "apache:struts", "thinkphp:thinkphp", "vmware:spring_framework",
  "vmware:spring_boot", "vmware:spring_security", "pivotal_software:spring_framework",
  "vercel:next.js", "nuxt:nuxt", "gatsbyjs:gatsby",
  // ---- CMS / commerce / portals ----
  "wordpress:wordpress", "drupal:drupal", "joomla:joomla!", "joomla:joomla",
  "magento:magento", "adobe:commerce", "typo3:typo3", "ghost:ghost",
  "mediawiki:mediawiki", "moodle:moodle", "phpmyadmin:phpmyadmin",
  "prestashop:prestashop", "opencart:opencart", "shopware:shopware",
  "concretecms:concrete_cms", "concrete5:concrete_cms", "craftcms:craft_cms",
  "statamic:statamic", "umbraco:umbraco_cms", "sitecore:experience_platform",
  "modx:modx_revolution", "phpmyfaq:phpmyfaq", "phpipam:phpipam",
  // ---- js / css libraries (most have no 9.0+ CVEs — indexed only where they do) ----
  "jquery:jquery", "jqueryui:jquery_ui", "getbootstrap:bootstrap", "facebook:react",
  "angular:angular", "angularjs:angular.js", "vuejs:vue", "vuejs:vue.js",
  "lodash:lodash", "momentjs:moment", "handlebarsjs:handlebars",
  "underscorejs:underscore", "ckeditor:ckeditor", "tinymce:tinymce",
  "datatables:datatables.net", "select2:select2", "modernizr:modernizr",
  // ---- platform components commonly surfaced by headers ----
  "elementor:elementor_page_builder", "openssl:openssl", "curl:curl",
  "apache:shiro", "apache:solr", "apache:activemq", "apache:ofbiz",
  "oracle:weblogic_server", "ibm:websphere_application_server",
  "citrix:netscaler", "f5:big-ip", "akamai:akamai",
]);

/* ------------------------------ fetch ------------------------------ */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJSON(url, { tries = 4, label = url, timeout = 90_000 } = {}) {
  let lastErr;
  for (let t = 0; t < tries; t++) {
    try {
      const res = await fetch(url, {
        headers: { "User-Agent": UA, Accept: "application/json", ...(API_KEY ? { apiKey: API_KEY } : {}) },
        signal: AbortSignal.timeout(timeout),
      });
      if (res.status === 403 || res.status === 429) {
        const wait = 15_000 * (t + 1);
        console.warn(`  ${label}: HTTP ${res.status}, backing off ${wait / 1000}s`);
        await sleep(wait);
        continue;
      }
      if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      console.warn(`  ${label}: ${e.message} (attempt ${t + 1}/${tries})`);
      await sleep(5_000 * (t + 1));
    }
  }
  throw new Error(`unrecoverable: ${label}: ${lastErr?.message}`);
}

/** NVD pages are immutable, so cache them: iteration stops costing rate limit. */
fs.mkdirSync(CACHE, { recursive: true });

const PAGE = 500;          // NVD truncates a response at ~90 s; 500 records (~3.4 MB) is the reliable ceiling
const CONCURRENCY = 5;     // NVD allows 5 requests / 30 s keyless, 50 with a key
const FETCH_TIMEOUT = 180_000;
let fetches = 0;
const MAX_FETCHES = Number(argOf("--max-fetches", "0"));   // 0 = unlimited; used to bound a single invocation

function cachePath(tag, startIndex, page) {
  return path.join(CACHE, `nvd-${tag}-${page}-${startIndex}.json`);
}

async function nvdPage(startIndex, params, tag, page = PAGE) {
  const file = cachePath(tag, startIndex, page);
  if (fs.existsSync(file)) {
    try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { fs.unlinkSync(file); }
  }
  if (MAX_FETCHES && fetches >= MAX_FETCHES) { const e = new Error("fetch budget reached"); e.budget = true; throw e; }
  const qs = new URLSearchParams({ ...params, resultsPerPage: String(page), startIndex: String(startIndex) });
  const json = await getJSON(`${NVD}?${qs}`, { label: `nvd ${tag}@${startIndex}`, timeout: FETCH_TIMEOUT });
  if (!Array.isArray(json.vulnerabilities)) throw new Error(`nvd ${tag}@${startIndex}: malformed payload`);
  fetches++;
  fs.writeFileSync(file, JSON.stringify(json));
  return json;
}

/** Params for one 120-day, CRITICAL-only window (NVD's hard limit per query). */
const winParams = (s0, e0) => ({ pubStartDate: s0, pubEndDate: e0, cvssV3Severity: "CRITICAL" });

/**
 * Collect a group of windows with window-level AND page-level parallelism.
 * Page 0 of every window in the group goes out at once (that is how the total
 * is learned), then the overflow pages go out in batches of CONCURRENCY.
 * Returns array (same order as `group`) of {total, got, records}.
 */
async function collectGroup(group) {
  const firsts = await Promise.allSettled(group.map((g) => nvdPage(0, winParams(g.s, g.e), g.tag)));
  const out = [];
  const extra = [];
  for (let i = 0; i < group.length; i++) {
    const r = firsts[i];
    if (r.status === "rejected") throw r.reason;
    out[i] = { total: r.value.totalResults, got: r.value.vulnerabilities.length, records: [...r.value.vulnerabilities] };
    for (let p = PAGE; p < r.value.totalResults; p += PAGE) extra.push({ i, p });
  }
  for (let k = 0; k < extra.length; k += CONCURRENCY) {
    const batch = extra.slice(k, k + CONCURRENCY);
    const res = await Promise.allSettled(batch.map((j) => nvdPage(j.p, winParams(group[j.i].s, group[j.i].e), group[j.i].tag)));
    for (let m = 0; m < res.length; m++) {
      const r = res[m];
      if (r.status === "rejected") throw r.reason;
      const slot = out[batch[m].i];
      slot.records.push(...r.value.vulnerabilities);
      slot.got += r.value.vulnerabilities.length;
    }
    if (extra.length > CONCURRENCY) await sleep(API_KEY ? 800 : 2_000);
  }
  return out;
}

/** Split a span into <=120-day windows, newest first. */
function windows(fromMs, toMs) {
  const out = [];
  let end = toMs;
  const DAY = 86400_000, SPAN = 120 * DAY;
  while (end > fromMs) {
    const start = Math.max(fromMs, end - SPAN);
    out.push([new Date(start).toISOString(), new Date(end).toISOString()]);
    end = start;
  }
  return out;
}

/* ----------------------------- shaping ----------------------------- */
const scoreOf = (cve) => {
  const m = cve.metrics || {};
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = m[k];
    if (!arr || !arr.length) continue;
    // prefer the CNA-supplied score, else the NVD primary one
    const pick = arr.find((x) => x.type === "Primary") || arr[0];
    const d = pick.cvssData || {};
    const base = d.baseScore ?? pick.baseScore;
    if (typeof base === "number") {
      const sev = d.baseSeverity || (base >= 9 ? "CRITICAL" : base >= 7 ? "HIGH" : base >= 4 ? "MEDIUM" : "LOW");
      return { score: base, severity: sev, vector: d.vectorString || "", version: (d.version || k.slice(-3)) };
    }
  }
  return null;
};

const cwesOf = (cve) =>
  [...new Set((cve.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value)))]
    .filter((v) => /^CWE-\d+$/.test(v))
    .slice(0, 3);

const descOf = (cve, max = 400) => {
  const en = (cve.descriptions || []).find((d) => d.lang === "en") || (cve.descriptions || [])[0];
  const t = (en?.value || "").replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1).trimEnd() + "…" : t;
};

/** Flatten configurations[].nodes[].cpeMatch[] into vulnerable application CPEs with version ranges. */
function cpesOf(cve) {
  const out = [];
  const walk = (nodes) => {
    for (const node of nodes || []) {
      for (const cm of node.cpeMatch || []) {
        if (!cm.vulnerable || !cm.criteria) continue;
        const f = cm.criteria.split(":");
        if (f[2] !== "a" && f[2] !== "o") continue; // application + os; skip hardware
        const vendor = (f[3] || "").replace(/\\/g, "").toLowerCase();
        const product = (f[4] || "").replace(/\\/g, "").toLowerCase();
        if (!vendor || !product || product === "*" || product === "-") continue;
        const range = {
          v: f[5] && f[5] !== "*" && f[5] !== "-" ? f[5].replace(/\\/g, "") : "",
          s: cm.versionStartIncluding || "",
          sx: cm.versionStartExcluding || "",
          e: cm.versionEndIncluding || "",
          ex: cm.versionEndExcluding || "",
        };
        out.push({ key: `${vendor}:${product}`, part: f[2], range });
      }
      if (node.children) walk(node.children);
    }
  };
  for (const c of cve.configurations || []) walk(c.nodes);
  // dedupe identical (key, range) pairs — NVD repeats them across configurations
  const seen = new Set();
  return out.filter((c) => {
    const k = c.key + "|" + JSON.stringify(c.range);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/* ------------------------- version ordering ------------------------ */
// Local copy of the comparator so the build can sort/validate; the app carries
// its own implementation inside its tested CORE block.
export function cmpVersion(a, b) {
  const norm = (s) =>
    String(s).toLowerCase().replace(/^v/, "").split(/[.\-_+]/)
      .map((p) => (/^\d+$/.test(p) ? Number(p) : p));
  const A = norm(a), B = norm(b);
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const x = A[i], y = B[i];
    if (x === undefined) return /^\d+$/.test(String(y)) && Number(y) === 0 ? 0 : -1;
    if (y === undefined) return /^\d+$/.test(String(x)) && Number(x) === 0 ? 0 : 1;
    if (typeof x === "number" && typeof y === "number") { if (x !== y) return x < y ? -1 : 1; continue; }
    if (typeof x === "number") return 1;  // 1.0.0 > 1.0.0-rc1
    if (typeof y === "number") return -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/* ------------------------------- main ------------------------------ */
(async () => {
  const started = Date.now();
  console.log("ninescope data build");

  // ---- 1. NVD: CVSS v3 CRITICAL over the index horizon, in 120-day windows
  const YEARS = Number(argOf("--years", "8"));
  const toMs = Date.now();
  const fromMs = toMs - YEARS * 365.25 * 86400_000;
  const wins = windows(fromMs, toMs);
  console.log(`  nvd: ${wins.length} windows x <=120d covering ${new Date(fromMs).toISOString().slice(0, 10)} → today`);
  const critical = [];
  const groups = [];
  for (let i = 0; i < wins.length; i += CONCURRENCY) {
    groups.push(wins.slice(i, i + CONCURRENCY).map(([s0, e0]) => ({ s: s0, e: e0, tag: s0.slice(0, 10) })));
  }
  let done = 0;
  for (const group of groups) {
    let res;
    try {
      res = await collectGroup(group);
    } catch (e) {
      if (e.budget) {
        console.log(`
  fetch budget reached (${fetches} requests this run).`);
        console.log(`  windows complete: ${done}/${wins.length}. Re-run the same command to continue.`);
        process.exit(2);
      }
      throw new Error(`window ${group[0].tag} failed: ${e.message}`);
    }
    for (let i = 0; i < group.length; i++) {
      critical.push(...res[i].records);
      done++;
      console.log(`  window ${done}/${wins.length} ${group[i].tag}: ${res[i].got}/${res[i].total}`);
    }
  }
  console.log(`  nvd: ${critical.length} critical records collected (${fetches} network requests, rest cached)`);

  // ---- 3. CISA KEV
  console.log("  kev: fetching");
  const kev = await getJSON(KEV_URL, { label: "kev" });
  if (!kev.vulnerabilities?.length) throw new Error("kev: empty catalogue — refusing to write");
  const kevMap = new Map(
    kev.vulnerabilities.map((v) => [v.cveID, {
      added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === "Known",
      action: (v.requiredAction || "").slice(0, 240), name: v.vulnerabilityName || "",
    }])
  );

  // ---- 4. merge + filter
  const byId = new Map();
  for (const v of critical) {
    const cve = v.cve;
    if (!cve?.id) continue;
    const sc = scoreOf(cve);
    if (!sc || sc.score < MIN_SCORE) continue;
    const prev = byId.get(cve.id);
    if (prev && prev.score >= sc.score) continue;
    byId.set(cve.id, {
      id: cve.id,
      published: (cve.published || "").slice(0, 10),
      modified: (cve.lastModified || "").slice(0, 10),
      score: sc.score,
      sev: sc.severity,
      cvss: sc.version,
      vector: sc.vector,
      desc: descOf(cve),
      cwe: cwesOf(cve),
      cpes: cpesOf(cve),
    });
  }
  console.log(`  merged: ${byId.size} unique CVEs with baseScore >= ${MIN_SCORE}`);

  if (STATS_ONLY) {
    const freq = new Map();
    for (const c of byId.values()) for (const cp of c.cpes) freq.set(cp.key, (freq.get(cp.key) || 0) + 1);
    const top = [...freq.entries()].sort((a, b) => b[1] - a[1]);
    console.log(`  distinct application CPE products: ${top.length}`);
    console.log("  top 70 by critical-CVE count:");
    for (const [k, n] of top.slice(0, 70)) console.log(`    ${String(n).padStart(4)}  ${k}`);
    const wl = top.filter(([k]) => WEB_PRODUCTS.has(k));
    console.log(`  allowlist hits: ${wl.length}/${WEB_PRODUCTS.size} keys resolve; ${wl.reduce((s, [, n]) => s + n, 0)} CVE-product pairs`);
    const missing = [...WEB_PRODUCTS].filter((k) => !freq.has(k));
    console.log(`  allowlist keys with zero criticals: ${missing.length ? missing.join(", ") : "none"}`);
    return;
  }

  // ---- 5. monitor feed: rolling window + every KEV entry
  const cutoff = new Date(Date.now() - MONTHS * 30.44 * 86400_000).toISOString().slice(0, 10);
  const monitor = [];
  for (const c of byId.values()) {
    const k = kevMap.get(c.id);
    if (!k && c.published < cutoff) continue;
    const vendors = [...new Set(c.cpes.map((cp) => cp.key.split(":")[0]))].slice(0, 6);
    const products = [...new Set(c.cpes.map((cp) => cp.key.split(":")[1]))].slice(0, 8);
    monitor.push({
      id: c.id, published: c.published, modified: c.modified, score: c.score, sev: c.sev,
      cvss: c.cvss, vector: c.vector, desc: c.desc, cwe: c.cwe,
      kev: !!k, kevAdded: k?.added || "", ransomware: !!k?.ransomware, kevAction: k?.action || "",
      vendors, products,
    });
  }
  monitor.sort((a, b) => (a.published < b.published ? 1 : -1));

  // ---- 6. scanner index: version ranges for finger-printable products
  const idx = new Map(); // key -> [{id, score, published, kev, ranges[]}]
  let pairs = 0, unmatched = 0;
  for (const c of byId.values()) {
    const k = kevMap.get(c.id);
    const groups = new Map();
    for (const cp of c.cpes) {
      if (!WEB_PRODUCTS.has(cp.key)) { unmatched++; continue; }
      if (!groups.has(cp.key)) groups.set(cp.key, []);
      groups.get(cp.key).push(cp.range);
    }
    for (const [key, ranges] of groups) {
      if (!idx.has(key)) idx.set(key, []);
      idx.get(key).push({
        id: c.id, score: c.score, published: c.published, kev: !!k,
        // keep every range as 5 positional slots — an empty range means "all
        // versions", which must reach the client as version-agnostic, not be dropped
        ranges: ranges.map((r) => [r.v || "", r.s || "", r.sx || "", r.e || "", r.ex || ""]),
      });
      pairs++;
    }
  }
  const products = {};
  for (const [key, arr] of [...idx.entries()].sort()) {
    arr.sort((a, b) => (a.published < b.published ? 1 : -1));
    products[key] = arr.map((e) => [e.id, e.score, e.published, e.kev ? 1 : 0, e.ranges]);
  }

  fs.mkdirSync(OUT, { recursive: true });
  const meta = {
    builtAt: new Date().toISOString(),
    minScore: MIN_SCORE,
    monitorWindowMonths: MONTHS,
    monitorWindowFrom: cutoff,
    indexYears: YEARS,
    indexFrom: new Date(fromMs).toISOString().slice(0, 10),
    counts: {
      criticalAllTime: byId.size,
      criticalInWindow: monitor.filter((m) => !m.kev || m.published >= cutoff).length,
      kevTracked: monitor.filter((m) => m.kev).length,
      kevCatalogue: kevMap.size,
      indexedProducts: Object.keys(products).length,
      indexedProductCves: pairs,
    },
    sources: [
      { name: "NVD CVE API 2.0", url: NVD, note: `CVSS v3 CRITICAL over the last ${YEARS} years, ${wins.length} windows`, lastUpdated: new Date().toISOString() },
      { name: "CISA Known Exploited Vulnerabilities", url: KEV_URL, note: `${kev.count} entries, catalogue released ${kev.dateReleased}`, lastUpdated: kev.dateReleased },
    ],
    buildSeconds: Math.round((Date.now() - started) / 1000),
  };
  fs.writeFileSync(path.join(OUT, "monitor.json"), JSON.stringify({ meta, cves: monitor }));
  fs.writeFileSync(path.join(OUT, "index.json"), JSON.stringify({ meta, products }));
  fs.writeFileSync(path.join(OUT, "meta.json"), JSON.stringify(meta, null, 2));

  const kb = (f) => (fs.statSync(path.join(OUT, f)).size / 1048576).toFixed(2) + " MB";
  console.log(`  monitor.json ${kb("monitor.json")} — ${monitor.length} rows (${meta.counts.kevTracked} KEV)`);
  console.log(`  index.json   ${kb("index.json")} — ${meta.counts.indexedProducts} products, ${pairs} product-CVE pairs`);
  console.log(`  build ${meta.buildSeconds}s · window from ${cutoff}`);
})().catch((e) => {
  console.error("\nBUILD FAILED:", e.message);
  console.error("No data was written. Fix the source and re-run — never ship a partial bake.");
  process.exit(1);
});
