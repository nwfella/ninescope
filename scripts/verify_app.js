#!/usr/bin/env node
/**
 * verify_app.js — tier-1 gate: the app's pure core, plus the integrity of the
 * baked dataset it renders. No browser, no network, no dependencies.
 *
 *   node scripts/verify_app.js          # exit 1 on any failed assertion
 *
 * What it proves:
 *   - the CORE block is genuinely DOM-free and loads in Node;
 *   - version comparison handles the boundary cases CVE ranges depend on;
 *   - the fingerprint engine detects the stacks it claims to, from synthetic
 *     fixtures modelled on real responses;
 *   - the CVE matcher implements versionStart/End Incl/Excl semantics exactly,
 *     including exact-version and unbounded ranges;
 *   - monitor.json and index.json are internally consistent (schema, ranges,
 *     score floor, no duplicate ids, KEV coverage) and the detectors can
 *     actually resolve against the shipped index.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const HTML = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");
const MON = JSON.parse(fs.readFileSync(path.join(ROOT, "public", "data", "monitor.json"), "utf8"));
const IDX = JSON.parse(fs.readFileSync(path.join(ROOT, "public", "data", "index.json"), "utf8"));

let pass = 0, fail = 0;
const failures = [];
function ok(cond, label, detail) {
  if (cond) { pass++; return true; }
  fail++; failures.push(label + (detail ? "  [" + detail + "]" : ""));
  return false;
}
const eq = (a, b, label) => ok(a === b, label, "got " + JSON.stringify(a) + " want " + JSON.stringify(b));
function near(a, b, tol, label) { return ok(Math.abs(a - b) <= tol, label, "got " + a + " want " + b + "±" + tol); }

/* ============================ static checks ============================ */
console.log("\n== static ==");
ok(HTML.length > 20_000, "index.html is non-trivial", HTML.length + " bytes");
ok(/\/\* CORE-START \*\//.test(HTML) && /\/\* CORE-END \*\//.test(HTML), "CORE markers present");
ok(!/<script[^>]+src=/i.test(HTML), "no external <script src>");
const links = HTML.match(/<link\b[^>]*>/gi) || [];
ok(links.every((l) => /rel=["']icon["']/i.test(l) && /href=["']data:/i.test(l)),
  "every <link> is an inline data: icon", links.length + " link tags");
ok(!/https?:\/\/[^"' ]+\.(?:js|css)\b/i.test(HTML), "no remote js/css assets");
ok(/<canvas[^>]+id="spark"/.test(HTML), "sparkline canvas present");
ok(!/\b(jQuery|ReactDOM|d3)\./i.test(HTML), "no third-party runtime referenced");

// slice by marker index: a regex ending at the first `*/` would cut into the block
const CS = HTML.indexOf("/* CORE-START */"), CE = HTML.indexOf("/* CORE-END */");
ok(CS >= 0 && CE > CS, "CORE block extractable");
const coreSrc = CS >= 0 && CE > CS ? HTML.slice(CS + "/* CORE-START */".length, CE) : "";
const stripped = coreSrc.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
for (const banned of ["document", "window", "localStorage", "fetch(", "XMLHttpRequest", "canvas"]) {
  ok(!new RegExp("\\b" + banned.replace("(", "\\(")).test(stripped), "CORE is free of `" + banned + "`");
}
const Core = new Function(coreSrc + "\nreturn Core;")();
ok(typeof Core.detect === "function" && typeof Core.matchVulns === "function", "CORE exports the engine");
ok(Array.isArray(Core.RULES) && Core.RULES.length >= 40, "detection rule table populated", Core.RULES.length + " rules");

/* ========================= version comparison ========================= */
console.log("\n== version comparison ==");
const V = Core.cmpVersion;
eq(V("8.1.0", "8.1.1"), -1, "8.1.0 < 8.1.1");
eq(V("8.1.10", "8.1.9"), 1, "8.1.10 > 8.1.9 (numeric, not lexical)");
eq(V("10.0.0", "9.9.9"), 1, "10.0.0 > 9.9.9");
eq(V("9.8", "9.8.0"), 0, "9.8 == 9.8.0");
eq(V("1.0.0", "1.0.0-rc1"), 1, "1.0.0 final outranks 1.0.0-rc1");
eq(V("v2.4.52", "2.4.52"), 0, "leading v ignored");
eq(V("5.4.0", "5.4"), 0, "5.4.0 == 5.4");
eq(V("2.0.36", "2.0.35"), 1, "2.0.36 > 2.0.35");

/* ============================ fingerprinting =========================== */
console.log("\n== fingerprinting ==");
const det = (ctx) => Core.detect(ctx);
const byName = (arr, n) => arr.find((t) => t.name.toLowerCase().indexOf(n.toLowerCase()) >= 0);

// fixture 1: a classic WordPress site
let s = det({
  finalUrl: "https://blog.example.com/",
  headers: { Server: "nginx/1.24.0", "X-Powered-By": "PHP/8.2.7", "Content-Type": "text/html" },
  html: '<html><head><meta name="Generator" content="WordPress 6.4.1">' +
    '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>' +
    '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body>hi</body></html>',
});
ok(byName(s, "wordpress") && byName(s, "wordpress").version === "6.4.1", "WordPress + version from generator meta",
  byName(s, "wordpress") && byName(s, "wordpress").version);
ok(byName(s, "nginx") && byName(s, "nginx").version === "1.24.0", "nginx + version from Server header");
ok(byName(s, "php") && byName(s, "php").version === "8.2.7", "PHP + version from X-Powered-By");
ok(byName(s, "wordpress").confidence >= 90, "generator-meta detection is high confidence", byName(s, "wordpress").confidence);
ok(byName(s, "wordpress").evidence.indexOf("generator") >= 0, "evidence names the signature", byName(s, "wordpress").evidence);

// fixture 2: Drupal with the X-Generator header
s = det({
  finalUrl: "https://www.example.org/",
  headers: { "X-Generator": "Drupal 10 (https://www.drupal.org)", Server: "Apache/2.4.58 (Unix)" },
  html: '<html data-drupal-selector="drupal-settings-json">',
});
ok(byName(s, "drupal") && byName(s, "drupal").version === "10", "Drupal + version from X-Generator", byName(s, "drupal") && byName(s, "drupal").version);
ok(byName(s, "apache") && byName(s, "apache").version === "2.4.58", "Apache httpd version parsed", byName(s, "apache") && byName(s, "apache").version);

// fixture 3: Joomla
s = det({
  finalUrl: "https://joomla.example.net/",
  headers: {},
  html: '<meta name="generator" content="Joomla! - Open Source Content Management"><script src="/media/system/js/core.js"></script>',
});
ok(byName(s, "joomla"), "Joomla detected from generator meta");

// fixture 4: cookie-only framework detections, no versions
s = det({
  finalUrl: "https://app.example.io/",
  headers: { "Set-Cookie": "laravel_session=abc; path=/, XSRF-TOKEN=def; path=/", Server: "Caddy" },
  html: "<html></html>",
});
ok(byName(s, "laravel") && byName(s, "laravel").version === "", "Laravel from cookie, no false version");
ok(byName(s, "caddy"), "Caddy from Server header");

// fixture 5: Next.js + Angular version attribute
s = det({
  finalUrl: "https://v.example.dev/",
  headers: { Server: "Vercel", "X-Vercel-Id": "abc" },
  html: '<html><body><app-root ng-version="16.2.0"></app-root><script src="/_next/static/chunks/main.js"></script></body></html>',
});
ok(byName(s, "angular") && byName(s, "angular").version === "16.2.0", "Angular version from ng-version attribute");
ok(byName(s, "next.js"), "Next.js from _next asset path");
ok(byName(s, "vercel"), "Vercel from edge header");

// fixture 6: nothing recognisable, and it must not throw or invent
s = det({ finalUrl: "https://unknown.example/", headers: { Server: "gws", "Content-Type": "text/html" }, html: "<html><body>hello</body></html>" });
eq(s.length, 0, "unknown stack yields zero detections (no invented modules)");

// fixture 7: degenerate inputs
ok(Array.isArray(det({ headers: {}, html: "" })), "empty context returns an array");
ok(Array.isArray(det({ headers: null, html: null, finalUrl: null })), "null context does not throw");
s = det({ headers: { server: "NGINX/1.25.1" }, html: "" });
ok(byName(s, "nginx") && byName(s, "nginx").version === "1.25.1", "lowercase header key + uppercase value still detected");

// fixture 8: version extraction must not invent digits
s = det({ finalUrl: "https://x.example/", headers: { "X-Powered-By": "PHP" }, html: "" });
ok(byName(s, "php") && byName(s, "php").version === "", "bare `PHP` header → no version");

/* =============================== CVE matching ========================== */
console.log("\n== CVE matching ==");
const products = {
  "php:php": [
    ["CVE-2099-0001", 9.8, "2099-01-01", 0, [["", "7.0.0", "", "", "8.1.0"]]],   // 7.0.0 <= v < 8.1.0
    ["CVE-2099-0002", 9.0, "2099-02-01", 1, [["8.2.7", "", "", "", ""]]],        // exactly 8.2.7, KEV
    ["CVE-2099-0003", 9.5, "2099-03-01", 0, [["", "", "", "", ""]]],             // unbounded
  ],
  "wordpress:wordpress": [
    ["CVE-2099-0004", 9.9, "2099-04-01", 1, [["", "", "", "6.4", ""]]],
  ],
  // only a bounded range: no unbounded entry, so "outside every range" is reachable
  "lighttpd:lighttpd": [
    ["CVE-2099-0005", 9.1, "2099-05-01", 0, [["", "", "", "", "1.0.0"]]],
  ],
};
const mk = (name, cpe, version) => ({ name, cat: "x", cpe, version, confidence: 90, evidence: "fixture" });

let m = Core.matchVulns([mk("PHP", ["php:php"], "8.0.30")], products);
eq(m.modules.length, 1, "one module matched");
eq(m.modules[0].status, "exposed", "range hit sets status=exposed");
// 8.0.30 matches the 7.0.0–8.1.0 range and the unbounded entry; the exact
// 8.2.7 entry must NOT match. Two hits, and the worst is the range's 9.8.
eq(m.modules[0].cves.length, 2, "range + unbounded counted, exact excluded", m.modules[0].cves.length);
eq(m.modules[0].worst, 9.8, "worst score is the max, not the first");
ok(m.modules[0].cves.some((c) => c.id === "CVE-2099-0001" && c.fixed.join() === "8.1.0"),
  "versionEndExcluding surfaces as the fixed version");
ok(m.modules[0].cves.some((c) => c.id === "CVE-2099-0003" && c.anyVersion), "unbounded range flagged version-agnostic");

// boundary: exclusive upper bound
m = Core.matchVulns([mk("PHP", ["php:php"], "8.1.0")], products);
ok(!m.modules[0].cves.some((c) => c.id === "CVE-2099-0001"), "8.1.0 does NOT match an endExcluding=8.1.0 range");
eq(m.modules[0].cves.length, 1, "only the unbounded range survives at the boundary", m.modules[0].cves.length);

// inclusive upper bound
m = Core.matchVulns([mk("WordPress", ["wordpress:wordpress"], "6.4")], products);
ok(m.modules[0].cves.some((c) => c.id === "CVE-2099-0004"), "6.4 matches an endIncluding=6.4 range");
m = Core.matchVulns([mk("WordPress", ["wordpress:wordpress"], "6.4.1")], products);
eq(m.modules[0].cves.length, 0, "6.4.1 does not match an endIncluding=6.4 range");

// exact version
m = Core.matchVulns([mk("PHP", ["php:php"], "8.2.7")], products);
ok(m.modules[0].cves.some((c) => c.id === "CVE-2099-0002"), "exact version match works");
m = Core.matchVulns([mk("PHP", ["php:php"], "8.2.8")], products);
ok(!m.modules[0].cves.some((c) => c.id === "CVE-2099-0002"), "exact version match is exact");

// statuses
m = Core.matchVulns([mk("LiteSpeed", ["lighttpd:lighttpd"], "2.0")], products);
eq(m.modules[0].status, "clear", "indexed product, version outside every range → clear");
m = Core.matchVulns([mk("Joomla", ["joomla:joomla!"], "3.9.0")], products);
eq(m.modules[0].status, "untracked", "product absent from the index → untracked");
m = Core.matchVulns([mk("Nginx", ["nginx:nginx"], "")], products);
eq(m.modules[0].status, "unversioned", "no version → unversioned, never clean");
eq(m.summary.exposedModules, 0, "empty summary when nothing is exposed");

// ranking: KEV exposure and severity order
m = Core.matchVulns([
  mk("WordPress", ["wordpress:wordpress"], "6.0"),
  mk("PHP", ["php:php"], "8.0.0"),
  mk("Nginx", ["nginx:nginx"], ""),
], products);
eq(m.modules[0].name, "WordPress", "KEV-listed exposure ranks first", m.modules[0].name);
eq(m.modules[m.modules.length - 1].name, "Nginx", "unversioned ranks below exposed");
eq(m.summary.kevExposures, 1, "KEV exposures counted across modules", m.summary.kevExposures);
eq(m.summary.totalCves, 3, "total CVEs summed", m.summary.totalCves);

/* ============================ feed filtering =========================== */
console.log("\n== feed filtering ==");
const nowISO = (d) => new Date(Date.now() - d * 86400_000).toISOString().slice(0, 10);
const feed = [
  { id: "CVE-1", score: 9.0, kev: false, published: nowISO(1), desc: "alpha widget", vendors: ["acme"], products: ["thing"], cwe: ["CWE-79"] },
  { id: "CVE-2", score: 10.0, kev: true, published: nowISO(40), desc: "beta server rce", vendors: ["globex"], products: ["server"], cwe: ["CWE-94"] },
  { id: "CVE-3", score: 9.8, kev: true, published: nowISO(400), desc: "gamma wordpress plugin", vendors: ["initech"], products: ["wordpress"], cwe: ["CWE-89"] },
];
eq(Core.filterMonitor(feed, { minScore: 9 }).length, 3, "score floor 9.0 keeps all");
eq(Core.filterMonitor(feed, { minScore: 9.8 }).length, 2, "score floor 9.8 keeps 9.8 and 10.0");
eq(Core.filterMonitor(feed, { minScore: 9.9 }).length, 1, "score floor 9.9 drops both 9.8 and 9.0");
eq(Core.filterMonitor(feed, { minScore: 10 }).length, 1, "score floor 10.0 keeps only 10.0");
eq(Core.filterMonitor(feed, { minScore: 9, kevOnly: true }).length, 2, "kevOnly filters on KEV flag");
eq(Core.filterMonitor(feed, { minScore: 9, days: 30 }).length, 1, "days=30 keeps only the recent row");
eq(Core.filterMonitor(feed, { minScore: 9, q: "WORDPRESS" }).length, 1, "search is case-insensitive");
eq(Core.filterMonitor(feed, { minScore: 9, q: "cwe-94" }).length, 1, "search reaches CWE ids");
eq(Core.filterMonitor(feed, { minScore: 9, q: "zzz" }).length, 0, "no match yields no rows");
eq(Core.filterMonitor(feed, { minScore: 9 })[0].id, "CVE-1", "newest first");
eq(Core.filterMonitor(null, {}).length, 0, "null feed is safe");

const st = Core.statsOf(feed);
eq(st.total, 3, "statsOf total");
eq(st.kev, 2, "statsOf kev count");
eq(st.last7, 1, "statsOf last-7-days window");
near(st.avgScore, (9.0 + 10.0 + 9.8) / 3, 1e-9, "statsOf mean score");

const series = Core.monthlySeries(feed, 12);
eq(series.length, 12, "monthly series has 12 buckets");
eq(series[series.length - 1].total >= 1, true, "current month bucket is last");
eq(series.reduce((a, b) => a + b.total, 0) <= 3, true, "only in-window rows are bucketed");

eq(Core.scoreClass(10), "s10", "scoreClass 10.0");
eq(Core.scoreClass(9.8), "s98", "scoreClass 9.8");
eq(Core.scoreClass(9.5), "s95", "scoreClass 9.5");
eq(Core.scoreClass(9.0), "s90", "scoreClass 9.0");

/* ========================= dataset integrity ========================== */
console.log("\n== dataset integrity ==");
ok(!!MON.meta && !!IDX.meta, "both artifacts carry meta");
ok(MON.cves.length >= 1000, "monitor feed is populated", MON.cves.length + " rows");
ok(MON.meta.minScore === 9, "score floor recorded as 9", MON.meta.minScore);
ok(Array.isArray(MON.meta.sources) && MON.meta.sources.length >= 2, "provenance lists both sources");
ok(MON.meta.sources.some((s) => /NVD/i.test(s.name)) && MON.meta.sources.some((s) => /CISA/i.test(s.name)),
  "provenance names NVD and CISA KEV");
ok(!!MON.meta.builtAt && !isNaN(Date.parse(MON.meta.builtAt)), "build timestamp is a real date");

const badScore = MON.cves.filter((c) => !(c.score >= 9.0 && c.score <= 10));
eq(badScore.length, 0, "every monitor row is 9.0-10.0", badScore.length + " out of range");
const badId = MON.cves.filter((c) => !/^CVE-\d{4}-\d{4,}$/.test(c.id));
eq(badId.length, 0, "every row id is a well-formed CVE id", badId.slice(0, 3).map((c) => c.id).join(","));
const badDate = MON.cves.filter((c) => isNaN(Date.parse(c.published)));
eq(badDate.length, 0, "every row has a parseable publication date");
const shortDesc = MON.cves.filter((c) => !c.desc || c.desc.length < 10);
eq(shortDesc.length, 0, "every row carries a description");
const ids = new Set(MON.cves.map((c) => c.id));
eq(ids.size, MON.cves.length, "no duplicate CVE ids in the feed");
const kevRows = MON.cves.filter((c) => c.kev);
ok(kevRows.length >= 50, "KEV coverage present in the feed", kevRows.length + " rows");
ok(kevRows.every((c) => /^\d{4}-\d{2}-\d{2}$/.test(c.kevAdded)), "every KEV row carries a date-added");
const ransomware = MON.cves.filter((c) => c.ransomware);
ok(ransomware.every((c) => c.kev), "ransomware flag only appears on KEV rows");

// the window is what it claims
const cutoff = new Date(Date.now() - (MON.meta.monitorWindowMonths * 30.44 + 31) * 86400_000).toISOString().slice(0, 10);
const outside = MON.cves.filter((c) => !c.kev && c.published < cutoff);
eq(outside.length, 0, "non-KEV rows all sit inside the declared window", outside.slice(0, 2).map((c) => c.id + "@" + c.published).join(","));

/* index */
const prods = IDX.products || {};
const pkeys = Object.keys(prods);
ok(pkeys.length >= 40, "scanner index covers many products", pkeys.length + " products");
const required = ["php:php", "wordpress:wordpress", "joomla:joomla!", "apache:http_server",
  "drupal:drupal", "djangoproject:django", "sensiolabs:symfony", "apache:tomcat", "nodejs:node.js"];
for (const k of required) ok(!!prods[k], "index contains " + k);
let entries = 0, badRange = 0, badIdxScore = 0, badIdxId = 0, empty = 0;
for (const k of pkeys) {
  for (const e of prods[k]) {
    entries++;
    if (!Array.isArray(e) || e.length !== 5) { badRange++; continue; }
    if (!/^CVE-\d{4}-\d{4,}$/.test(e[0])) badIdxId++;
    if (!(e[1] >= 9 && e[1] <= 10)) badIdxScore++;
    if (!Array.isArray(e[4]) || e[4].length === 0) empty++;
    for (const r of e[4] || []) if (!Array.isArray(r) || r.length !== 5) badRange++;
  }
}
eq(badRange, 0, "every index entry is [id,score,published,kev,ranges] with 5-slot ranges");
eq(badIdxId, 0, "every index CVE id is well formed");
eq(badIdxScore, 0, "every index score respects the 9.0 floor");
eq(empty, 0, "no index entry ships an empty range list");
ok(entries >= 300, "index holds a meaningful number of product-CVE pairs", entries + " pairs");

// every detector key resolves against the shipped index, or is a documented zero
const detectorKeys = new Set();
for (const r of Core.RULES) for (const k of r.cpe) detectorKeys.add(k);
const resolved = [...detectorKeys].filter((k) => prods[k]);
ok(resolved.length >= 12, "detectors resolve against the shipped index", resolved.length + "/" + detectorKeys.size + " keys");

// end-to-end on the real data: an old, widely-deployed stack must be flagged
const e2e = Core.matchVulns([
  { name: "PHP", cat: "language", cpe: ["php:php"], version: "5.6.40", confidence: 96, evidence: "X-Powered-By" },
  { name: "WordPress", cat: "cms", cpe: ["wordpress:wordpress"], version: "4.9.0", confidence: 96, evidence: "generator meta" },
  { name: "Joomla", cat: "cms", cpe: ["joomla:joomla!"], version: "3.4.0", confidence: 95, evidence: "generator meta" },
], prods);
ok(e2e.summary.exposedModules >= 2, "real index flags an end-of-life stack", JSON.stringify(e2e.summary));
ok(e2e.summary.totalCves >= 3, "real index produces concrete CVE hits", e2e.summary.totalCves + " CVEs");
ok(e2e.modules.filter((m) => m.status === "exposed").every((m) => m.cves.every((c) => c.id && c.score >= 9)),
  "every reported real hit is a real critical CVE");

/* ================================ verdict ============================= */
console.log("\n" + "-".repeat(62));
if (fail) {
  console.log(`\x1b[31mRED\x1b[0m — ${pass} passed, ${fail} failed`);
  for (const f of failures) console.log("  \x1b[31m✗\x1b[0m " + f);
  process.exit(1);
}
console.log(`\x1b[32mGREEN\x1b[0m — ${pass} assertions passed`);
console.log(`  feed ${MON.cves.length} rows (${MON.meta.counts.kevTracked} KEV) · index ${pkeys.length} products / ${entries} pairs · ${Core.RULES.length} detectors`);
