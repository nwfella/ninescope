#!/usr/bin/env node
/**
 * cpe_freq.mjs — audit which CPE product keys the critical corpus actually uses.
 * Reads the NVD page cache (populated by build_data.mjs) and prints the
 * frequency table, filtered by substring, so the scanner's allowlist can be
 * built from real names instead of guessed ones.
 *
 *   node scripts/cpe_freq.mjs nginx jquery wordpress php
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CACHE = path.join(ROOT, ".cache");
const pats = process.argv.slice(2).map((s) => s.toLowerCase());

const freq = new Map();
let files = 0;
for (const f of fs.readdirSync(CACHE).filter((f) => f.startsWith("nvd-"))) {
  const json = JSON.parse(fs.readFileSync(path.join(CACHE, f), "utf8"));
  files++;
  for (const v of json.vulnerabilities || []) {
    const cve = v.cve;
    const seen = new Set();
    const walk = (nodes) => {
      for (const n of nodes || []) {
        for (const cm of n.cpeMatch || []) {
          if (!cm.vulnerable || !cm.criteria) continue;
          const f2 = cm.criteria.split(":");
          if (f2[2] !== "a") continue;
          const key = (f2[3] + ":" + f2[4]).replace(/\\/g, "").toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          freq.set(key, (freq.get(key) || 0) + 1);
        }
      }
      for (const n of nodes || []) if (n.children) walk(n.children);
    };
    for (const c of cve.configurations || []) walk(c.nodes);
  }
}
console.log(`scanned ${files} cached pages, ${freq.size} distinct application CPE products`);
const rows = [...freq.entries()].sort((a, b) => b[1] - a[1]);
const out = pats.length ? rows.filter(([k]) => pats.some((p) => k.includes(p))) : rows.slice(0, 80);
for (const [k, n] of out) console.log(`${String(n).padStart(5)}  ${k}`);
fs.writeFileSync(path.join(CACHE, "cpe-freq.json"), JSON.stringify(rows));
console.log(`full table: ${path.join(CACHE, "cpe-freq.json")}`);
