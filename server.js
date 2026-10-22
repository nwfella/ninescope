#!/usr/bin/env node
/**
 * server.js — zero-dependency static host + non-intrusive scan collector.
 *
 *   GET /                 the app (public/index.html)
 *   GET /data/*.json      baked dataset
 *   GET /api/scan?url=    one passive GET of a target origin; returns
 *                         {status, headers, html, finalUrl, ms, htmlBytes}
 *
 * The collector does exactly what a browser does when it loads the page —
 * a single GET with redirects — and returns the *raw* response to the client,
 * which does all the fingerprinting. Nothing is posted, nothing is probed,
 * no credentials or cookies are stored.
 *
 * SSRF hardening: http/https only, DNS-resolved to a public address,
 * private/loopback/link-local/metadata ranges refused, 5 redirects max,
 * 2 MB body cap, 12 s timeout, per-IP token bucket.
 */
import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(ROOT, "public");
const PORT = Number(process.env.PORT || 8119);
const UA = "Mozilla/5.0 (compatible; NINESCOPE/1.0; +https://github.com/nwfella/ninescope) passive-stack-check";
const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;

const MIME = {
  ".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png",
  ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
};

/* ------------------------------- SSRF guard ------------------------------- */
const BLOCKED = [
  [/^0\./, "this-network"], [/^10\./, "private"], [/^127\./, "loopback"],
  [/^169\.254\./, "link-local/metadata"], [/^172\.(1[6-9]|2\d|3[01])\./, "private"],
  [/^192\.168\./, "private"], [/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, "cgnat"],
  [/^192\.0\.0\./, "ietf"], [/^198\.1[89]\./, "benchmark"], [/^22[4-9]\./, "multicast"],
  [/^2[3-5]\d\./, "reserved"],
];

function ipBlocked(ip) {
  if (net.isIPv4(ip)) {
    for (const [re, why] of BLOCKED) if (re.test(ip)) return why;
    return "";
  }
  const v = ip.toLowerCase();
  if (v === "::1" || v === "::" || v.startsWith("fe80") || v.startsWith("fc") || v.startsWith("fd")) return "private-ipv6";
  if (v.startsWith("::ffff:")) return ipBlocked(v.slice(7));
  return "";
}

async function assertSafeUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error("invalid URL"); }
  if (!/^https?:$/.test(u.protocol)) throw new Error("only http and https targets are allowed");
  if (!u.hostname) throw new Error("missing hostname");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  // test-only escape hatch: the browser gate scans a loopback fixture origin.
  // Never set NINESCOPE_ALLOW_LOOPBACK in a deployment — link-local/metadata,
  // private ranges and every non-loopback reservation stay refused regardless.
  const loopbackOk = process.env.NINESCOPE_ALLOW_LOOPBACK === "1" && (host === "127.0.0.1" || host === "::1" || host === "localhost");
  if (!loopbackOk && /^(localhost|.*\.localhost|.*\.local|.*\.internal)$/i.test(host)) throw new Error("target resolves to a private name");
  if (net.isIP(host)) {
    const why = ipBlocked(host);
    if (why && !(loopbackOk && why === "loopback")) throw new Error(`target address is refused (${why})`);
    return u;
  }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true, verbatim: true }); }
  catch { throw new Error("DNS lookup failed for " + host); }
  if (!addrs.length) throw new Error("DNS returned no addresses for " + host);
  for (const a of addrs) {
    const why = ipBlocked(a.address);
    if (why && !(loopbackOk && (why === "loopback" || why === "private-ipv6"))) throw new Error(`target resolves to a refused address (${why})`);
  }
  return u;
}

/* -------------------------------- rate limit ------------------------------- */
const buckets = new Map();
function allow(ip) {
  const now = Date.now();
  const b = buckets.get(ip) || { t: now, n: 0 };
  if (now - b.t > 60_000) { b.t = now; b.n = 0; }
  b.n++;
  buckets.set(ip, b);
  if (buckets.size > 5000) buckets.clear();
  return b.n <= 20; // 20 scans / minute / IP
}

/* --------------------------------- fetching ------------------------------- */
function fetchOnce(u, hops) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === "https:" ? https : http;
    const started = Date.now();
    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || undefined,
      path: u.pathname + u.search, method: "GET",
      headers: {
        "User-Agent": UA,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        Connection: "close",
      },
      timeout: TIMEOUT_MS,
    }, (res) => {
      const status = res.statusCode || 0;
      const loc = res.headers.location;
      if (status >= 300 && status < 400 && loc) {
        res.resume();
        if (hops >= MAX_REDIRECTS) return reject(new Error("too many redirects"));
        let next;
        try { next = new URL(loc, u); } catch { return reject(new Error("bad redirect target")); }
        assertSafeUrl(next.toString())
          .then((safe) => fetchOnce(safe, hops + 1))
          .then(resolve, reject);
        return;
      }
      const chunks = [];
      let size = 0, aborted = false;
      res.on("data", (c) => {
        size += c.length;
        if (size > MAX_BYTES) { aborted = true; req.destroy(); return; }
        chunks.push(c);
      });
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        const ctype = String(res.headers["content-type"] || "");
        const isText = /text|html|xml|json|javascript/i.test(ctype) || !ctype;
        resolve({
          status,
          finalUrl: u.toString(),
          headers: res.headers,
          html: isText ? buf.toString("utf8").slice(0, MAX_BYTES) : "",
          htmlBytes: buf.length,
          truncated: aborted || size > MAX_BYTES,
          ms: Date.now() - started,
          contentType: ctype,
        });
      });
      res.on("error", reject);
    });
    req.on("timeout", () => { req.destroy(new Error("target timed out after " + TIMEOUT_MS / 1000 + "s")); });
    req.on("error", (e) => reject(e));
    req.end();
  });
}

/* ---------------------------------- server -------------------------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://localhost:${PORT}`);
  const send = (code, body, type) => {
    res.writeHead(code, {
      "Content-Type": type || "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };

  if (url.pathname === "/api/scan") {
    const target = url.searchParams.get("url") || "";
    const ip = (req.socket.remoteAddress || "?").replace(/^::ffff:/, "");
    if (!allow(ip)) return send(429, { error: "rate limited — 20 scans per minute" });
    if (!target) return send(400, { error: "missing ?url=" });
    try {
      const safe = await assertSafeUrl(target);
      const out = await fetchOnce(safe, 0);
      console.log(`scan ${out.status} ${out.ms}ms ${out.finalUrl}`);
      return send(200, out);
    } catch (e) {
      const msg = String(e && e.message || e);
      console.log(`scan FAILED ${target} — ${msg}`);
      const code = /refused|private|invalid|only http|DNS/.test(msg) ? 400 : 502;
      return send(code, { error: msg, detail: "the collector sends one passive GET and reads the response — nothing else" });
    }
  }

  if (url.pathname === "/api/health") return send(200, { ok: true, service: "ninescope-collector", ua: UA });

  // static
  let rel = decodeURIComponent(url.pathname);
  if (rel === "/" || rel === "") rel = "/index.html";
  const file = path.join(PUB, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(PUB)) return send(403, { error: "forbidden" });
  fs.readFile(file, (err, data) => {
    if (err) {
      // SPA-ish fallback so #tab links and unknown paths still land on the app
      return fs.readFile(path.join(PUB, "index.html"), (e2, html) => {
        if (e2) return send(404, { error: "not found" });
        send(200, html, MIME[".html"]);
      });
    }
    send(200, data, MIME[path.extname(file)] || "application/octet-stream");
  });
});

server.listen(PORT, () => {
  console.log(`NINESCOPE on http://127.0.0.1:${PORT}  (collector at /api/scan?url=)`);
});
