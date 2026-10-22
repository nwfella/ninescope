/**
 * scan-proxy.js — Cloudflare Worker: the collector for a static deployment.
 *
 * A browser cannot read another origin's response headers, so the GitHub Pages
 * build needs this hop. Same contract as server.js's /api/scan:
 *
 *   GET /api/scan?url=https://example.com  ->  { status, headers, html, finalUrl, ms, htmlBytes }
 *
 * It sends one GET, follows redirects, caps the body, and refuses internal
 * targets. No cookies are stored, nothing is posted to the target.
 *
 * Deploy:
 *   npm i -g wrangler
 *   wrangler deploy worker/scan-proxy.js --name ninescope-collector --compatibility-date=2025-01-01
 * then paste the worker URL into the app's scan tab (it is remembered in localStorage).
 *
 * Set ALLOW_ORIGIN to your Pages origin to stop other sites using your worker:
 *   wrangler deploy ... --var ALLOW_ORIGIN:https://nwfella.github.io
 */
const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;

const PRIVATE_HOST = new RegExp(
  "^(localhost|.*\\.localhost|.*\\.local|.*\\.internal" +
  "|0\\..*|10\\..*|127\\..*|169\\.254\\..*" +
  "|172\\.(1[6-9]|2\\d|3[01])\\..*|192\\.168\\..*" +
  "|100\\.(6[4-9]|[7-9]\\d|1[0-1]\\d|12[0-7])\\..*" +
  "|192\\.0\\.0\\..*|198\\.1[89]\\..*|22[4-9]\\..*|2[3-5]\\d\\..*)$", "i");

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Accept,Content-Type",
    "Cache-Control": "no-store",
  };
}

function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) },
  });
}

export default {
  async fetch(request, env) {
    const origin = env.ALLOW_ORIGIN || "*";
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
    if (url.pathname === "/api/health") return json({ ok: true, service: "ninescope-collector", edge: true }, 200, origin);
    if (url.pathname !== "/api/scan") return json({ error: "not found — use /api/scan?url=" }, 404, origin);

    const target = url.searchParams.get("url") || "";
    let u;
    try { u = new URL(target); } catch { return json({ error: "invalid URL" }, 400, origin); }
    if (!/^https?:$/.test(u.protocol)) return json({ error: "only http and https targets are allowed" }, 400, origin);
    if (PRIVATE_HOST.test(u.hostname)) return json({ error: "target address is refused (private)" }, 400, origin);
    if (u.port && !/^(80|443|8080|8443)$/.test(u.port)) return json({ error: "only standard web ports are allowed" }, 400, origin);

    const started = Date.now();
    try {
      const res = await fetch(u.toString(), {
        redirect: "follow",
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; NINESCOPE/1.0; +https://github.com/nwfella/ninescope) passive-stack-check",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
        },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });

      // read at most MAX_BYTES, never buffer an unbounded stream
      const reader = res.body ? res.body.getReader() : null;
      const chunks = [];
      let size = 0, truncated = false;
      if (reader) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_BYTES) { truncated = true; try { await reader.cancel(); } catch (e) {} break; }
          chunks.push(value);
        }
      }
      const buf = new Uint8Array(size > MAX_BYTES ? MAX_BYTES : size);
      let off = 0;
      for (const c of chunks) { if (off >= buf.length) break; const take = Math.min(c.byteLength, buf.length - off); buf.set(c.subarray(0, take), off); off += take; }

      const ctype = res.headers.get("content-type") || "";
      const isText = /text|html|xml|json|javascript/i.test(ctype) || !ctype;
      const headers = {};
      for (const [k, v] of res.headers) headers[k] = v;

      return json({
        status: res.status,
        finalUrl: res.url || u.toString(),
        headers,
        html: isText ? new TextDecoder("utf-8").decode(buf) : "",
        htmlBytes: size,
        truncated,
        contentType: ctype,
        ms: Date.now() - started,
      }, 200, origin);
    } catch (e) {
      const msg = String((e && e.message) || e);
      return json({ error: msg, detail: "the collector sends one passive GET and reads the response — nothing else" }, 502, origin);
    }
  },
};
