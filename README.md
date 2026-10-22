# NINESCOPE

A monitor for the tail of the CVSS distribution that actually gets exploited — every
vulnerability scored **9.0 or above** — plus a non-intrusive scanner that works out what
software a live site is running and matches those versions against NVD's published ranges.

Two views, one dataset:

- **Critical feed** — 2,900+ criticals in a rolling 24-month window (plus every CISA
  KEV entry, however old), filterable by score, date, exploit status and free text.
- **Scan a site** — one passive `GET`, then header/cookie/meta/asset fingerprinting →
  version-range matching → "Immediate attention" with the safe upgrade target.

## Quickstart

```bash
npm start                 # http://127.0.0.1:8119 — app + scan collector
node scripts/build_data.mjs   # re-bake the dataset from NVD + CISA KEV (needs network)
npm run verify            # tier 1: 118 assertions, no browser needed
npm run verify:browser    # tier 2: 70 assertions in headless Chrome + screenshots
npm run probe https://wordpress.org   # see the engine's reasoning on a real site
```

Node 20+. Zero runtime dependencies — no build step, no framework, no npm install.

## How the two halves fit

```
NVD API 2.0 ──┐
              ├─ scripts/build_data.mjs ──> docs/data/{monitor,index,meta}.json
CISA KEV ─────┘                                   │
                                                  ▼
browser ──GET /api/scan?url=──> collector ──> raw response ──> app: detect() ──> matchVulns()
```

The collector is deliberately dumb: one `GET`, follow redirects, cap the body, return the
raw response. **All analysis happens in the page**, in a DOM-free `Core` block that the
Node gate loads and tests directly — the same code path the browser runs.

That split is why the scan needs a server at all: a browser cannot read another origin's
response headers. On GitHub Pages the collector is the included Cloudflare Worker:

```bash
npx wrangler deploy worker/scan-proxy.js --name ninescope-collector --compatibility-date=2025-01-01
```

then paste the worker URL into the scan tab (remembered in `localStorage`). Without it the
feed works fully static and the scan shows an honest "collector not reachable" notice.

## What the scan does and does not do

**Does:** one GET of the URL you give it, following redirects, with a normal UA; reads
headers, cookie names, `<meta name="generator">`, script/stylesheet paths, framework
markers, final hostname.

**Does not:** send payloads, brute-force paths, guess credentials, enumerate ports, or
modify anything. Every detected module shows the exact string it was inferred from and a
confidence; nothing under 35% is displayed.

A scan cannot tell you a site is *safe* — only that no version it could fingerprint falls
inside a known critical range. Modules without a visible version are reported as
`unversioned`, which is not the same as clean.

## Matching semantics

NVD's `configurations[].cpeMatch[]` entries carry either an exact version or bounds
(`versionStartIncluding`, `versionEndExcluding`, …). The index keeps those as **5
positional slots** — compacting the array silently shifts every bound, which is the
single nastiest bug this codebase has had.

`versionEndExcluding` is surfaced as the fixed version, and the module's *recommended*
target is the **highest** boundary across all matched CVEs. Listing `2.4.49 / 2.4.52 /
2.4.53` as alternatives invites someone to patch to the lowest and stay exploitable, so the
UI shows one unambiguous `upgrade to ≥ X`.

## Data provenance

| Source | Endpoint | Notes |
|---|---|---|
| NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | CVSS v3 CRITICAL, 8-year horizon, 120-day windows × 500 records (NVD truncates a response at ~90 s) |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | merged by CVE id; drives the "exploited" chips |

Every page shows `builtAt`, the window, the score floor and per-source details in the
Methodology tab. The collector **aborts rather than writing a partial bake**, and there is
no synthetic fallback anywhere — a failed source exits non-zero with nothing written.

Cache: `.cache/` holds every fetched NVD page, so re-runs are instant and a timeout costs
nothing. Delete it to force a cold rebuild.

## Verified, not asserted

- `scripts/verify_app.js` — 118 assertions: CORE block is DOM-free and loads in Node;
  version comparator boundary cases; range inclusivity/exclusivity at every edge;
  exact-version and unbounded ranges; ranking; feed filtering; dataset integrity (schema,
  score floor, no duplicate ids, KEV coverage, window correctness); an end-of-life stack
  flagged against the *real* index.
- `scripts/browser_check.js` — 70 assertions in headless Chrome: renders 40 rows, filters
  agree with their badges, row expansion, then scans a loopback fixture origin running
  Apache 2.4.29 / PHP 7.2.34 / WordPress 5.0.1 and asserts **3 exposed modules, 29 critical
  CVEs, 2 KEV hits, a recommended fix above every boundary**; a patched fixture reports
  `clear` vs `untracked` correctly; SSRF guard refuses metadata, `file://`, private ranges
  and loopback-by-name in default mode; no overflow at 320/390/1024/1500 px; zero console
  errors. Screenshots land in `artifacts/`.
- `scripts/live_check.js` — 9 assertions against the **deployed** URL: the served page boots,
  the dataset arrives over the network, 40 rows render, the sparkline paints, zero console
  errors. `npm run verify:live`.

## Known limits

- CVSS 9.0+ is a severity floor, not a probability of exploitation — check the KEV chip.
- Server-side WordPress plugins/themes rarely expose versions, so the most-attacked surface
  is the least visible to this scanner.
- A CDN/WAF in front means you may fingerprint the CDN, not the origin.
- Only products in the scanner's index (62 today) can be matched; a product with no 9.0+
  CVE on record shows as `untracked`, not `clear`.
- CVEs scored *only* under CVSS v4.0 and never under v3.x are outside the v3 filter.

MIT.
