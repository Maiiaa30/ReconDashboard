import { guardedFetch } from './guard'
import { mapLimit } from '../util/async'
import { BROWSER_UA } from '../util/http'

// Mine already-discovered .js URLs for API endpoints, hidden parameters, and
// leaked secrets (LinkFinder / SecretFinder territory) — one of the highest-yield
// modern techniques, and the URL corpus that feeds it already exists (wayback /
// commoncrawl / katana). SSRF-guarded fetch; secrets are labelled needs-review.

const MAX_FILES = 40
const MAX_BYTES = 2 * 1024 * 1024
const MAX_MAP_BYTES = 8 * 1024 * 1024 // source maps embed the whole source — larger cap

// High-signal secret patterns. Kept conservative to limit false positives.
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g },
  { name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: 'Stripe live key', re: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
  { name: 'Google OAuth', re: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g },
  { name: 'Generic API key assignment', re: /["']?(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/gi },
]

// Endpoint-ish path/URL references inside JS.
const ENDPOINT_RE = /["'`](\/[A-Za-z0-9._~\-/]{1,120}(?:\?[A-Za-z0-9._~\-/=&%]{0,120})?)["'`]/g
// API-ish paths WITHOUT a leading slash (minified bundles often store "api/v1/x"
// relative to a base). Normalized to a leading slash by the caller.
const ENDPOINT_NOSLASH_RE =
  /["'`]((?:api|apis|rest|graphql|gql|v\d+|internal|services?|oauth|auth)\/[A-Za-z0-9._~\-/]{1,120}(?:\?[A-Za-z0-9._~\-/=&%]{0,120})?)["'`]/gi
const PARAM_IN_URL = /[?&]([a-zA-Z0-9_.-]{1,40})=/g
// Absolute http(s) URLs (so we catch API calls to https://api.target.com/... that
// the relative-path regex above can't see). Callers scope these to the target.
const ABS_URL_RE = /https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~\-/]{0,160}(?:\?[A-Za-z0-9._~\-/=&%]{0,160})?/g

// SPA framework signatures inside the bundle (a target built with React/Vue/etc.
// leaks its stack + config into the client). Non-global so `.test()` is safe.
const FRAMEWORK_SIGS: { name: string; re: RegExp }[] = [
  { name: 'Next.js', re: /__NEXT_DATA__|next\/dist\/|__next_f\b|_buildManifest/ },
  { name: 'React', re: /react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__|_jsxRuntime|\bjsxDEV\b|react\.production/ },
  { name: 'Vue', re: /__VUE__|__VUE_DEVTOOLS|vue-router|createApp\(/ },
  { name: 'Nuxt', re: /__NUXT__|nuxt\.config|\/_nuxt\// },
  { name: 'Angular', re: /@angular\/core|ngDevMode|ɵɵ|platformBrowserDynamic/ },
  { name: 'Svelte', re: /svelte\/internal|__svelte|SvelteComponent/ },
  { name: 'Preact', re: /\bpreact\b/ },
]
// Client-side route paths (React Router / similar: { path: "/x/:id" }).
const ROUTE_RE = /["'`]path["'`]?\s*:\s*["'`](\/[A-Za-z0-9._~:%*\-/]{0,120})["'`]/gi
// Build-time-inlined PUBLIC env vars — base URLs, keys, feature flags baked into
// the bundle by the framework. `NAME:"value"` / `NAME="value"` where inlined.
const ENV_ASSIGN_RE =
  /["']?((?:REACT_APP|NEXT_PUBLIC|VITE|VUE_APP|GATSBY|EXPO_PUBLIC)_[A-Z0-9_]{1,60})["']?\s*[:=]\s*["']([^"']{0,300})["']/g
const ENV_NAME_RE = /\b((?:REACT_APP|NEXT_PUBLIC|VITE|VUE_APP|GATSBY|EXPO_PUBLIC)_[A-Z0-9_]{1,60})\b/g

export interface JsReconResult {
  filesScanned: number
  mapsScanned: number // reachable .js.map source maps parsed (un-minified sources)
  endpoints: string[]
  urls: string[] // absolute URLs found (unscoped; callers filter to the target)
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
  frameworks: string[] // SPA frameworks detected in the bundles
  routes: string[] // client-side route paths
  env: { key: string; value: string | null }[] // baked-in public env vars
}

export interface JsSignals {
  endpoints: string[]
  urls: string[]
  params: string[]
  secrets: { pattern: string; sample: string }[]
  frameworks: string[]
  routes: string[]
  env: { key: string; value: string | null }[]
}

// Show the secret in full so the operator can verify it (these are their own
// authorized findings, flagged needs-review); only trim pathologically long
// matches so a minified blob can't blow up the UI.
function truncSecret(s: string): string {
  return s.length > 200 ? `${s.slice(0, 160)}…${s.slice(-24)}` : s
}

// Pull every signal out of ONE source body — a minified bundle OR an un-minified
// source-map source. Pure + per-body bounded, so it can be reused across both.
export function extractSignals(body: string): JsSignals {
  const endpoints = new Set<string>()
  const urls = new Set<string>()
  const params = new Set<string>()
  const secrets: { pattern: string; sample: string }[] = []
  const frameworks = new Set<string>()
  const routes = new Set<string>()
  const env = new Map<string, string | null>()

  for (const m of body.matchAll(ENDPOINT_RE)) {
    const p = m[1]
    if (p && !/\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|map)$/i.test(p)) endpoints.add(p)
    for (const pm of p.matchAll(PARAM_IN_URL)) params.add(pm[1])
  }
  for (const m of body.matchAll(ENDPOINT_NOSLASH_RE)) {
    endpoints.add('/' + m[1])
    for (const pm of m[1].matchAll(PARAM_IN_URL)) params.add(pm[1])
  }
  for (const m of body.matchAll(ABS_URL_RE)) {
    if (urls.size >= 500) break
    urls.add(m[0])
    for (const pm of m[0].matchAll(PARAM_IN_URL)) params.add(pm[1])
  }
  for (const { name, re } of SECRET_PATTERNS) {
    for (const sm of body.matchAll(re)) {
      if (secrets.length >= 100) break
      secrets.push({ pattern: name, sample: truncSecret(sm[0]) })
    }
  }
  for (const { name, re } of FRAMEWORK_SIGS) if (re.test(body)) frameworks.add(name)
  for (const m of body.matchAll(ROUTE_RE)) if (routes.size < 300) routes.add(m[1])
  for (const m of body.matchAll(ENV_ASSIGN_RE)) env.set(m[1], m[2] || null)
  for (const m of body.matchAll(ENV_NAME_RE)) if (!env.has(m[1])) env.set(m[1], null)

  return {
    endpoints: [...endpoints],
    urls: [...urls],
    params: [...params],
    secrets,
    frameworks: [...frameworks],
    routes: [...routes],
    env: [...env.entries()].map(([key, value]) => ({ key, value })),
  }
}

// Find the source-map reference at the tail of a bundle (//# or the older //@).
// Skips inline data: maps (already in-body). Resolves relative to the bundle URL;
// only http(s) targets are returned (the caller SSRF-guards the fetch).
export function sourceMapUrl(body: string, baseUrl: string): string | null {
  const m = body.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/)
  if (!m) return null
  const ref = m[1].trim()
  if (!ref || ref.startsWith('data:')) return null
  try {
    const u = new URL(ref, baseUrl)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null
  } catch {
    return null
  }
}

// Parse a source map's original sources (sourcesContent). Bounded; skips empty
// entries. Names come from `sources` for labelling.
export function parseSourceMapSources(mapText: string): { name: string; content: string }[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(mapText)
  } catch {
    return []
  }
  if (!parsed || typeof parsed !== 'object') return []
  const p = parsed as { sources?: unknown; sourcesContent?: unknown }
  const contents = Array.isArray(p.sourcesContent) ? p.sourcesContent : []
  const names = Array.isArray(p.sources) ? p.sources : []
  const out: { name: string; content: string }[] = []
  for (let i = 0; i < contents.length && out.length < 500; i++) {
    const c = contents[i]
    if (typeof c === 'string' && c) {
      out.push({ name: typeof names[i] === 'string' ? String(names[i]) : `source[${i}]`, content: c })
    }
  }
  return out
}

export async function jsRecon(jsUrls: string[]): Promise<JsReconResult> {
  // Accept .js AND .mjs (modern ESM bundles), with or without a query string.
  const files = [...new Set(jsUrls.filter((u) => /^https?:\/\/[^\s"']+\.m?js(\?|$)/i.test(u)))].slice(0, MAX_FILES)
  const endpoints = new Set<string>()
  const abs = new Set<string>()
  const params = new Set<string>()
  const secrets: JsReconResult['secrets'] = []
  const frameworks = new Set<string>()
  const routes = new Set<string>()
  const env = new Map<string, string | null>()
  let mapsScanned = 0

  // Fold one body's extracted signals into the shared accumulators (globally
  // capped), tagging secrets with where they came from.
  const merge = (sig: JsSignals, fileLabel: string) => {
    for (const e of sig.endpoints) endpoints.add(e)
    for (const u of sig.urls) if (abs.size < 500) abs.add(u)
    for (const p of sig.params) params.add(p)
    for (const s of sig.secrets) if (secrets.length < 50) secrets.push({ ...s, file: fileLabel })
    for (const f of sig.frameworks) frameworks.add(f)
    for (const r of sig.routes) if (routes.size < 300) routes.add(r)
    for (const { key, value } of sig.env) if (!env.has(key) || (value && !env.get(key))) env.set(key, value)
  }

  await mapLimit(
    files,
    6,
    async (url) => {
      const res = await guardedFetch(url, { timeoutMs: 9_000, maxBytes: MAX_BYTES, headers: { 'User-Agent': BROWSER_UA } })
      if (!res || res.status !== 200) return
      merge(extractSignals(res.body), url)

      // A reachable source map reverses the minified bundle back to its original
      // TypeScript/JS sources — route tables, API clients, comments, far more
      // secrets than survive minification. SSRF-guarded fetch, byte-capped.
      const mapUrl = sourceMapUrl(res.body, url)
      if (mapUrl) {
        const mres = await guardedFetch(mapUrl, { timeoutMs: 12_000, maxBytes: MAX_MAP_BYTES, headers: { 'User-Agent': BROWSER_UA } })
        if (mres && mres.status === 200) {
          const sources = parseSourceMapSources(mres.body)
          if (sources.length) {
            mapsScanned++
            for (const s of sources) merge(extractSignals(s.content), `${url}.map:${s.name}`)
          }
        }
      }
    },
    undefined,
  )

  return {
    filesScanned: files.length,
    mapsScanned,
    endpoints: [...endpoints].slice(0, 300),
    urls: [...abs].slice(0, 500),
    params: [...params].slice(0, 100),
    secrets,
    frameworks: [...frameworks],
    routes: [...routes].slice(0, 300),
    env: [...env.entries()].map(([key, value]) => ({ key, value })).slice(0, 100),
  }
}
