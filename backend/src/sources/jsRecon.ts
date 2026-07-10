import { guardedFetch } from './guard'
import { mapLimit } from '../util/async'
import { BROWSER_UA } from '../util/http'

// Mine already-discovered .js URLs for API endpoints, hidden parameters, and
// leaked secrets (LinkFinder / SecretFinder territory) — one of the highest-yield
// modern techniques, and the URL corpus that feeds it already exists (wayback /
// commoncrawl / katana). SSRF-guarded fetch; secrets are labelled needs-review.

const MAX_FILES = 40
const MAX_BYTES = 2 * 1024 * 1024

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

export interface JsReconResult {
  filesScanned: number
  endpoints: string[]
  urls: string[] // absolute URLs found (unscoped; callers filter to the target)
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
}

// Show the secret in full so the operator can verify it (these are their own
// authorized findings, flagged needs-review); only trim pathologically long
// matches so a minified blob can't blow up the UI.
function truncSecret(s: string): string {
  return s.length > 200 ? `${s.slice(0, 160)}…${s.slice(-24)}` : s
}

export async function jsRecon(jsUrls: string[]): Promise<JsReconResult> {
  // Accept .js AND .mjs (modern ESM bundles), with or without a query string.
  const files = [...new Set(jsUrls.filter((u) => /^https?:\/\/[^\s"']+\.m?js(\?|$)/i.test(u)))].slice(0, MAX_FILES)
  const endpoints = new Set<string>()
  const abs = new Set<string>()
  const params = new Set<string>()
  const secrets: JsReconResult['secrets'] = []

  await mapLimit(
    files,
    6,
    async (url) => {
      const res = await guardedFetch(url, { timeoutMs: 9_000, maxBytes: MAX_BYTES, headers: { 'User-Agent': BROWSER_UA } })
      if (!res || res.status !== 200) return
      const body = res.body

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
        if (abs.size >= 500) break
        abs.add(m[0])
        for (const pm of m[0].matchAll(PARAM_IN_URL)) params.add(pm[1])
      }
      for (const { name, re } of SECRET_PATTERNS) {
        for (const sm of body.matchAll(re)) {
          if (secrets.length >= 50) break
          secrets.push({ pattern: name, sample: truncSecret(sm[0]), file: url })
        }
      }
    },
    undefined,
  )

  return {
    filesScanned: files.length,
    endpoints: [...endpoints].slice(0, 200),
    urls: [...abs].slice(0, 500),
    params: [...params].slice(0, 100),
    secrets,
  }
}
