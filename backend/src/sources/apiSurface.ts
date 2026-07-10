import { assertPublicHost, guardedFetch } from './guard'
import { jsRecon } from './jsRecon'
import { mapLimit } from '../util/async'
import { BROWSER_UA } from '../util/http'

// Passive API-surface discovery for a host: locate published OpenAPI/Swagger
// specs (JSON directly OR referenced from a Swagger-UI/ReDoc page), GraphQL
// endpoints (+ whether introspection is enabled), and — the part that works on
// the modern SPA majority that publishes NO spec — API endpoints/params/secrets
// mined from the site's own JavaScript bundles. All SSRF-guarded and bounded.

const TIMEOUT_MS = 8_000
const MAX_SPEC_BYTES = 4 * 1024 * 1024
const MAX_ENDPOINTS = 300
const PROBE_CONCURRENCY = 8 // parallel path probes per host, so one slow path can't stall the sweep

// High-signal, framework-common JSON spec locations.
const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/swagger/v1/swagger.json',
  '/v3/api-docs',
  '/v2/api-docs',
  '/api-docs',
  '/api/openapi.json',
  '/api/swagger.json',
  '/api/v1/openapi.json',
  '/openapi/v1.json',
  '/.well-known/openapi.json',
  '/docs/openapi.json',
]
// Swagger-UI / ReDoc HTML pages. If present, the referenced spec URL is pulled
// out of the HTML and fetched — this catches specs served at non-standard paths.
const DOC_HTML_PATHS = ['/swagger', '/swagger-ui', '/swagger-ui.html', '/docs', '/api/docs', '/redoc', '/api-docs']
const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/graphql/v1']

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] as const

// Endpoints that look like actual API calls: strong path markers, a version
// segment followed by a resource (/v1/users), or a framework data route.
const API_ENDPOINT_RE =
  /(^|\/)(api|rest|graphql|gql|internal|services?|ajax|rpc|oauth|auth|token|admin|webhook|callback|wp-json|_next\/data|umbraco|graphile)(\/|$|\?)|\/v\d+\/[a-z]/i
// Asset extensions to exclude even when the path otherwise matches.
const ASSET_RE = /\.(js|mjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|pdf|txt|xml)(\?|$)/i

function isApiEndpoint(e: string): boolean {
  if (typeof e !== 'string' || !e.startsWith('/') || e.startsWith('//')) return false // same-origin paths only
  if (ASSET_RE.test(e)) return false
  if (API_ENDPOINT_RE.test(e)) return true
  // A query string usually means a dynamic/data call — but skip pure marketing /
  // tracking links (utm_, gclid, campaign, …) which aren't API endpoints.
  if (e.includes('?') && !/[?&](utm_\w+|gclid|fbclid|mc_\w+|ref|source|campaign|medium|content)=/i.test(e)) return true
  return false
}

export interface ApiSpec {
  specUrl: string
  format: 'openapi' | 'swagger'
  version: string | null // spec version (3.0.1 / 2.0)
  title: string | null
  apiVersion: string | null // info.version
  servers: string[]
  authSchemes: string[]
  operationCount: number
  endpoints: { method: string; path: string }[]
}

export interface GraphqlInfo {
  endpoint: string
  introspectionEnabled: boolean
  queryType: string | null
  typeCount: number
}

export interface JsFindings {
  filesScanned: number
  endpoints: string[] // API-ish paths pulled from JS
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
}

export interface ApiSurfaceResult {
  host: string
  specs: ApiSpec[]
  graphql: GraphqlInfo[]
  js: JsFindings
}

export function parseSpec(url: string, body: string): ApiSpec | null {
  let doc: any
  try {
    doc = JSON.parse(body)
  } catch {
    return null // not JSON (YAML specs are skipped for now)
  }
  const isOpenapi = typeof doc?.openapi === 'string'
  const isSwagger = typeof doc?.swagger === 'string'
  if (!isOpenapi && !isSwagger) return null

  const paths = doc.paths && typeof doc.paths === 'object' ? doc.paths : {}
  const endpoints: { method: string; path: string }[] = []
  for (const [p, ops] of Object.entries(paths)) {
    if (!ops || typeof ops !== 'object') continue
    for (const m of HTTP_METHODS) {
      if ((ops as Record<string, unknown>)[m]) endpoints.push({ method: m.toUpperCase(), path: p })
    }
  }

  const servers: string[] = Array.isArray(doc.servers)
    ? doc.servers.map((s: any) => s?.url).filter((u: unknown): u is string => typeof u === 'string')
    : typeof doc.host === 'string'
      ? [`${doc.schemes?.[0] ?? 'https'}://${doc.host}${doc.basePath ?? ''}`]
      : []

  // OpenAPI 3: components.securitySchemes; Swagger 2: securityDefinitions.
  const schemesObj = doc.components?.securitySchemes ?? doc.securityDefinitions ?? {}
  const authSchemes =
    schemesObj && typeof schemesObj === 'object'
      ? Object.entries(schemesObj).map(([name, v]: [string, any]) => (v?.type ? `${name}:${v.type}` : name))
      : []

  return {
    specUrl: url,
    format: isOpenapi ? 'openapi' : 'swagger',
    version: (isOpenapi ? doc.openapi : doc.swagger) ?? null,
    title: doc.info?.title ?? null,
    apiVersion: doc.info?.version ?? null,
    servers,
    authSchemes,
    operationCount: endpoints.length,
    endpoints: endpoints.slice(0, MAX_ENDPOINTS),
  }
}

const INTROSPECTION_QUERY = JSON.stringify({
  query: '{__schema{queryType{name} types{name}}}',
})

// Fetch a host's homepage and pull out its JS bundle URLs — the live corpus
// jsRecon mines for API endpoints. Matches BOTH <script src> AND
// <link rel="modulepreload"/"preload" href> (modern bundlers — Next/Vite — load
// their main chunks via modulepreload, which the app's API calls live in). Uses
// a browser UA so CDN/bot gates don't hide the real page. https first, then http.
async function homepageJsUrls(host: string): Promise<string[]> {
  const urls = new Set<string>()
  for (const scheme of ['https', 'http'] as const) {
    const base = `${scheme}://${host}/`
    const res = await guardedFetch(base, {
      timeoutMs: TIMEOUT_MS,
      maxBytes: MAX_SPEC_BYTES,
      headers: { 'User-Agent': BROWSER_UA },
    })
    if (!res || res.status >= 400) continue
    // Any src= or href= attribute pointing at a .js/.mjs file.
    for (const m of res.body.matchAll(/(?:src|href)=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi)) {
      try {
        urls.add(new URL(m[1], res.finalUrl || base).toString())
      } catch {
        /* skip unparseable url */
      }
    }
    if (urls.size) break
  }
  return [...urls]
}

// Pull spec URLs referenced inside a Swagger-UI / ReDoc HTML page.
function extractSpecRefsFromHtml(html: string, baseUrl: string): string[] {
  const refs = new Set<string>()
  const patterns = [
    /\burl\s*:\s*["']([^"']+?\.(?:json|ya?ml)(?:\?[^"']*)?)["']/gi, // SwaggerUIBundle({ url: '...' })
    /\bconfigUrl\s*:\s*["']([^"']+)["']/gi,
    /spec-url=["']([^"']+)["']/gi, // <redoc spec-url="...">
    /["']([^"']*\/(?:openapi|swagger)[^"']*\.(?:json|ya?ml))["']/gi,
  ]
  for (const re of patterns) {
    for (const m of html.matchAll(re)) {
      try {
        refs.add(new URL(m[1], baseUrl).toString())
      } catch {
        /* skip */
      }
    }
  }
  return [...refs]
}

// OpenAPI/Swagger: parallel JSON path probes (https then http), then a
// Swagger-UI/ReDoc HTML fallback that fetches the spec URL those pages reference.
async function sweepSpecs(host: string): Promise<ApiSpec[]> {
  const specs: ApiSpec[] = []
  const seen = new Set<string>()
  const add = (s: ApiSpec | null) => {
    if (s && !seen.has(s.specUrl)) {
      seen.add(s.specUrl)
      specs.push(s)
    }
  }
  for (const scheme of ['https', 'http'] as const) {
    const results = await mapLimit(
      SPEC_PATHS,
      PROBE_CONCURRENCY,
      async (path) => {
        const url = `${scheme}://${host}${path}`
        const res = await guardedFetch(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_SPEC_BYTES })
        return res && res.status === 200 ? parseSpec(res.finalUrl || url, res.body) : null
      },
      null,
    )
    results.forEach(add)
    if (specs.length) break
  }
  if (specs.length) return specs

  for (const scheme of ['https', 'http'] as const) {
    const refLists = await mapLimit(
      DOC_HTML_PATHS,
      PROBE_CONCURRENCY,
      async (path) => {
        const base = `${scheme}://${host}${path}`
        const res = await guardedFetch(base, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_SPEC_BYTES })
        if (!res || res.status !== 200 || !/swagger|redoc|openapi/i.test(res.body)) return []
        return extractSpecRefsFromHtml(res.body, res.finalUrl || base)
      },
      [],
    )
    const refs = [...new Set(refLists.flat())]
    const fetched = await mapLimit(
      refs,
      PROBE_CONCURRENCY,
      async (ref) => {
        const sr = await guardedFetch(ref, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_SPEC_BYTES })
        return sr && sr.status === 200 ? parseSpec(sr.finalUrl || ref, sr.body) : null
      },
      null,
    )
    fetched.forEach(add)
    if (specs.length) break
  }
  return specs
}

// GraphQL: parallel introspection probes; report a SINGLE endpoint per host,
// preferring one where introspection is enabled.
async function sweepGraphql(host: string): Promise<GraphqlInfo[]> {
  for (const scheme of ['https', 'http'] as const) {
    const probed = await mapLimit(
      GRAPHQL_PATHS,
      PROBE_CONCURRENCY,
      async (path): Promise<GraphqlInfo | null> => {
        const url = `${scheme}://${host}${path}`
        const res = await guardedFetch(url, {
          method: 'POST',
          timeoutMs: TIMEOUT_MS,
          headers: { 'Content-Type': 'application/json' },
          body: INTROSPECTION_QUERY,
          maxBytes: MAX_SPEC_BYTES,
        })
        if (!res) return null
        let doc: any = null
        try {
          doc = JSON.parse(res.body)
        } catch {
          return null
        }
        const schema = doc?.data?.__schema
        const gqlError =
          Array.isArray(doc?.errors) &&
          /cannot query field|must provide (a )?query|graphql|syntax error|unknown operation|introspection/i.test(res.body)
        if (!schema && !gqlError) return null
        return {
          endpoint: url,
          introspectionEnabled: !!schema,
          queryType: schema?.queryType?.name ?? null,
          typeCount: Array.isArray(schema?.types) ? schema.types.length : 0,
        }
      },
      null,
    )
    const matches = probed.filter((m): m is GraphqlInfo => m !== null)
    if (matches.length) {
      const best = matches.find((m) => m.introspectionEnabled) ?? matches[0]
      return best ? [best] : []
    }
  }
  return []
}

// Registrable-domain heuristic (last two labels) for scoping absolute URLs.
function baseDomain(host: string): string {
  const parts = host.toLowerCase().split('.')
  return parts.length <= 2 ? host.toLowerCase() : parts.slice(-2).join('.')
}
const API_HOST_RE = /(^|\.)(api|apis|graphql|gql|gateway|gw|rest|backend|bff|services?|svc|auth|sso|data|admin)\b/i

// JS bundle mining (the modern-SPA workhorse): pull the site's own JS (homepage
// bundles + any already-known .js URLs from prior recon) and extract API
// endpoints (relative paths AND in-scope absolute URLs like api.target.com/…),
// params and leaked secrets — surfaces an API even when no spec is published.
async function mineJs(host: string, extraJsUrls: string[]): Promise<JsFindings> {
  const jsUrls = [...new Set([...(await homepageJsUrls(host)), ...extraJsUrls])]
  if (!jsUrls.length) return { filesScanned: 0, endpoints: [], params: [], secrets: [] }
  const raw = await jsRecon(jsUrls)

  const relative = raw.endpoints.filter(isApiEndpoint)

  // Absolute URLs on the target's own domain/subdomains that look like API calls.
  const base = baseDomain(host)
  const absolute: string[] = []
  for (const u of raw.urls) {
    try {
      const url = new URL(u)
      const h = url.hostname.toLowerCase()
      const inScope = h === host.toLowerCase() || h === base || h.endsWith('.' + base)
      if (!inScope) continue
      const looksApi = API_HOST_RE.test(h) || API_ENDPOINT_RE.test(url.pathname) || !!url.search
      if (!looksApi) continue
      // Cross-host → keep the host prefix; same-host → bare path (dedups vs relative).
      absolute.push(h === host.toLowerCase() ? url.pathname + url.search : `${h}${url.pathname}${url.search}`)
    } catch {
      /* skip */
    }
  }

  const endpoints = [...new Set([...relative, ...absolute])].slice(0, MAX_ENDPOINTS)
  return { filesScanned: raw.filesScanned, endpoints, params: raw.params, secrets: raw.secrets }
}

export async function discoverApiSurface(host: string, extraJsUrls: string[] = []): Promise<ApiSurfaceResult> {
  // SSRF: refuse a host that resolves internal before probing it.
  await assertPublicHost(host)
  // The three probes are independent — run them concurrently so total time is
  // the slowest phase, not their sum.
  const [specs, graphql, js] = await Promise.all([sweepSpecs(host), sweepGraphql(host), mineJs(host, extraJsUrls)])
  return { host, specs, graphql, js }
}
