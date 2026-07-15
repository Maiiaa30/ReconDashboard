import { assertPublicHost, guardedFetch } from './guard'
import { jsRecon, type JsReconResult } from './jsRecon'
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

// A single parameter (query/path/header/cookie) an operation accepts.
export interface SpecParam {
  name: string
  in: string // query | path | header | cookie | body
  required: boolean
}
// One field of a JSON request body (name + declared type + required flag).
export interface SpecBodyField {
  name: string
  type: string
  required: boolean
}
// A single operation with enough detail to actually call it.
export interface SpecEndpoint {
  method: string
  path: string
  summary?: string | null
  params?: SpecParam[]
  body?: { contentType: string; fields: SpecBodyField[] } | null
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
  endpoints: SpecEndpoint[]
}

// A callable GraphQL root field (query/mutation) + the arguments it takes — the
// "how to call it" detail that a bare "introspection enabled" flag hides.
export interface GqlOperation {
  kind: 'query' | 'mutation'
  name: string
  args: { name: string; type: string }[]
}

export interface GraphqlInfo {
  endpoint: string
  introspectionEnabled: boolean
  queryType: string | null
  typeCount: number
  operations?: GqlOperation[]
}

export interface JsFindings {
  filesScanned: number
  endpoints: string[] // API-ish paths pulled from JS
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
  fromCorpus?: number // how many endpoints came from the passive URL corpus (not JS)
  hosts?: string[] // in-scope sibling hostnames the bundle references (→ subdomain inventory)
  // Frontend/SPA recon: the stack + config a React/Vue/… app exposes client-side.
  frameworks?: string[]
  routes?: string[]
  env?: { key: string; value: string | null }[]
}

// Detect the frontend framework from the homepage HTML (strong markers only).
function detectFrameworkFromHtml(html: string): string[] {
  const out: string[] = []
  if (/<script[^>]+id=["']__NEXT_DATA__["']/i.test(html) || /\/_next\//.test(html)) out.push('Next.js')
  if (/window\.__NUXT__|\/_nuxt\/|id=["']__nuxt["']/i.test(html)) out.push('Nuxt')
  const ng = html.match(/ng-version=["']([^"']+)["']/i)
  if (ng) out.push(`Angular ${ng[1]}`)
  else if (/<app-root/i.test(html)) out.push('Angular')
  if (/__sveltekit|\/_app\/immutable\//i.test(html)) out.push('SvelteKit')
  if (/id=["']___gatsby["']|\/page-data\//i.test(html)) out.push('Gatsby')
  if (/window\.__remixContext|__remixManifest/i.test(html)) out.push('Remix')
  if (/data-reactroot|id=["']root["']/i.test(html) && !out.includes('Next.js')) out.push('React')
  return out
}

export interface ApiSurfaceResult {
  host: string
  specs: ApiSpec[]
  graphql: GraphqlInfo[]
  js: JsFindings
}

// Resolve a local JSON-pointer $ref (`#/components/schemas/X`, `#/definitions/X`)
// against the spec document. Returns null for external/unresolvable refs.
function resolveRef(doc: any, ref: unknown): any {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return null
  let cur = doc
  for (const raw of ref.slice(2).split('/')) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    cur = cur?.[key]
    if (cur == null) return null
  }
  return cur
}

// Short type label for a schema node (follows one $ref / array items level).
function schemaTypeLabel(doc: any, schema: any, depth = 0): string {
  if (!schema || typeof schema !== 'object' || depth > 3) return 'any'
  if (schema.$ref) {
    const name = String(schema.$ref).split('/').pop() || 'object'
    return name
  }
  if (schema.type === 'array') return `${schemaTypeLabel(doc, schema.items, depth + 1)}[]`
  if (Array.isArray(schema.enum)) return `enum(${schema.type ?? 'string'})`
  return typeof schema.type === 'string' ? schema.type : 'object'
}

// Flatten a request-body schema into a bounded list of top-level fields.
function bodyFields(doc: any, schema: any, depth = 0): SpecBodyField[] {
  if (!schema || typeof schema !== 'object' || depth > 3) return []
  if (schema.$ref) return bodyFields(doc, resolveRef(doc, schema.$ref), depth + 1)
  let obj = schema
  if (schema.type === 'array' && schema.items) {
    obj = schema.items.$ref ? resolveRef(doc, schema.items.$ref) : schema.items
  }
  const props = obj?.properties
  if (!props || typeof props !== 'object') return []
  const required = new Set(Array.isArray(obj.required) ? obj.required.map(String) : [])
  const fields: SpecBodyField[] = []
  for (const [name, s] of Object.entries(props)) {
    if (fields.length >= 30) break
    fields.push({ name, type: schemaTypeLabel(doc, s), required: required.has(name) })
  }
  return fields
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
  const endpoints: SpecEndpoint[] = []
  for (const [p, itemRaw] of Object.entries(paths)) {
    const pathItem = itemRaw as Record<string, any> | null
    if (!pathItem || typeof pathItem !== 'object') continue
    // Path-level parameters apply to every operation under this path.
    const sharedParams: any[] = Array.isArray(pathItem.parameters) ? pathItem.parameters : []
    for (const m of HTTP_METHODS) {
      const op = pathItem[m]
      if (!op || typeof op !== 'object') continue

      const params: SpecParam[] = []
      let bodyContract: SpecEndpoint['body'] = null
      const rawParams = [...sharedParams, ...(Array.isArray(op.parameters) ? op.parameters : [])]
        .map((pp: any) => (pp?.$ref ? resolveRef(doc, pp.$ref) : pp))
        .filter((pp: any) => pp && typeof pp === 'object')
      for (const pp of rawParams) {
        if (pp.in === 'body') {
          // Swagger 2 body parameter carries the schema directly.
          bodyContract = { contentType: 'application/json', fields: bodyFields(doc, pp.schema) }
        } else if (pp.name && pp.in && params.length < 20) {
          params.push({ name: String(pp.name), in: String(pp.in), required: !!pp.required })
        }
      }
      // OpenAPI 3 request body: components-referenced content by media type.
      if (!bodyContract && op.requestBody) {
        const rb = op.requestBody.$ref ? resolveRef(doc, op.requestBody.$ref) : op.requestBody
        const content = rb?.content
        if (content && typeof content === 'object') {
          const ct = content['application/json'] ? 'application/json' : Object.keys(content)[0]
          const schema = ct ? content[ct]?.schema : null
          if (schema) bodyContract = { contentType: ct, fields: bodyFields(doc, schema) }
        }
      }

      const summaryRaw = typeof op.summary === 'string' ? op.summary : typeof op.description === 'string' ? op.description : null
      endpoints.push({
        method: m.toUpperCase(),
        path: p,
        summary: summaryRaw ? summaryRaw.slice(0, 120) : null,
        ...(params.length ? { params } : {}),
        ...(bodyContract ? { body: bodyContract } : {}),
      })
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

// Shallow probe: reliably detects the endpoint + whether introspection is on,
// WITHOUT the deep nesting that trips server query-depth guards (a deep query can
// be rejected outright, hiding a real endpoint). The operations query below is a
// best-effort second step only after this confirms introspection.
const DETECT_QUERY = JSON.stringify({ query: '{__schema{queryType{name} types{name}}}' })
// Ask for the root query/mutation FIELDS (+ their argument types) — those fields
// are the operations an operator can actually call. Three ofType levels unwrap the
// common NON_NULL(LIST(NON_NULL(Named))) nesting.
const ARG_TYPE = 'type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}'
const OPERATIONS_QUERY = JSON.stringify({
  query: `{__schema{queryType{name fields{name args{name ${ARG_TYPE}}}} mutationType{name fields{name args{name ${ARG_TYPE}}}}}}`,
})

// Render a GraphQL type reference (NON_NULL / LIST wrappers) to SDL, e.g. "[ID!]!".
function gqlTypeName(t: any): string {
  if (!t || typeof t !== 'object') return 'Unknown'
  if (t.kind === 'NON_NULL') return `${gqlTypeName(t.ofType)}!`
  if (t.kind === 'LIST') return `[${gqlTypeName(t.ofType)}]`
  return typeof t.name === 'string' ? t.name : 'Unknown'
}

// Build the callable operation list from an introspected __schema (bounded).
function buildGqlOperations(schema: any): GqlOperation[] {
  const out: GqlOperation[] = []
  const take = (root: any, kind: 'query' | 'mutation') => {
    const fields = Array.isArray(root?.fields) ? root.fields : []
    for (const f of fields) {
      if (out.length >= 150 || !f?.name) break
      const args = (Array.isArray(f.args) ? f.args : [])
        .slice(0, 20)
        .map((a: any) => ({ name: String(a?.name ?? ''), type: gqlTypeName(a?.type) }))
        .filter((a: { name: string }) => a.name)
      out.push({ kind, name: String(f.name), args })
    }
  }
  take(schema?.queryType, 'query')
  take(schema?.mutationType, 'mutation')
  return out
}

// Fetch a host's homepage and pull out its JS bundle URLs — the live corpus
// jsRecon mines for API endpoints. Matches BOTH <script src> AND
// <link rel="modulepreload"/"preload" href> (modern bundlers — Next/Vite — load
// their main chunks via modulepreload, which the app's API calls live in). Uses
// a browser UA so CDN/bot gates don't hide the real page. https first, then http.
async function homepageJs(host: string): Promise<{ jsUrls: string[]; html: string | null }> {
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
    return { jsUrls: [...urls], html: res.body }
  }
  return { jsUrls: [...urls], html: null }
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

// Best-effort second step: fetch the callable operations from an endpoint already
// confirmed to allow introspection. The deeper query can be rejected by a query-
// depth/cost guard — that's fine, we just return none and keep the detection.
async function fetchGqlOperations(endpoint: string): Promise<GqlOperation[]> {
  const res = await guardedFetch(endpoint, {
    method: 'POST',
    timeoutMs: TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
    body: OPERATIONS_QUERY,
    maxBytes: MAX_SPEC_BYTES,
  })
  if (!res) return []
  try {
    const schema = JSON.parse(res.body)?.data?.__schema
    return schema ? buildGqlOperations(schema) : []
  } catch {
    return []
  }
}

// GraphQL: parallel introspection probes; report a SINGLE endpoint per host,
// preferring one where introspection is enabled. Detection uses a SHALLOW query
// (deep queries get rejected by query-depth guards, which would hide the
// endpoint); the winner is then enriched with its callable operations.
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
          body: DETECT_QUERY,
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
          /cannot query field|must provide (a )?query|graphql|syntax error|unknown operation|introspection|depth limit|query (is too )?complex|complexity|cost limit/i.test(
            res.body,
          )
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
      if (!best) return []
      if (best.introspectionEnabled) {
        const operations = await fetchGqlOperations(best.endpoint)
        if (operations.length) best.operations = operations
      }
      return [best]
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

const PARAM_IN_QUERY = /[?&]([a-zA-Z0-9_.-]{1,40})=/g

// Pull API-looking paths this exact host already exposed in the passive URL
// corpus (wayback / CommonCrawl / urlscan / katana results the domain already
// collected) — surfaces real, historically-live endpoints with NO new request
// to the target. Scoped to the one host so each finding is correctly attributed.
export function apiPathsFromCorpus(host: string, knownUrls: string[]): { endpoints: string[]; params: string[] } {
  const endpoints = new Set<string>()
  const params = new Set<string>()
  const h = host.toLowerCase()
  for (const u of knownUrls) {
    let url: URL
    try {
      url = new URL(u)
    } catch {
      continue // not an absolute URL — skip
    }
    if (url.hostname.toLowerCase() !== h) continue
    const path = url.pathname + url.search
    if (ASSET_RE.test(path) || !isApiEndpoint(path)) continue
    endpoints.add(path)
    for (const pm of url.search.matchAll(PARAM_IN_QUERY)) params.add(pm[1])
  }
  return { endpoints: [...endpoints], params: [...params] }
}

// JS bundle mining (the modern-SPA workhorse): pull the site's own JS (homepage
// bundles + any already-known .js URLs from prior recon) and extract API
// endpoints (relative paths AND in-scope absolute URLs like api.target.com/…),
// params and leaked secrets — surfaces an API even when no spec is published.
async function mineJs(host: string, extraJsUrls: string[], knownUrls: string[] = []): Promise<JsFindings> {
  const home = await homepageJs(host)
  const jsUrls = [...new Set([...home.jsUrls, ...extraJsUrls])]
  const raw: JsReconResult = jsUrls.length
    ? await jsRecon(jsUrls)
    : { filesScanned: 0, mapsScanned: 0, endpoints: [], urls: [], params: [], secrets: [], frameworks: [], routes: [], env: [] }

  const relative = raw.endpoints.filter(isApiEndpoint)

  // Absolute URLs on the target's own domain/subdomains that look like API calls.
  const base = baseDomain(host)
  const absolute: string[] = []
  const hostSet = new Set<string>() // every in-scope hostname the bundle references
  const noteHost = (raw: string) => {
    const h = raw.toLowerCase()
    if (h === host.toLowerCase() || h === base || h.endsWith('.' + base)) hostSet.add(h)
  }
  for (const u of raw.urls) {
    try {
      const url = new URL(u)
      const h = url.hostname.toLowerCase()
      noteHost(h) // capture the host even if the path doesn't look API-ish
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
  // Baked-in env URL values (NEXT_PUBLIC_API_URL, VITE_API_BASE, …) also point at
  // in-scope sibling hosts.
  for (const e of raw.env) {
    if (e.value && /^https?:\/\//i.test(e.value)) {
      try {
        noteHost(new URL(e.value).hostname)
      } catch {
        /* skip */
      }
    }
  }

  // Fold in API paths this host already exposed in the passive corpus (wayback /
  // CommonCrawl / urlscan / katana) — no extra request, and it works even when a
  // host publishes zero JS (jsUrls empty above but the corpus still has paths).
  const corpus = apiPathsFromCorpus(host, knownUrls)

  const endpoints = [...new Set([...relative, ...absolute, ...corpus.endpoints])].slice(0, MAX_ENDPOINTS)
  const params = [...new Set([...raw.params, ...corpus.params])].slice(0, 100)
  // Framework = homepage-HTML markers ∪ bundle signatures. Dedup by base name so
  // "Angular 17" and "Angular" don't both show.
  const frameworks = [...new Set([...(home.html ? detectFrameworkFromHtml(home.html) : []), ...raw.frameworks])].filter(
    (f, _i, arr) => !arr.some((o) => o !== f && o.startsWith(f + ' ')),
  )
  return {
    filesScanned: raw.filesScanned,
    endpoints,
    params,
    secrets: raw.secrets,
    fromCorpus: corpus.endpoints.length,
    hosts: [...hostSet],
    frameworks,
    routes: raw.routes,
    env: raw.env,
  }
}

export async function discoverApiSurface(
  host: string,
  extraJsUrls: string[] = [],
  knownUrls: string[] = [],
): Promise<ApiSurfaceResult> {
  // SSRF: refuse a host that resolves internal before probing it.
  await assertPublicHost(host)
  // The three probes are independent — run them concurrently so total time is
  // the slowest phase, not their sum.
  const [specs, graphql, js] = await Promise.all([
    sweepSpecs(host),
    sweepGraphql(host),
    mineJs(host, extraJsUrls, knownUrls),
  ])
  return { host, specs, graphql, js }
}
