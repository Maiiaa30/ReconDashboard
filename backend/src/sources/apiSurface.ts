import { assertPublicHost, guardedFetch } from './guard'

// Passive API-surface discovery for a host: locate published OpenAPI/Swagger
// specs and GraphQL endpoints, and (for GraphQL) whether introspection is left
// enabled. Every request is SSRF-guarded and bounded — this is light recon (the
// same GETs a browser/crawler would make), not a loud scan.

const TIMEOUT_MS = 9_000
const MAX_SPEC_BYTES = 4 * 1024 * 1024
const MAX_ENDPOINTS = 300

// High-signal, framework-common locations. Kept tight to limit request volume.
const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/swagger/v1/swagger.json',
  '/v3/api-docs',
  '/v2/api-docs',
  '/api-docs',
  '/api/openapi.json',
  '/api/swagger.json',
  '/.well-known/openapi.json',
  '/docs/openapi.json',
]
const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/graphql/v1']

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] as const

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

export interface ApiSurfaceResult {
  host: string
  specs: ApiSpec[]
  graphql: GraphqlInfo[]
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

export async function discoverApiSurface(host: string): Promise<ApiSurfaceResult> {
  // SSRF: refuse a host that resolves internal before probing it.
  await assertPublicHost(host)

  // --- OpenAPI / Swagger specs ---
  const specs: ApiSpec[] = []
  const seenSpec = new Set<string>()
  for (const scheme of ['https', 'http'] as const) {
    for (const path of SPEC_PATHS) {
      const url = `${scheme}://${host}${path}`
      const res = await guardedFetch(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_SPEC_BYTES })
      if (!res || res.status !== 200) continue
      const spec = parseSpec(res.finalUrl || url, res.body)
      if (spec && !seenSpec.has(spec.specUrl)) {
        seenSpec.add(spec.specUrl)
        specs.push(spec)
      }
    }
    if (specs.length) break // found on https — don't repeat the sweep over http
  }

  // --- GraphQL endpoint + introspection state ---
  // Many servers route several paths to one GraphQL handler, so we collect
  // matches then report a SINGLE endpoint per host (preferring one where
  // introspection is enabled) rather than a finding per path.
  const matches: GraphqlInfo[] = []
  for (const scheme of ['https', 'http'] as const) {
    for (const path of GRAPHQL_PATHS) {
      const url = `${scheme}://${host}${path}`
      const res = await guardedFetch(url, {
        method: 'POST',
        timeoutMs: TIMEOUT_MS,
        headers: { 'Content-Type': 'application/json' },
        body: INTROSPECTION_QUERY,
        maxBytes: MAX_SPEC_BYTES,
      })
      if (!res) continue
      let doc: any = null
      try {
        doc = JSON.parse(res.body)
      } catch {
        continue // not JSON — not a GraphQL endpoint
      }
      const schema = doc?.data?.__schema
      // A real schema, OR a distinctly GraphQL-shaped error (endpoint exists but
      // introspection is off). The error regex is strict to avoid matching any
      // random JSON error body.
      const gqlError =
        Array.isArray(doc?.errors) &&
        /cannot query field|must provide (a )?query|graphql|syntax error|unknown operation|introspection/i.test(res.body)
      if (!schema && !gqlError) continue
      matches.push({
        endpoint: url,
        introspectionEnabled: !!schema,
        queryType: schema?.queryType?.name ?? null,
        typeCount: Array.isArray(schema?.types) ? schema.types.length : 0,
      })
    }
    if (matches.length) break // found on https — don't repeat over http
  }
  const best = matches.find((m) => m.introspectionEnabled) ?? matches[0]
  const graphql = best ? [best] : []

  return { host, specs, graphql }
}
