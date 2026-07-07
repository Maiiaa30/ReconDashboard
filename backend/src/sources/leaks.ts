import { config } from '../config'

// Breach-data lookup by domain. Provider-agnostic: dispatches to the configured
// provider (HIBP / DeHashed / LeakCheck) and normalises every result into a
// common LeakEntry. These are calls to KNOWN provider hosts with the operator's
// own API key — not user-controlled URLs — so the SSRF guard does not apply.
// For AUTHORIZED engagement exposure assessment only.

export type LeakProvider = 'hibp' | 'dehashed' | 'leakcheck'

export interface LeakEntry {
  email: string | null
  username: string | null
  password: string | null
  hashedPassword: string | null
  name: string | null
  phone: string | null
  ip: string | null
  source: string | null // breach / database name
  breachDate: string | null
}

export interface LeakSearchResult {
  provider: LeakProvider
  domain: string
  entries: LeakEntry[]
  total: number
  truncated: boolean
}

const MAX_ENTRIES = 2000 // cap what we ingest so a huge breach set can't blow memory
const TIMEOUT_MS = 25_000
const UA = 'recon-dashboard/0.1 (+authorized exposure assessment)'

class LeakProviderError extends Error {}

// Small fetch wrapper: custom headers + method + timeout, honouring the job's
// AbortSignal so a cancel/timeout kills the request.
async function call(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
): Promise<{ status: number; text: string }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  // Abort if the caller's signal fires too.
  const onAbort = () => controller.abort()
  opts.signal?.addEventListener('abort', onAbort, { once: true })
  try {
    const res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers: { 'User-Agent': UA, ...(opts.headers ?? {}) },
      body: opts.body,
      signal: controller.signal,
    })
    const text = await res.text()
    return { status: res.status, text }
  } finally {
    clearTimeout(timer)
    opts.signal?.removeEventListener('abort', onAbort)
  }
}

function empty(v: unknown): string | null {
  if (v == null) return null
  const s = String(v).trim()
  return s === '' ? null : s
}

// ---- HIBP -------------------------------------------------------------------
// GET /breacheddomain/{domain} → { "alias": ["Breach1","Breach2"], ... }
// Requires a paid subscription AND domain ownership verified in your HIBP
// account. Returns which local-parts appear in which breaches — never passwords.
async function hibp(domain: string, signal?: AbortSignal): Promise<LeakSearchResult> {
  const { status, text } = await call(
    `https://haveibeenpwned.com/api/v3/breacheddomain/${encodeURIComponent(domain)}`,
    { headers: { 'hibp-api-key': config.leaks.apiKey }, signal },
  )
  if (status === 404) return { provider: 'hibp', domain, entries: [], total: 0, truncated: false }
  if (status === 401 || status === 403)
    throw new LeakProviderError('HIBP rejected the API key or the domain is not verified on your account')
  if (status !== 200) throw new LeakProviderError(`HIBP returned HTTP ${status}`)

  const map = JSON.parse(text || '{}') as Record<string, string[]>
  const entries: LeakEntry[] = []
  for (const [alias, breaches] of Object.entries(map)) {
    for (const b of breaches ?? []) {
      entries.push({
        email: `${alias}@${domain}`,
        username: alias,
        password: null,
        hashedPassword: null,
        name: null,
        phone: null,
        ip: null,
        source: empty(b),
        breachDate: null,
      })
      if (entries.length >= MAX_ENTRIES) break
    }
    if (entries.length >= MAX_ENTRIES) break
  }
  return { provider: 'hibp', domain, entries, total: entries.length, truncated: entries.length >= MAX_ENTRIES }
}

// ---- DeHashed (v2) ----------------------------------------------------------
// POST /v2/search { query: "domain:example.com" } with Dehashed-Api-Key header.
async function dehashed(domain: string, signal?: AbortSignal): Promise<LeakSearchResult> {
  const { status, text } = await call('https://api.dehashed.com/v2/search', {
    method: 'POST',
    headers: { 'Dehashed-Api-Key': config.leaks.apiKey, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ query: `domain:${domain}`, size: MAX_ENTRIES }),
    signal,
  })
  if (status === 401 || status === 403) throw new LeakProviderError('DeHashed rejected the API key')
  if (status !== 200) throw new LeakProviderError(`DeHashed returned HTTP ${status}`)

  const json = JSON.parse(text || '{}') as { entries?: any[]; total?: number }
  const rows = Array.isArray(json.entries) ? json.entries : []
  const entries: LeakEntry[] = rows.slice(0, MAX_ENTRIES).map((r) => ({
    email: empty(pick(r.email)),
    username: empty(pick(r.username)),
    password: empty(pick(r.password)),
    hashedPassword: empty(pick(r.hashed_password)),
    name: empty(pick(r.name)),
    phone: empty(pick(r.phone)),
    ip: empty(pick(r.ip_address)),
    source: empty(r.database_name),
    breachDate: null,
  }))
  return {
    provider: 'dehashed',
    domain,
    entries,
    total: Number(json.total ?? entries.length),
    truncated: rows.length >= MAX_ENTRIES,
  }
}

// DeHashed sometimes returns array-valued fields; take the first non-empty.
function pick(v: unknown): unknown {
  if (Array.isArray(v)) return v.find((x) => x != null && String(x).trim() !== '') ?? null
  return v
}

// ---- LeakCheck (v2 Pro) -----------------------------------------------------
// GET /v2/query/{domain}?type=domain with X-API-Key header.
async function leakcheck(domain: string, signal?: AbortSignal): Promise<LeakSearchResult> {
  const { status, text } = await call(
    `https://leakcheck.io/api/v2/query/${encodeURIComponent(domain)}?type=domain&limit=${MAX_ENTRIES}`,
    { headers: { 'X-API-Key': config.leaks.apiKey, Accept: 'application/json' }, signal },
  )
  if (status === 401 || status === 403) throw new LeakProviderError('LeakCheck rejected the API key')
  if (status !== 200) throw new LeakProviderError(`LeakCheck returned HTTP ${status}`)

  const json = JSON.parse(text || '{}') as { success?: boolean; found?: number; result?: any[]; error?: string }
  if (json.success === false) throw new LeakProviderError(`LeakCheck error: ${json.error ?? 'unknown'}`)
  const rows = Array.isArray(json.result) ? json.result : []
  const entries: LeakEntry[] = rows.slice(0, MAX_ENTRIES).map((r) => ({
    email: empty(r.email),
    username: empty(r.username),
    password: empty(r.password),
    hashedPassword: null,
    name: empty(r.first_name || r.name),
    phone: empty(r.phone),
    ip: empty(r.ip),
    source: empty(r.source?.name),
    breachDate: empty(r.source?.breach_date),
  }))
  return { provider: 'leakcheck', domain, entries, total: Number(json.found ?? entries.length), truncated: rows.length >= MAX_ENTRIES }
}

// Public entry point: query the configured provider for accounts on this domain.
export async function searchDomainLeaks(domain: string, signal?: AbortSignal): Promise<LeakSearchResult> {
  if (!config.leaks.enabled) {
    throw new LeakProviderError('leak provider not configured (set LEAK_PROVIDER + LEAK_API_KEY)')
  }
  switch (config.leaks.provider) {
    case 'hibp':
      return hibp(domain, signal)
    case 'dehashed':
      return dehashed(domain, signal)
    case 'leakcheck':
      return leakcheck(domain, signal)
    default:
      throw new LeakProviderError(`unsupported leak provider "${config.leaks.provider}"`)
  }
}
