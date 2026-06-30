import { resolveDns } from '../sources/dns'
import { isInternalIp } from '../util/validate'

// Direct, HTTP-based OWASP active checks — the engine that makes the OWASP tab
// useful without leaning entirely on nuclei. Each check sends benign probes a
// pentester would send by hand and reports concrete evidence. SSRF-guarded;
// only ever run against an authorized target (the route enforces the gate).

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ActiveFinding {
  category: string // OWASP id, e.g. A05
  name: string
  severity: Severity
  url: string
  evidence: string
}

const TIMEOUT_MS = 8_000
const MAX_BODY = 256 * 1024
const UA = 'recon-dashboard/0.1 (+authorized owasp check)'

interface RawResponse {
  status: number
  headers: Headers
  body: string
}

async function fetchRaw(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; redirect?: 'follow' | 'manual' | 'error' } = {},
): Promise<RawResponse | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: opts.method ?? 'GET',
      redirect: opts.redirect ?? 'manual',
      signal: controller.signal,
      headers: { 'User-Agent': UA, ...(opts.headers ?? {}) },
    })
    let body = ''
    if (res.body) {
      const reader = res.body.getReader()
      const chunks: Uint8Array[] = []
      let total = 0
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (value) {
          chunks.push(value)
          total += value.byteLength
          if (total >= MAX_BODY) {
            await reader.cancel()
            break
          }
        }
      }
      body = Buffer.concat(chunks).toString('utf8')
    }
    return { status: res.status, headers: res.headers, body }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

// --- individual checks -------------------------------------------------------

const SECURITY_HEADERS: { header: string; name: string; severity: Severity }[] = [
  { header: 'content-security-policy', name: 'Content-Security-Policy', severity: 'low' },
  { header: 'strict-transport-security', name: 'Strict-Transport-Security (HSTS)', severity: 'low' },
  { header: 'x-frame-options', name: 'X-Frame-Options (clickjacking)', severity: 'low' },
  { header: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'info' },
]

function checkSecurityHeaders(base: RawResponse, baseUrl: string): ActiveFinding[] {
  const out: ActiveFinding[] = []
  for (const h of SECURITY_HEADERS) {
    if (!base.headers.get(h.header)) {
      out.push({ category: 'A05', name: `Missing security header: ${h.name}`, severity: h.severity, url: baseUrl, evidence: `Response has no ${h.header} header` })
    }
  }
  const server = base.headers.get('server')
  const powered = base.headers.get('x-powered-by')
  if (powered || (server && /\d/.test(server))) {
    out.push({ category: 'A05', name: 'Software version disclosure', severity: 'info', url: baseUrl, evidence: [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join(' · ') })
  }
  return out
}

const SENSITIVE_FILES: { path: string; signatures: RegExp[]; name: string; severity: Severity }[] = [
  { path: '/.env', signatures: [/^[A-Z0-9_]+=/m, /APP_KEY|SECRET|PASSWORD|DB_/i], name: 'Exposed .env file', severity: 'high' },
  { path: '/.git/config', signatures: [/\[core\]/, /\[remote/], name: 'Exposed .git/config', severity: 'high' },
  { path: '/.git/HEAD', signatures: [/^ref:\s+refs\//], name: 'Exposed .git repository', severity: 'high' },
  { path: '/phpinfo.php', signatures: [/phpinfo\(\)|PHP Version/i], name: 'Exposed phpinfo()', severity: 'medium' },
  { path: '/server-status', signatures: [/Apache Server Status/i], name: 'Apache server-status exposed', severity: 'medium' },
  { path: '/.aws/credentials', signatures: [/aws_access_key_id/i], name: 'Exposed AWS credentials', severity: 'critical' },
  { path: '/config.json', signatures: [/"(password|secret|api[_-]?key|token)"/i], name: 'Exposed config.json with secrets', severity: 'high' },
  { path: '/.DS_Store', signatures: [/Bud1|\x00\x00\x00/], name: 'Exposed .DS_Store (path leak)', severity: 'low' },
]

async function checkSensitiveFiles(baseUrl: string): Promise<ActiveFinding[]> {
  const out: ActiveFinding[] = []
  for (const f of SENSITIVE_FILES) {
    const res = await fetchRaw(baseUrl + f.path)
    if (res && res.status === 200 && f.signatures.some((re) => re.test(res.body))) {
      out.push({ category: 'A02', name: f.name, severity: f.severity, url: baseUrl + f.path, evidence: `HTTP 200 with matching content at ${f.path}` })
    }
  }
  return out
}

const XSS_PARAMS = ['q', 's', 'search', 'id', 'page', 'query']

async function checkReflectedXss(baseUrl: string): Promise<ActiveFinding[]> {
  const marker = 'rxss9842'
  const payload = `"'><svg/onload=${marker}>`
  for (const param of XSS_PARAMS) {
    const url = `${baseUrl}?${param}=${encodeURIComponent(payload)}`
    const res = await fetchRaw(url, { redirect: 'follow' })
    // Reflected unencoded (the raw < and the marker survive) → likely XSS sink.
    if (res && res.body.includes(`<svg/onload=${marker}>`)) {
      return [{ category: 'A03', name: 'Reflected XSS — unencoded input', severity: 'high', url, evidence: `Payload reflected unencoded via ?${param}=` }]
    }
  }
  return []
}

const REDIRECT_PARAMS = ['url', 'next', 'redirect', 'return', 'dest', 'r', 'u', 'continue']

async function checkOpenRedirect(baseUrl: string): Promise<ActiveFinding[]> {
  const evil = 'https://example.org/owasp-redirect-probe'
  for (const param of REDIRECT_PARAMS) {
    const url = `${baseUrl}?${param}=${encodeURIComponent(evil)}`
    const res = await fetchRaw(url, { redirect: 'manual' })
    if (res && res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location') ?? ''
      if (/^https?:\/\/(www\.)?example\.org/i.test(loc) || loc.startsWith('//example.org')) {
        return [{ category: 'A10', name: 'Open redirect', severity: 'medium', url, evidence: `?${param}= redirects to ${loc}` }]
      }
    }
  }
  return []
}

async function checkCors(baseUrl: string): Promise<ActiveFinding[]> {
  const evil = 'https://evil.example.org'
  const res = await fetchRaw(baseUrl, { headers: { Origin: evil } })
  if (!res) return []
  const acao = res.headers.get('access-control-allow-origin')
  const acac = res.headers.get('access-control-allow-credentials')
  if (acao === evil || acao === '*') {
    const withCreds = acac === 'true'
    return [{
      category: 'A05',
      name: withCreds ? 'CORS misconfiguration (reflects origin + credentials)' : 'Permissive CORS policy',
      severity: withCreds ? 'high' : 'low',
      url: baseUrl,
      evidence: `Access-Control-Allow-Origin: ${acao}${withCreds ? ' with Allow-Credentials: true' : ''}`,
    }]
  }
  return []
}

async function checkTrace(baseUrl: string): Promise<ActiveFinding[]> {
  const res = await fetchRaw(baseUrl, { method: 'TRACE' })
  if (res && res.status === 200 && /TRACE\s|X-Recon-Probe/i.test(res.body)) {
    return [{ category: 'A05', name: 'HTTP TRACE method enabled (XST)', severity: 'low', url: baseUrl, evidence: 'TRACE returned 200 and echoed the request' }]
  }
  return []
}

const LISTING_DIRS = ['/uploads/', '/files/', '/backup/', '/images/', '/assets/', '/static/']

async function checkDirListing(baseUrl: string): Promise<ActiveFinding[]> {
  for (const dir of LISTING_DIRS) {
    const res = await fetchRaw(baseUrl + dir)
    if (res && res.status === 200 && /<title>Index of \/|Directory listing for/i.test(res.body)) {
      return [{ category: 'A05', name: 'Directory listing enabled', severity: 'low', url: baseUrl + dir, evidence: `Index listing at ${dir}` }]
    }
  }
  return []
}

// --- orchestrator ------------------------------------------------------------

export async function runActiveChecks(
  scheme: 'https' | 'http',
  host: string,
): Promise<{ findings: ActiveFinding[]; reachable: boolean }> {
  const baseUrl = `${scheme}://${host}`

  // SSRF guard — refuse a target that resolves to an internal address.
  const dns = await resolveDns(host).catch(() => null)
  const ip = dns?.a[0] ?? null
  if (ip && isInternalIp(ip)) {
    return { findings: [], reachable: false }
  }

  const base = await fetchRaw(baseUrl, { redirect: 'follow' })
  if (!base) return { findings: [], reachable: false }

  const findings: ActiveFinding[] = [...checkSecurityHeaders(base, baseUrl)]
  const groups = await Promise.all([
    checkSensitiveFiles(baseUrl),
    checkReflectedXss(baseUrl),
    checkOpenRedirect(baseUrl),
    checkCors(baseUrl),
    checkTrace(baseUrl),
    checkDirListing(baseUrl),
  ])
  for (const g of groups) findings.push(...g)
  return { findings, reachable: true }
}
