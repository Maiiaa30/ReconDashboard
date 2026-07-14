import { randomUUID } from 'node:crypto'
import { resolveDns } from '../sources/dns'
import { guardedFetchRaw } from '../sources/guard'
import { isInternalIp } from '../util/validate'
import { analyzeCsp, analyzeHsts } from './csp'
import { corsVerdict } from './cors'
import { gitTriadComplete, type GitPart } from './vcs'

// Direct, HTTP-based OWASP active checks — the engine that makes the OWASP tab
// useful without leaning entirely on nuclei. Each check sends benign probes a
// pentester would send by hand and reports concrete evidence. SSRF-guarded;
// only ever run against an authorized target (the route enforces the gate).
//
// Target-aware: callers can pass custom payloads, extra params/paths, an auth
// header (for authenticated scans), and the real query params discovered for
// the target — so XSS/redirect checks hit the parameters the app actually uses.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

// Structured, reproducible evidence so a finding is retestable in a deliverable.
export interface EvidenceRepro {
  request?: string // e.g. "GET https://host/?q=<payload>"
  payload?: string
  responseStatus?: number
  headersSnippet?: string
  bodyExcerpt?: string
}

export interface ActiveFinding {
  category: string // OWASP id, e.g. A05
  name: string
  severity: Severity
  url: string
  evidence: string
  repro?: EvidenceRepro
}

// A short excerpt of the response body around a marker (for XSS reflection repro).
function excerptAround(body: string, needle: string, span = 160): string {
  const i = body.indexOf(needle)
  if (i < 0) return body.slice(0, span).replace(/\s+/g, ' ')
  const start = Math.max(0, i - Math.floor(span / 2))
  return body.slice(start, i + needle.length + Math.floor(span / 2)).replace(/\s+/g, ' ')
}

export interface OwaspChecksOptions {
  xssParams?: string[]
  xssPayloads?: string[] // custom XSS payloads to test for reflection
  redirectParams?: string[]
  sensitivePaths?: string[] // custom paths to probe (reported on 200)
  authHeader?: string // "Name: value" — sent on every request
  discoveredParams?: string[] // real query params seen for this target
  signal?: AbortSignal // job cancel/timeout — stops probing mid-loop
}

const TIMEOUT_MS = 8_000
const MAX_BODY = 256 * 1024
const UA = 'recon-dashboard/0.1 (+authorized owasp check)'

const SAFE_PARAM = /^[a-zA-Z0-9_.[\]-]{1,64}$/
const SAFE_PATH = /^\/[a-zA-Z0-9_.~/-]{0,128}$/

const uniqCap = (arr: (string | undefined)[], n: number): string[] =>
  [...new Set(arr.map((s) => String(s ?? '').trim()).filter(Boolean))].slice(0, n)

// Resolved, validated context passed to each check.
interface Ctx {
  host: string // the validated target host (for origin-confusion CORS probes)
  headers: Record<string, string>
  xssParams: string[]
  xssPayloads: string[]
  redirectParams: string[]
  customPaths: string[]
  signal?: AbortSignal // forwarded to every probe so a cancelled job stops
}

interface RawResponse {
  status: number
  headers: Headers
  body: string
}

// All target requests go through the one guarded client (guardedFetchRaw), which
// re-runs the SSRF check on every hop. `follow` controls redirect handling:
// checks that INSPECT a Location header (open redirect) pass follow=false and get
// the 30x response verbatim; checks that need the final page pass follow=true and
// the redirect is followed under the per-hop guard. No raw fetch() here — the
// lint rule enforces that so this guard can't be silently dropped again.
async function fetchRaw(
  url: string,
  opts: { method?: string; headers?: Record<string, string>; follow?: boolean; signal?: AbortSignal } = {},
): Promise<RawResponse | null> {
  const res = await guardedFetchRaw(url, {
    method: opts.method ?? 'GET',
    headers: { 'User-Agent': UA, ...(opts.headers ?? {}) },
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_BODY,
    follow: opts.follow ?? false,
    signal: opts.signal,
  })
  return res ? { status: res.status, headers: res.headers, body: res.body } : null
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

// CSP + HSTS quality (passive — reads only headers already on `base`, no extra
// request). A present-but-weak policy is a distinct, higher-signal finding than a
// missing one, so this runs alongside checkSecurityHeaders. Capped so a sprawling
// policy can't produce a wall of low findings.
const CSP_MAX_FINDINGS = 4

function checkCsp(base: RawResponse, baseUrl: string): ActiveFinding[] {
  const out: ActiveFinding[] = []
  const csp = base.headers.get('content-security-policy')
  const cspReportOnly = base.headers.get('content-security-policy-report-only')

  if (csp) {
    for (const issue of analyzeCsp(csp).slice(0, CSP_MAX_FINDINGS)) {
      out.push({ category: 'A05', name: issue.name, severity: issue.severity, url: baseUrl, evidence: issue.evidence })
    }
  } else if (cspReportOnly) {
    // A report-only policy is monitored but NOT enforced — it blocks nothing.
    out.push({
      category: 'A05',
      name: 'CSP is report-only (not enforced)',
      severity: 'low',
      url: baseUrl,
      evidence: 'Only Content-Security-Policy-Report-Only is set; violations are reported but not blocked',
    })
  }

  const hsts = analyzeHsts(base.headers.get('strict-transport-security'))
  if (hsts) out.push({ category: 'A05', name: hsts.name, severity: hsts.severity, url: baseUrl, evidence: hsts.evidence })

  return out
}

// Signature-gated so an SPA that returns its index.html for every path (content
// that never matches these KEY=VALUE / binary / config signatures) doesn't
// produce false positives. `git` marks the three .git members whose simultaneous
// presence proves a dumpable repository (escalated to critical below).
const SENSITIVE_FILES: { path: string; signatures: RegExp[]; name: string; severity: Severity; git?: GitPart }[] = [
  { path: '/.env', signatures: [/^[A-Z0-9_]+=/m, /APP_KEY|SECRET|PASSWORD|DB_/i], name: 'Exposed .env file', severity: 'high' },
  { path: '/.env.local', signatures: [/^[A-Z0-9_]+=/m, /APP_KEY|SECRET|PASSWORD|DB_/i], name: 'Exposed .env.local file', severity: 'high' },
  { path: '/.env.bak', signatures: [/^[A-Z0-9_]+=/m, /APP_KEY|SECRET|PASSWORD|DB_/i], name: 'Exposed .env backup', severity: 'high' },
  { path: '/.git/config', signatures: [/\[core\]/, /\[remote/], name: 'Exposed .git/config', severity: 'high', git: 'config' },
  { path: '/.git/HEAD', signatures: [/^ref:\s+refs\//], name: 'Exposed .git repository', severity: 'high', git: 'head' },
  { path: '/.git/index', signatures: [/^DIRC/], name: 'Exposed .git index', severity: 'high', git: 'index' },
  { path: '/.svn/wc.db', signatures: [/^SQLite format 3/], name: 'Exposed .svn repository (wc.db)', severity: 'high' },
  { path: '/.hg/requires', signatures: [/^(revlogv1|store|dotencode|fncache|generaldelta)$/m], name: 'Exposed Mercurial (.hg) repository', severity: 'high' },
  { path: '/phpinfo.php', signatures: [/phpinfo\(\)|PHP Version/i], name: 'Exposed phpinfo()', severity: 'medium' },
  { path: '/server-status', signatures: [/Apache Server Status/i], name: 'Apache server-status exposed', severity: 'medium' },
  { path: '/.aws/credentials', signatures: [/aws_access_key_id/i], name: 'Exposed AWS credentials', severity: 'critical' },
  { path: '/config.json', signatures: [/"(password|secret|api[_-]?key|token)"/i], name: 'Exposed config.json with secrets', severity: 'high' },
  { path: '/.htpasswd', signatures: [/^[^:\s]+:(\$(?:apr1|2y|1|6)\$|\{SHA\})/m], name: 'Exposed .htpasswd (password hashes)', severity: 'high' },
  { path: '/.npmrc', signatures: [/(_authToken|_auth|_password)=/], name: 'Exposed .npmrc (registry token)', severity: 'high' },
  { path: '/backup.sql', signatures: [/(CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump)/i], name: 'Exposed SQL backup (backup.sql)', severity: 'high' },
  { path: '/dump.sql', signatures: [/(CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump)/i], name: 'Exposed SQL dump (dump.sql)', severity: 'high' },
  { path: '/wp-config.php.bak', signatures: [/DB_PASSWORD|DB_NAME|DB_USER/], name: 'Exposed wp-config backup (DB credentials)', severity: 'critical' },
  { path: '/.DS_Store', signatures: [/Bud1|\x00\x00\x00/], name: 'Exposed .DS_Store (path leak)', severity: 'low' },
]

// Catch-all / SPA guard: fetch a path that cannot legitimately exist and see if
// the app answers 200 with HTML. Such a server returns 200 for EVERYTHING, so a
// bare 200 (with no content signature) proves nothing — this lets the custom-path
// check suppress those. Signature-gated checks above are already immune (HTML
// never matches their signatures).
async function detectCatchAll(baseUrl: string, ctx: Ctx): Promise<boolean> {
  const bogus = `/${randomUUID()}/${randomUUID()}.txt`
  const res = await fetchRaw(baseUrl + bogus, { headers: ctx.headers, signal: ctx.signal })
  if (!res || res.status !== 200) return false
  const ct = res.headers.get('content-type') ?? ''
  return /text\/html/i.test(ct) || /<html|<!doctype html/i.test(res.body.slice(0, 512))
}

async function checkSensitiveFiles(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  const out: ActiveFinding[] = []
  const catchAll = await detectCatchAll(baseUrl, ctx)
  const gitParts: GitPart[] = []
  const gitFindings: ActiveFinding[] = []

  for (const f of SENSITIVE_FILES) {
    if (ctx.signal?.aborted) break
    const res = await fetchRaw(baseUrl + f.path, { headers: ctx.headers, signal: ctx.signal })
    if (!(res && res.status === 200 && f.signatures.some((re) => re.test(res.body)))) continue
    const finding: ActiveFinding = {
      category: 'A02',
      name: f.name,
      severity: f.severity,
      url: baseUrl + f.path,
      evidence: `HTTP 200 with matching content at ${f.path}`,
      repro: { request: `GET ${baseUrl + f.path}`, responseStatus: res.status, bodyExcerpt: res.body.slice(0, 300).replace(/\s+/g, ' ') },
    }
    if (f.git) {
      gitParts.push(f.git)
      gitFindings.push(finding)
    } else {
      out.push(finding)
    }
  }

  // .git triad: HEAD + config + index all valid ⇒ a fully dumpable repository
  // (source, secrets, history). Collapse the three highs into one critical; a
  // partial exposure keeps its individual finding(s).
  if (gitTriadComplete(gitParts)) {
    out.push({
      category: 'A02',
      name: 'Dumpable .git repository (HEAD + config + index)',
      severity: 'critical',
      url: baseUrl + '/.git/',
      evidence: 'All of /.git/HEAD, /.git/config and /.git/index are exposed — the full repository (source + history + secrets) is downloadable',
      repro: { request: `GET ${baseUrl}/.git/index`, responseStatus: 200 },
    })
  } else {
    out.push(...gitFindings)
  }

  // Operator-supplied custom paths — reported on any 200 (verify manually), but
  // suppressed under a catch-all server where a bare 200 is meaningless.
  if (!catchAll) {
    for (const p of ctx.customPaths) {
      if (ctx.signal?.aborted) break
      const res = await fetchRaw(baseUrl + p, { headers: ctx.headers, signal: ctx.signal })
      if (res && res.status === 200) {
        out.push({
          category: 'A02',
          name: `Custom path returned 200: ${p}`,
          severity: 'low',
          url: baseUrl + p,
          evidence: `Custom sensitive path ${p} responded 200 — verify`,
          repro: { request: `GET ${baseUrl + p}`, responseStatus: res.status },
        })
      }
    }
  }
  return out
}

const XSS_PARAMS = ['q', 's', 'search', 'id', 'page', 'query']
const DEFAULT_XSS = { inject: `"'><svg/onload=rxss9842>`, needle: `<svg/onload=rxss9842>` }

async function checkReflectedXss(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  const out: ActiveFinding[] = []
  // 1) Parameter coverage with the marker payload — tests the real params the
  //    target uses (discovered + defaults + custom).
  for (const param of ctx.xssParams) {
    if (ctx.signal?.aborted) return out
    const url = `${baseUrl}?${param}=${encodeURIComponent(DEFAULT_XSS.inject)}`
    const res = await fetchRaw(url, { follow: true, headers: ctx.headers, signal: ctx.signal })
    if (res && res.body.includes(DEFAULT_XSS.needle)) {
      out.push({
        category: 'A03',
        name: 'Reflected XSS — unencoded input',
        severity: 'high',
        url,
        evidence: `Payload reflected unencoded via ?${param}=`,
        repro: { request: `GET ${url}`, payload: DEFAULT_XSS.inject, responseStatus: res.status, bodyExcerpt: excerptAround(res.body, DEFAULT_XSS.needle) },
      })
      break // one confirmed sink is enough to flag
    }
  }
  // 2) Custom payloads (operator's bypass attempts) reflected on a common param.
  for (const p of ctx.xssPayloads) {
    if (ctx.signal?.aborted) return out
    const url = `${baseUrl}?q=${encodeURIComponent(p)}`
    const res = await fetchRaw(url, { follow: true, headers: ctx.headers, signal: ctx.signal })
    if (res && res.body.includes(p)) {
      out.push({
        category: 'A03',
        name: 'Custom XSS payload reflected',
        severity: 'high',
        url,
        evidence: `Custom payload reflected unencoded: ${p.slice(0, 80)}`,
        repro: { request: `GET ${url}`, payload: p, responseStatus: res.status, bodyExcerpt: excerptAround(res.body, p) },
      })
    }
  }
  return out
}

const REDIRECT_PARAMS = ['url', 'next', 'redirect', 'return', 'dest', 'r', 'u', 'continue']

async function checkOpenRedirect(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  const evil = 'https://example.org/owasp-redirect-probe'
  for (const param of ctx.redirectParams) {
    if (ctx.signal?.aborted) return []
    const url = `${baseUrl}?${param}=${encodeURIComponent(evil)}`
    // follow:false — we INSPECT the Location header, we do not chase it.
    const res = await fetchRaw(url, { headers: ctx.headers, signal: ctx.signal })
    if (res && res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location') ?? ''
      if (/^https?:\/\/(www\.)?example\.org/i.test(loc) || loc.startsWith('//example.org')) {
        return [{
          category: 'A10',
          name: 'Open redirect',
          severity: 'medium',
          url,
          evidence: `?${param}= redirects to ${loc}`,
          repro: { request: `GET ${url}`, payload: evil, responseStatus: res.status, headersSnippet: `Location: ${loc}` },
        }]
      }
    }
  }
  return []
}

async function checkCors(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  // Four probe classes: an arbitrary external origin, the `null` origin (sent by
  // sandboxed iframes / file:// / some redirects — a reflected null trusts them
  // all), and two origin-confusion strings a naive prefix/substring allowlist
  // would wrongly trust (the target host as a subdomain of an attacker domain,
  // and an attacker domain that merely CONTAINS the target host).
  const probes: { origin: string; kind: string }[] = [
    { origin: 'https://evil.example.org', kind: 'arbitrary external origin' },
    { origin: 'null', kind: 'null origin' },
    { origin: `https://${ctx.host}.evil.example.org`, kind: 'origin prefix confusion' },
    { origin: `https://evil-${ctx.host}`, kind: 'origin substring confusion' },
  ]
  const out: ActiveFinding[] = []
  const seen = new Set<string>()
  for (const p of probes) {
    if (ctx.signal?.aborted) break
    const res = await fetchRaw(baseUrl, { headers: { ...ctx.headers, Origin: p.origin }, signal: ctx.signal })
    if (!res) continue
    const acao = res.headers.get('access-control-allow-origin')
    const acac = res.headers.get('access-control-allow-credentials')
    const v = corsVerdict(p.origin, acao, acac)
    if (!v) continue
    // A wildcard reflects on every probe; collapse identical verdicts so one
    // misconfig isn't reported four times.
    const key = `${v.reflected}:${v.withCreds}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({
      category: 'A05',
      name:
        v.reflected === 'wildcard'
          ? 'Permissive CORS policy (wildcard origin)'
          : v.withCreds
            ? `CORS reflects ${p.kind} with credentials`
            : `CORS reflects ${p.kind}`,
      severity: v.severity,
      url: baseUrl,
      evidence: `Origin: ${p.origin} → Access-Control-Allow-Origin: ${acao}${v.withCreds ? ' + Allow-Credentials: true' : ''}`,
      repro: {
        request: `GET ${baseUrl}  (Origin: ${p.origin})`,
        responseStatus: res.status,
        headersSnippet: `Access-Control-Allow-Origin: ${acao}${v.withCreds ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
      },
    })
  }
  return out
}

async function checkTrace(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  const res = await fetchRaw(baseUrl, { method: 'TRACE', headers: ctx.headers, signal: ctx.signal })
  if (res && res.status === 200 && /TRACE\s|X-Recon-Probe/i.test(res.body)) {
    return [{ category: 'A05', name: 'HTTP TRACE method enabled (XST)', severity: 'low', url: baseUrl, evidence: 'TRACE returned 200 and echoed the request' }]
  }
  return []
}

const LISTING_DIRS = ['/uploads/', '/files/', '/backup/', '/images/', '/assets/', '/static/']

async function checkDirListing(baseUrl: string, ctx: Ctx): Promise<ActiveFinding[]> {
  for (const dir of LISTING_DIRS) {
    if (ctx.signal?.aborted) return []
    const res = await fetchRaw(baseUrl + dir, { headers: ctx.headers, signal: ctx.signal })
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
  opts: OwaspChecksOptions = {},
): Promise<{ findings: ActiveFinding[]; reachable: boolean; targetedParams: number }> {
  const baseUrl = `${scheme}://${host}`

  // Auth header for authenticated scans, e.g. "Cookie: session=abc".
  const headers: Record<string, string> = {}
  if (opts.authHeader && opts.authHeader.includes(':')) {
    const i = opts.authHeader.indexOf(':')
    const name = opts.authHeader.slice(0, i).trim()
    const value = opts.authHeader.slice(i + 1).trim()
    if (/^[a-zA-Z0-9-]{1,64}$/.test(name) && value) headers[name] = value
  }

  const discovered = (opts.discoveredParams ?? []).filter((p) => SAFE_PARAM.test(p))
  const customXssParams = (opts.xssParams ?? []).filter((p) => SAFE_PARAM.test(p))
  const customRedirect = (opts.redirectParams ?? []).filter((p) => SAFE_PARAM.test(p))

  const ctx: Ctx = {
    host,
    headers,
    xssParams: uniqCap([...XSS_PARAMS, ...discovered, ...customXssParams], 25),
    xssPayloads: uniqCap(opts.xssPayloads ?? [], 6),
    redirectParams: uniqCap([...REDIRECT_PARAMS, ...discovered, ...customRedirect], 25),
    customPaths: uniqCap((opts.sensitivePaths ?? []).filter((p) => SAFE_PATH.test(p)), 25),
    signal: opts.signal,
  }

  // SSRF guard — refuse if ANY resolved address (all A + AAAA, not just the
  // first A) is internal.
  const dns = await resolveDns(host).catch(() => null)
  const allIps = [...(dns?.a ?? []), ...(dns?.aaaa ?? [])]
  if (allIps.some(isInternalIp)) return { findings: [], reachable: false, targetedParams: 0 }

  const base = await fetchRaw(baseUrl, { follow: true, headers, signal: ctx.signal })
  if (!base) return { findings: [], reachable: false, targetedParams: 0 }

  const findings: ActiveFinding[] = [...checkSecurityHeaders(base, baseUrl), ...checkCsp(base, baseUrl)]
  const groups = await Promise.all([
    checkSensitiveFiles(baseUrl, ctx),
    checkReflectedXss(baseUrl, ctx),
    checkOpenRedirect(baseUrl, ctx),
    checkCors(baseUrl, ctx),
    checkTrace(baseUrl, ctx),
    checkDirListing(baseUrl, ctx),
  ])
  for (const g of groups) findings.push(...g)
  return { findings, reachable: true, targetedParams: discovered.length }
}
