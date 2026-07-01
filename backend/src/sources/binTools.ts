import { run, ToolNotFoundError } from '../util/exec'
import { assertPublicHost, guardedFetch } from './guard'
import type { Severity } from '../owasp/activeChecks'

// Runners for the extra recon binaries (katana, naabu, dalfox, sslscan) plus an
// HTTP-based WordPress enumeration (no binary). Each returns a single summary
// finding. SECURITY: every binary is invoked via execFile with an argv array
// (util/exec.ts) on an already-validated host. The HTTP runner is SSRF-guarded.

export interface ToolFinding {
  tool: string
  target: string
  severity: Severity
  title: string
  detail: string
  items: string[]
}

const ADMIN_PORTS = new Set([22, 23, 3389, 5900, 5985, 5986, 2375, 2376])
const MAX_ITEMS = 100

const linesOf = (s: string) =>
  s.split('\n').map((l) => l.trim()).filter(Boolean)

// --- katana (crawler) --------------------------------------------------------
export async function runKatana(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  const { stdout } = await run(
    'katana',
    ['-u', `${scheme}://${host}`, '-silent', '-nc', '-d', '2', '-jc', '-timeout', '10', '-c', '10'],
    { timeoutMs: 300_000, signal },
  )
  const urls = [...new Set(linesOf(stdout).filter((u) => /^https?:\/\//.test(u)))]
  if (!urls.length) return null
  const withParams = urls.filter((u) => u.includes('?'))
  return {
    tool: 'katana',
    target: host,
    severity: 'info',
    title: `Crawled ${urls.length} URL(s)`,
    detail: `${withParams.length} carry query parameters (testable)`,
    items: (withParams.length ? withParams : urls).slice(0, MAX_ITEMS),
  }
}

// --- naabu (fast port scan) --------------------------------------------------
export async function runNaabu(host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  // Connect scan (-s c) needs no raw sockets; top-1000 ports. naabu can exit
  // non-zero on its internal enumeration timeout, so keep any partial output.
  let stdout = ''
  try {
    const res = await run('naabu', ['-host', host, '-s', 'c', '-tp', '1000', '-silent', '-nc'], { timeoutMs: 300_000, signal })
    stdout = res.stdout
  } catch (err) {
    const e = err as { stdout?: string; code?: string }
    if (e.code === 'ENOENT') throw err
    stdout = e.stdout ?? ''
  }
  const ports = [...new Set(linesOf(stdout).map((l) => Number(l.split(':').pop())).filter((p) => Number.isFinite(p)))].sort(
    (a, b) => a - b,
  )
  if (!ports.length) return null
  const admin = ports.filter((p) => ADMIN_PORTS.has(p))
  return {
    tool: 'naabu',
    target: host,
    severity: admin.length ? 'medium' : 'low',
    title: `${ports.length} open port(s)`,
    detail: admin.length ? `Admin/remote ports open: ${admin.join(', ')}` : 'No admin ports in the open set',
    items: ports.map(String),
  }
}

// --- dalfox (XSS) ------------------------------------------------------------
export async function runDalfox(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  let stdout = ''
  try {
    const res = await run(
      'dalfox',
      ['url', `${scheme}://${host}`, '--silence', '--no-color', '--skip-bav', '--timeout', '10', '--worker', '30'],
      { timeoutMs: 300_000, signal },
    )
    stdout = res.stdout
  } catch (err) {
    // dalfox can exit non-zero with useful output.
    const e = err as { stdout?: string; code?: string }
    if (e.code === 'ENOENT') throw err
    stdout = e.stdout ?? ''
  }
  const pocs = linesOf(stdout).filter((l) => /\[POC\]|\[VULN\]/i.test(l))
  if (!pocs.length) return null
  return {
    tool: 'dalfox',
    target: host,
    severity: 'high',
    title: `Reflected XSS — ${pocs.length} PoC(s)`,
    detail: 'dalfox confirmed cross-site scripting',
    items: pocs.slice(0, MAX_ITEMS),
  }
}

// --- sslscan (TLS audit) -----------------------------------------------------
export async function runSslscan(host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  let stdout = ''
  try {
    const res = await run('sslscan', ['--no-colour', `${host}:443`], { timeoutMs: 90_000, signal })
    stdout = res.stdout
  } catch (err) {
    const e = err as { stdout?: string; code?: string }
    if (e.code === 'ENOENT') throw err
    stdout = e.stdout ?? ''
  }
  const weak: string[] = []
  if (/SSLv2\s+enabled/i.test(stdout)) weak.push('SSLv2 enabled (broken)')
  if (/SSLv3\s+enabled/i.test(stdout)) weak.push('SSLv3 enabled (POODLE)')
  if (/TLSv1\.0\s+enabled/i.test(stdout)) weak.push('TLS 1.0 enabled (deprecated)')
  if (/TLSv1\.1\s+enabled/i.test(stdout)) weak.push('TLS 1.1 enabled (deprecated)')
  if (/vulnerable to heartbleed/i.test(stdout)) weak.push('Heartbleed vulnerable')
  // Weak cipher bit-strengths (<128).
  for (const m of stdout.matchAll(/Accepted\s+\S+\s+(\d{2,3})\s+bits\s+([\w-]+)/gi)) {
    if (Number(m[1]) < 128) weak.push(`Weak cipher ${m[2]} (${m[1]} bits)`)
  }
  if (/RC4|MD5|EXPORT|DES-CBC/i.test(stdout)) weak.push('Insecure cipher suite offered (RC4/DES/EXPORT/MD5)')
  const expired = stdout.match(/Not valid after:\s*(.+)/i)?.[1]?.trim()

  if (!weak.length) return null
  return {
    tool: 'sslscan',
    target: host,
    severity: weak.some((w) => /SSLv|Heartbleed|RC4|DES|EXPORT/i.test(w)) ? 'medium' : 'low',
    title: `${weak.length} TLS weakness(es)`,
    detail: expired ? `Cert not valid after: ${expired}` : 'Outdated protocols or weak ciphers offered',
    items: [...new Set(weak)].slice(0, MAX_ITEMS),
  }
}

// --- sqlmap (SQL injection) --------------------------------------------------
// Autonomous run against a host: crawl for testable URLs + submit forms, then
// probe them for SQLi at the default (light) level/risk. --batch makes it fully
// non-interactive. sqlmap can be slow, so a longer 10-min cap (the job worker's
// 20-min timeout + AbortSignal still bound it and allow operator cancel).
export async function runSqlmap(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  let stdout = ''
  try {
    const res = await run(
      'sqlmap',
      [
        '-u', `${scheme}://${host}`,
        '--batch', // non-interactive: accept the safe defaults
        '--crawl=2', // discover testable URLs under the host
        '--forms', // also submit + test HTML forms
        '--level=1', '--risk=1', // keep it light (default depth/aggressiveness)
        '--random-agent',
        '--disable-coloring',
        '--timeout=10', '--retries=1',
        '--flush-session',
      ],
      { timeoutMs: 600_000, signal },
    )
    stdout = res.stdout
  } catch (err) {
    if (err instanceof ToolNotFoundError) throw err // -> handler reports "not installed"
    stdout = (err as { stdout?: string }).stdout ?? '' // sqlmap can exit non-zero with useful output
  }

  if (!/injection point|is vulnerable|appears to be injectable/i.test(stdout)) return null

  const params = [...new Set([...stdout.matchAll(/Parameter:\s*([^\n(]+?)\s*\(/gi)].map((m) => m[1].trim()))]
  const dbms = stdout.match(/back-end DBMS:\s*(.+)/i)?.[1]?.trim()
  const techniques = [...new Set([...stdout.matchAll(/^\s*Type:\s*(.+)$/gim)].map((m) => m[1].trim()))]
  const items = [
    ...params.map((p) => `Injectable parameter: ${p}`),
    ...(dbms ? [`Back-end DBMS: ${dbms}`] : []),
    ...techniques.map((t) => `Technique: ${t}`),
  ]
  return {
    tool: 'sqlmap',
    target: host,
    severity: 'high',
    title: `SQL injection — ${params.length || 1} parameter(s)`,
    detail: dbms ? `Confirmed SQLi (back-end DBMS: ${dbms})` : 'sqlmap confirmed SQL injection',
    items: items.length ? items.slice(0, MAX_ITEMS) : ['sqlmap flagged the target as injectable'],
  }
}

// --- WordPress enumeration (HTTP, no binary) ---------------------------------
const WP_TIMEOUT = 9_000

// SSRF-guarded: re-resolves the host on every redirect hop and refuses internal
// addresses, so a WordPress site that 30x-redirects into an internal URL can't
// be used to reach our own infrastructure.
async function wpFetch(url: string): Promise<{ status: number; body: string } | null> {
  const res = await guardedFetch(url, { timeoutMs: WP_TIMEOUT })
  return res ? { status: res.status, body: res.body } : null
}

export async function runWpEnum(scheme: string, host: string): Promise<ToolFinding | null> {
  // Guard the initial host against all resolved A/AAAA records before probing
  // (throws SsrfBlockedError with a clear message if it resolves internal).
  await assertPublicHost(host)
  const base = `${scheme}://${host}`

  const home = await wpFetch(base)
  const isWp = !!home && (/wp-content|wp-includes|<meta name="generator" content="WordPress/i.test(home.body))
  if (!isWp) return null

  const items: string[] = []
  // Version
  const gen = home!.body.match(/<meta name="generator" content="WordPress ([\d.]+)"/i)?.[1]
  const readme = await wpFetch(`${base}/readme.html`)
  const rmVer = readme?.body.match(/Version ([\d.]+)/i)?.[1]
  const version = gen || rmVer
  if (version) items.push(`WordPress ${version}`)

  // Users via the REST API
  const users = await wpFetch(`${base}/wp-json/wp/v2/users`)
  if (users && users.status === 200) {
    try {
      const arr = JSON.parse(users.body) as { slug?: string; name?: string }[]
      const names = arr.map((u) => u.slug || u.name).filter(Boolean)
      if (names.length) items.push(`Users (REST): ${names.slice(0, 20).join(', ')}`)
    } catch {
      /* not JSON */
    }
  }

  // Plugins referenced in the HTML
  const plugins = [...new Set([...home!.body.matchAll(/wp-content\/plugins\/([a-z0-9._-]+)/gi)].map((m) => m[1]))]
  if (plugins.length) items.push(`Plugins: ${plugins.slice(0, 20).join(', ')}`)

  // Exposed endpoints
  const xmlrpc = await wpFetch(`${base}/xmlrpc.php`)
  if (xmlrpc && (xmlrpc.status === 200 || xmlrpc.status === 405)) items.push('xmlrpc.php reachable (brute-force / pingback)')

  return {
    tool: 'wpenum',
    target: host,
    severity: items.some((i) => i.startsWith('Users')) ? 'medium' : 'low',
    title: 'WordPress detected',
    detail: version ? `Version ${version}` : 'Version not disclosed',
    items,
  }
}

// --- 403/401 bypass (HTTP, no binary) ----------------------------------------
// Finds commonly-protected paths that return 401/403, then retries each with a
// battery of classic access-control bypass tricks (spoofed client-IP headers,
// X-Original-URL / X-Rewrite-URL routing headers, path-normalisation quirks, and
// alternate HTTP methods). A retry that returns 2xx where the plain GET was
// forbidden is a real bypass. Every request goes through guardedFetch, so each
// hop is re-resolved and SSRF-blocked. Bounded so it can't fan out unboundedly.
const BYPASS_PATHS = [
  '/admin', '/admin/', '/.git/config', '/server-status', '/manager/html',
  '/.env', '/actuator', '/api/admin', '/wp-admin/', '/private', '/config', '/dashboard',
]
const IP_SPOOF_HEADERS = [
  'X-Forwarded-For', 'X-Forwarded-Host', 'X-Originating-IP', 'X-Remote-IP',
  'X-Client-IP', 'X-Host', 'X-Custom-IP-Authorization', 'X-Real-IP',
]
const BYPASS_METHODS = ['POST', 'HEAD', 'OPTIONS', 'PUT', 'TRACE']
const MAX_FORBIDDEN = 5 // cap how many protected paths we exhaustively retry
const BYPASS_TIMEOUT = 8_000

function pathMutations(p: string): string[] {
  return [
    `${p}/`, `${p}/.`, `/.${p}`, `//${p}//`, `${p}%20`, `${p}%09`,
    `${p}?`, `${p}#`, `${p}/..;/`, `${p};/`, `${p}.json`, p.toUpperCase(),
  ]
}

export async function runBypass403(scheme: string, host: string): Promise<ToolFinding | null> {
  await assertPublicHost(host)
  const base = `${scheme}://${host}`

  // 1. Find protected paths (plain GET returns 401/403).
  const forbidden: string[] = []
  for (const p of BYPASS_PATHS) {
    const res = await guardedFetch(`${base}${p}`, { timeoutMs: BYPASS_TIMEOUT })
    if (res && (res.status === 401 || res.status === 403)) forbidden.push(p)
    if (forbidden.length >= MAX_FORBIDDEN) break
  }
  if (!forbidden.length) return null

  // 2. For each, try the bypass battery; a 2xx means access was granted.
  const hits: string[] = []
  for (const p of forbidden) {
    const attempts: { url: string; method?: string; headers?: Record<string, string>; label: string }[] = [
      ...IP_SPOOF_HEADERS.map((h) => ({ url: `${base}${p}`, headers: { [h]: '127.0.0.1' }, label: `header ${h}: 127.0.0.1` })),
      { url: `${base}/`, headers: { 'X-Original-URL': p }, label: `header X-Original-URL: ${p}` },
      { url: `${base}/`, headers: { 'X-Rewrite-URL': p }, label: `header X-Rewrite-URL: ${p}` },
      ...pathMutations(p).map((mp) => ({ url: `${base}${mp}`, label: `path ${mp}` })),
      ...BYPASS_METHODS.map((m) => ({ url: `${base}${p}`, method: m, label: `method ${m}` })),
    ]
    for (const a of attempts) {
      const res = await guardedFetch(a.url, { timeoutMs: BYPASS_TIMEOUT, headers: a.headers, method: a.method })
      if (res && res.status >= 200 && res.status < 300) {
        hits.push(`${p} → ${res.status} via ${a.label}`)
      }
    }
  }

  if (!hits.length) return null
  return {
    tool: 'bypass403',
    target: host,
    severity: 'high',
    title: `403/401 bypass — ${hits.length} on ${forbidden.length} protected path(s)`,
    detail: 'A restricted path returned 2xx after an access-control bypass trick',
    items: hits.slice(0, MAX_ITEMS),
  }
}
