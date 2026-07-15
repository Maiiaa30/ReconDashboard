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
async function wpFetch(url: string, signal?: AbortSignal): Promise<{ status: number; body: string } | null> {
  const res = await guardedFetch(url, { timeoutMs: WP_TIMEOUT, signal })
  return res ? { status: res.status, body: res.body } : null
}

export async function runWpEnum(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  // Guard the initial host against all resolved A/AAAA records before probing
  // (throws SsrfBlockedError with a clear message if it resolves internal).
  await assertPublicHost(host)
  const base = `${scheme}://${host}`

  const home = await wpFetch(base, signal)
  const isWp = !!home && (/wp-content|wp-includes|<meta name="generator" content="WordPress/i.test(home.body))
  if (!isWp) return null

  const items: string[] = []
  // Version
  const gen = home!.body.match(/<meta name="generator" content="WordPress ([\d.]+)"/i)?.[1]
  const readme = await wpFetch(`${base}/readme.html`, signal)
  const rmVer = readme?.body.match(/Version ([\d.]+)/i)?.[1]
  const version = gen || rmVer
  if (version) items.push(`WordPress ${version}`)

  // Users via the REST API
  const users = await wpFetch(`${base}/wp-json/wp/v2/users`, signal)
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
  const xmlrpc = await wpFetch(`${base}/xmlrpc.php`, signal)
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
// Headers that ask an upstream proxy/gateway to route to a different path — a
// classic control-vs-origin authorization gap.
const ROUTING_HEADERS = ['X-Original-URL', 'X-Rewrite-URL', 'X-Override-URL', 'X-Forwarded-Path']
const BYPASS_METHODS = ['POST', 'HEAD', 'OPTIONS', 'PUT', 'TRACE']
const MAX_FORBIDDEN = 5 // cap how many protected paths we exhaustively retry
const BYPASS_TIMEOUT = 8_000
// Operator-supplied paths must match a strict charset (audit AUDIT-2026-07): the
// path is interpolated into the request URL, so free-text could smuggle a host or
// a scheme. Encoding-bypass tricks are added by US afterwards, not accepted raw.
const OPERATOR_PATH_RE = /^\/[A-Za-z0-9._~%\-/?#&=]{0,300}$/

// Categorised path mutations, each labelled with its technique so a hit names the
// exact trick that worked.
function pathMutations(p: string): { path: string; technique: string }[] {
  return [
    { path: `${p}/`, technique: 'append: trailing slash' },
    { path: `${p}/.`, technique: 'append: /.' },
    { path: `/.${p}`, technique: 'prepend: /.' },
    { path: `//${p}//`, technique: 'append: double slash' },
    { path: `${p}%20`, technique: 'encoding: %20' },
    { path: `${p}%09`, technique: 'encoding: %09 (tab)' },
    { path: `${p}%2e`, technique: 'encoding: %2e' },
    { path: `${p}?`, technique: 'append: ?' },
    { path: `${p}#`, technique: 'append: #' },
    { path: `${p}/..;/`, technique: 'traversal: /..;/' },
    { path: `${p}..;/`, technique: 'traversal: ..;/' },
    { path: `${p};/`, technique: 'append: ;/ (matrix param)' },
    { path: `${p}/./`, technique: 'traversal: /./' },
    { path: `${p.replace(/\//g, '%2f')}`, technique: 'encoding: %2f slashes' },
    { path: `${p.replace(/\//g, '%252f')}`, technique: 'encoding: %252f (double)' },
    { path: `${p}.json`, technique: 'append: .json' },
    { path: p.toUpperCase(), technique: 'case: uppercase' },
  ]
}

// A bypass "worked" only if the 2xx body genuinely DIFFERS from the plain 401/403
// denial body — a soft-403 returns 200 with the same denied content, which must
// not be flagged. Match on length within 5% (plus a small floor for tiny bodies).
export function sameAsDenied(bypassBody: string, deniedBody: string): boolean {
  if (!deniedBody) return false
  const a = bypassBody.length
  const b = deniedBody.length
  const m = Math.max(a, b, 1)
  return Math.abs(a - b) / m <= 0.05
}

export async function runBypass403(
  scheme: string,
  host: string,
  paths?: string[],
  signal?: AbortSignal,
): Promise<ToolFinding | null> {
  await assertPublicHost(host)
  const base = `${scheme}://${host}`

  // Candidate paths: an explicit list (e.g. a 403 hit sent over from Fuzzing,
  // charset-guarded) or the built-in list of commonly-protected paths.
  const candidates =
    paths && paths.length
      ? paths.map((p) => (p.startsWith('/') ? p : `/${p}`)).filter((p) => OPERATOR_PATH_RE.test(p))
      : BYPASS_PATHS

  // 1. Find protected paths (plain GET returns 401/403) — and CAPTURE the denial
  //    body so a soft-403 (200 with the same body) can't be mistaken for a bypass.
  const forbidden: { path: string; deniedBody: string }[] = []
  for (const p of candidates) {
    if (signal?.aborted) break
    const res = await guardedFetch(`${base}${p}`, { timeoutMs: BYPASS_TIMEOUT, signal })
    if (res && (res.status === 401 || res.status === 403)) forbidden.push({ path: p, deniedBody: res.body })
    if (forbidden.length >= MAX_FORBIDDEN) break
  }
  // When the operator hand-picked a path (from Fuzzing), try to bypass it even if
  // the re-check didn't reproduce the 401/403 (transient WAF/rate-limit). Capture
  // whatever body the plain GET returns as the denial baseline for the diff.
  if (!forbidden.length) {
    if (paths && paths.length) {
      for (const p of candidates.slice(0, MAX_FORBIDDEN)) {
        const res = await guardedFetch(`${base}${p}`, { timeoutMs: BYPASS_TIMEOUT, signal })
        forbidden.push({ path: p, deniedBody: res?.body ?? '' })
      }
    } else {
      return null
    }
  }

  // 2. For each, run the categorised bypass battery; a 2xx whose body differs from
  //    the denial body means access was actually granted.
  const hits: string[] = []
  for (const { path: p, deniedBody } of forbidden) {
    if (signal?.aborted) break
    const attempts: { url: string; method?: string; headers?: Record<string, string>; technique: string }[] = [
      ...IP_SPOOF_HEADERS.map((h) => ({ url: `${base}${p}`, headers: { [h]: '127.0.0.1' }, technique: `header ${h}: 127.0.0.1` })),
      ...ROUTING_HEADERS.map((h) => ({ url: `${base}/`, headers: { [h]: p }, technique: `routing header ${h}: ${p}` })),
      ...pathMutations(p).map((m) => ({ url: `${base}${m.path}`, technique: m.technique })),
      ...BYPASS_METHODS.map((m) => ({ url: `${base}${p}`, method: m, technique: `verb tampering: ${m}` })),
      // method-override: ask the app to treat a GET as another verb via the header.
      { url: `${base}${p}`, headers: { 'X-HTTP-Method-Override': 'GET' }, technique: 'method-override: X-HTTP-Method-Override GET' },
    ]
    for (const a of attempts) {
      if (signal?.aborted) break
      const res = await guardedFetch(a.url, { timeoutMs: BYPASS_TIMEOUT, headers: a.headers, method: a.method, signal })
      if (res && res.status >= 200 && res.status < 300 && !sameAsDenied(res.body, deniedBody)) {
        hits.push(`${p} → ${res.status} via ${a.technique}`)
      }
    }
  }

  if (!hits.length) return null
  return {
    tool: 'bypass403',
    target: host,
    severity: 'high',
    title: `403/401 bypass — ${hits.length} on ${forbidden.length} protected path(s)`,
    detail: 'A restricted path returned 2xx (with content differing from the denial page) after an access-control bypass trick',
    items: hits.slice(0, MAX_ITEMS),
  }
}

// --- HTTP methods / verb-tampering audit (HTTP, no binary) -------------------
// Probes write-methods against the target root. A server that ACCEPTS PUT/DELETE/
// PATCH (doesn't reject with 400/403/404/405/501) may allow unintended writes or
// deletes. (TRACE/CONNECT are forbidden by the fetch spec so can't be sent here;
// the OWASP engine already covers TRACE.) Status-only, SSRF-guarded, always on.
const WRITE_METHODS = ['PUT', 'DELETE', 'PATCH']
export async function runHttpMethods(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  await assertPublicHost(host)
  const base = `${scheme}://${host}/`
  const accepted: string[] = []
  for (const m of WRITE_METHODS) {
    if (signal?.aborted) break
    const res = await guardedFetch(base, { method: m, timeoutMs: BYPASS_TIMEOUT, signal })
    if (res && ![400, 401, 403, 404, 405, 501].includes(res.status)) {
      accepted.push(`${m} → ${res.status} (not rejected)`)
    }
  }
  if (!accepted.length) return null
  return {
    tool: 'methods',
    target: host,
    severity: 'medium',
    title: `${accepted.length} write method(s) not rejected`,
    detail: 'Server did not reject PUT/DELETE/PATCH on / — check for unintended write/delete access',
    items: accepted,
  }
}

// --- Exposed datastores & DB admin panels (HTTP, no binary) ------------------
// Active exposure probe: HTTP-reachable datastores that answer metadata WITHOUT
// auth (Elasticsearch, CouchDB), Spring-actuator env leaks, and DB admin panels
// (phpMyAdmin/Adminer/pgAdmin/Fauxton/Mongo-Express). Confirmed by CONTENT
// SIGNATURE, not status code (a SPA catch-all 200s everything). Records only
// proof-of-exposure metadata — versions and index/db NAMES — never rows/docs.
export async function runDatastores(scheme: string, host: string, signal?: AbortSignal): Promise<ToolFinding | null> {
  await assertPublicHost(host)
  const hits: { label: string; severity: Severity; detail: string }[] = []
  const get = (url: string) => guardedFetch(url, { timeoutMs: BYPASS_TIMEOUT, signal })

  // Elasticsearch (:9200) — no-auth cluster info + index names.
  for (const sc of ['http', 'https']) {
    const root = await get(`${sc}://${host}:9200/`)
    if (root && root.status === 200 && /"cluster_name"|You Know, for Search|"lucene_version"/.test(root.body)) {
      const ver = root.body.match(/"number"\s*:\s*"([^"]+)"/)?.[1]
      const idx = await get(`${sc}://${host}:9200/_cat/indices?h=index`)
      const names = idx && idx.status === 200 ? linesOf(idx.body).slice(0, 15) : []
      hits.push({
        label: 'Elasticsearch',
        severity: 'critical',
        detail: `No-auth Elasticsearch${ver ? ` ${ver}` : ''} on :9200${names.length ? ` — indices: ${names.join(', ')}` : ''}`,
      })
      break
    }
  }

  // CouchDB (:5984) — welcome banner + db names.
  for (const sc of ['http', 'https']) {
    const root = await get(`${sc}://${host}:5984/`)
    if (root && root.status === 200 && /"couchdb"\s*:\s*"Welcome"/.test(root.body)) {
      const ver = root.body.match(/"version"\s*:\s*"([^"]+)"/)?.[1]
      const dbs = await get(`${sc}://${host}:5984/_all_dbs`)
      let names: string[] = []
      try {
        if (dbs?.status === 200) names = (JSON.parse(dbs.body) as string[]).slice(0, 15)
      } catch {
        /* not JSON */
      }
      hits.push({
        label: 'CouchDB',
        severity: 'critical',
        detail: `No-auth CouchDB${ver ? ` ${ver}` : ''} on :5984${names.length ? ` — dbs: ${names.join(', ')}` : ''}`,
      })
      break
    }
  }

  // Spring Boot actuator env leak (confirm by JSON shape).
  for (const p of ['/actuator/env', '/actuator']) {
    const r = await get(`${scheme}://${host}${p}`)
    if (r && r.status === 200 && /"activeProfiles"|"propertySources"|"_links"\s*:/.test(r.body)) {
      hits.push({ label: 'Spring actuator', severity: 'high', detail: `Exposed actuator at ${p} (config/env leak)` })
      break
    }
  }

  // DB admin panels — content-signature match on the web host.
  const panels: { path: string; sig: RegExp; name: string }[] = [
    { path: '/phpmyadmin/', sig: /phpMyAdmin/i, name: 'phpMyAdmin' },
    { path: '/adminer.php', sig: /Adminer/i, name: 'Adminer' },
    { path: '/adminer/', sig: /Adminer/i, name: 'Adminer' },
    { path: '/pgadmin4/', sig: /pgAdmin/i, name: 'pgAdmin' },
    { path: '/_utils/', sig: /Fauxton|CouchDB/i, name: 'CouchDB Fauxton' },
    { path: '/mongo-express/', sig: /Mongo Express/i, name: 'Mongo Express' },
  ]
  const seenPanels = new Set<string>()
  for (const pn of panels) {
    if (seenPanels.has(pn.name)) continue
    const r = await get(`${scheme}://${host}${pn.path}`)
    if (r && r.status >= 200 && r.status < 400 && pn.sig.test(r.body)) {
      seenPanels.add(pn.name)
      hits.push({ label: pn.name, severity: 'medium', detail: `${pn.name} admin panel exposed at ${pn.path}` })
    }
  }

  // Orchestration / infra control planes — the crown jewels. An unauthenticated
  // Docker/kubelet/etcd endpoint is host- or cluster-level RCE. Content-signature
  // gated (a SPA catch-all 200s everything), proof-only.
  const infra: { name: string; url: string; sig: RegExp; severity: Severity; detail: string }[] = [
    { name: 'Docker API', url: `http://${host}:2375/version`, sig: /"ApiVersion"|"GitCommit"/, severity: 'critical', detail: 'Unauthenticated Docker Engine API on :2375 (/version reachable) — full host takeover' },
    { name: 'Docker API', url: `https://${host}:2376/version`, sig: /"ApiVersion"|"GitCommit"/, severity: 'critical', detail: 'Unauthenticated Docker Engine API on :2376 — full host takeover' },
    { name: 'kubelet', url: `https://${host}:10250/pods`, sig: /"kind"\s*:\s*"PodList"/, severity: 'critical', detail: 'Unauthenticated kubelet /pods on :10250 — cluster foothold' },
    { name: 'etcd', url: `http://${host}:2379/version`, sig: /"etcdserver"|"etcdcluster"/, severity: 'critical', detail: 'Unauthenticated etcd on :2379 — cluster secrets' },
    { name: 'Consul', url: `http://${host}:8500/v1/agent/self`, sig: /"Config"\s*:|"Member"\s*:/, severity: 'high', detail: 'Unauthenticated Consul agent API on :8500' },
    { name: 'Prometheus', url: `http://${host}:9090/api/v1/status/config`, sig: /"status"\s*:\s*"success"/, severity: 'high', detail: 'Unauthenticated Prometheus config on :9090 — internal targets/labels leak' },
    { name: 'Jenkins script console', url: `${scheme}://${host}/script`, sig: /Script Console|System Groovy/i, severity: 'critical', detail: 'Jenkins /script Groovy console reachable — RCE' },
    { name: 'Grafana (anon)', url: `${scheme}://${host}/api/org`, sig: /"id"\s*:\s*\d+\s*,\s*"name"/, severity: 'medium', detail: 'Grafana /api/org reachable without auth — anonymous access enabled' },
  ]
  const seenInfra = new Set<string>()
  for (const probe of infra) {
    if (signal?.aborted) break
    if (seenInfra.has(probe.name)) continue
    const r = await get(probe.url)
    if (r && r.status === 200 && probe.sig.test(r.body)) {
      seenInfra.add(probe.name)
      hits.push({ label: probe.name, severity: probe.severity, detail: probe.detail })
    }
  }

  if (!hits.length) return null
  const worst: Severity = hits.some((h) => h.severity === 'critical')
    ? 'critical'
    : hits.some((h) => h.severity === 'high')
      ? 'high'
      : 'medium'
  return {
    tool: 'datastores',
    target: host,
    severity: worst,
    title: `${hits.length} exposed datastore/panel(s)`,
    detail: 'Datastores/admin panels reachable — proof-of-exposure only, no data pulled',
    items: hits.map((h) => `[${h.severity}] ${h.label}: ${h.detail}`),
  }
}
