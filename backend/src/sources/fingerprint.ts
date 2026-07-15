import { resolveDns } from './dns'
import { guardedFetchBytes, guardedFetchRaw } from './guard'
import { faviconHash } from '../util/mmh3'
import { isInternalIp } from '../util/validate'

// Passive technology fingerprint: one GET to the host, then map response
// headers, cookies, and a slice of HTML (plus any InternetDB CPEs) to an OS,
// server, and a stack of detected technologies. This is standard light recon —
// a single request a browser would also make — not an active scan.

export interface Fingerprint {
  url: string | null
  scheme: 'https' | 'http' | null
  status: number | null
  os: string | null
  server: string | null
  poweredBy: string | null
  cdn: string | null
  technologies: string[]
  headers: Record<string, string>
  faviconHash: number | null // mmh3 of the favicon — correlates assets across IPs
}

const MAX_FAVICON_BYTES = 256 * 1024

// Fetch the site's favicon (the <link rel=icon> href if present, else /favicon.ico)
// and compute its mmh3 hash. SSRF-guarded, byte-capped. Null on any failure.
async function faviconHashFor(base: string, html: string): Promise<number | null> {
  const linkHref = (html.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>/i) || [])[0]
  const href = linkHref ? (linkHref.match(/href=["']([^"']+)["']/i) || [])[1] : null
  let url: string
  try {
    url = new URL(href || '/favicon.ico', base).toString()
  } catch {
    return null
  }
  const res = await guardedFetchBytes(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_FAVICON_BYTES })
  if (!res || res.status !== 200 || res.bytes.length === 0) return null
  return faviconHash(res.bytes)
}

const TIMEOUT_MS = 9_000
const MAX_HTML = 96 * 1024

// Headers worth surfacing verbatim in the UI.
const INTERESTING_HEADERS = [
  'server', 'x-powered-by', 'via', 'x-aspnet-version', 'x-generator', 'x-drupal-cache',
  'x-vercel-id', 'x-served-by', 'cf-ray', 'x-amz-cf-id', 'x-fastly-request-id', 'content-type',
]

function osFromSignals(server: string, poweredBy: string, cookieNames: string[], cpes: string[]): string | null {
  const s = server.toLowerCase()
  const p = poweredBy.toLowerCase()
  const cookies = cookieNames.map((c) => c.toLowerCase())
  // Windows signals.
  if (/iis|microsoft|win32|win64|asp\.net/.test(s + p)) return 'Windows Server'
  if (cookies.some((c) => c.startsWith('asp.net') || c.startsWith('aspsession'))) return 'Windows Server'
  // Linux distro named in the Server banner, e.g. "Apache/2.4 (Ubuntu)".
  const distro = (server.match(/\((ubuntu|debian|centos|red hat|fedora|unix|freebsd|opensuse|oracle)\)/i) || [])[1]
  if (distro) return distro.replace(/\b\w/g, (m) => m.toUpperCase())
  // CPE OS component (cpe:/o:vendor:product or cpe:2.3:o:vendor:product).
  for (const cpe of cpes) {
    const m = cpe.match(/cpe:(?:2\.3:)?\/?o:([^:]+):([^:]+)/i)
    if (m) {
      const vendor = m[1].toLowerCase()
      const product = m[2].toLowerCase()
      if (vendor.includes('microsoft') || product.includes('windows')) return 'Windows'
      if (product.includes('ubuntu')) return 'Ubuntu'
      if (product.includes('debian')) return 'Debian'
      if (product.includes('linux')) return 'Linux'
    }
  }
  // nginx/Apache/LiteSpeed with no Windows markers → almost certainly Unix-like.
  if (/nginx|apache|litespeed|openresty/.test(s)) return 'Linux / Unix (likely)'
  return null
}

function techFromSignals(
  server: string,
  poweredBy: string,
  generator: string,
  cookieNames: string[],
  html: string,
  cpes: string[],
): string[] {
  const tech = new Set<string>()
  const add = (t: string | null | undefined) => t && tech.add(t)

  // Server software (keep version if present).
  const srvMatch = server.match(/(nginx|apache|microsoft-iis|litespeed|openresty|caddy|cloudflare)[/ ]?([\d.]+)?/i)
  if (srvMatch) add(`${srvMatch[1].replace(/microsoft-iis/i, 'IIS')}${srvMatch[2] ? ` ${srvMatch[2]}` : ''}`)

  // Language / framework from X-Powered-By (e.g. "PHP/7.4.3", "ASP.NET", "Express").
  for (const part of poweredBy.split(/[,;]/)) {
    const m = part.trim().match(/([a-z.+ -]+?)[/ ]?([\d.]+)?$/i)
    if (m && m[1].trim()) add(`${m[1].trim()}${m[2] ? ` ${m[2]}` : ''}`)
  }

  // CMS / generator.
  if (generator) add(generator.split(/\s+/).slice(0, 3).join(' '))

  // Cookie fingerprints.
  const cookies = cookieNames.map((c) => c.toLowerCase())
  const cookieMap: [RegExp, string][] = [
    [/^phpsessid/, 'PHP'], [/^jsessionid/, 'Java'], [/^asp\.net_sessionid|^aspsession/, 'ASP.NET'],
    [/^laravel_session/, 'Laravel'], [/^ci_session/, 'CodeIgniter'], [/^csrftoken|^sessionid/, 'Django'],
    [/^_session_id/, 'Ruby on Rails'], [/^wordpress_|^wp-/, 'WordPress'], [/^_shopify|^shopify/, 'Shopify'],
    [/^connect\.sid/, 'Express'], [/^xsrf-token/, 'Angular'],
  ]
  for (const c of cookies) for (const [re, name] of cookieMap) if (re.test(c)) add(name)

  // HTML body hints.
  const bodyMap: [RegExp, string][] = [
    [/wp-content|wp-includes/i, 'WordPress'], [/\/_next\/|__NEXT_DATA__/i, 'Next.js'],
    [/window\.__NUXT__|\/_nuxt\//i, 'Nuxt'], [/data-reactroot|react(?:-dom)?\./i, 'React'],
    [/ng-version=|ng-app/i, 'Angular'], [/\/sites\/default\/files|Drupal\.settings/i, 'Drupal'],
    [/cdn\.shopify\.com/i, 'Shopify'], [/static\.wixstatic\.com/i, 'Wix'], [/squarespace/i, 'Squarespace'],
  ]
  for (const [re, name] of bodyMap) if (re.test(html)) add(name)

  // CPE application components from InternetDB.
  for (const cpe of cpes) {
    const m = cpe.match(/cpe:(?:2\.3:)?\/?a:([^:]+):([^:]+):?([\d.]+)?/i)
    if (m) {
      const product = m[2].replace(/internet_information_services/i, 'IIS').replace(/_/g, ' ')
      add(`${product}${m[3] ? ` ${m[3]}` : ''}`)
    }
  }

  // Drop a bare "Name" when a versioned "Name x.y" is also present.
  const arr = [...tech]
  return arr.filter(
    (t) => /\s[\d.]+$/.test(t) || !arr.some((o) => o !== t && o.toLowerCase().startsWith(`${t.toLowerCase()} `)),
  )
}

function cdnFromSignals(headers: Record<string, string>, server: string): string | null {
  if (/cloudflare/i.test(server) || headers['cf-ray']) return 'Cloudflare'
  if (headers['x-amz-cf-id']) return 'CloudFront'
  if (headers['x-fastly-request-id'] || /fastly/i.test(headers['via'] ?? '')) return 'Fastly'
  if (headers['x-vercel-id']) return 'Vercel'
  if (/akamai/i.test((headers['via'] ?? '') + (headers['x-served-by'] ?? ''))) return 'Akamai'
  return null
}

async function fetchOnce(url: string): Promise<{
  status: number
  headers: Record<string, string>
  cookieNames: string[]
  html: string
} | null> {
  // Guarded fetch that re-checks every redirect hop — a target can 30x this
  // passive probe into an internal address, and Node's redirect:'follow' would
  // chase it without re-validating.
  const res = await guardedFetchRaw(url, {
    method: 'GET',
    follow: true,
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_HTML,
    headers: { 'User-Agent': 'recon-dashboard/0.1 (+passive fingerprint)' },
  })
  if (!res) return null

  const headers: Record<string, string> = {}
  for (const name of INTERESTING_HEADERS) {
    const v = res.headers.get(name)
    if (v) headers[name] = v
  }
  const setCookies = res.headers.getSetCookie?.() ?? []
  const cookieNames = setCookies.map((c) => c.split('=')[0].trim()).filter(Boolean)
  const ct = res.headers.get('content-type') ?? ''
  const html = ct.includes('html') ? res.body : ''
  return { status: res.status, headers, cookieNames, html }
}

export async function fingerprintHost(host: string, cpes: string[] = []): Promise<Fingerprint> {
  const empty: Fingerprint = {
    url: null, scheme: null, status: null, os: null, server: null, poweredBy: null,
    cdn: null, technologies: [], headers: {}, faviconHash: null,
  }

  // SSRF defense: refuse if ANY resolved address (all A + AAAA, not just the
  // first A) is internal. guardedFetchRaw re-checks each redirect hop too.
  const dns = await resolveDns(host).catch(() => null)
  const allIps = [...(dns?.a ?? []), ...(dns?.aaaa ?? [])]
  if (allIps.some(isInternalIp)) return empty

  for (const scheme of ['https', 'http'] as const) {
    const res = await fetchOnce(`${scheme}://${host}`)
    if (!res) continue
    const server = res.headers['server'] ?? ''
    const poweredBy = res.headers['x-powered-by'] ?? res.headers['x-aspnet-version'] ?? ''
    const generator = res.headers['x-generator'] ?? (res.html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) || [])[1] ?? ''
    const favicon = await faviconHashFor(`${scheme}://${host}`, res.html).catch(() => null)
    return {
      url: `${scheme}://${host}`,
      scheme,
      status: res.status,
      os: osFromSignals(server, poweredBy, res.cookieNames, cpes),
      server: server || null,
      poweredBy: poweredBy || null,
      cdn: cdnFromSignals(res.headers, server),
      technologies: techFromSignals(server, poweredBy, generator, res.cookieNames, res.html, cpes),
      headers: res.headers,
      faviconHash: favicon,
    }
  }
  // Couldn't reach the host over HTTP(S); still surface any CPE-derived tech.
  return {
    ...empty,
    os: osFromSignals('', '', [], cpes),
    technologies: techFromSignals('', '', '', [], '', cpes),
    faviconHash: null,
  }
}
