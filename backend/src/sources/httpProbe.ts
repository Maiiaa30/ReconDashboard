import { resolveDns } from './dns'
import { assertPublicHost } from './guard'
import { isInternalIp } from '../util/validate'
import { BROWSER_UA } from '../util/http'

// Lightweight HTTP probe (httpx-style): one GET to learn status, page title, and
// server header for a host. Tries https then http. Capped body read + tight
// timeout so it stays cheap. This is standard light recon (a single request a
// browser would also make), not a loud/active scan.

export interface ProbeResult {
  host: string
  scheme: 'https' | 'http' | null
  status: number | null
  title: string | null
  server: string | null
  ip: string | null
  url: string | null
  cnames: string[]
  loginHint: boolean
  apiHint: boolean
}

const TIMEOUT_MS = 8_000
const MAX_TITLE_BYTES = 64 * 1024

interface FetchInfo {
  status: number
  server: string | null
  title: string | null
  loginHint: boolean
  apiHint: boolean
}

// Follow redirects MANUALLY, re-resolving and SSRF-checking every hop — a
// public host can otherwise 30x-redirect the probe into http://127.0.0.1/, and
// fetch's redirect:'follow' would chase it without re-validating.
const MAX_REDIRECTS = 5

async function fetchOnce(startUrl: string): Promise<FetchInfo | null> {
  let current = startUrl
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let u: URL
    try {
      u = new URL(current)
    } catch {
      return null
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    try {
      await assertPublicHost(u.hostname)
    } catch {
      return null // this hop resolves to an internal address — refuse
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
    try {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        // Look like a real browser — a bot-ish UA gets challenged (Cloudflare
        // "Just a moment…" 403/503) by WAF-fronted hosts, which made every
        // subdomain look dead. This is still a single, standard GET.
        headers: {
          'User-Agent': BROWSER_UA,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      })

      // Redirect: re-loop so the next hop is guarded too.
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location')
        if (res.body) await res.body.cancel().catch(() => {})
        if (!loc) return { status: res.status, server: res.headers.get('server'), title: null, loginHint: false, apiHint: false }
        current = new URL(loc, current).toString()
        continue
      }

      const server = res.headers.get('server')
      const ct = res.headers.get('content-type') ?? ''
      let title: string | null = null
      let loginHint = false
      const apiHint = ct.includes('json') || ct.includes('graphql')

      if (ct.includes('html') && res.body) {
        const reader = res.body.getReader()
        const chunks: Uint8Array[] = []
        let total = 0
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          if (value) {
            chunks.push(value)
            total += value.byteLength
            if (total >= MAX_TITLE_BYTES) {
              await reader.cancel()
              break
            }
          }
        }
        const html = Buffer.concat(chunks).toString('utf8')
        const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
        if (m) title = m[1].replace(/\s+/g, ' ').trim().slice(0, 200)
        // Login heuristic: a password input, or login wording in the title.
        loginHint =
          /<input[^>]+type=["']?password/i.test(html) ||
          /\b(sign[\s-]?in|log[\s-]?in)\b/i.test(title ?? '')
      } else if (res.body) {
        await res.body.cancel().catch(() => {})
      }
      return { status: res.status, server, title, loginHint, apiHint }
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }
  return null // too many redirects
}

export async function probeHost(host: string): Promise<ProbeResult> {
  const dns = await resolveDns(host).catch(() => null)
  const ip = dns?.a[0] ?? null
  const cnames = dns?.cname ?? []
  const apiByName = /^api[.-]/i.test(host) || /\bapi\b/i.test(host)

  // SSRF defense: refuse if ANY resolved address (all A + AAAA records, not just
  // the first A) is internal. fetchOnce re-checks each redirect hop too.
  const allIps = [...(dns?.a ?? []), ...(dns?.aaaa ?? [])]
  if (allIps.some(isInternalIp)) {
    return {
      host, scheme: null, status: null, title: null, server: null, ip, url: null, cnames,
      loginHint: false, apiHint: apiByName,
    }
  }
  for (const scheme of ['https', 'http'] as const) {
    const url = `${scheme}://${host}`
    const res = await fetchOnce(url)
    if (res) {
      return {
        host, scheme, status: res.status, title: res.title, server: res.server, ip, url, cnames,
        loginHint: res.loginHint,
        apiHint: res.apiHint || apiByName,
      }
    }
  }
  return {
    host, scheme: null, status: null, title: null, server: null, ip, url: null, cnames,
    loginHint: false, apiHint: apiByName,
  }
}
