import { resolveDns } from './dns'
import { isInternalIp } from '../util/validate'

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

async function fetchOnce(url: string): Promise<FetchInfo | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'recon-dashboard/0.1 (+probe)' },
    })
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

export async function probeHost(host: string): Promise<ProbeResult> {
  const dns = await resolveDns(host).catch(() => null)
  const ip = dns?.a[0] ?? null
  const cnames = dns?.cname ?? []
  const apiByName = /^api[.-]/i.test(host) || /\bapi\b/i.test(host)

  // SSRF defense: refuse to fetch a host that resolves to an internal address.
  if (ip && isInternalIp(ip)) {
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
