import { request as httpsRequest } from 'node:https'
import { request as httpRequest } from 'node:http'
import { cdnForIp } from './cdn'
import { isInternalIp } from '../util/validate'

// Origin-server discovery: given a candidate IP and the target domain, connect
// DIRECTLY to the IP (bypassing the CDN) with Host header + SNI = domain, and
// see whether it serves the site. A non-CDN IP that returns the site's content
// is the real origin behind the WAF/CDN.

export interface OriginProbe {
  ip: string
  reachable: boolean
  scheme: 'https' | 'http' | null
  status: number | null
  title: string | null
  server: string | null
}

const TIMEOUT_MS = 6_000
const MAX_BYTES = 64 * 1024

function fetchDirect(
  ip: string,
  domain: string,
  scheme: 'https' | 'http',
): Promise<{ status: number; title: string | null; server: string | null } | null> {
  return new Promise((resolve) => {
    let settled = false
    const done = (v: { status: number; title: string | null; server: string | null } | null) => {
      if (settled) return
      settled = true
      resolve(v)
    }
    const opts = {
      host: ip,
      servername: domain, // TLS SNI = the real domain
      path: '/',
      method: 'GET',
      headers: { Host: domain, 'User-Agent': 'recon-dashboard/0.1 (+origin)' },
      timeout: TIMEOUT_MS,
      rejectUnauthorized: false, // origin cert may not validate against the bare IP
    }
    const req = (scheme === 'https' ? httpsRequest : httpRequest)(opts, (res) => {
      const chunks: Buffer[] = []
      let total = 0
      res.on('data', (c: Buffer) => {
        total += c.length
        if (total <= MAX_BYTES) chunks.push(c)
        if (total > MAX_BYTES) res.destroy()
      })
      res.on('end', () => {
        const html = Buffer.concat(chunks).toString('utf8')
        const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
        done({
          status: res.statusCode ?? 0,
          title: m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 200) : null,
          server: (res.headers['server'] as string) ?? null,
        })
      })
      res.on('error', () => done(null))
    })
    // Hard backstop + socket-timeout: always resolve so a candidate can't hang.
    const hard = setTimeout(() => {
      req.destroy()
      done(null)
    }, TIMEOUT_MS + 2000)
    hard.unref()
    req.on('timeout', () => {
      req.destroy()
      done(null)
    })
    req.on('error', () => done(null))
    req.on('close', () => done(null))
    req.end()
  })
}

export async function probeOrigin(ip: string, domain: string): Promise<OriginProbe> {
  for (const scheme of ['https', 'http'] as const) {
    const res = await fetchDirect(ip, domain, scheme)
    if (res) {
      return { ip, reachable: true, scheme, status: res.status, title: res.title, server: res.server }
    }
  }
  return { ip, reachable: false, scheme: null, status: null, title: null, server: null }
}

// Candidate origin IPs = IPs seen across the domain's hosts/DNS that are NOT
// known CDN edges and not internal.
export function originCandidates(ips: string[]): string[] {
  return [...new Set(ips)].filter((ip) => ip && !cdnForIp(ip) && !isInternalIp(ip))
}
