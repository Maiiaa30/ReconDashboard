// SSRF guard for target-controlled hosts.
//
// A target's DNS can point a subdomain at an internal / Tailscale / loopback
// address. Any code that connects to a target host (a port scanner, a crawler,
// an HTTP probe) must refuse those, or an authorized external engagement turns
// into an accidental scan of our own infrastructure. isInternalIp already knows
// the private/loopback/CGNAT/ULA ranges; this module applies it at the point of
// connection, checking EVERY resolved A/AAAA record (not just the first).

import { resolveDns } from './dns'
import { isInternalIp, isValidIp } from '../util/validate'

export class SsrfBlockedError extends Error {
  constructor(public host: string, public ip: string) {
    super(`refusing to connect to ${host}: resolves to internal address ${ip}`)
    this.name = 'SsrfBlockedError'
  }
}

/**
 * Throw SsrfBlockedError if the host resolves to any internal address.
 * A host that does not resolve is allowed through — the underlying connection
 * will simply fail on its own, and we don't want DNS hiccups to mask a scan.
 *
 * RESIDUAL RISK (accepted for this threat model): this is a check-then-connect
 * guard — the tool/fetch re-resolves at connect time, so a hostile short-TTL
 * record that flips public→internal between the check and the connection (DNS
 * rebinding) can still defeat it. Fully closing this requires pinning the vetted
 * IP for the actual connection (the SNI/Host pattern in sources/origin.ts).
 */
export async function assertPublicHost(host: string): Promise<void> {
  // A literal IP host (http://127.0.0.1, http://[::1], http://169.254.169.254)
  // has no DNS to resolve, so the loop below would never see it — check it
  // directly. Without this, a literal internal IP slips past and is "blocked"
  // only by the connection happening to fail, which is not guaranteed.
  const bare = host.replace(/^\[/, '').replace(/\]$/, '')
  if (isValidIp(bare)) {
    if (isInternalIp(bare)) throw new SsrfBlockedError(host, bare)
    return // public literal IP — nothing to resolve
  }
  // `localhost` (and *.localhost) is loopback by convention but resolves via the
  // hosts file, which dns.resolve below bypasses — block it by name.
  const lower = bare.toLowerCase()
  if (lower === 'localhost' || lower.endsWith('.localhost')) throw new SsrfBlockedError(host, '127.0.0.1')
  let ips: string[]
  try {
    const dns = await resolveDns(host)
    ips = [...dns.a, ...dns.aaaa]
  } catch {
    return // invalid/unresolvable host — let the real connection fail naturally
  }
  for (const ip of ips) {
    if (isInternalIp(ip)) throw new SsrfBlockedError(host, ip)
  }
}

export interface GuardedResponse {
  status: number
  body: string
  finalUrl: string
}

/**
 * fetch() that re-resolves and SSRF-guards the host on EVERY redirect hop.
 * Node's redirect:'follow' would happily follow a public host's 30x into an
 * internal URL without re-checking; this follows manually and re-validates each
 * hop. Returns null on any failure (including an SSRF block or a redirect to an
 * internal host), so passive callers can treat "can't safely fetch" as "no data".
 */
export async function guardedFetch(
  url: string,
  opts: {
    timeoutMs?: number
    headers?: Record<string, string>
    maxRedirects?: number
    maxBytes?: number
    method?: string
    body?: string
    signal?: AbortSignal
  } = {},
): Promise<GuardedResponse | null> {
  const timeoutMs = opts.timeoutMs ?? 9_000
  const maxRedirects = opts.maxRedirects ?? 5
  const maxBytes = opts.maxBytes ?? 256 * 1024
  let current = url

  for (let hop = 0; hop <= maxRedirects; hop++) {
    // Bail promptly if the caller's job was cancelled / timed out.
    if (opts.signal?.aborted) return null
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
      return null // SSRF-blocked hop
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetch(current, {
        method: opts.method,
        body: opts.body,
        redirect: 'manual',
        // Combine our per-request timeout with the caller's cancel signal.
        signal: opts.signal ? AbortSignal.any([controller.signal, opts.signal]) : controller.signal,
        headers: { 'User-Agent': 'recon-dashboard/0.1', ...opts.headers },
      })
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location')
        if (!loc) {
          const body = (await res.text()).slice(0, maxBytes)
          return { status: res.status, body, finalUrl: current }
        }
        current = new URL(loc, current).toString()
        continue
      }
      const body = (await res.text()).slice(0, maxBytes)
      return { status: res.status, body, finalUrl: current }
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }
  return null // too many redirects
}
