import { Socket } from 'node:net'
import { assertPublicHost } from './guard'
import { isValidDomain, isValidIp } from '../util/validate'

// Minimal, dependency-free WHOIS client (TCP port 43). Passive.
// Strategy: ask whois.iana.org which server is authoritative for the TLD,
// then query that server. Falls back to the IANA response if no referral.

const QUERY_TIMEOUT_MS = 12_000
const MAX_RESPONSE_BYTES = 256 * 1024

function whoisQuery(server: string, query: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = new Socket()
    let data = ''
    let bytes = 0
    let settled = false

    // Idle timeout AND a hard overall deadline (a server that dribbles bytes
    // slowly could otherwise keep the connection alive well past the idle cap).
    socket.setTimeout(QUERY_TIMEOUT_MS)
    const hardDeadline = setTimeout(() => done(new Error('whois overall timeout')), QUERY_TIMEOUT_MS)
    hardDeadline.unref()

    function done(err?: Error) {
      if (settled) return
      settled = true
      clearTimeout(hardDeadline)
      socket.destroy()
      if (err) reject(err)
      else resolve(data)
    }

    socket.on('timeout', () => done(new Error('whois timeout')))
    socket.on('error', (err) => done(err))
    socket.on('data', (chunk) => {
      bytes += chunk.length
      if (bytes > MAX_RESPONSE_BYTES) {
        done()
        return
      }
      data += chunk.toString('utf8')
    })
    socket.on('close', () => done())
    socket.connect(43, server, () => {
      socket.write(`${query}\r\n`)
    })
  })
}

function parseReferral(text: string): string | null {
  // `refer:` is what IANA returns for IP ranges (the responsible RIR); `whois:`
  // is what it returns for TLDs; "Registrar WHOIS Server:" is the registrar hop.
  const match =
    text.match(/refer:\s*([a-z0-9.-]+)/i) ??
    text.match(/whois:\s*([a-z0-9.-]+)/i) ??
    text.match(/Registrar WHOIS Server:\s*([a-z0-9.-]+)/i)
  return match ? match[1].trim().toLowerCase() : null
}

export interface WhoisResult {
  query: string
  kind: 'domain' | 'ip'
  server: string
  raw: string
}

// Core lookup chain: ask IANA which server is authoritative, follow up to two
// referral hops, fall back to the most specific response we managed to get.
// `query` is already validated by the caller.
async function whoisResolve(query: string, kind: 'domain' | 'ip'): Promise<WhoisResult> {
  const ianaResponse = await whoisQuery('whois.iana.org', query)
  const referral = parseReferral(ianaResponse)

  if (referral && referral !== 'whois.iana.org') {
    try {
      // SSRF: the referral host comes from the (untrusted) IANA/registrar
      // response. Refuse a referral that resolves to an internal address before
      // opening the port-43 socket; on refusal we fall back to the IANA response.
      await assertPublicHost(referral)
      const authoritative = await whoisQuery(referral, query)
      // Some registries refer once more (thin registries). One hop is enough here.
      const secondReferral = parseReferral(authoritative)
      if (secondReferral && secondReferral !== referral) {
        try {
          await assertPublicHost(secondReferral)
          const final = await whoisQuery(secondReferral, query)
          return { query, kind, server: secondReferral, raw: final || authoritative }
        } catch {
          return { query, kind, server: referral, raw: authoritative }
        }
      }
      return { query, kind, server: referral, raw: authoritative }
    } catch {
      return { query, kind, server: 'whois.iana.org', raw: ianaResponse }
    }
  }

  return { query, kind, server: 'whois.iana.org', raw: ianaResponse }
}

export async function whoisDomain(domain: string): Promise<WhoisResult> {
  if (!isValidDomain(domain)) throw new Error(`invalid domain: ${domain}`)
  return whoisResolve(domain, 'domain')
}

/** WHOIS for a domain OR an IP address. IPs resolve to the responsible RIR. */
export async function whoisLookup(query: string): Promise<WhoisResult> {
  const q = query.trim().toLowerCase().replace(/\.$/, '')
  if (isValidIp(q)) return whoisResolve(q, 'ip')
  if (isValidDomain(q)) return whoisResolve(q, 'domain')
  throw new Error(`invalid query (expected a domain or IP): ${query}`)
}
