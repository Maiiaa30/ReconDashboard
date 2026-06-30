import { Socket } from 'node:net'
import { isValidDomain } from '../util/validate'

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
  const match = text.match(/whois:\s*([a-z0-9.-]+)/i) ?? text.match(/Registrar WHOIS Server:\s*([a-z0-9.-]+)/i)
  return match ? match[1].trim().toLowerCase() : null
}

export interface WhoisResult {
  server: string
  raw: string
}

export async function whoisDomain(domain: string): Promise<WhoisResult> {
  if (!isValidDomain(domain)) throw new Error(`invalid domain: ${domain}`)

  const ianaResponse = await whoisQuery('whois.iana.org', domain)
  const referral = parseReferral(ianaResponse)

  if (referral && referral !== 'whois.iana.org') {
    try {
      const authoritative = await whoisQuery(referral, domain)
      // Some registries refer once more (thin registries). One hop is enough here.
      const secondReferral = parseReferral(authoritative)
      if (secondReferral && secondReferral !== referral) {
        try {
          const final = await whoisQuery(secondReferral, domain)
          return { server: secondReferral, raw: final || authoritative }
        } catch {
          return { server: referral, raw: authoritative }
        }
      }
      return { server: referral, raw: authoritative }
    } catch {
      return { server: 'whois.iana.org', raw: ianaResponse }
    }
  }

  return { server: 'whois.iana.org', raw: ianaResponse }
}
