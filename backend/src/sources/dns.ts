import { Resolver } from 'node:dns/promises'
import { isValidDomain, isValidHostname } from '../util/validate'

export interface DnsRecords {
  a: string[]
  aaaa: string[]
  cname: string[]
  mx: { exchange: string; priority: number }[]
  ns: string[]
  txt: string[]
}

// Passive DNS resolution via public resolvers. Each record type is best-effort;
// a missing record (NODATA/NXDOMAIN) yields an empty array rather than an error.
export async function resolveDns(host: string): Promise<DnsRecords> {
  if (!isValidDomain(host) && !isValidHostname(host)) {
    throw new Error(`invalid host: ${host}`)
  }

  const resolver = new Resolver({ timeout: 8_000, tries: 2 })
  resolver.setServers(['1.1.1.1', '8.8.8.8'])

  const safe = async <T>(p: Promise<T>): Promise<T | []> => {
    try {
      return await p
    } catch {
      return []
    }
  }

  const [a, aaaa, cname, mx, ns, txt] = await Promise.all([
    safe(resolver.resolve4(host)),
    safe(resolver.resolve6(host)),
    safe(resolver.resolveCname(host)),
    safe(resolver.resolveMx(host)),
    safe(resolver.resolveNs(host)),
    safe(resolver.resolveTxt(host)),
  ])

  return {
    a: a as string[],
    aaaa: aaaa as string[],
    cname: cname as string[],
    mx: (mx as { exchange: string; priority: number }[]).map((m) => ({
      exchange: m.exchange,
      priority: m.priority,
    })),
    ns: ns as string[],
    txt: (txt as string[][]).map((parts) => parts.join('')),
  }
}

/** First resolvable IPv4 for a host, or null. */
export async function firstIpv4(host: string): Promise<string | null> {
  const records = await resolveDns(host)
  return records.a[0] ?? null
}
