import { getJsonOrNull } from '../util/http'
import { TtlCache } from '../util/cache'
import { isValidIp } from '../util/validate'

// Shodan InternetDB — free, passive, no API key. One IP at a time.
// https://internetdb.shodan.io/{ip}
export interface InternetDbRecord {
  ip: string
  ports: number[]
  cpes: string[]
  hostnames: string[]
  tags: string[]
  vulns: string[]
}

// Short TTL cache: the same IP recurs across domains / quick re-runs, and its
// exposure changes slowly. 10 min keeps us off the free API without going stale.
const idbCache = new TtlCache<string, InternetDbRecord | null>(10 * 60_000)

export async function internetDbLookup(ip: string): Promise<InternetDbRecord | null> {
  if (!isValidIp(ip)) throw new Error(`invalid ip: ${ip}`)
  const cached = idbCache.get(ip)
  if (cached !== undefined) return cached

  const data = await getJsonOrNull<Partial<InternetDbRecord>>(
    `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
  )
  const rec: InternetDbRecord | null = data
    ? {
        ip,
        ports: data.ports ?? [],
        cpes: data.cpes ?? [],
        hostnames: data.hostnames ?? [],
        tags: data.tags ?? [],
        vulns: data.vulns ?? [],
      }
    : null // 404 => nothing known about this IP
  idbCache.set(ip, rec)
  return rec
}
