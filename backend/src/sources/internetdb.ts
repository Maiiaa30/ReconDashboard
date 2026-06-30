import { getJsonOrNull } from '../util/http'
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

export async function internetDbLookup(ip: string): Promise<InternetDbRecord | null> {
  if (!isValidIp(ip)) throw new Error(`invalid ip: ${ip}`)
  const data = await getJsonOrNull<Partial<InternetDbRecord>>(
    `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
  )
  if (!data) return null // 404 => nothing known about this IP
  return {
    ip,
    ports: data.ports ?? [],
    cpes: data.cpes ?? [],
    hostnames: data.hostnames ?? [],
    tags: data.tags ?? [],
    vulns: data.vulns ?? [],
  }
}
