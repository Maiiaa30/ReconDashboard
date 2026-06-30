import { getJsonOrNull } from '../util/http'

// Shodan CVEDB — free, passive, no API key. Enriches a CVE id.
// https://cvedb.shodan.io/cve/{cve}
export interface CveRecord {
  cve_id: string
  summary?: string
  cvss?: number
  cvss_v3?: number
  kev?: boolean
  ranking_epss?: number
  references?: string[]
  published_time?: string
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i

// Process-lifetime cache: the same CVE recurs across many IPs/hosts in one
// exposure scan, so caching avoids hammering the free API. CVE data is static
// enough that a long-lived cache is fine.
const cveCache = new Map<string, CveRecord | null>()

export async function cveLookup(cveId: string): Promise<CveRecord | null> {
  if (!CVE_RE.test(cveId)) return null
  const id = cveId.toUpperCase()
  if (cveCache.has(id)) return cveCache.get(id) ?? null
  const rec = await getJsonOrNull<CveRecord>(`https://cvedb.shodan.io/cve/${encodeURIComponent(id)}`)
  cveCache.set(id, rec)
  return rec
}

// Enrich a set of CVE ids, tolerating individual failures.
export async function enrichCves(cveIds: string[]): Promise<CveRecord[]> {
  const unique = [...new Set(cveIds.map((c) => c.toUpperCase()))].filter((c) => CVE_RE.test(c))
  const out: CveRecord[] = []
  // Sequential with a small cap to be polite to the free API.
  for (const id of unique.slice(0, 100)) {
    try {
      const rec = await cveLookup(id)
      if (rec) out.push(rec)
      else out.push({ cve_id: id })
    } catch {
      out.push({ cve_id: id })
    }
  }
  return out
}
