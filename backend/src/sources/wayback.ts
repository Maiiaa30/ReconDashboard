import { getJson } from '../util/http'

// Passive URL discovery via the Wayback Machine CDX API. Surfaces historical
// URLs (and crucially, their query parameters) the target ever exposed — a rich
// source of endpoints and params to test. Free, no key, pure HTTP.
// https://web.archive.org/cdx/search/cdx

export interface WaybackResult {
  count: number
  sample: string[]
  withParams: string[] // URLs carrying query params — the most testable
}

export async function waybackUrls(domain: string): Promise<WaybackResult> {
  // matchType=domain covers the apex and its subdomains; collapse=urlkey dedups.
  const url =
    `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}` +
    `&matchType=domain&fl=original&collapse=urlkey&output=json&limit=3000`

  const rows = await getJson<string[][]>(url, { timeoutMs: 20_000 })
  const urls = new Set<string>()
  // Row 0 is the header (["original"]); skip it.
  for (let i = 1; i < rows.length; i++) {
    const u = rows[i]?.[0]
    if (typeof u === 'string' && u) urls.add(u)
  }

  const all = [...urls]
  const withParams = all.filter((u) => u.includes('?'))
  return {
    count: all.length,
    sample: all.slice(0, 50),
    withParams: withParams.slice(0, 50),
  }
}
