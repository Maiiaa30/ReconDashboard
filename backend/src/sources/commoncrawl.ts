import { getJson, getText } from '../util/http'

// Passive URL discovery via the Common Crawl index (no key). Queries the newest
// monthly crawl's CDX index for every URL seen under the domain — complements
// the Wayback Machine with a different corpus.
// https://index.commoncrawl.org/

export interface CommonCrawlResult {
  index: string
  count: number
  sample: string[]
  withParams: string[]
}

interface CollInfo {
  id: string
  'cdx-api': string
}

export async function commonCrawlUrls(domain: string): Promise<CommonCrawlResult> {
  // collinfo.json lists indexes newest-first; use the most recent crawl.
  const indexes = await getJson<CollInfo[]>('https://index.commoncrawl.org/collinfo.json', { timeoutMs: 15_000 })
  const api = indexes?.[0]?.['cdx-api']
  const index = indexes?.[0]?.id ?? ''
  if (!api) return { index, count: 0, sample: [], withParams: [] }

  const url = `${api}?url=${encodeURIComponent(domain)}&matchType=domain&fl=url&output=json&limit=2000`
  const text = await getText(url, { timeoutMs: 20_000 })

  const urls = new Set<string>()
  for (const line of text.split('\n')) {
    const t = line.trim()
    if (!t) continue
    try {
      const o = JSON.parse(t) as { url?: string }
      if (o.url) urls.add(o.url)
    } catch {
      /* ignore malformed lines */
    }
  }
  const all = [...urls]
  return {
    index,
    count: all.length,
    sample: all.slice(0, 50),
    withParams: all.filter((u) => u.includes('?')).slice(0, 50),
  }
}
