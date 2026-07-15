import { getJson, getText } from '../util/http'

// Passive URL discovery via the Common Crawl index (no key). Queries the CDX
// index of the most recent crawls for every URL seen under the domain — a URL
// that appeared in an older crawl but not the latest is otherwise missed, so we
// merge the last few indexes to actually deliver a corpus distinct from Wayback.
// https://index.commoncrawl.org/

export interface CommonCrawlResult {
  indexes: string[]
  count: number
  truncated: boolean
  sample: string[]
  withParams: string[]
  urls: string[] // the FULL deduped list (persisted to url_corpus; not stored in the finding blob)
}

interface CollInfo {
  id: string
  'cdx-api': string
}

const INDEXES_TO_QUERY = 3
const PER_INDEX_LIMIT = 2000

export async function commonCrawlUrls(domain: string): Promise<CommonCrawlResult> {
  // collinfo.json lists indexes newest-first.
  const indexes = await getJson<CollInfo[]>('https://index.commoncrawl.org/collinfo.json', { timeoutMs: 15_000 })
  const recent = (indexes ?? []).slice(0, INDEXES_TO_QUERY)
  if (!recent.length) return { indexes: [], count: 0, truncated: false, sample: [], withParams: [], urls: [] }

  const urls = new Set<string>()
  const queried: string[] = []
  let truncated = false
  for (const coll of recent) {
    const api = coll['cdx-api']
    if (!api) continue
    try {
      const url = `${api}?url=${encodeURIComponent(domain)}&matchType=domain&fl=url&output=json&limit=${PER_INDEX_LIMIT}`
      const text = await getText(url, { timeoutMs: 20_000 })
      let lines = 0
      for (const line of text.split('\n')) {
        const t = line.trim()
        if (!t) continue
        lines++
        try {
          const o = JSON.parse(t) as { url?: string }
          if (o.url) urls.add(o.url)
        } catch {
          /* ignore malformed lines */
        }
      }
      if (lines >= PER_INDEX_LIMIT) truncated = true
      queried.push(coll.id)
    } catch {
      /* one index down — keep the others (each is best-effort) */
    }
  }

  const all = [...urls]
  return {
    indexes: queried,
    count: all.length,
    truncated,
    sample: all.slice(0, 50),
    withParams: all.filter((u) => u.includes('?')).slice(0, 50),
    urls: all.slice(0, 5000),
  }
}
