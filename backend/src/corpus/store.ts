import { and, desc, eq, isNull } from 'drizzle-orm'
import { db } from '../db/index'
import { urlCorpus } from '../db/schema'

// Persisted passive URL corpus. Recon collects thousands of URLs per domain
// (Wayback / Common Crawl / urlscan / OTX); this stores them all so JS-recon,
// parameter discovery and the OWASP checks see the whole surface, not a 50-URL
// sample. One row per (domain, url); re-scans dedupe and keep the first-seen time.

export interface CorpusUrl {
  url: string
  source: string
}

// Cap what a single ingest can insert so a pathological source can't blow up the
// table (and to bound the transaction).
const MAX_INGEST = 20_000
const URL_MAX_LEN = 2048

function hostOf(u: string): string | null {
  try {
    return new URL(u).hostname || null
  } catch {
    return null
  }
}

// Insert new (domain, url) rows; existing ones are left untouched (first-seen
// wins). Returns how many rows were newly inserted.
export function recordCorpusUrls(domainId: number, urls: CorpusUrl[]): number {
  const seen = new Set<string>()
  const rows = urls
    .filter((u) => typeof u.url === 'string' && u.url.length > 0 && u.url.length <= URL_MAX_LEN)
    .filter((u) => (seen.has(u.url) ? false : (seen.add(u.url), true)))
    .slice(0, MAX_INGEST)
    .map((u) => ({ domainId, url: u.url, host: hostOf(u.url), source: u.source }))
  if (!rows.length) return 0
  let inserted = 0
  db.transaction((tx) => {
    for (let i = 0; i < rows.length; i += 500) {
      const res = tx.insert(urlCorpus).values(rows.slice(i, i + 500)).onConflictDoNothing().run()
      inserted += res.changes
    }
  })
  return inserted
}

// All corpus URLs for a domain (newest first), bounded by limit.
export function getCorpusUrls(domainId: number, opts: { limit?: number } = {}): string[] {
  const limit = Math.max(1, Math.min(opts.limit ?? 20_000, 50_000))
  return db
    .select({ url: urlCorpus.url })
    .from(urlCorpus)
    .where(domainId == null ? isNull(urlCorpus.domainId) : eq(urlCorpus.domainId, domainId))
    .orderBy(desc(urlCorpus.id))
    .limit(limit)
    .all()
    .map((r) => r.url)
}

// Count of stored corpus URLs for a domain (for status/UI).
export function countCorpusUrls(domainId: number): number {
  return db
    .select({ id: urlCorpus.id })
    .from(urlCorpus)
    .where(and(eq(urlCorpus.domainId, domainId)))
    .all().length
}
