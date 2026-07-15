import { describe, expect, it, vi } from 'vitest'

// Real in-memory DB (just the url_corpus table) so we exercise the actual
// insert/dedup SQL. The store only uses the core query builder.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE url_corpus (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer,
      url text NOT NULL,
      host text,
      source text NOT NULL,
      first_seen integer NOT NULL
    );
    CREATE UNIQUE INDEX url_corpus_domain_url_uq ON url_corpus (domain_id, url);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { countCorpusUrls, getCorpusUrls, recordCorpusUrls } from './store'

describe('url corpus store', () => {
  it('persists the full set (not a 50-URL sample) and reads it back', () => {
    const many = Array.from({ length: 3000 }, (_, i) => ({ url: `https://t.com/p/${i}?a=${i}`, source: 'wayback' }))
    const added = recordCorpusUrls(1, many)
    expect(added).toBe(3000)
    expect(countCorpusUrls(1)).toBe(3000)
    expect(getCorpusUrls(1, { limit: 5000 }).length).toBe(3000)
  })

  it('dedupes on re-scan (first-seen wins) and only counts new rows', () => {
    recordCorpusUrls(2, [{ url: 'https://a.com/x', source: 'wayback' }])
    const added = recordCorpusUrls(2, [
      { url: 'https://a.com/x', source: 'commoncrawl' }, // dup — ignored
      { url: 'https://a.com/y', source: 'commoncrawl' }, // new
    ])
    expect(added).toBe(1)
    expect(getCorpusUrls(2).sort()).toEqual(['https://a.com/x', 'https://a.com/y'])
  })

  it('scopes URLs per domain', () => {
    recordCorpusUrls(10, [{ url: 'https://d10.com/a', source: 'otx' }])
    recordCorpusUrls(11, [{ url: 'https://d11.com/a', source: 'otx' }])
    expect(getCorpusUrls(10)).toEqual(['https://d10.com/a'])
    expect(getCorpusUrls(11)).toEqual(['https://d11.com/a'])
  })

  it('drops blank/oversized URLs', () => {
    const added = recordCorpusUrls(3, [
      { url: '', source: 'wayback' },
      { url: 'x'.repeat(5000), source: 'wayback' },
      { url: 'https://ok.com/', source: 'wayback' },
    ])
    expect(added).toBe(1)
  })
})
