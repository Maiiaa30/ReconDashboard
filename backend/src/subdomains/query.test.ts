import { describe, expect, it, vi } from 'vitest'

// Real in-memory subdomains table so the SQL filters, the per-sort keyset ORDER
// BY, and the summary counts are actually exercised (mirrors findings/query.test).
// Row 6 lives in another domain to prove the domain scope is always applied.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE subdomains (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer NOT NULL,
      host text NOT NULL,
      source text,
      is_new integer NOT NULL DEFAULT 1,
      ip_address text,
      http_status integer,
      title text,
      server text,
      scheme text,
      waf text,
      cert_fp text,
      favicon_hash integer,
      login_hint integer NOT NULL DEFAULT 0,
      probed_at integer,
      screenshot_path text,
      screenshot_at integer,
      first_seen integer NOT NULL DEFAULT 0,
      last_seen integer NOT NULL DEFAULT 0
    );
  `)
  sqlite.exec(`
    INSERT INTO subdomains (id, domain_id, host, is_new, http_status, ip_address, first_seen, last_seen) VALUES
      (1, 1, 'a.example.com', 0, 200,  '10.0.0.2',  1000, 1000),
      (2, 1, 'b.example.com', 1, 200,  '10.0.0.10', 2000, 2000),
      (3, 1, 'c.example.com', 0, 404,  NULL,        3000, 3000),
      (4, 1, 'd.example.com', 1, NULL, '10.0.0.1',  4000, 4000),
      (5, 1, 'e_test.com',    0, 301,  '10.0.0.3',  5000, 5000),
      (6, 2, 'z.other.com',   1, 200,  '10.0.0.9',  6000, 6000);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { querySubdomains, summarizeSubdomains, type SubdomainQuery } from './store'

const ids = (r: { subdomains: { id: number }[] }) => r.subdomains.map((s) => s.id)
const run = (q: Partial<SubdomainQuery> = {}) => querySubdomains({ domainId: 1, ...q })

describe('querySubdomains', () => {
  it('defaults to status desc, id desc tiebreak, scoped to the domain', () => {
    expect(ids(run())).toEqual([3, 5, 2, 1, 4])
  })

  it('sorts by host (nocase) both directions', () => {
    expect(ids(run({ sort: 'host', dir: 'asc' }))).toEqual([1, 2, 3, 4, 5])
    expect(ids(run({ sort: 'host', dir: 'desc' }))).toEqual([5, 4, 3, 2, 1])
  })

  it('sorts by ip with nulls first (coalesced to empty string) ascending', () => {
    // String (not numeric) order: '' < 10.0.0.1 < 10.0.0.10 < 10.0.0.2 < 10.0.0.3
    expect(ids(run({ sort: 'ip', dir: 'asc' }))).toEqual([3, 4, 2, 1, 5])
  })

  it('sorts by lastSeen and by new flag', () => {
    expect(ids(run({ sort: 'lastSeen', dir: 'desc' }))).toEqual([5, 4, 3, 2, 1])
    expect(ids(run({ sort: 'new', dir: 'desc' }))).toEqual([4, 2, 5, 3, 1])
  })

  it('pages with a keyset cursor covering every row exactly once (default sort)', () => {
    const p1 = run({ limit: 2 })
    expect(ids(p1)).toEqual([3, 5])
    const p2 = run({ limit: 2, cursor: p1.nextCursor! })
    expect(ids(p2)).toEqual([2, 1])
    const p3 = run({ limit: 2, cursor: p2.nextCursor! })
    expect(ids(p3)).toEqual([4])
    expect(p3.nextCursor).toBeNull()
  })

  it('keyset paging is exact for an ascending sort too', () => {
    const p1 = run({ sort: 'host', dir: 'asc', limit: 2 })
    expect(ids(p1)).toEqual([1, 2])
    const p2 = run({ sort: 'host', dir: 'asc', limit: 2, cursor: p1.nextCursor! })
    expect(ids(p2)).toEqual([3, 4])
    const p3 = run({ sort: 'host', dir: 'asc', limit: 2, cursor: p2.nextCursor! })
    expect(ids(p3)).toEqual([5])
    expect(p3.nextCursor).toBeNull()
  })

  it('filters by host substring', () => {
    expect(ids(run({ q: 'example' }))).toEqual([3, 2, 1, 4])
  })

  it('treats a literal _ in the host filter as text, not a wildcard', () => {
    expect(ids(run({ q: 'e_test' }))).toEqual([5])
    expect(ids(run({ q: '%' }))).toEqual([])
  })

  it('filters to new hosts only', () => {
    expect(ids(run({ newOnly: true }))).toEqual([2, 4])
  })

  it('ignores a garbled cursor (restarts from the top)', () => {
    expect(ids(run({ cursor: 'not-base64!' }))).toEqual([3, 5, 2, 1, 4])
  })
})

describe('summarizeSubdomains', () => {
  it('counts total and new for the domain', () => {
    expect(summarizeSubdomains({ domainId: 1 })).toEqual({ total: 5, newCount: 2 })
  })

  it('applies the host filter but ignores the newOnly facet', () => {
    expect(summarizeSubdomains({ domainId: 1, q: 'example' })).toEqual({ total: 4, newCount: 2 })
  })
})
