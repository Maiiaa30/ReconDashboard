import { describe, expect, it, vi } from 'vitest'

// Real in-memory DB with the findings + finding_links tables so the link insert +
// the join in getFindingLinks are actually exercised. getFinding selects every
// findings column, so the table mirrors the full schema.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE findings (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer, type text NOT NULL, data text, score integer, tags text,
      status text NOT NULL DEFAULT 'open', note text,
      severity text, host text, ip text, url text, job_id integer,
      dedupe_key text, created_at integer NOT NULL DEFAULT 0, last_seen_at integer
    );
    CREATE TABLE finding_links (
      id integer PRIMARY KEY AUTOINCREMENT,
      from_id integer NOT NULL, to_id integer NOT NULL, kind text NOT NULL,
      created_at integer NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX finding_links_uq ON finding_links (from_id, to_id, kind);
  `)
  // Two findings: a nuclei PoC (1) and the cve_new it confirms (2).
  sqlite.exec(`
    INSERT INTO findings (id, type, data, tags) VALUES
      (1, 'nuclei', '{"templateId":"CVE-2024-1","name":"PoC"}', '[]'),
      (2, 'cve_new', '{"cveId":"CVE-2024-1","ip":"1.2.3.4"}', '[]');
  `)
  return { db: drizzle(sqlite), sqlite }
})

// jobContext import in store.ts pulls node:async_hooks — fine under vitest.
import { getFindingLinks, linkFindings } from './store'

describe('finding links', () => {
  it('links a PoC to the CVE it confirms, resolvable from both ends', () => {
    linkFindings(1, 2, 'confirms')

    const fromPoc = getFindingLinks(1)
    expect(fromPoc).toHaveLength(1)
    expect(fromPoc[0]).toMatchObject({ kind: 'confirms', direction: 'outgoing' })
    expect(fromPoc[0].finding.id).toBe(2)

    const fromCve = getFindingLinks(2)
    expect(fromCve).toHaveLength(1)
    expect(fromCve[0]).toMatchObject({ kind: 'confirms', direction: 'incoming' })
    expect(fromCve[0].finding.id).toBe(1)
  })

  it('is idempotent and ignores self-links', () => {
    linkFindings(1, 2, 'confirms') // dup — ignored by the unique index
    linkFindings(1, 1, 'confirms') // self — ignored
    expect(getFindingLinks(1)).toHaveLength(1)
  })
})
