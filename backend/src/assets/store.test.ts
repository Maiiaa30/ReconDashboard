import { describe, expect, it, vi } from 'vitest'

// Real in-memory DB with the assets + asset_findings tables so the upsert/dedup
// and link SQL is actually exercised.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE assets (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer,
      kind text NOT NULL,
      value text NOT NULL,
      ip text, port integer, asn text, asn_name text, cdn text,
      first_seen integer NOT NULL, last_seen integer NOT NULL
    );
    CREATE UNIQUE INDEX assets_domain_kind_value_uq ON assets (domain_id, kind, value);
    CREATE TABLE asset_findings (
      id integer PRIMARY KEY AUTOINCREMENT,
      asset_id integer NOT NULL,
      finding_id integer NOT NULL
    );
    CREATE UNIQUE INDEX asset_findings_uq ON asset_findings (asset_id, finding_id);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { countAssets, linkAssetFinding, listAssets, upsertAsset } from './store'

describe('assets store', () => {
  it('upserts by (domain, kind, value) — the same asset does not duplicate', () => {
    const a = upsertAsset({ domainId: 1, kind: 'ip', value: '1.2.3.4' })
    const b = upsertAsset({ domainId: 1, kind: 'ip', value: '1.2.3.4', asn: 'AS15169', cdn: 'cloudflare' })
    expect(a).toBe(b)
    expect(countAssets(1)).toBe(1)
  })

  it('enriches on re-upsert without clobbering with nulls', () => {
    const id = upsertAsset({ domainId: 2, kind: 'ip', value: '9.9.9.9', asn: 'AS19281' })
    upsertAsset({ domainId: 2, kind: 'ip', value: '9.9.9.9', cdn: 'fastly' }) // no asn this time
    const row = listAssets(2).find((r) => r.id === id)!
    expect(row.asn).toBe('AS19281') // preserved
    expect(row.cdn).toBe('fastly') // added
  })

  it('separates host and ip assets, and scopes per domain', () => {
    upsertAsset({ domainId: 3, kind: 'host', value: 'a.t.com', ip: '5.5.5.5' })
    upsertAsset({ domainId: 3, kind: 'ip', value: '5.5.5.5' })
    upsertAsset({ domainId: 4, kind: 'host', value: 'a.t.com', ip: '5.5.5.5' })
    expect(countAssets(3)).toBe(2)
    expect(countAssets(4)).toBe(1)
  })

  it('links an asset to findings idempotently and ignores null finding ids', () => {
    const id = upsertAsset({ domainId: 5, kind: 'ip', value: '8.8.8.8' })
    linkAssetFinding(id, 100)
    linkAssetFinding(id, 100) // dup — ignored
    linkAssetFinding(id, null) // no-op
    // no throw = pass; the unique index would reject a real duplicate insert
    expect(countAssets(5)).toBe(1)
  })
})
