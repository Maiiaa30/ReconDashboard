import { describe, expect, it, vi } from 'vitest'

// Real in-memory DB (just the asset_cves table) so we exercise the actual
// record/mark SQL. cveWatch only uses the core query builder, so drizzle needs
// no schema object here.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE asset_cves (
      id integer PRIMARY KEY AUTOINCREMENT,
      domain_id integer,
      ip text NOT NULL,
      cve_id text NOT NULL,
      cvss real,
      kev integer NOT NULL DEFAULT 0,
      first_seen_at integer NOT NULL,
      alerted_at integer
    );
    CREATE UNIQUE INDEX asset_cve_uq ON asset_cves (domain_id, ip, cve_id);
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { markCvesAlerted, recordAndDetectNewCves } from './cveWatch'

// Audit §3 #5: a CVE recorded but not yet alerted must survive a crash between the
// two — i.e. still be reported as needing an alert on the next run, not silently
// marked "known" and dropped forever.
describe('cveWatch crash-safety (audit §3 #5)', () => {
  const domainId = 1

  it('re-drives a new-CVE alert that was recorded but never marked alerted', () => {
    const ip = '203.0.113.7'
    const cve = { id: 'CVE-2024-9999', cvss: 9.8, kev: true }

    // 1) First scan of the asset = baseline (no alert, even if CVEs were present).
    expect(recordAndDetectNewCves(domainId, ip, [])).toEqual([])

    // 2) Second scan finds a genuinely new CVE → it is due an alert.
    expect(recordAndDetectNewCves(domainId, ip, [cve]).map((c) => c.id)).toEqual(['CVE-2024-9999'])

    // 3) SIMULATE CRASH: the alert never fired, markCvesAlerted was NOT called.
    //    Re-running must STILL report the CVE as needing an alert.
    expect(recordAndDetectNewCves(domainId, ip, [cve]).map((c) => c.id)).toEqual(['CVE-2024-9999'])

    // 4) Once the alert has fired and we stamp it, it is not re-alerted.
    markCvesAlerted(domainId, ip, ['CVE-2024-9999'])
    expect(recordAndDetectNewCves(domainId, ip, [cve])).toEqual([])
  })

  it('never alerts CVEs already present at the asset baseline (first scan)', () => {
    const ip = '203.0.113.8'
    const cve = { id: 'CVE-2020-1111', cvss: 7.5, kev: false }
    // First-ever scan already has the CVE → baselined, not alerted.
    expect(recordAndDetectNewCves(domainId, ip, [cve])).toEqual([])
    // Same CVE next scan → still nothing (it was part of the baseline).
    expect(recordAndDetectNewCves(domainId, ip, [cve])).toEqual([])
  })
})
