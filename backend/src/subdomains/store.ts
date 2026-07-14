import { and, desc, eq, inArray, isNull } from 'drizzle-orm'
import { db } from '../db/index'
import { subdomains } from '../db/schema'

export function listSubdomains(domainId: number) {
  return db
    .select()
    .from(subdomains)
    .where(eq(subdomains.domainId, domainId))
    .orderBy(desc(subdomains.isNew), desc(subdomains.lastSeen))
    .all()
}

export interface DiffResult {
  newHosts: string[]
  updatedCount: number
  total: number
}

// Diff discovered hosts against what's stored for a domain. New hosts are
// inserted with is_new=true; existing hosts get last_seen bumped. Runs in a
// single transaction for consistency.
export function diffAndStore(
  domainId: number,
  discovered: { host: string; source: string }[],
): DiffResult {
  const now = new Date()
  const bySource = new Map<string, string>()
  for (const d of discovered) {
    if (!bySource.has(d.host)) bySource.set(d.host, d.source)
  }
  const hosts = [...bySource.keys()]

  const newHosts: string[] = []
  let updatedCount = 0

  db.transaction((tx) => {
    // Chunk the existence lookup to stay under SQLite's bound-variable limit
    // (a busy domain can yield thousands of hosts from crt.sh).
    const existing = new Set<string>()
    for (let i = 0; i < hosts.length; i += 500) {
      const chunk = hosts.slice(i, i + 500)
      for (const r of tx
        .select({ host: subdomains.host })
        .from(subdomains)
        .where(and(eq(subdomains.domainId, domainId), inArray(subdomains.host, chunk)))
        .all()) {
        existing.add(r.host)
      }
    }

    for (const host of hosts) {
      if (existing.has(host)) {
        tx
          .update(subdomains)
          .set({ lastSeen: now, source: bySource.get(host) ?? null })
          .where(and(eq(subdomains.domainId, domainId), eq(subdomains.host, host)))
          .run()
        updatedCount++
      } else {
        tx
          .insert(subdomains)
          .values({
            domainId,
            host,
            source: bySource.get(host) ?? null,
            isNew: true,
            firstSeen: now,
            lastSeen: now,
          })
          .run()
        newHosts.push(host)
      }
    }
  })

  return { newHosts, updatedCount, total: hosts.length }
}

/** Hosts that have never been HTTP-probed (e.g. discovered before probing existed). */
export function listUnprobed(domainId: number, limit: number): string[] {
  return db
    .select({ host: subdomains.host })
    .from(subdomains)
    .where(and(eq(subdomains.domainId, domainId), isNull(subdomains.probedAt)))
    .limit(limit)
    .all()
    .map((r) => r.host)
}

export interface ProbeData {
  ip: string | null
  status: number | null
  title: string | null
  server: string | null
  scheme: string | null
  loginHint?: boolean
}

/** Store HTTP-probe enrichment for a discovered host. */
export function updateProbe(domainId: number, host: string, p: ProbeData): void {
  db.update(subdomains)
    .set({
      ipAddress: p.ip,
      httpStatus: p.status,
      title: p.title,
      server: p.server,
      scheme: p.scheme,
      loginHint: p.loginHint ?? false,
      probedAt: new Date(),
    })
    .where(and(eq(subdomains.domainId, domainId), eq(subdomains.host, host)))
    .run()
}

export function updateScreenshot(domainId: number, host: string, path: string): void {
  db.update(subdomains)
    .set({ screenshotPath: path, screenshotAt: new Date() })
    .where(and(eq(subdomains.domainId, domainId), eq(subdomains.host, host)))
    .run()
}

/** Clear the is_new flag (operator acknowledged the new subdomains). */
export function acknowledgeNew(domainId: number): number {
  const res = db
    .update(subdomains)
    .set({ isNew: false })
    .where(and(eq(subdomains.domainId, domainId), eq(subdomains.isNew, true)))
    .run()
  return res.changes
}
