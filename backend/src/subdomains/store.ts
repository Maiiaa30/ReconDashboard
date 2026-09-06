import { and, asc, desc, eq, inArray, isNull, sql, type AnyColumn, type SQL } from 'drizzle-orm'
import { db } from '../db/index'
import { subdomains, type Subdomain } from '../db/schema'

// Full unpaged list, oldest behaviour preserved. Kept for the callers that
// genuinely need every row (export, correlation, scan seeding, global counts);
// the Subdomains PAGE uses querySubdomains below so a busy domain's thousands of
// hosts don't ship in one response.
export function listSubdomains(domainId: number) {
  return db
    .select()
    .from(subdomains)
    .where(eq(subdomains.domainId, domainId))
    .orderBy(desc(subdomains.isNew), desc(subdomains.lastSeen))
    .all()
}

// querySubdomains pushes filtering, sorting and paging into SQL and pages with a
// keyset cursor over the chosen sort column plus the primary key as a stable
// tiebreak, so a page is O(page) regardless of how many hosts a domain has. The
// keyset comparison mirrors the ORDER BY exactly (same coalesce, same direction,
// same id tiebreak) so pages never overlap or drop a row.

export type SubdomainSort = 'status' | 'host' | 'ip' | 'lastSeen' | 'new'
const SORTS: SubdomainSort[] = ['status', 'host', 'ip', 'lastSeen', 'new']
export function isSubdomainSort(v: string): v is SubdomainSort {
  return (SORTS as string[]).includes(v)
}

export interface SubdomainFilter {
  domainId: number
  // Substring match (case-insensitive) against the host.
  q?: string
  newOnly?: boolean
}

export interface SubdomainQuery extends SubdomainFilter {
  sort?: SubdomainSort
  dir?: 'asc' | 'desc'
  limit?: number
  cursor?: string
}

export interface SubdomainPage {
  subdomains: Subdomain[]
  nextCursor: string | null
}

const MAX_PAGE = 500
const DEFAULT_PAGE = 100

function likeContains(col: AnyColumn, term: string): SQL {
  const esc = term.replace(/[\\%_]/g, (c) => `\\${c}`)
  return sql`${col} like ${`%${esc}%`} escape '\\'`
}

// The coalesced sort expression for a key. NULLs collapse to a low sentinel so
// they land consistently in both the ORDER BY and the keyset comparison. Host is
// compared case-insensitively so the order matches the UI's old localeCompare.
function sortExpr(sort: SubdomainSort): SQL {
  switch (sort) {
    case 'host':
      return sql`${subdomains.host} collate nocase`
    case 'ip':
      return sql`coalesce(${subdomains.ipAddress}, '') collate nocase`
    case 'status':
      return sql`coalesce(${subdomains.httpStatus}, -1)`
    case 'new':
      return sql`case when ${subdomains.isNew} then 1 else 0 end`
    case 'lastSeen':
    default:
      return sql`${subdomains.lastSeen}`
  }
}

// The sort key's value for a row, as it must appear on the cursor (matching the
// coalesced sortExpr so the keyset comparison is exact).
function cursorValue(row: Subdomain, sort: SubdomainSort): string | number {
  switch (sort) {
    case 'host':
      return row.host
    case 'ip':
      return row.ipAddress ?? ''
    case 'status':
      return row.httpStatus ?? -1
    case 'new':
      return row.isNew ? 1 : 0
    case 'lastSeen':
    default:
      return row.lastSeen.getTime()
  }
}

function encodeCursor(row: Subdomain, sort: SubdomainSort): string {
  return Buffer.from(JSON.stringify([cursorValue(row, sort), row.id]), 'utf8').toString('base64url')
}

function decodeCursor(cursor: string): { v: string | number; id: number } | null {
  try {
    const arr = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown
    if (!Array.isArray(arr) || arr.length !== 2) return null
    const [v, id] = arr
    if ((typeof v !== 'string' && typeof v !== 'number') || !Number.isSafeInteger(id) || id <= 0) return null
    return { v, id }
  } catch {
    return null
  }
}

function subdomainConds(f: SubdomainFilter): SQL[] {
  const conds: SQL[] = [eq(subdomains.domainId, f.domainId)]
  if (f.q && f.q.trim()) conds.push(likeContains(subdomains.host, f.q.trim()))
  if (f.newOnly) conds.push(eq(subdomains.isNew, true))
  return conds
}

// A page of a domain's subdomains for the given filter/sort, with a keyset cursor
// for the next page. An invalid/garbled cursor is ignored (restart from the top)
// rather than thrown. `collate nocase` keeps host/ip ordering aligned with the
// browser's previous localeCompare (byte order would sort A..Z before a..z).
export function querySubdomains(q: SubdomainQuery): SubdomainPage {
  const limit = Math.min(MAX_PAGE, Math.max(1, q.limit ?? DEFAULT_PAGE))
  const sort: SubdomainSort = q.sort && isSubdomainSort(q.sort) ? q.sort : 'status'
  const dir: 'asc' | 'desc' = q.dir === 'asc' ? 'asc' : 'desc'
  const expr = sortExpr(sort)
  const conds = subdomainConds(q)

  if (q.cursor) {
    const c = decodeCursor(q.cursor)
    if (c) {
      // Continue strictly past the cursor tuple in the active order. Row-value
      // '<' matches ORDER BY (expr desc, id desc); '>' matches (expr asc, id asc).
      conds.push(
        dir === 'asc'
          ? sql`(${expr}, ${subdomains.id}) > (${c.v}, ${c.id})`
          : sql`(${expr}, ${subdomains.id}) < (${c.v}, ${c.id})`,
      )
    }
  }

  const orderBy =
    dir === 'asc' ? [sql`${expr} asc`, asc(subdomains.id)] : [sql`${expr} desc`, desc(subdomains.id)]

  const rows = db
    .select()
    .from(subdomains)
    .where(and(...conds))
    .orderBy(...orderBy)
    .limit(limit + 1)
    .all()

  const hasMore = rows.length > limit
  const page = hasMore ? rows.slice(0, limit) : rows
  const nextCursor = hasMore ? encodeCursor(page[page.length - 1], sort) : null
  return { subdomains: page, nextCursor }
}

export interface SubdomainSummary {
  total: number
  newCount: number
}

// total + new-host count for the filter set WITHOUT the newOnly facet, so the
// header can show "N known, M new" without loading every row.
export function summarizeSubdomains(f: Omit<SubdomainFilter, 'newOnly'>): SubdomainSummary {
  const row = db
    .select({
      total: sql<number>`count(*)`,
      newCount: sql<number>`sum(case when ${subdomains.isNew} then 1 else 0 end)`,
    })
    .from(subdomains)
    .where(and(...subdomainConds(f)))
    .get()
  return { total: Number(row?.total ?? 0), newCount: Number(row?.newCount ?? 0) }
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

/** Store correlation signatures (TLS cert fingerprint + mmh3 favicon hash). */
export function updateSignature(domainId: number, host: string, sig: { certFp?: string | null; faviconHash?: number | null }): void {
  const set: Record<string, unknown> = {}
  if (sig.certFp !== undefined) set.certFp = sig.certFp
  if (sig.faviconHash !== undefined) set.faviconHash = sig.faviconHash
  if (Object.keys(set).length === 0) return
  db.update(subdomains).set(set).where(and(eq(subdomains.domainId, domainId), eq(subdomains.host, host))).run()
}

/** Per-host correlation signatures for a domain (for cross-IP asset clustering). */
export function listSignatures(domainId: number): { host: string; ip: string | null; certFp: string | null; faviconHash: number | null }[] {
  return db
    .select({ host: subdomains.host, ip: subdomains.ipAddress, certFp: subdomains.certFp, faviconHash: subdomains.faviconHash })
    .from(subdomains)
    .where(eq(subdomains.domainId, domainId))
    .all()
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
