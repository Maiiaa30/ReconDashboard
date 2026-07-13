import { desc, eq, lt, sql } from 'drizzle-orm'
import { db } from '../db/index'
import { capturedRequests } from '../db/schema'
import { safeJsonParse } from '../util/json'

export interface NewCapture {
  domainId: number | null
  method: string
  url: string
  host: string
  headers: [string, string][]
  body: string | null
  source?: string
}

const MAX_BODY = 512 * 1024 // cap stored body — the extension shouldn't ship megabytes
const MAX_HEADERS = 100

export function insertCapture(c: NewCapture): number {
  const headers = (Array.isArray(c.headers) ? c.headers : [])
    .filter((h) => Array.isArray(h) && typeof h[0] === 'string' && typeof h[1] === 'string')
    .slice(0, MAX_HEADERS)
  const res = db
    .insert(capturedRequests)
    .values({
      domainId: c.domainId,
      method: String(c.method || 'GET').toUpperCase().slice(0, 10),
      url: String(c.url).slice(0, 4096),
      host: String(c.host).slice(0, 253),
      headers: JSON.stringify(headers),
      body: c.body != null ? String(c.body).slice(0, MAX_BODY) : null,
      source: c.source ?? 'extension',
    })
    .run()
  return Number(res.lastInsertRowid)
}

function mapRow(r: typeof capturedRequests.$inferSelect) {
  return { ...r, headers: safeJsonParse<[string, string][]>(r.headers, []) }
}

// List WITHOUT the (up-to-512KB) body — the Traffic page polls this every ~2s,
// so shipping every body each cycle is wasteful. `hasBody` tells the UI there's
// a body to lazy-load via getCapture(id) on expand / send-to-replay.
export function listCaptures(opts: { domainId?: number; limit?: number } = {}) {
  const limit = Math.min(Math.max(opts.limit ?? 200, 1), 1000)
  const rows = db
    .select({
      id: capturedRequests.id,
      domainId: capturedRequests.domainId,
      method: capturedRequests.method,
      url: capturedRequests.url,
      host: capturedRequests.host,
      headers: capturedRequests.headers,
      source: capturedRequests.source,
      createdAt: capturedRequests.createdAt,
      hasBody: sql<number>`(${capturedRequests.body} is not null and length(${capturedRequests.body}) > 0)`,
    })
    .from(capturedRequests)
    .where(opts.domainId != null ? eq(capturedRequests.domainId, opts.domainId) : undefined)
    .orderBy(desc(capturedRequests.id))
    .limit(limit)
    .all()
  return rows.map((r) => ({
    ...r,
    headers: safeJsonParse<[string, string][]>(r.headers, []),
    hasBody: !!r.hasBody,
    body: null as string | null,
  }))
}

export function getCapture(id: number) {
  const r = db.select().from(capturedRequests).where(eq(capturedRequests.id, id)).limit(1).all()[0]
  return r ? mapRow(r) : undefined
}

// Delete a single captured request.
export function deleteCapture(id: number): number {
  return db.delete(capturedRequests).where(eq(capturedRequests.id, id)).run().changes
}

// Clear a domain's captured history (operator housekeeping).
export function clearCaptures(domainId: number): number {
  const res = db.delete(capturedRequests).where(eq(capturedRequests.domainId, domainId)).run()
  return res.changes
}

// Retention: drop captures older than N days so the table can't grow unbounded.
export function pruneCapturesOlderThan(days: number): number {
  if (days <= 0) return 0
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
  const res = db.delete(capturedRequests).where(lt(capturedRequests.createdAt, cutoff)).run()
  return res.changes
}
