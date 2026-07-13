import { desc, eq, notInArray, and } from 'drizzle-orm'
import { db } from '../db/index'
import { replayHistory } from '../db/schema'
import { safeJsonParse } from '../util/json'

// Keep the stored response body bounded and the per-domain history capped so a
// long session of sends can't grow the DB without limit.
const MAX_RESP_BODY = 256 * 1024
const KEEP_PER_DOMAIN = 100

export interface NewReplayHistory {
  domainId: number | null
  method: string
  url: string
  reqHeaders: [string, string][]
  reqBody: string | null
  status: number
  statusText: string
  timeMs: number
  respBytes: number
  respHeaders: [string, string][]
  respBody: string
}

export function insertReplayHistory(h: NewReplayHistory): number {
  const res = db
    .insert(replayHistory)
    .values({
      domainId: h.domainId,
      method: h.method,
      url: h.url,
      reqHeaders: JSON.stringify(h.reqHeaders ?? []),
      reqBody: h.reqBody ?? null,
      status: h.status,
      statusText: h.statusText,
      timeMs: h.timeMs,
      respBytes: h.respBytes,
      respHeaders: JSON.stringify(h.respHeaders ?? []),
      respBody: h.respBody.length > MAX_RESP_BODY ? h.respBody.slice(0, MAX_RESP_BODY) : h.respBody,
    })
    .run()
  if (h.domainId != null) pruneDomainHistory(h.domainId)
  return Number(res.lastInsertRowid)
}

// Retain only the newest KEEP_PER_DOMAIN rows for a domain.
function pruneDomainHistory(domainId: number): void {
  const keep = db
    .select({ id: replayHistory.id })
    .from(replayHistory)
    .where(eq(replayHistory.domainId, domainId))
    .orderBy(desc(replayHistory.id))
    .limit(KEEP_PER_DOMAIN)
    .all()
    .map((r) => r.id)
  if (keep.length < KEEP_PER_DOMAIN) return
  db.delete(replayHistory)
    .where(and(eq(replayHistory.domainId, domainId), notInArray(replayHistory.id, keep)))
    .run()
}

// List rows WITHOUT the heavy response body (the list is polled). The request is
// small, so it's included — clicking a row can restore it without a detail fetch.
export function listReplayHistory(domainId: number, limit = 100) {
  const rows = db
    .select({
      id: replayHistory.id,
      method: replayHistory.method,
      url: replayHistory.url,
      reqHeaders: replayHistory.reqHeaders,
      reqBody: replayHistory.reqBody,
      status: replayHistory.status,
      statusText: replayHistory.statusText,
      timeMs: replayHistory.timeMs,
      respBytes: replayHistory.respBytes,
      createdAt: replayHistory.createdAt,
    })
    .from(replayHistory)
    .where(eq(replayHistory.domainId, domainId))
    .orderBy(desc(replayHistory.id))
    .limit(Math.min(Math.max(limit, 1), 200))
    .all()
  return rows.map((r) => ({ ...r, reqHeaders: safeJsonParse<[string, string][]>(r.reqHeaders, []) }))
}

// Full row incl. response body + headers — fetched when a history entry is opened.
export function getReplayHistory(id: number) {
  const r = db.select().from(replayHistory).where(eq(replayHistory.id, id)).limit(1).all()[0]
  if (!r) return undefined
  return {
    ...r,
    reqHeaders: safeJsonParse<[string, string][]>(r.reqHeaders, []),
    respHeaders: safeJsonParse<[string, string][]>(r.respHeaders, []),
  }
}

export function clearReplayHistory(domainId: number): number {
  return db.delete(replayHistory).where(eq(replayHistory.domainId, domainId)).run().changes
}
