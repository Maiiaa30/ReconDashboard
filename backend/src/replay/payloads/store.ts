import { desc, eq } from 'drizzle-orm'
import { db } from '../../db/index'
import { payloadSets } from '../../db/schema'
import { safeJsonParse } from '../../util/json'

// CRUD for operator-defined payload lists. Payloads are stored as a JSON string
// array; the API layer bounds the count and length before anything lands here.
export interface PayloadSetRow {
  id: number
  name: string
  category: string | null
  payloads: string[]
  createdAt: Date
  updatedAt: Date
}

const MAX_PAYLOADS = 5000
const MAX_PAYLOAD_LEN = 8192

function clean(payloads: unknown): string[] {
  if (!Array.isArray(payloads)) return []
  return payloads
    .filter((p): p is string => typeof p === 'string')
    .map((p) => p.slice(0, MAX_PAYLOAD_LEN))
    .slice(0, MAX_PAYLOADS)
}

function mapRow(r: typeof payloadSets.$inferSelect): PayloadSetRow {
  return { id: r.id, name: r.name, category: r.category, payloads: safeJsonParse<string[]>(r.payloads, []), createdAt: r.createdAt, updatedAt: r.updatedAt }
}

export function listPayloadSets(): PayloadSetRow[] {
  return db.select().from(payloadSets).orderBy(desc(payloadSets.updatedAt)).all().map(mapRow)
}

export function getPayloadSet(id: number): PayloadSetRow | undefined {
  const r = db.select().from(payloadSets).where(eq(payloadSets.id, id)).limit(1).all()[0]
  return r ? mapRow(r) : undefined
}

export function createPayloadSet(input: { name: string; category?: string; payloads: unknown }): PayloadSetRow {
  const res = db
    .insert(payloadSets)
    .values({ name: input.name.slice(0, 120), category: input.category?.slice(0, 60) ?? null, payloads: JSON.stringify(clean(input.payloads)) })
    .run()
  return getPayloadSet(Number(res.lastInsertRowid))!
}

export function updatePayloadSet(id: number, patch: { name?: string; category?: string | null; payloads?: unknown }): PayloadSetRow | undefined {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (patch.name !== undefined) set.name = patch.name.slice(0, 120)
  if (patch.category !== undefined) set.category = patch.category == null ? null : patch.category.slice(0, 60)
  if (patch.payloads !== undefined) set.payloads = JSON.stringify(clean(patch.payloads))
  db.update(payloadSets).set(set).where(eq(payloadSets.id, id)).run()
  return getPayloadSet(id)
}

export function deletePayloadSet(id: number): boolean {
  return db.delete(payloadSets).where(eq(payloadSets.id, id)).run().changes > 0
}
