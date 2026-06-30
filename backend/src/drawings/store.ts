import { desc, eq } from 'drizzle-orm'
import { db } from '../db/index'
import { drawings } from '../db/schema'

export function listDrawings() {
  return db
    .select({
      id: drawings.id,
      domainId: drawings.domainId,
      name: drawings.name,
      createdAt: drawings.createdAt,
      updatedAt: drawings.updatedAt,
    })
    .from(drawings)
    .orderBy(desc(drawings.updatedAt))
    .all()
}

export function getDrawing(id: number) {
  const row = db.select().from(drawings).where(eq(drawings.id, id)).limit(1).all()[0]
  if (!row) return undefined
  return { ...row, data: row.data ? JSON.parse(row.data) : null }
}

export function createDrawing(input: { name?: string; domainId?: number | null; data?: unknown }) {
  const res = db
    .insert(drawings)
    .values({
      name: input.name?.trim() || 'Untitled',
      domainId: input.domainId ?? null,
      data: JSON.stringify(input.data ?? { elements: [], appState: {} }),
    })
    .run()
  return getDrawing(Number(res.lastInsertRowid))
}

export function updateDrawing(id: number, input: { name?: string; data?: unknown }) {
  const set: Record<string, unknown> = { updatedAt: new Date() }
  if (input.name !== undefined) set.name = input.name.trim() || 'Untitled'
  if (input.data !== undefined) set.data = JSON.stringify(input.data)
  db.update(drawings).set(set).where(eq(drawings.id, id)).run()
  return getDrawing(id)
}

export function deleteDrawing(id: number): void {
  db.delete(drawings).where(eq(drawings.id, id)).run()
}
