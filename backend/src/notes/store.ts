import { desc, eq, isNull } from 'drizzle-orm'
import { db } from '../db/index'
import { notes } from '../db/schema'

export function listNotes(domainId: number | null) {
  const where = domainId == null ? isNull(notes.domainId) : eq(notes.domainId, domainId)
  return db.select().from(notes).where(where).orderBy(desc(notes.updatedAt)).all()
}

export function getNote(id: number) {
  return db.select().from(notes).where(eq(notes.id, id)).limit(1).all()[0]
}

export function createNote(input: { domainId: number | null; title?: string; body?: string }) {
  const res = db
    .insert(notes)
    .values({
      domainId: input.domainId,
      title: input.title?.trim() || null,
      body: input.body ?? '',
    })
    .run()
  return getNote(Number(res.lastInsertRowid))
}

export function updateNote(id: number, input: { title?: string; body?: string }) {
  db.update(notes)
    .set({ title: input.title?.trim() ?? null, body: input.body ?? '', updatedAt: new Date() })
    .where(eq(notes.id, id))
    .run()
  return getNote(id)
}

export function deleteNote(id: number): void {
  db.delete(notes).where(eq(notes.id, id)).run()
}
