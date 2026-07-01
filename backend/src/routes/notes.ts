import type { FastifyPluginAsync } from 'fastify'
import { createNote, deleteNote, getNote, listNotes, updateNote } from '../notes/store'
import { sendNoteToDiscord } from '../notify/discord'

export const noteRoutes: FastifyPluginAsync = async (app) => {
  // domainId query param: numeric => domain notes; omitted/"global" => global notes.
  app.get<{ Querystring: { domainId?: string } }>('/api/notes', async (request) => {
    const raw = request.query.domainId
    const domainId = raw && raw !== 'global' ? Number(raw) : null
    return { notes: listNotes(domainId) }
  })

  app.post<{ Body: { domainId?: number | null; title?: string; body?: string } }>(
    '/api/notes',
    async (request) => {
      const { domainId = null, title, body } = request.body ?? {}
      return { note: createNote({ domainId: domainId ?? null, title, body }) }
    },
  )

  app.put<{ Params: { id: string }; Body: { title?: string; body?: string } }>(
    '/api/notes/:id',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getNote(id)) return reply.code(404).send({ error: 'note not found' })
      return { note: updateNote(id, request.body ?? {}) }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/notes/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getNote(id)) return reply.code(404).send({ error: 'note not found' })
    deleteNote(id)
    return reply.send({ ok: true })
  })

  // Push a note to the configured Discord webhook on demand.
  app.post<{ Params: { id: string } }>('/api/notes/:id/discord', async (request, reply) => {
    const id = Number(request.params.id)
    const note = getNote(id)
    if (!note) return reply.code(404).send({ error: 'note not found' })
    const result = await sendNoteToDiscord(note.title, note.body)
    if (!result.ok) return reply.code(400).send({ error: result.reason ?? 'failed to send to Discord' })
    return { ok: true }
  })
}
