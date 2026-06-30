import type { FastifyPluginAsync } from 'fastify'
import {
  createDrawing,
  deleteDrawing,
  getDrawing,
  listDrawings,
  updateDrawing,
} from '../drawings/store'

export const drawingRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/drawings', async () => ({ drawings: listDrawings() }))

  app.get<{ Params: { id: string } }>('/api/drawings/:id', async (request, reply) => {
    const d = getDrawing(Number(request.params.id))
    if (!d) return reply.code(404).send({ error: 'drawing not found' })
    return { drawing: d }
  })

  app.post<{ Body: { name?: string; domainId?: number | null; data?: unknown } }>(
    '/api/drawings',
    async (request) => ({ drawing: createDrawing(request.body ?? {}) }),
  )

  app.put<{ Params: { id: string }; Body: { name?: string; data?: unknown } }>(
    '/api/drawings/:id',
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getDrawing(id)) return reply.code(404).send({ error: 'drawing not found' })
      return { drawing: updateDrawing(id, request.body ?? {}) }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/drawings/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDrawing(id)) return reply.code(404).send({ error: 'drawing not found' })
    deleteDrawing(id)
    return reply.send({ ok: true })
  })
}
