import type { FastifyPluginAsync } from 'fastify'
import {
  createDrawing,
  deleteDrawing,
  getDrawing,
  listDrawings,
  updateDrawing,
} from '../drawings/store'

// `data` is the arbitrary Excalidraw scene payload — validate its wrapper fields
// but leave the scene itself unconstrained (bodyLimit caps its size).
const drawingCreateSchema = {
  body: {
    type: 'object',
    properties: {
      name: { type: 'string', maxLength: 200 },
      domainId: { type: ['integer', 'null'] },
      data: {},
    },
    additionalProperties: false,
  },
}
const drawingUpdateSchema = {
  body: {
    type: 'object',
    properties: {
      name: { type: 'string', maxLength: 200 },
      data: {},
    },
    additionalProperties: false,
  },
}

export const drawingRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/drawings', async () => ({ drawings: listDrawings() }))

  app.get<{ Params: { id: string } }>('/api/drawings/:id', async (request, reply) => {
    const d = getDrawing(Number(request.params.id))
    if (!d) return reply.code(404).send({ error: 'drawing not found' })
    return { drawing: d }
  })

  app.post<{ Body: { name?: string; domainId?: number | null; data?: unknown } }>(
    '/api/drawings',
    { schema: drawingCreateSchema },
    async (request) => ({ drawing: createDrawing(request.body ?? {}) }),
  )

  app.put<{ Params: { id: string }; Body: { name?: string; data?: unknown } }>(
    '/api/drawings/:id',
    { schema: drawingUpdateSchema },
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
