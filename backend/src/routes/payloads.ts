import type { FastifyPluginAsync } from 'fastify'
import { BUILTIN_GREP_PHRASES, BUILTIN_PAYLOAD_SETS } from '../replay/payloads/builtins'
import { applyChain, TRANSFORM_NAMES } from '../replay/payloads/encoders'
import { createPayloadSet, deletePayloadSet, getPayloadSet, listPayloadSets, updatePayloadSet } from '../replay/payloads/store'

const setBodySchema = {
  body: {
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1, maxLength: 120 },
      category: { type: 'string', maxLength: 60 },
      payloads: { type: 'array', maxItems: 5000, items: { type: 'string', maxLength: 8192 } },
    },
    additionalProperties: false,
  },
}

const encodeSchema = {
  body: {
    type: 'object',
    required: ['input', 'chain'],
    properties: {
      input: { type: 'string', maxLength: 65536 },
      chain: { type: 'array', maxItems: 8, items: { type: 'string', maxLength: 40 } },
    },
    additionalProperties: false,
  },
}

// Payload library + encoder. Session-authed (the default guard) but NOT
// scan-gated: these routes touch no target — the encoder is a pure string
// transform, and the library is local CRUD. Gating a string transform behind the
// active-scan policy would be wrong.
export const payloadRoutes: FastifyPluginAsync = async (app) => {
  // Everything the UI needs to populate the picker: built-in sets, grep phrases,
  // the operator's saved lists, and the available encoder names.
  app.get('/api/payloads', async () => ({
    builtins: BUILTIN_PAYLOAD_SETS,
    grepPhrases: BUILTIN_GREP_PHRASES,
    custom: listPayloadSets(),
    transforms: TRANSFORM_NAMES,
  }))

  app.post<{ Body: { name?: string; category?: string; payloads?: string[] } }>(
    '/api/payloads',
    { schema: setBodySchema },
    async (request, reply) => {
      const { name, payloads } = request.body ?? {}
      if (!name || !Array.isArray(payloads)) return reply.code(400).send({ error: 'name and payloads[] are required', code: 'invalid' })
      try {
        return { set: createPayloadSet({ name, category: request.body?.category, payloads }) }
      } catch {
        // Unique-name collision is the only expected failure.
        return reply.code(409).send({ error: `a payload set named "${name}" already exists`, code: 'duplicate' })
      }
    },
  )

  app.put<{ Params: { id: string }; Body: { name?: string; category?: string; payloads?: string[] } }>(
    '/api/payloads/:id',
    { schema: setBodySchema },
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getPayloadSet(id)) return reply.code(404).send({ error: 'payload set not found', code: 'not_found' })
      return { set: updatePayloadSet(id, request.body ?? {}) }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/payloads/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getPayloadSet(id)) return reply.code(404).send({ error: 'payload set not found', code: 'not_found' })
    deletePayloadSet(id)
    return reply.send({ ok: true })
  })

  // Pure transform: apply an encoder chain to a string. No egress, not gated.
  app.post<{ Body: { input?: string; chain?: string[] } }>(
    '/api/payloads/encode',
    { schema: encodeSchema },
    async (request, reply) => {
      const { input = '', chain = [] } = request.body ?? {}
      try {
        return { output: applyChain(input, chain) }
      } catch (err) {
        return reply.code(400).send({ error: err instanceof Error ? err.message : 'encode failed', code: 'invalid_chain' })
      }
    },
  )
}
