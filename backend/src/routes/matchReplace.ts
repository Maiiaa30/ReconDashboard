import type { FastifyPluginAsync } from 'fastify'
import { applyRules, orderRules, type RulePart } from '../replay/matchReplace'
import { applicableRules, createRule, deleteRule, getRule, listRules, updateRule } from '../replay/matchReplaceStore'
import type { ReplayRequest } from '../replay/send'

const PARTS: RulePart[] = ['url', 'header', 'body']

const ruleBodySchema = {
  body: {
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1, maxLength: 120 },
      domainId: { type: ['integer', 'null'] },
      part: { type: 'string', enum: PARTS },
      match: { type: 'string', maxLength: 2000 },
      replace: { type: 'string', maxLength: 4000 },
      isRegex: { type: 'boolean' },
      enabled: { type: 'boolean' },
    },
    additionalProperties: false,
  },
}

// Match/replace rules: session-authed CRUD + a no-egress preview. NOT scan-gated —
// rules are configuration, and preview sends nothing. They are enforced inside
// sendRawRequest (Repeater + Intruder), where the SSRF/redirect guards still win.
export const matchReplaceRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/match-replace', async () => ({ rules: listRules() }))

  app.post<{ Body: { name?: string; domainId?: number | null; part?: RulePart; match?: string; replace?: string; isRegex?: boolean; enabled?: boolean } }>(
    '/api/match-replace',
    { schema: ruleBodySchema },
    async (request, reply) => {
      const b = request.body ?? {}
      if (!b.name || !b.part) return reply.code(400).send({ error: 'name and part are required', code: 'invalid' })
      return { rule: createRule({ name: b.name, domainId: b.domainId ?? null, part: b.part, match: b.match, replace: b.replace, isRegex: b.isRegex, enabled: b.enabled }) }
    },
  )

  app.put<{ Params: { id: string }; Body: Record<string, unknown> }>(
    '/api/match-replace/:id',
    { schema: ruleBodySchema },
    async (request, reply) => {
      const id = Number(request.params.id)
      if (!getRule(id)) return reply.code(404).send({ error: 'rule not found', code: 'not_found' })
      return { rule: updateRule(id, request.body ?? {}) }
    },
  )

  app.delete<{ Params: { id: string } }>('/api/match-replace/:id', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getRule(id)) return reply.code(404).send({ error: 'rule not found', code: 'not_found' })
    deleteRule(id)
    return reply.send({ ok: true })
  })

  // Preview: show what a request becomes after the applicable rules run. No egress.
  app.post<{ Body: { request?: ReplayRequest; domainId?: number | null } }>('/api/match-replace/preview', async (request, reply) => {
    const req = request.body?.request
    if (!req || typeof req.url !== 'string') return reply.code(400).send({ error: 'request.url is required', code: 'invalid' })
    const rules = orderRules(applicableRules(request.body?.domainId ?? null))
    return { before: req, after: applyRules(req, rules), applied: rules.map((r) => ({ id: r.id, name: r.name, part: r.part, global: r.domainId == null })) }
  })
}
