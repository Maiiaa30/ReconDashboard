import type { FastifyPluginAsync } from 'fastify'
import { getDomain } from '../domains/store'
import { explainIntruderRow, narrateChain, suggestPayloadMutation, suggestSecretTriage } from '../ai/assists'

// AI-assist routes — all SUGGEST-ONLY, session-authed, NOT scan-gated (they send
// no target traffic and the model never touches the wire). Each degrades cleanly
// to { enabled: false, note } when no LLM is configured.
export const aiRoutes: FastifyPluginAsync = async (app) => {
  // Explain one interesting Intruder row (uses the stored baseline + body excerpt).
  app.post<{ Params: { jobId: string }; Body: { rowIndex?: number } }>('/api/intruder/:jobId/explain', async (request, reply) => {
    const jobId = Number(request.params.jobId)
    if (!Number.isFinite(jobId)) return reply.code(400).send({ error: 'invalid jobId' })
    const rowIndex = Math.max(0, Math.floor(Number(request.body?.rowIndex) || 0))
    return explainIntruderRow(jobId, rowIndex)
  })

  // Suggest encoder chains for a blocked payload (operator applies via /payloads/encode).
  app.post<{ Body: { payload?: string; status?: number } }>('/api/payloads/mutate', async (request, reply) => {
    const payload = typeof request.body?.payload === 'string' ? request.body.payload : ''
    if (!payload) return reply.code(400).send({ error: 'payload required' })
    return suggestPayloadMutation(payload, Number(request.body?.status) || undefined)
  })

  // Classify the FP-heavy JS-secret findings as real vs placeholder (suggestion only).
  app.post<{ Params: { id: string } }>('/api/domains/:id/secret-triage', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    return suggestSecretTriage(id)
  })

  // Narrate a deterministic attack chain (structure from Task 9 + LLM prose).
  app.post<{ Params: { id: string }; Body: { chainId?: string } }>('/api/domains/:id/chains/narrate', async (request, reply) => {
    const id = Number(request.params.id)
    if (!getDomain(id)) return reply.code(404).send({ error: 'domain not found' })
    const chainId = typeof request.body?.chainId === 'string' ? request.body.chainId : ''
    if (!chainId) return reply.code(400).send({ error: 'chainId required' })
    return narrateChain(id, chainId)
  })
}
