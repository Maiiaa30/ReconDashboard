import type { FastifyPluginAsync } from 'fastify'
import {
  AssessmentRunError,
  cancelAssessmentRun,
  cancelAssessmentTarget,
  createAssessmentReport,
  createAssessmentRun,
  getAssessmentRun,
  getAssessmentComparison,
  listAssessmentRuns,
  retryAssessmentRun,
  retryAssessmentTarget,
  type AssessmentAction,
  type AssessmentProfile,
} from '../assessments/runs'
import { getDomain } from '../domains/store'

const PROFILES: AssessmentProfile[] = ['passive', 'monitor', 'web', 'full', 'custom']
const ACTIONS: AssessmentAction[] = ['discover', 'exposure', 'osint', 'screenshots', 'api', 'nmap', 'nuclei', 'ffuf', 'owasp', 'params']

function sendError(reply: any, error: unknown) {
  if (error instanceof AssessmentRunError) return reply.code(error.status).send({ error: error.message, code: error.code })
  throw error
}

export const assessmentRoutes: FastifyPluginAsync = async (app) => {
  app.get<{ Params: { id: string } }>('/api/domains/:id/assessment-runs', async (request, reply) => {
    const domainId = Number(request.params.id)
    if (!getDomain(domainId)) return reply.code(404).send({ error: 'domain not found' })
    return { runs: listAssessmentRuns(domainId) }
  })

  app.get<{ Params: { id: string } }>('/api/assessment-runs/:id', async (request, reply) => {
    const run = getAssessmentRun(Number(request.params.id))
    if (!run) return reply.code(404).send({ error: 'assessment run not found' })
    return { run }
  })

  app.post<{ Params: { id: string }; Body: { profile?: AssessmentProfile; name?: string; steps?: AssessmentAction[]; confirm?: boolean } }>(
    '/api/domains/:id/assessment-runs',
    {
      schema: {
        body: {
          type: 'object', required: ['profile'], additionalProperties: false,
          properties: {
            profile: { type: 'string', enum: PROFILES },
            name: { type: 'string', maxLength: 120 },
            steps: { type: 'array', maxItems: ACTIONS.length, uniqueItems: true, items: { type: 'string', enum: ACTIONS } },
            confirm: { type: 'boolean' },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        const run = await createAssessmentRun({ domainId: Number(request.params.id), profile: request.body.profile!, name: request.body.name, customActions: request.body.steps, confirm: request.body.confirm, userId: request.session.userId })
        return reply.code(202).send({ run })
      } catch (error) { return sendError(reply, error) }
    },
  )

  app.post<{ Params: { id: string } }>('/api/assessment-runs/:id/retry', async (request, reply) => {
    try { return { run: await retryAssessmentRun(Number(request.params.id)) } } catch (error) { return sendError(reply, error) }
  })

  app.post<{ Params: { id: string } }>('/api/assessment-runs/:id/cancel', async (request, reply) => {
    try { return { run: cancelAssessmentRun(Number(request.params.id)) } } catch (error) { return sendError(reply, error) }
  })

  app.get<{ Params: { id: string } }>('/api/assessment-runs/:id/comparison', async (request, reply) => {
    const comparison = getAssessmentComparison(Number(request.params.id))
    if (!comparison) return reply.code(404).send({ error: 'assessment run not found' })
    return { comparison }
  })

  app.post<{ Params: { id: string; stepId: string; jobId: string } }>('/api/assessment-runs/:id/steps/:stepId/jobs/:jobId/retry', async (request, reply) => {
    try { return { run: await retryAssessmentTarget(Number(request.params.id), Number(request.params.stepId), Number(request.params.jobId)) } } catch (error) { return sendError(reply, error) }
  })

  app.post<{ Params: { id: string; stepId: string; jobId: string } }>('/api/assessment-runs/:id/steps/:stepId/jobs/:jobId/cancel', async (request, reply) => {
    try { return { run: await cancelAssessmentTarget(Number(request.params.id), Number(request.params.stepId), Number(request.params.jobId)) } } catch (error) { return sendError(reply, error) }
  })

  app.post<{ Params: { id: string } }>('/api/assessment-runs/:id/report-snapshot', async (request, reply) => {
    try {
      const snapshot = createAssessmentReport(Number(request.params.id))
      if (!snapshot) return reply.code(404).send({ error: 'domain not found' })
      return { snapshot }
    } catch (error) { return sendError(reply, error) }
  })
}
