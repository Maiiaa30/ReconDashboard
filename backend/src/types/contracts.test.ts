import { beforeAll, describe, expect, it } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// config (imported transitively by responseValidation) validates SESSION_SECRET
// at module load, so set it before the dynamic imports below.
process.env.SESSION_SECRET = 'x'.repeat(48)
process.env.NODE_ENV = 'test' // isProd=false → a contract mismatch throws (loud)

// Loosely typed so the test does not thread zod's inferred types.
let contracts: typeof import('./contracts')
let registerResponseValidation: typeof import('./responseValidation')['registerResponseValidation']

beforeAll(async () => {
  contracts = await import('./contracts')
  registerResponseValidation = (await import('./responseValidation')).registerResponseValidation
})

const validFinding = {
  id: 1, domainId: 2, type: 'owasp', data: { note: 'x' }, score: 40, severity: 'high',
  host: 'a.example.com', ip: '203.0.113.1', url: 'https://a.example.com/', jobId: 5,
  tags: ['xss'], status: 'open', note: null, createdAt: '2026-01-01T00:00:00.000Z',
  lastSeenAt: null, retestRequestedAt: null,
}

describe('transport schemas', () => {
  it('accepts a well-formed finding page and rejects a bad one', () => {
    expect(contracts.findingPageSchema.safeParse({ findings: [validFinding], nextCursor: null }).success).toBe(true)
    // Missing the required `nextCursor` field is a contract violation.
    expect(contracts.findingPageSchema.safeParse({ findings: [validFinding] }).success).toBe(false)
    // A wrong-typed known field on the finding fails too.
    expect(
      contracts.findingPageSchema.safeParse({ findings: [{ ...validFinding, id: 'nope' }], nextCursor: null }).success,
    ).toBe(false)
  })

  it('is additive-tolerant: an unknown extra field still validates (.passthrough)', () => {
    expect(
      contracts.findingPageSchema.safeParse({ findings: [{ ...validFinding, brandNew: true }], nextCursor: null })
        .success,
    ).toBe(true)
  })

  it('registers a contract for the core paged/summary endpoints', () => {
    for (const key of ['GET /api/jobs', 'GET /api/findings', 'GET /api/findings/summary', 'GET /api/audit']) {
      expect(contracts.responseContracts[key]).toBeDefined()
    }
  })
})

describe('preSerialization contract hook', () => {
  // A bare Fastify app with the hook + routes whose URLs match registry keys.
  async function buildHooked(): Promise<FastifyInstance> {
    const app = Fastify()
    registerResponseValidation(app)
    // Matches `GET /api/jobs` in the registry.
    app.get('/api/jobs', async (_req, reply) => {
      if (reply.request.headers['x-bad'] === '1') return { jobs: [{ id: 'not-a-number' }] }
      if (reply.request.headers['x-error'] === '1') return reply.code(400).send({ jobs: 'wrong-but-error' })
      // A realistic row still holds Date objects at preSerialization time — the
      // schema wants strings (the wire form). The hook must normalize before it
      // validates, or this 500s (the real bug live-testing caught).
      if (reply.request.headers['x-dates'] === '1') {
        return {
          jobs: [{
            id: 1, type: 'nmap_scan', status: 'done', domainId: 3, params: {}, result: {},
            error: null, progress: null,
            createdAt: new Date(), startedAt: new Date(), finishedAt: new Date(), updatedAt: new Date(),
          }],
        }
      }
      return { jobs: [] }
    })
    // NOT in the registry → never validated, even if the shape is junk.
    app.get('/api/uncovered', async () => ({ anything: 123 }))
    await app.ready()
    return app
  }

  it('passes a conforming payload through untouched (200)', async () => {
    const app = await buildHooked()
    const res = await app.inject({ method: 'GET', url: '/api/jobs' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ jobs: [] })
    await app.close()
  })

  it('fails loud (500) when a covered route emits the wrong shape', async () => {
    const app = await buildHooked()
    const res = await app.inject({ method: 'GET', url: '/api/jobs', headers: { 'x-bad': '1' } })
    expect(res.statusCode).toBe(500)
    await app.close()
  })

  it('normalizes Date fields to the wire form before validating (200)', async () => {
    const app = await buildHooked()
    const res = await app.inject({ method: 'GET', url: '/api/jobs', headers: { 'x-dates': '1' } })
    expect(res.statusCode).toBe(200)
    // Dates serialize to ISO strings, matching the z.string() contract.
    expect(typeof res.json().jobs[0].createdAt).toBe('string')
    await app.close()
  })

  it('does not validate non-2xx responses (error envelopes have their own shape)', async () => {
    const app = await buildHooked()
    const res = await app.inject({ method: 'GET', url: '/api/jobs', headers: { 'x-error': '1' } })
    expect(res.statusCode).toBe(400)
    await app.close()
  })

  it('ignores routes with no registered contract (opt-in)', async () => {
    const app = await buildHooked()
    const res = await app.inject({ method: 'GET', url: '/api/uncovered' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ anything: 123 })
    await app.close()
  })
})
