import { describe, expect, it } from 'vitest'
import { discoverParams, makeProbe, type Probe, type ProbeFetch, type ProbeResult } from './paramDiscovery'

const opts = { runToken: 'tok', maxProbes: 500 }

// Build a fake target: baseline body of fixed length; certain params, when present,
// either reflect their canary value or change the body length (honored).
function fakeTarget(cfg: { reflect?: string[]; lengthen?: string[]; baseLen?: number }): Probe {
  const base = 'x'.repeat(cfg.baseLen ?? 500)
  return async (params: Record<string, string>): Promise<ProbeResult | null> => {
    let body = base
    for (const p of cfg.reflect ?? []) if (params[p] != null) body += params[p] // echo the canary
    for (const p of cfg.lengthen ?? []) if (params[p] != null) body += 'y'.repeat(300) // big length delta
    return { status: 200, body }
  }
}

describe('discoverParams', () => {
  it('finds a reflected parameter by its canary', async () => {
    const hits = await discoverParams(['debug', 'admin', 'id'], fakeTarget({ reflect: ['admin'] }), opts)
    expect(hits.map((h) => h.param)).toContain('admin')
    expect(hits.find((h) => h.param === 'admin')?.reason).toBe('reflected')
  })

  it('finds a length-honored parameter by bisection', async () => {
    const many = Array.from({ length: 40 }, (_, i) => `p${i}`)
    const hits = await discoverParams(many, fakeTarget({ lengthen: ['p37'] }), opts)
    expect(hits.map((h) => h.param)).toContain('p37')
    expect(hits.find((h) => h.param === 'p37')?.reason).toBe('length')
  })

  it('reports nothing on a target that honors no params', async () => {
    const hits = await discoverParams(['a', 'b', 'c', 'd'], fakeTarget({}), opts)
    expect(hits).toEqual([])
  })

  it('finds multiple honored params in one chunk', async () => {
    const many = Array.from({ length: 30 }, (_, i) => `q${i}`)
    const hits = await discoverParams(many, fakeTarget({ lengthen: ['q3', 'q27'] }), opts)
    const found = hits.map((h) => h.param)
    expect(found).toEqual(expect.arrayContaining(['q3', 'q27']))
  })

  it('ignores invalid param names', async () => {
    const hits = await discoverParams(['bad name', 'ok_param'], fakeTarget({ reflect: ['ok_param'] }), opts)
    expect(hits.map((h) => h.param)).toEqual(['ok_param'])
  })

  it('stops early when aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const hits = await discoverParams(['a', 'b'], fakeTarget({ reflect: ['a'] }), { ...opts, signal: controller.signal })
    // baseline probes short-circuit on abort → no hits
    expect(hits).toEqual([])
  })
})

describe('makeProbe transports', () => {
  // Capture the request the probe would send for one candidate param.
  async function capture(transport: Parameters<typeof makeProbe>[0]) {
    let seen: { url: string; method: string; headers: Record<string, string>; body?: string } | null = null
    const doFetch: ProbeFetch = async (url, init) => {
      seen = { url, ...init }
      return { status: 200, body: '' }
    }
    await makeProbe(transport, 'https://t.com/api', doFetch)({ is_admin: 'CANARY' })
    return seen!
  }

  it('query → GET with the param in the query string', async () => {
    const r = await capture('query')
    expect(r.method).toBe('GET')
    expect(r.url).toContain('is_admin=CANARY')
  })

  it('json → POST with a JSON body', async () => {
    const r = await capture('json')
    expect(r.method).toBe('POST')
    expect(r.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(r.body!)).toEqual({ is_admin: 'CANARY' })
  })

  it('form → POST with a urlencoded body', async () => {
    const r = await capture('form')
    expect(r.headers['Content-Type']).toBe('application/x-www-form-urlencoded')
    expect(r.body).toBe('is_admin=CANARY')
  })

  it('header → GET with the param as a request header', async () => {
    const r = await capture('header')
    expect(r.headers.is_admin).toBe('CANARY')
    expect(r.url).toBe('https://t.com/api') // not in the URL
  })

  it('discovers a BODY-only honored param end to end', async () => {
    // Backend that ignores query but honors a JSON body field (mass assignment).
    const doFetch: ProbeFetch = async (_url, init) => {
      let body = 'x'.repeat(500)
      if (init.body && init.body.includes('is_admin')) body += 'y'.repeat(300) // honored → length delta
      return { status: 200, body }
    }
    const jsonProbe = makeProbe('json', 'https://t.com/api', doFetch)
    const hits = await discoverParams(['debug', 'is_admin', 'role'], jsonProbe, opts)
    expect(hits.map((h) => h.param)).toContain('is_admin')
  })
})
