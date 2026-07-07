import { describe, expect, it, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { authGuard } from './guard'

// The auth guard is DEFAULT-DENY: every route needs a session except the exact
// method+path pairs on the public allowlist. A regression here means either an
// auth bypass or a locked-out login, so it gets explicit coverage.

function mkReply() {
  const reply: any = { statusCode: null as number | null, payload: null as unknown }
  reply.code = vi.fn((c: number) => {
    reply.statusCode = c
    return reply
  })
  reply.send = vi.fn((p: unknown) => {
    reply.payload = p
    return reply
  })
  return reply as FastifyReply & { statusCode: number | null; payload: unknown }
}

function mkReq(method: string, url: string, userId?: number): FastifyRequest {
  return { method, url, session: userId ? { userId } : {} } as unknown as FastifyRequest
}

describe('authGuard', () => {
  it('lets the public allowlist through without a session', async () => {
    for (const [method, url] of [
      ['GET', '/api/health'],
      ['POST', '/api/auth/login'],
    ] as const) {
      const reply = mkReply()
      await authGuard(mkReq(method, url), reply)
      expect(reply.code).not.toHaveBeenCalled()
    }
  })

  it('401s an unauthenticated request to a protected route', async () => {
    const reply = mkReply()
    await authGuard(mkReq('GET', '/api/domains'), reply)
    expect(reply.code).toHaveBeenCalledWith(401)
    expect(reply.payload).toEqual({ error: 'unauthorized' })
  })

  it('allows a protected route when a session exists', async () => {
    const reply = mkReply()
    await authGuard(mkReq('GET', '/api/domains', 42), reply)
    expect(reply.code).not.toHaveBeenCalled()
  })

  it('ignores the query string when matching the path', async () => {
    const reply = mkReply()
    await authGuard(mkReq('GET', '/api/findings?domainId=1&type=leak'), reply)
    expect(reply.code).toHaveBeenCalledWith(401)
  })

  it('matches on METHOD too — wrong method for a public route is denied', async () => {
    // /api/auth/login is public only for POST; a GET must still require auth.
    const reply = mkReply()
    await authGuard(mkReq('GET', '/api/auth/login'), reply)
    expect(reply.code).toHaveBeenCalledWith(401)
  })

  it('does not treat a path that merely contains a public path as public', async () => {
    const reply = mkReply()
    await authGuard(mkReq('GET', '/api/health/../domains'), reply)
    expect(reply.code).toHaveBeenCalledWith(401)
  })
})
