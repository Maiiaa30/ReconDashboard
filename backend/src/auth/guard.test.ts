import { describe, expect, it } from 'vitest'
import { authGuard } from './guard'

// Minimal fakes for the two things authGuard reads/writes.
function fakeReq(method: string, url: string, userId?: number) {
  return { method, url, session: userId ? { userId } : {} } as unknown as Parameters<typeof authGuard>[0]
}
function fakeReply() {
  const calls: { code?: number; body?: unknown } = {}
  const reply = {
    code(c: number) {
      calls.code = c
      return reply
    },
    send(b: unknown) {
      calls.body = b
      return reply
    },
  }
  return { reply: reply as unknown as Parameters<typeof authGuard>[1], calls }
}

describe('authGuard', () => {
  it('401s an unauthenticated API request', async () => {
    const { reply, calls } = fakeReply()
    await authGuard(fakeReq('GET', '/api/domains'), reply)
    expect(calls.code).toBe(401)
  })

  it('lets an authenticated API request through', async () => {
    const { reply, calls } = fakeReply()
    await authGuard(fakeReq('GET', '/api/domains', 7), reply)
    expect(calls.code).toBeUndefined()
  })

  it('lets public routes through unauthenticated', async () => {
    const { reply, calls } = fakeReply()
    await authGuard(fakeReq('GET', '/api/health'), reply)
    expect(calls.code).toBeUndefined()
  })

  it('lets a non-API GET (the SPA shell / assets) through unauthenticated', async () => {
    // The single-origin regression: without this the login page itself 401s.
    for (const url of ['/', '/index.html', '/assets/index-abc.js', '/findings']) {
      const { reply, calls } = fakeReply()
      await authGuard(fakeReq('GET', url), reply)
      expect(calls.code, url).toBeUndefined()
    }
  })

  it('still guards a non-API NON-GET without a session', async () => {
    const { reply, calls } = fakeReply()
    await authGuard(fakeReq('POST', '/something'), reply)
    expect(calls.code).toBe(401)
  })
})
