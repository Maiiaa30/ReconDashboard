import { afterEach, describe, expect, it, vi } from 'vitest'
import { get } from './http'
import { getConnection, resetConnection } from './connection'

function response(body: unknown, options: { ok?: boolean; status?: number } = {}): Response {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    text: async () => JSON.stringify(body),
  } as Response
}

describe('connection status derived from the transport', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    resetConnection()
  })

  it('marks the app offline when fetch fails at the network level', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))

    await expect(get('/anything')).rejects.toThrow('Failed to fetch')
    expect(getConnection().online).toBe(false)
  })

  it('does not go offline when a request is deliberately aborted', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('aborted', 'AbortError')))

    await expect(get('/cancelled')).rejects.toThrow()
    expect(getConnection().online).toBe(true)
  })

  it('recovers to online on the next successful response', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(response({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(get('/first')).rejects.toThrow()
    expect(getConnection().online).toBe(false)

    await get('/second')
    expect(getConnection().online).toBe(true)
  })

  it('flags an expired session when an authed request returns 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ error: 'unauthorized' }, { ok: false, status: 401 })))

    await expect(get('/protected')).rejects.toThrow()
    expect(getConnection().sessionExpired).toBe(true)
    // A reachable 401 still means the backend is up.
    expect(getConnection().online).toBe(true)
  })

  it('leaves the session flag untouched for other error statuses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ error: 'nope' }, { ok: false, status: 403 })))

    await expect(get('/forbidden')).rejects.toThrow()
    expect(getConnection().sessionExpired).toBe(false)
  })
})
