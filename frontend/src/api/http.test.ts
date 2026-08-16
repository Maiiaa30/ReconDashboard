import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, get, post } from './http'

function response(body: unknown, options: { ok?: boolean; status?: number } = {}): Response {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body),
  } as Response
}

describe('HTTP transport', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('keeps bodyless requests simple and forwards cancellation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    await get('/health', { signal: controller.signal })

    expect(fetchMock).toHaveBeenCalledWith('/api/health', { headers: {}, signal: controller.signal })
  })

  it('serializes JSON bodies with the correct content type', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)

    await post('/example', { value: 3 })

    expect(fetchMock).toHaveBeenCalledWith('/api/example', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: 3 }),
    })
  })

  it('preserves backend error envelopes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ error: 'not allowed' }, { ok: false, status: 403 })))

    await expect(get('/private')).rejects.toEqual(new ApiError(403, 'not allowed'))
  })
})
