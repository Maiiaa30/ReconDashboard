import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

// Drive assertPublicHost with exact A/AAAA records, and stub global fetch to
// return crafted redirects. Proves the two target-facing fetch paths that the
// audit (§3 #1) flagged — fingerprint + owasp active checks — refuse to follow a
// redirect into an internal address, and that the shared guarded client does too.
vi.mock('./dns', () => ({ resolveDns: vi.fn() }))

import { resolveDns } from './dns'
import { guardedFetchRaw } from './guard'
import { fingerprintHost } from './fingerprint'
import { runActiveChecks } from '../owasp/activeChecks'

const mockDns = vi.mocked(resolveDns)
const publicDns = { a: ['8.8.8.8'], aaaa: [] } as any

// Minimal Response-like stubs (only the fields the guard actually reads).
function redirectTo(location: string) {
  return {
    status: 302,
    headers: {
      get: (k: string) => (k.toLowerCase() === 'location' ? location : null),
      getSetCookie: () => [],
    },
    body: null,
  } as any
}
function ok(body: string, contentType = 'text/html') {
  const bytes = new TextEncoder().encode(body)
  let sent = false
  return {
    status: 200,
    headers: {
      get: (k: string) => (k.toLowerCase() === 'content-type' ? contentType : null),
      getSetCookie: () => [],
    },
    body: {
      getReader: () => ({
        read: async () => (sent ? { done: true, value: undefined } : ((sent = true), { done: false, value: bytes })),
        cancel: async () => {},
      }),
      cancel: async () => {},
    },
  } as any
}

describe('SSRF redirect guard on target-facing fetches (audit §3 #1)', () => {
  beforeEach(() => {
    mockDns.mockReset()
    mockDns.mockResolvedValue(publicDns)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('guardedFetchRaw refuses to follow a redirect to an internal address', async () => {
    const fetchMock = vi.fn().mockResolvedValue(redirectTo('http://127.0.0.1/'))
    vi.stubGlobal('fetch', fetchMock)
    const res = await guardedFetchRaw('https://target.example.com/', { follow: true })
    expect(res).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(1) // never fetched the internal hop
  })

  it('guardedFetchRaw follows a redirect to a public host and returns the final body', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(redirectTo('https://final.example.com/'))
      .mockResolvedValueOnce(ok('FINAL-BODY'))
    vi.stubGlobal('fetch', fetchMock)
    const res = await guardedFetchRaw('https://target.example.com/', { follow: true })
    expect(res?.status).toBe(200)
    expect(res?.body).toContain('FINAL-BODY')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('fingerprintHost bails when the target redirects to cloud metadata', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(redirectTo('http://169.254.169.254/')))
    const fp = await fingerprintHost('target.example.com')
    expect(fp.status).toBeNull()
    expect(fp.server).toBeNull()
  })

  it('runActiveChecks bails when the base URL redirects to loopback', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(redirectTo('http://127.0.0.1/')))
    const r = await runActiveChecks('https', 'target.example.com')
    expect(r.reachable).toBe(false)
    expect(r.findings).toEqual([])
  })
})
