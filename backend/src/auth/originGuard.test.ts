import { describe, expect, it, vi, beforeEach } from 'vitest'

// The guard reads config.trustedOrigins live, so drive it by mocking config.
// vi.hoisted so the object exists when the hoisted vi.mock factory runs.
const mockConfig = vi.hoisted(() => ({ trustedOrigins: [] as string[] }))
vi.mock('../config', () => ({ config: mockConfig }))

import { originGuard } from './originGuard'

type Req = { method: string; url: string; headers: Record<string, string | undefined> }
function run(req: Req) {
  let code: number | null = null
  let body: unknown = null
  let called = false
  const reply = {
    code(c: number) { code = c; return reply },
    send(b: unknown) { body = b; return reply },
  }
  const done = () => { called = true }
  originGuard(req as never, reply as never, done)
  return { code, body, allowed: called }
}

describe('originGuard (CSRF Origin allowlist)', () => {
  beforeEach(() => { mockConfig.trustedOrigins = [] })

  it('is a no-op when no trusted origins are configured', () => {
    expect(run({ method: 'POST', url: '/api/domains', headers: { origin: 'https://evil.test' } }).allowed).toBe(true)
  })

  it('allows safe methods regardless of Origin', () => {
    mockConfig.trustedOrigins = ['https://app.ts.net']
    expect(run({ method: 'GET', url: '/api/findings', headers: { origin: 'https://evil.test' } }).allowed).toBe(true)
  })

  it('allows a mutating request with no Origin header (same-origin / non-browser)', () => {
    mockConfig.trustedOrigins = ['https://app.ts.net']
    expect(run({ method: 'POST', url: '/api/domains', headers: {} }).allowed).toBe(true)
  })

  it('allows a mutating request from a trusted origin (trailing slash tolerated)', () => {
    mockConfig.trustedOrigins = ['https://app.ts.net']
    expect(run({ method: 'POST', url: '/api/domains', headers: { origin: 'https://app.ts.net/' } }).allowed).toBe(true)
  })

  it('refuses a mutating request from an untrusted origin', () => {
    mockConfig.trustedOrigins = ['https://app.ts.net']
    const r = run({ method: 'POST', url: '/api/domains', headers: { origin: 'https://evil.test' } })
    expect(r.allowed).toBe(false)
    expect(r.code).toBe(403)
    expect(r.body).toMatchObject({ code: 'bad_origin' })
  })

  it('exempts the token-authed capture ingest (cross-origin by design)', () => {
    mockConfig.trustedOrigins = ['https://app.ts.net']
    expect(run({ method: 'POST', url: '/api/capture', headers: { origin: 'https://some-target.example' } }).allowed).toBe(true)
    // but still guards other capture subpaths' mutations
    expect(run({ method: 'DELETE', url: '/api/capture/5', headers: { origin: 'https://evil.test' } }).allowed).toBe(false)
  })
})
