import { describe, expect, it } from 'vitest'
import { analyzeCsp, analyzeHsts } from './csp'

const names = (csp: string) => analyzeCsp(csp).map((i) => i.name)

describe('analyzeCsp', () => {
  it('flags unsafe-inline script with no nonce/hash', () => {
    const n = names("default-src 'self'; script-src 'self' 'unsafe-inline'")
    expect(n.some((x) => /unsafe-inline/.test(x))).toBe(true)
  })

  it('does NOT flag unsafe-inline when a nonce is present (browser ignores it)', () => {
    // Per spec, a nonce/hash in the same source list neutralizes 'unsafe-inline'.
    const n = names("script-src 'self' 'unsafe-inline' 'nonce-abc123'")
    expect(n.some((x) => /unsafe-inline/.test(x))).toBe(false)
  })

  it('does NOT flag unsafe-inline when a sha256 hash is present', () => {
    const n = names("script-src 'unsafe-inline' 'sha256-AbCdEf=='")
    expect(n.some((x) => /unsafe-inline/.test(x))).toBe(false)
  })

  it('falls back to default-src when script-src is absent', () => {
    const n = names("default-src 'self' 'unsafe-inline'")
    expect(n.some((x) => /unsafe-inline/.test(x))).toBe(true)
  })

  it('flags a wildcard script source', () => {
    expect(names("script-src *").some((x) => /wildcard/.test(x))).toBe(true)
    expect(names("script-src https:").some((x) => /wildcard/.test(x))).toBe(true)
  })

  it('flags missing object-src and base-uri', () => {
    const n = names("default-src 'self'; script-src 'self'")
    expect(n.some((x) => /object-src/.test(x))).toBe(true)
    expect(n.some((x) => /base-uri/.test(x))).toBe(true)
  })

  it("does not flag missing object-src when default-src is 'none'", () => {
    const n = names("default-src 'none'; script-src 'self'; base-uri 'self'")
    expect(n.some((x) => /object-src/.test(x))).toBe(false)
  })

  it('returns nothing for an empty string', () => {
    expect(analyzeCsp('')).toEqual([])
  })
})

describe('analyzeHsts', () => {
  it('returns null for an absent header', () => {
    expect(analyzeHsts(null)).toBeNull()
  })
  it('flags a short max-age', () => {
    expect(analyzeHsts('max-age=3600; includeSubDomains')?.name).toBe('Weak HSTS policy')
  })
  it('flags a missing includeSubDomains', () => {
    expect(analyzeHsts('max-age=31536000')?.name).toBe('Weak HSTS policy')
  })
  it('accepts a strong policy', () => {
    expect(analyzeHsts('max-age=63072000; includeSubDomains; preload')).toBeNull()
  })
})
