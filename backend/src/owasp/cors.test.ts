import { describe, expect, it } from 'vitest'
import { corsVerdict } from './cors'

describe('corsVerdict', () => {
  it('returns null when no ACAO header is present', () => {
    expect(corsVerdict('https://evil.example.org', null, null)).toBeNull()
  })

  it('reflects an arbitrary origin without creds, WITH Vary: Origin → medium (not cacheable)', () => {
    const v = corsVerdict('https://evil.example.org', 'https://evil.example.org', null, 'Origin')
    expect(v).toEqual({ severity: 'medium', reflected: 'origin', withCreds: false, cacheable: false })
  })

  it('reflects an arbitrary origin without creds and NO Vary: Origin → high (cacheable/poisonable)', () => {
    const v = corsVerdict('https://evil.example.org', 'https://evil.example.org', null)
    expect(v).toEqual({ severity: 'high', reflected: 'origin', withCreds: false, cacheable: true })
  })

  it('reflects an arbitrary origin WITH creds → high', () => {
    const v = corsVerdict('https://evil.example.org', 'https://evil.example.org', 'true', 'Origin, Accept-Encoding')
    expect(v).toEqual({ severity: 'high', reflected: 'origin', withCreds: true, cacheable: false })
  })

  it('reflects the null origin', () => {
    expect(corsVerdict('null', 'null', 'true', 'Origin')).toEqual({ severity: 'high', reflected: 'null', withCreds: true, cacheable: false })
  })

  it('treats a wildcard as low (browsers refuse creds with it)', () => {
    expect(corsVerdict('https://evil.example.org', '*', 'true')).toEqual({ severity: 'low', reflected: 'wildcard', withCreds: true, cacheable: false })
  })

  it('does NOT flag when the server echoes a DIFFERENT allowed origin', () => {
    // Exact-match guard: reflecting a trusted origin we did not send is not a bug.
    expect(corsVerdict('https://evil.example.org', 'https://trusted.example.com', 'true')).toBeNull()
  })

  it('flags a suffix-escape origin (host directly concatenated) when reflected', () => {
    const v = corsVerdict('https://target.comevil.example.org', 'https://target.comevil.example.org', null, 'Origin')
    expect(v?.reflected).toBe('origin')
  })

  it('ignores Allow-Credentials casing/whitespace', () => {
    expect(corsVerdict('https://e.org', 'https://e.org', ' TRUE ')?.withCreds).toBe(true)
    expect(corsVerdict('https://e.org', 'https://e.org', 'false')?.withCreds).toBe(false)
  })
})
