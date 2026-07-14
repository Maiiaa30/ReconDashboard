import { describe, expect, it } from 'vitest'
import { corsVerdict } from './cors'

describe('corsVerdict', () => {
  it('returns null when no ACAO header is present', () => {
    expect(corsVerdict('https://evil.example.org', null, null)).toBeNull()
  })

  it('reflects an arbitrary origin without creds → medium', () => {
    const v = corsVerdict('https://evil.example.org', 'https://evil.example.org', null)
    expect(v).toEqual({ severity: 'medium', reflected: 'origin', withCreds: false })
  })

  it('reflects an arbitrary origin WITH creds → high', () => {
    const v = corsVerdict('https://evil.example.org', 'https://evil.example.org', 'true')
    expect(v).toEqual({ severity: 'high', reflected: 'origin', withCreds: true })
  })

  it('reflects the null origin', () => {
    expect(corsVerdict('null', 'null', 'true')).toEqual({ severity: 'high', reflected: 'null', withCreds: true })
  })

  it('treats a wildcard as low (browsers refuse creds with it)', () => {
    expect(corsVerdict('https://evil.example.org', '*', 'true')).toEqual({ severity: 'low', reflected: 'wildcard', withCreds: true })
  })

  it('does NOT flag when the server echoes a DIFFERENT allowed origin', () => {
    // Exact-match guard: reflecting a trusted origin we did not send is not a bug.
    expect(corsVerdict('https://evil.example.org', 'https://trusted.example.com', 'true')).toBeNull()
  })

  it('ignores Allow-Credentials casing/whitespace', () => {
    expect(corsVerdict('https://e.org', 'https://e.org', ' TRUE ')?.withCreds).toBe(true)
    expect(corsVerdict('https://e.org', 'https://e.org', 'false')?.withCreds).toBe(false)
  })
})
