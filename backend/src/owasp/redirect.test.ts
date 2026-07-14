import { describe, expect, it } from 'vitest'
import { isSsrfParam, redirectsToAttacker } from './redirect'

const REQ = 'https://target.com/login?next=x'

describe('redirectsToAttacker', () => {
  it('confirms an absolute redirect to the attacker host', () => {
    expect(redirectsToAttacker('https://evil.example.org/', REQ)).toBe(true)
  })
  it('confirms a protocol-relative redirect', () => {
    expect(redirectsToAttacker('//evil.example.org/', REQ)).toBe(true)
  })
  it('confirms a backslash bypass (browser treats \\ as /)', () => {
    expect(redirectsToAttacker('/\\evil.example.org/', REQ)).toBe(true)
  })
  it('confirms a subdomain of the attacker host', () => {
    expect(redirectsToAttacker('https://x.evil.example.org/', REQ)).toBe(true)
  })
  it('does NOT flag a same-origin redirect', () => {
    expect(redirectsToAttacker('/dashboard', REQ)).toBe(false)
    expect(redirectsToAttacker('https://target.com/home', REQ)).toBe(false)
  })
  it('does NOT flag an encoded slash the server echoed verbatim (stays a path)', () => {
    // %2f%2fevil… returned literally resolves to a same-origin PATH, not a host.
    expect(redirectsToAttacker('/%2f%2fevil.example.org', REQ)).toBe(false)
  })
  it('does NOT flag a lookalike host that merely contains the string', () => {
    expect(redirectsToAttacker('https://evil.example.org.attacker-not.com/', REQ)).toBe(false)
    expect(redirectsToAttacker('https://notevil.example.org.legit.com/', REQ)).toBe(false)
  })
  it('handles an empty/garbage Location safely', () => {
    expect(redirectsToAttacker('', REQ)).toBe(false)
    expect(redirectsToAttacker('::::', REQ)).toBe(false)
  })
})

describe('isSsrfParam', () => {
  it('matches fetch-shaped param names', () => {
    for (const p of ['url', 'uri', 'dest', 'callback', 'image', 'proxy', 'webhook']) expect(isSsrfParam(p)).toBe(true)
  })
  it('does not match ordinary params', () => {
    for (const p of ['page', 'q', 'sort', 'id']) expect(isSsrfParam(p)).toBe(false)
  })
})
