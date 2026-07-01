import { describe, expect, it } from 'vitest'
import { evaluateScope, ipInCidr, parseScopeConfig, scopeIsEmpty, scopeNeedsIps } from './scope'

describe('ipInCidr (IPv4)', () => {
  it('matches inside the range', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true)
    expect(ipInCidr('192.168.1.5', '192.168.1.0/24')).toBe(true)
    expect(ipInCidr('1.2.3.4', '1.2.3.4/32')).toBe(true)
  })
  it('rejects outside the range', () => {
    expect(ipInCidr('11.0.0.1', '10.0.0.0/8')).toBe(false)
    expect(ipInCidr('192.168.2.5', '192.168.1.0/24')).toBe(false)
    expect(ipInCidr('1.2.3.5', '1.2.3.4/32')).toBe(false)
  })
  it('handles /0 (everything) and rejects malformed input', () => {
    expect(ipInCidr('8.8.8.8', '0.0.0.0/0')).toBe(true)
    expect(ipInCidr('8.8.8.8', 'not-a-cidr')).toBe(false)
    expect(ipInCidr('8.8.8.8', '10.0.0.0/33')).toBe(false)
  })
  it('does not cross IP families', () => {
    expect(ipInCidr('10.0.0.1', '2001:db8::/32')).toBe(false)
    expect(ipInCidr('2001:db8::1', '10.0.0.0/8')).toBe(false)
  })
})

describe('ipInCidr (IPv6)', () => {
  it('matches inside the range', () => {
    expect(ipInCidr('2001:db8::1', '2001:db8::/32')).toBe(true)
    expect(ipInCidr('2001:db8:abcd::5', '2001:db8::/32')).toBe(true)
    expect(ipInCidr('::1', '::1/128')).toBe(true)
  })
  it('rejects outside the range', () => {
    expect(ipInCidr('2001:db9::1', '2001:db8::/32')).toBe(false)
    expect(ipInCidr('fe80::1', '2001:db8::/32')).toBe(false)
  })
})

describe('parseScopeConfig', () => {
  it('normalizes and drops junk', () => {
    const s = parseScopeConfig({ allow: [' Example.com ', '', 'A.B.C'], deny: ['10.0.0.0/8'] })
    expect(s.allow).toEqual(['example.com', 'a.b.c'])
    expect(s.deny).toEqual(['10.0.0.0/8'])
  })
  it('tolerates missing / wrong-typed input', () => {
    expect(parseScopeConfig(null)).toEqual({ allow: [], deny: [] })
    expect(parseScopeConfig({ allow: 'nope' })).toEqual({ allow: [], deny: [] })
    expect(scopeIsEmpty(parseScopeConfig({}))).toBe(true)
  })
})

describe('scopeNeedsIps', () => {
  it('is true only when a CIDR entry is present', () => {
    expect(scopeNeedsIps(parseScopeConfig({ allow: ['example.com'] }))).toBe(false)
    expect(scopeNeedsIps(parseScopeConfig({ allow: ['example.com', '10.0.0.0/8'] }))).toBe(true)
  })
})

describe('evaluateScope', () => {
  const empty = parseScopeConfig({})

  it('allows everything when scope is empty', () => {
    expect(evaluateScope('anything.example.com', [], empty).inScope).toBe(true)
  })

  it('deny always wins, even over allow', () => {
    const s = parseScopeConfig({ allow: ['example.com'], deny: ['secret.example.com'] })
    expect(evaluateScope('secret.example.com', [], s).inScope).toBe(false)
    expect(evaluateScope('www.example.com', [], s).inScope).toBe(true)
  })

  it('a non-empty allow list restricts to matching hosts/subdomains', () => {
    const s = parseScopeConfig({ allow: ['example.com'] })
    expect(evaluateScope('example.com', [], s).inScope).toBe(true)
    expect(evaluateScope('api.example.com', [], s).inScope).toBe(true)
    expect(evaluateScope('evil.com', [], s).inScope).toBe(false)
    // suffix must be on a dot boundary — notexample.com must NOT match example.com
    expect(evaluateScope('notexample.com', [], s).inScope).toBe(false)
  })

  it('matches allow/deny CIDRs against resolved IPs', () => {
    const allow = parseScopeConfig({ allow: ['10.0.0.0/8'] })
    expect(evaluateScope('host.example.com', ['10.9.9.9'], allow).inScope).toBe(true)
    expect(evaluateScope('host.example.com', ['8.8.8.8'], allow).inScope).toBe(false)

    const deny = parseScopeConfig({ deny: ['203.0.113.0/24'] })
    expect(evaluateScope('host.example.com', ['203.0.113.7'], deny).inScope).toBe(false)
    expect(evaluateScope('host.example.com', ['203.0.114.7'], deny).inScope).toBe(true)
  })
})
