import { describe, expect, it } from 'vitest'
import {
  hostBelongsToDomain,
  isInternalIp,
  isValidDomain,
  isValidHostname,
  isValidIp,
  normalizeDomain,
  normalizeHost,
} from './validate'

describe('normalizeDomain', () => {
  it('lowercases, trims, and strips a trailing dot', () => {
    expect(normalizeDomain('  Example.COM.  ')).toBe('example.com')
  })
})

describe('isValidDomain', () => {
  it('accepts registrable domains', () => {
    for (const d of ['example.com', 'sub.example.co.uk', 'a.b.c.example.org', 'xn--80ak6aa92e.com']) {
      expect(isValidDomain(d), d).toBe(true)
    }
  })
  it('rejects schemes, paths, ports, wildcards, and junk', () => {
    for (const d of ['http://example.com', 'example.com/path', 'example.com:8080', '*.example.com', '', 'example', 'exa mple.com', '-bad.com']) {
      expect(isValidDomain(d), d).toBe(false)
    }
  })
})

describe('normalizeHost / isValidHostname', () => {
  it('allows underscore labels from passive sources', () => {
    expect(normalizeHost('_dmarc.example.com')).toBe('_dmarc.example.com')
    expect(isValidHostname('_dmarc.example.com')).toBe(true)
  })
  it('strips a leading wildcard and trailing dot', () => {
    expect(normalizeHost('*.example.com')).toBe('example.com')
    expect(normalizeHost('host.example.com.')).toBe('host.example.com')
  })
  it('returns null for unusable input', () => {
    expect(normalizeHost('')).toBeNull()
    expect(normalizeHost('not a host')).toBeNull()
  })
})

describe('isValidIp', () => {
  it('accepts well-formed v4 and v6', () => {
    for (const ip of ['1.1.1.1', '255.255.255.255', '0.0.0.0', '2606:4700:4700::1111', '::1']) {
      expect(isValidIp(ip), ip).toBe(true)
    }
  })
  it('rejects out-of-range and malformed', () => {
    for (const ip of ['256.1.1.1', '1.1.1', '1.1.1.1.1', '999.999.999.999', 'nope', '12345::']) {
      expect(isValidIp(ip), ip).toBe(false)
    }
  })
})

describe('isInternalIp (SSRF guard)', () => {
  it('flags private, loopback, link-local, CGNAT, and reserved v4', () => {
    for (const ip of [
      '10.0.0.1', '10.255.255.255', '127.0.0.1', '172.16.0.1', '172.31.255.255',
      '192.168.1.1', '169.254.169.254', '100.64.0.1', '100.127.0.0', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    ]) {
      expect(isInternalIp(ip), ip).toBe(true)
    }
  })
  it('flags loopback, ULA, link-local, and IPv4-mapped v6', () => {
    for (const ip of ['::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1']) {
      expect(isInternalIp(ip), ip).toBe(true)
    }
  })
  it('does NOT flag public addresses', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1', '2606:4700:4700::1111']) {
      expect(isInternalIp(ip), ip).toBe(false)
    }
  })
})

describe('hostBelongsToDomain', () => {
  it('accepts the apex and true subdomains', () => {
    expect(hostBelongsToDomain('example.com', 'example.com')).toBe(true)
    expect(hostBelongsToDomain('a.b.example.com', 'example.com')).toBe(true)
  })
  it('rejects look-alike and unrelated hosts', () => {
    expect(hostBelongsToDomain('notexample.com', 'example.com')).toBe(false)
    expect(hostBelongsToDomain('example.com.evil.com', 'example.com')).toBe(false)
    expect(hostBelongsToDomain('evil.com', 'example.com')).toBe(false)
  })
})
