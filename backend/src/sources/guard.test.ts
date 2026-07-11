import { describe, expect, it, vi, beforeEach } from 'vitest'

// Mock DNS so we can drive assertPublicHost with exact A/AAAA records.
vi.mock('./dns', () => ({ resolveDns: vi.fn() }))

import { resolveDns } from './dns'
import { assertPublicHost, SsrfBlockedError } from './guard'

const mockDns = vi.mocked(resolveDns)
const dns = (a: string[] = [], aaaa: string[] = []) => ({ a, aaaa }) as any

describe('assertPublicHost (SSRF guard)', () => {
  beforeEach(() => mockDns.mockReset())

  it('allows a host that resolves only to public addresses', async () => {
    mockDns.mockResolvedValue(dns(['8.8.8.8'], ['2606:4700:4700::1111']))
    await expect(assertPublicHost('example.com')).resolves.toBeUndefined()
  })

  it('blocks loopback', async () => {
    mockDns.mockResolvedValue(dns(['127.0.0.1']))
    await expect(assertPublicHost('evil.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
  })

  it('blocks RFC1918 private ranges', async () => {
    for (const ip of ['10.0.0.5', '192.168.1.10', '172.16.0.1']) {
      mockDns.mockResolvedValue(dns([ip]))
      await expect(assertPublicHost('h.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
    }
  })

  it('blocks CGNAT / Tailscale range (100.64.0.0/10)', async () => {
    // The dashboard itself sits on a tailnet IP in this range — an engagement
    // target pointing here must never be connected to.
    mockDns.mockResolvedValue(dns(['100.86.63.107']))
    await expect(assertPublicHost('sneaky.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
  })

  it('blocks IPv6 loopback and ULA', async () => {
    for (const ip of ['::1', 'fc00::1', 'fd12:3456::1']) {
      mockDns.mockResolvedValue(dns([], [ip]))
      await expect(assertPublicHost('h.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
    }
  })

  it('blocks when ANY record is internal, even if the first is public', async () => {
    mockDns.mockResolvedValue(dns(['8.8.8.8', '10.0.0.9']))
    await expect(assertPublicHost('mixed.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
  })

  it('blocks the IPv4-mapped IPv6 loopback form', async () => {
    mockDns.mockResolvedValue(dns([], ['::ffff:127.0.0.1']))
    await expect(assertPublicHost('mapped.example.com')).rejects.toBeInstanceOf(SsrfBlockedError)
  })

  it('allows a host that resolves to no records', async () => {
    // No A/AAAA -> nothing to block; the connection just fails on its own later.
    mockDns.mockResolvedValue(dns([], []))
    await expect(assertPublicHost('empty.example.com')).resolves.toBeUndefined()
  })

  // Literal-IP + localhost hosts have no DNS to resolve, so they must be blocked
  // synchronously (the Replay tool lets an operator type any URL directly).
  it('blocks literal internal IPs and localhost without DNS', async () => {
    for (const host of ['127.0.0.1', '10.0.0.5', '169.254.169.254', '[::1]', 'localhost', 'foo.localhost']) {
      await expect(assertPublicHost(host)).rejects.toBeInstanceOf(SsrfBlockedError)
    }
    expect(mockDns).not.toHaveBeenCalled() // resolved by the literal/name short-circuit, no DNS
  })

  it('allows a public literal IP without a DNS lookup', async () => {
    await expect(assertPublicHost('8.8.8.8')).resolves.toBeUndefined()
    expect(mockDns).not.toHaveBeenCalled()
  })
})
