import { describe, expect, it } from 'vitest'
import { buildDnsIntelFindings, gatherDnsIntel, parseCaaIssuers, parseDmarc, parseSpf } from './dnsIntel'

describe('parseSpf', () => {
  it('extracts includes, ip4/ip6 ranges, and the all qualifier', () => {
    const spf = parseSpf(['some other txt', 'v=spf1 include:_spf.google.com ip4:203.0.113.0/24 ip6:2001:db8::/32 -all'])
    expect(spf.includes).toContain('_spf.google.com')
    expect(spf.ip4).toContain('203.0.113.0/24')
    expect(spf.ip6).toContain('2001:db8::/32')
    expect(spf.all).toBe('fail')
  })

  it('flags a permissive +all', () => {
    expect(parseSpf(['v=spf1 +all']).all).toBe('pass')
    expect(parseSpf(['v=spf1 ~all']).all).toBe('softfail')
  })

  it('returns a null record when there is no SPF', () => {
    expect(parseSpf(['google-site-verification=abc']).record).toBeNull()
  })
})

describe('parseDmarc', () => {
  it('extracts the policy, subdomain policy and reporting addresses', () => {
    const d = parseDmarc(['v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:agg@x.com'])
    expect(d.policy).toBe('reject')
    expect(d.subdomainPolicy).toBe('quarantine')
    expect(d.pct).toBe(100)
    expect(d.rua).toContain('mailto:agg@x.com')
  })
  it('returns null policy when absent', () => {
    expect(parseDmarc(['nope']).record).toBeNull()
  })
})

describe('parseCaaIssuers', () => {
  it('lists authorized CA hostnames', () => {
    expect(parseCaaIssuers(['issue:letsencrypt.org', 'issuewild:digicert.com', 'iodef:mailto:a@b.com'])).toEqual([
      'letsencrypt.org',
      'digicert.com',
    ])
  })
})

describe('buildDnsIntelFindings', () => {
  it('produces sender + range findings for a real SPF and none for a strong DMARC', () => {
    const spf = parseSpf(['v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all'])
    const dmarc = parseDmarc(['v=DMARC1; p=reject'])
    const f = buildDnsIntelFindings('t.com', spf, dmarc, ['letsencrypt.org'])
    const kinds = f.map((x) => x.kind)
    expect(kinds).toContain('dns_spf_senders')
    expect(kinds).toContain('dns_spf_ranges')
    expect(f.find((x) => x.kind === 'dns_dmarc')?.severity).toBe('info') // p=reject is fine
  })

  it('flags a spoofable domain (no SPF, no DMARC) as medium', () => {
    const f = buildDnsIntelFindings('weak.com', parseSpf([]), parseDmarc([]), [])
    expect(f.find((x) => x.kind === 'dns_dmarc')?.severity).toBe('medium')
    expect(f.find((x) => x.kind === 'dns_spf')?.name).toMatch(/No SPF/)
  })
})

describe('gatherDnsIntel', () => {
  it('resolves _dmarc and returns candidate ranges from SPF', async () => {
    const resolveTxt = async (h: string) => (h === '_dmarc.t.com' ? ['v=DMARC1; p=none'] : [])
    const intel = await gatherDnsIntel('t.com', ['v=spf1 ip4:198.51.100.0/24 -all'], ['issue:letsencrypt.org'], resolveTxt)
    expect(intel.candidateRanges).toEqual(['198.51.100.0/24'])
    expect(intel.dmarc.policy).toBe('none')
    expect(intel.caaIssuers).toEqual(['letsencrypt.org'])
  })
})
