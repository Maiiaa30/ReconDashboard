import { describe, expect, it } from 'vitest'
import { bruteResolve, buildPermutationCandidates, isWildcardZone, PERMUTE_WORDS, type ResolveFn } from './dnsPermute'

describe('buildPermutationCandidates', () => {
  it('generates word.<domain> candidates and excludes known hosts', () => {
    const cands = buildPermutationCandidates('example.com', ['api.example.com'], { words: ['api', 'admin', 'staging'] })
    expect(cands).toContain('admin.example.com')
    expect(cands).toContain('staging.example.com')
    expect(cands).not.toContain('api.example.com') // already known → excluded
  })

  it('permutes existing labels: numeric neighbours and word-affixes', () => {
    const cands = buildPermutationCandidates('t.com', ['admin.t.com', 'web1.t.com'], { words: ['dev'] })
    expect(cands).toContain('admin2.t.com') // numeric bump on non-numeric label
    expect(cands).toContain('web2.t.com') // increment web1 -> web2
    expect(cands).toContain('dev-admin.t.com')
    expect(cands).toContain('admin-dev.t.com')
  })

  it('honours the max cap and only emits valid labels', () => {
    const many = Array.from({ length: 200 }, (_, i) => `h${i}.t.com`)
    const cands = buildPermutationCandidates('t.com', many, { max: 50 })
    expect(cands.length).toBeLessThanOrEqual(50)
    expect(cands.every((c) => /^[a-z0-9-]+\.t\.com$/.test(c))).toBe(true)
  })

  it('ships a non-trivial builtin wordlist', () => {
    expect(PERMUTE_WORDS.length).toBeGreaterThan(50)
  })
})

describe('isWildcardZone', () => {
  it('flags a wildcard zone when a random label resolves', async () => {
    const resolve: ResolveFn = async () => ['10.0.0.1'] // everything resolves
    const { wildcard, ips } = await isWildcardZone('wild.com', resolve)
    expect(wildcard).toBe(true)
    expect(ips).toContain('10.0.0.1')
  })

  it('does not flag a normal zone (random labels NXDOMAIN)', async () => {
    const resolve: ResolveFn = async () => []
    expect((await isWildcardZone('real.com', resolve)).wildcard).toBe(false)
  })
})

describe('bruteResolve', () => {
  it('keeps only resolvable candidates', async () => {
    const live = new Set(['api.t.com'])
    const resolve: ResolveFn = async (h) => (live.has(h) ? ['1.2.3.4'] : [])
    const hits = await bruteResolve(['api.t.com', 'nope.t.com'], resolve)
    expect(hits.map((h) => h.host)).toEqual(['api.t.com'])
  })

  it('drops hosts that resolve only to the wildcard IP set', async () => {
    const resolve: ResolveFn = async (h) => (h === 'real.t.com' ? ['9.9.9.9'] : ['10.0.0.1'])
    const hits = await bruteResolve(['real.t.com', 'catchall.t.com'], resolve, { wildcardIps: ['10.0.0.1'] })
    expect(hits.map((h) => h.host)).toEqual(['real.t.com'])
  })
})
