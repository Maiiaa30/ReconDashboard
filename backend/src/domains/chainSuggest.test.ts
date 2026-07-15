import { describe, expect, it } from 'vitest'
import { buildChainSuggestions } from './chainSuggest'

// Minimal finding factory — buildChainSuggestions only reads type/data/tags/id.
let seq = 1
const f = (type: string, data: Record<string, unknown>, tags: string[] = []): any => ({ id: seq++, type, data, tags })

const ids = (s: ReturnType<typeof buildChainSuggestions>) => s.map((x) => x.id.split(':').slice(0, 2).join(':'))

describe('buildChainSuggestions', () => {
  it('suggests token forgery when a JWT secret is cracked', () => {
    const out = buildChainSuggestions(
      [f('owasp', { name: 'JWT HMAC secret cracked' }, ['owasp', 'jwt', 'cracked']), f('api', { kind: 'graphql', host: 'api.t.com' })],
      't.com',
    )
    const jwt = out.find((s) => s.id.startsWith('chain:jwt-forge'))
    expect(jwt?.severity).toBe('critical')
    expect(jwt?.findingIds.length).toBeGreaterThanOrEqual(1)
  })

  it('suggests IDOR testing for a honored authorization-shaped param', () => {
    const out = buildChainSuggestions([f('param', { param: 'is_admin', url: 'https://t.com/api/me' })], 't.com')
    expect(ids(out)).toContain('chain:authz-param')
    expect(out[0].severity).toBe('high')
  })

  it('does NOT suggest for an ordinary honored param', () => {
    const out = buildChainSuggestions([f('param', { param: 'page', url: 'https://t.com/list' })], 't.com')
    expect(ids(out)).not.toContain('chain:authz-param')
  })

  it('chains an open redirect into OAuth token theft only when both exist', () => {
    const both = buildChainSuggestions(
      [f('owasp', { name: 'Open redirect', url: 'https://t.com/go?next=x' }), f('api', { kind: 'openapi', endpoint: 'https://t.com/oauth/authorize' })],
      't.com',
    )
    expect(ids(both)).toContain('chain:redirect-oauth')
    // redirect alone → no chain
    const redirectOnly = buildChainSuggestions([f('owasp', { name: 'Open redirect', url: 'https://t.com/go?next=x' })], 't.com')
    expect(ids(redirectOnly)).not.toContain('chain:redirect-oauth')
  })

  it('suggests the SSRF/metadata probe for an SSRF-candidate param', () => {
    const out = buildChainSuggestions([f('owasp', { name: 'SSRF candidate parameter: url', url: 'https://t.com/fetch?url=x' })], 't.com')
    expect(ids(out)).toContain('chain:ssrf-imds')
  })

  it('suggests a repo dump for an exposed .git', () => {
    const out = buildChainSuggestions([f('owasp', { name: 'Dumpable .git repository (HEAD + config + index)', url: 'https://t.com/.git/' })], 't.com')
    const git = out.find((s) => s.id.startsWith('chain:git-dump'))
    expect(git?.severity).toBe('critical')
  })

  it('attaches a gated katana action to an introspectable GraphQL endpoint', () => {
    const out = buildChainSuggestions([f('api', { kind: 'graphql', host: 'api.t.com', endpoint: 'https://api.t.com/graphql', introspection: true })], 't.com')
    const gql = out.find((s) => s.id.startsWith('chain:graphql-authz'))
    expect(gql?.action).toEqual({ kind: 'katana', target: 'api.t.com' })
  })

  it('returns nothing for a domain with no chainable pairs', () => {
    expect(buildChainSuggestions([f('new_subdomain', { host: 'a.t.com' }), f('exposure', { ip: '1.2.3.4' })], 't.com')).toEqual([])
  })

  it('orders critical suggestions before high', () => {
    const out = buildChainSuggestions(
      [f('param', { param: 'role', url: 'https://t.com/x' }), f('owasp', { name: 'Dumpable .git repository' }, ['cracked'])],
      't.com',
    )
    expect(out[0].severity).toBe('critical')
  })
})
