import { describe, expect, it, vi } from 'vitest'

// store.ts opens the SQLite handle at import; stub it out so we can unit-test the
// pure dedup-key logic without a database.
vi.mock('../db/index', () => ({ db: {} }))

import { findingKey } from './store'

// findingKey is the identity used to UPSERT findings — a wrong key either dupes a
// finding on every re-scan or silently overwrites a distinct one.
describe('findingKey', () => {
  it('keys each finding type on its stable identity', () => {
    expect(findingKey('new_subdomain', { host: 'a.example.com' })).toBe('host:a.example.com')
    expect(findingKey('exposure', { ip: '1.2.3.4' })).toBe('ip:1.2.3.4')
    expect(findingKey('origin', { domain: 'example.com' })).toBe('origin:example.com')
    expect(findingKey('osint', { kind: 'dns' })).toBe('osint:dns')
    expect(findingKey('nmap', { target: 'example.com' })).toBe('nmap:example.com')
    expect(findingKey('nuclei', { templateId: 'cve-x', matched: 'https://e.com' })).toBe('nuclei:cve-x@https://e.com')
    expect(findingKey('owasp', { category: 'A03', name: 'XSS', url: 'https://e.com' })).toBe('owasp:A03:XSS@https://e.com')
    expect(findingKey('tool', { tool: 'sslscan', target: 'e.com' })).toBe('tool:sslscan@e.com')
    expect(findingKey('ffuf', { url: 'https://e.com/admin' })).toBe('url:https://e.com/admin')
    expect(findingKey('cve_new', { ip: '1.2.3.4', cveId: 'CVE-2024-1' })).toBe('cvenew:1.2.3.4:CVE-2024-1')
  })

  it('keys a leak on identity + breach + credential fingerprint', () => {
    const k = findingKey('leak', { email: 'Bob@Example.com', source: 'Adobe', password: 'hunter2xyz' })
    expect(k).toBe('leak:bob@example.com:Adobe:hunter2xyz')
  })

  it('distinguishes the same account in the same breach with different passwords', () => {
    const a = findingKey('leak', { email: 'a@e.com', source: 'X', password: 'pw-one' })
    const b = findingKey('leak', { email: 'a@e.com', source: 'X', password: 'pw-two' })
    expect(a).not.toBe(b)
  })

  it('falls back to username when a leak has no email', () => {
    expect(findingKey('leak', { username: 'neo', source: 'Y' })).toBe('leak:neo:Y:')
  })

  it('returns null when there is nothing stable to key on', () => {
    expect(findingKey('new_subdomain', {})).toBeNull()
    expect(findingKey('exposure', {})).toBeNull()
    expect(findingKey('leak', {})).toBeNull()
    expect(findingKey('unknown_type', { anything: 1 })).toBeNull()
    expect(findingKey('exposure', null)).toBeNull()
  })
})
