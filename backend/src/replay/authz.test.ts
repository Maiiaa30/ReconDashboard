import { describe, expect, it } from 'vitest'
import { applyId, authzVerdict, hasIdMarker, ID_MARKER } from './authz'

const ok = (length: number) => ({ status: 200, length })
const denied = { status: 403, length: 20 }

describe('authzVerdict', () => {
  it('flags missing_authz when anonymous gets A’s object', () => {
    const v = authzVerdict(ok(1000), denied, ok(1000))
    expect(v.verdict).toBe('missing_authz')
  })

  it('flags likely_idor when identity B gets a body matching A', () => {
    const v = authzVerdict(ok(1000), ok(1010), denied)
    expect(v.verdict).toBe('likely_idor')
  })

  it('reports enforced when B and anonymous are both refused', () => {
    const v = authzVerdict(ok(1000), denied, denied)
    expect(v.verdict).toBe('enforced')
  })

  it('is inconclusive when A itself did not succeed', () => {
    expect(authzVerdict(denied, denied, denied).verdict).toBe('inconclusive')
  })

  it('does not call it IDOR when B’s body is a different size (e.g. B’s own object)', () => {
    // B gets 2xx but a very different length — likely B seeing B's own object, not A's.
    const v = authzVerdict(ok(1000), ok(200), denied)
    expect(v.verdict).not.toBe('likely_idor')
  })

  it('prioritises missing_authz over idor when both anonymous and B succeed', () => {
    expect(authzVerdict(ok(1000), ok(1000), ok(1000)).verdict).toBe('missing_authz')
  })

  it('treats an errored identity as not-ok', () => {
    expect(authzVerdict(ok(1000), { status: 0, length: 0, error: 'timeout' }, denied).verdict).toBe('enforced')
  })
})

describe('applyId / hasIdMarker', () => {
  it('substitutes the id marker', () => {
    expect(applyId(`https://t.com/api/users/${ID_MARKER}`, '42')).toBe('https://t.com/api/users/42')
  })
  it('detects the marker across parts', () => {
    expect(hasIdMarker(['https://t.com/', undefined, `{"id":"${ID_MARKER}"}`])).toBe(true)
    expect(hasIdMarker(['https://t.com/', undefined])).toBe(false)
  })
})
