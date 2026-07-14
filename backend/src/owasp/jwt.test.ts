import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { analyzeJwtToken, BUILTIN_JWT_SECRETS, crackHmacSecret, decodeJwt, findJwts } from './jwt'

// Build a real HS256 token so the crack is exercised against a genuine signature.
function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function makeHs256(payload: Record<string, unknown>, secret: string, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  const h = b64url(JSON.stringify(header))
  const p = b64url(JSON.stringify(payload))
  const sig = b64url(createHmac('sha256', secret).update(`${h}.${p}`).digest())
  return `${h}.${p}.${sig}`
}

describe('findJwts', () => {
  it('extracts JWT-shaped tokens from a blob', () => {
    const t = makeHs256({ sub: 1 }, 'secret')
    expect(findJwts(`Authorization: Bearer ${t}`)).toContain(t)
  })
  it('returns nothing for non-JWT text', () => {
    expect(findJwts('just some text with dots a.b.c')).toEqual([])
  })
})

describe('decodeJwt', () => {
  it('decodes header and payload', () => {
    const d = decodeJwt(makeHs256({ sub: 'abc', role: 'admin' }, 'secret'))
    expect(d?.header.alg).toBe('HS256')
    expect(d?.payload.role).toBe('admin')
  })
  it('rejects a non-three-part token', () => {
    expect(decodeJwt('a.b')).toBeNull()
  })
})

describe('crackHmacSecret', () => {
  it('recovers a weak secret from the builtin list (self-verifying)', () => {
    const t = makeHs256({ sub: 1 }, 'changeme')
    expect(crackHmacSecret(t, BUILTIN_JWT_SECRETS)).toBe('changeme')
  })
  it('recovers an operator-supplied secret', () => {
    const t = makeHs256({ sub: 1 }, 'hunter2-unusual')
    expect(crackHmacSecret(t, ['hunter2-unusual'])).toBe('hunter2-unusual')
  })
  it('returns null for a strong (uncracked) secret', () => {
    const t = makeHs256({ sub: 1 }, 'f9c2b1a4-really-long-random-and-not-in-any-list-8842')
    expect(crackHmacSecret(t, BUILTIN_JWT_SECRETS)).toBeNull()
  })
  it('does not attempt non-HMAC algorithms', () => {
    const rs256 = `${b64url(JSON.stringify({ alg: 'RS256' }))}.${b64url(JSON.stringify({ sub: 1 }))}.AAAA`
    expect(crackHmacSecret(rs256, BUILTIN_JWT_SECRETS)).toBeNull()
  })
})

describe('analyzeJwtToken', () => {
  it('flags alg:none as critical', () => {
    const t = `${b64url(JSON.stringify({ alg: 'none' }))}.${b64url(JSON.stringify({ sub: 1 }))}.`
    const names = analyzeJwtToken(t, 'test').map((f) => f.name)
    expect(names.some((n) => /alg:none/.test(n))).toBe(true)
  })

  it('flags a cracked HMAC secret as critical', () => {
    const f = analyzeJwtToken(makeHs256({ sub: 1 }, 'secret'), 'test')
    const cracked = f.find((x) => /cracked/.test(x.name))
    expect(cracked?.severity).toBe('critical')
    expect(cracked?.evidence).toContain('"secret"')
  })

  it('flags a missing expiry', () => {
    const names = analyzeJwtToken(makeHs256({ sub: 1 }, 'strong-uncrackable-secret-xyz-123'), 'test').map((f) => f.name)
    expect(names.some((n) => /no expiry/.test(n))).toBe(true)
  })

  it('flags jku/x5u key-URL headers', () => {
    const t = makeHs256({ sub: 1 }, 'x', { alg: 'HS256', jku: 'https://evil.example/keys' })
    expect(analyzeJwtToken(t, 'test').some((f) => /external key URL/.test(f.name))).toBe(true)
  })

  it('returns [] for a non-JWT', () => {
    expect(analyzeJwtToken('not-a-jwt', 'test')).toEqual([])
  })
})
