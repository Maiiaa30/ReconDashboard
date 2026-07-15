import { createHmac, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  algIsAsymmetric,
  analyzeJwtToken,
  BUILTIN_JWT_SECRETS,
  confusionConfirmed,
  crackHmacSecret,
  decodeJwt,
  findJwts,
  forgeAlgConfusion,
  jwkToPem,
  jwtWordlistPathOk,
  keyMaterialCandidates,
  verifyHs256,
} from './jwt'

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

  it('flags an asymmetric alg as an RS256->HS256 confusion candidate', () => {
    const rs256 = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: 1, exp: 9999999999 }))}.AAAA`
    expect(analyzeJwtToken(rs256, 'test').some((f) => /confusion candidate/.test(f.name))).toBe(true)
  })

  it('does not flag confusion for an HS256 token', () => {
    const t = makeHs256({ sub: 1, exp: 9999999999 }, 'strong-uncrackable-secret-xyz-123')
    expect(analyzeJwtToken(t, 'test').some((f) => /confusion candidate/.test(f.name))).toBe(false)
  })

  it('flags a crit header', () => {
    const t = makeHs256({ sub: 1 }, 'x', { alg: 'HS256', crit: ['b64'], b64: false })
    expect(analyzeJwtToken(t, 'test').some((f) => /crit \(critical\) header/.test(f.name))).toBe(true)
  })

  it('flags an unusual typ but not the standard ones', () => {
    const weird = makeHs256({ sub: 1 }, 'x', { alg: 'HS256', typ: 'x-custom' })
    expect(analyzeJwtToken(weird, 'test').some((f) => /unusual typ/.test(f.name))).toBe(true)
    const normal = makeHs256({ sub: 1 }, 'x', { alg: 'HS256', typ: 'at+jwt' })
    expect(analyzeJwtToken(normal, 'test').some((f) => /unusual typ/.test(f.name))).toBe(false)
  })
})

describe('algIsAsymmetric', () => {
  it('is true for RS/ES/PS/EdDSA and false for HS/none', () => {
    for (const a of ['RS256', 'rs512', 'ES256', 'PS384', 'EdDSA']) expect(algIsAsymmetric(a)).toBe(true)
    for (const a of ['HS256', 'HS512', 'none', '', undefined]) expect(algIsAsymmetric(a)).toBe(false)
  })
})

describe('RS256->HS256 confusion forge', () => {
  // A real RSA keypair so the forge round-trips against a genuine public key.
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>
  const rs256 = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: 'u', role: 'user' }))}.sig`

  it('forges an HS256 token signed with the public key and it self-verifies', () => {
    const forged = forgeAlgConfusion(rs256, pem)!
    expect(decodeJwt(forged)?.header.alg).toBe('HS256')
    expect(verifyHs256(forged, pem)).toBe(true)
    // A different key must NOT verify — the forge is bound to that public key.
    expect(verifyHs256(forged, 'not-the-key')).toBe(false)
  })

  it('applies claim overrides (privilege escalation)', () => {
    const forged = forgeAlgConfusion(rs256, pem, { role: 'admin', is_admin: true })!
    const p = decodeJwt(forged)?.payload
    expect(p?.role).toBe('admin')
    expect(p?.is_admin).toBe(true)
    expect(p?.sub).toBe('u') // untouched claims carried over
  })

  it('returns null for an undecodable token', () => {
    expect(forgeAlgConfusion('nope', pem)).toBeNull()
  })

  it('jwkToPem round-trips an RSA jwk to a key the forge accepts', () => {
    const derived = jwkToPem(jwk)!
    expect(derived).toContain('BEGIN PUBLIC KEY')
    const forged = forgeAlgConfusion(rs256, derived)!
    expect(verifyHs256(forged, derived)).toBe(true)
  })

  it('jwkToPem rejects non-RSA / malformed jwks', () => {
    expect(jwkToPem({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' })).toBeNull()
    expect(jwkToPem({ kty: 'RSA' })).toBeNull()
    expect(jwkToPem(null)).toBeNull()
  })

  it('keyMaterialCandidates yields distinct representations including the base64 body', () => {
    const cands = keyMaterialCandidates(pem)
    expect(cands.length).toBeGreaterThanOrEqual(2)
    expect(cands.some((c) => c.includes('BEGIN PUBLIC KEY'))).toBe(true)
    expect(cands.some((c) => !c.includes('BEGIN'))).toBe(true) // the stripped body
  })
})

describe('confusionConfirmed', () => {
  const ok = { status: 200, body: 'a'.repeat(1000) }
  const denied = { status: 401, body: 'unauthorized' }

  it('confirms when forged is accepted like baseline and control is rejected', () => {
    expect(confusionConfirmed(ok, denied, { status: 200, body: 'a'.repeat(1010) })).toBe(true)
  })

  it('does NOT confirm when the control (wrong key) is also accepted', () => {
    // Endpoint accepts any token → cannot attribute acceptance to alg-confusion.
    expect(confusionConfirmed(ok, { status: 200, body: 'a'.repeat(1000) }, ok)).toBe(false)
  })

  it('does NOT confirm when the forged token is rejected', () => {
    expect(confusionConfirmed(ok, denied, denied)).toBe(false)
  })

  it('does NOT confirm when the baseline is itself unauthorized', () => {
    expect(confusionConfirmed(denied, { status: 500, body: '' }, denied)).toBe(false)
  })

  it('does NOT confirm when the forged body diverges materially from baseline', () => {
    expect(confusionConfirmed(ok, denied, { status: 200, body: 'a'.repeat(200) })).toBe(false)
  })
})

describe('jwtWordlistPathOk', () => {
  it('accepts an absolute path under the wordlists dir', () => {
    expect(jwtWordlistPathOk('/usr/share/wordlists/jwt.secrets.list')).toBe(true)
  })
  it('rejects traversal and out-of-jail paths', () => {
    expect(jwtWordlistPathOk('/usr/share/wordlists/../../etc/passwd')).toBe(false)
    expect(jwtWordlistPathOk('/etc/passwd')).toBe(false)
    expect(jwtWordlistPathOk('relative/path.txt')).toBe(false)
  })
})
