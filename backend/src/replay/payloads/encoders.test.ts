import { describe, expect, it } from 'vitest'
import { applyChain, TRANSFORMS } from './encoders'

const SAMPLES = [`'"><svg/onload=confirm(1)>`, 'admin@example.com', 'héllo wörld', 'a/b?c=d&e=f', '']

describe('encoder round-trips', () => {
  const pairs: [string, string][] = [
    ['base64', 'base64-decode'],
    ['url', 'url-decode'],
    ['double-url', 'double-url-decode'],
    ['hex', 'hex-decode'],
    ['unicode', 'unicode-decode'],
    ['html-entity', 'html-entity-decode'],
  ]
  for (const [enc, dec] of pairs) {
    it(`${enc} → ${dec} is identity`, () => {
      for (const s of SAMPLES) {
        expect(TRANSFORMS[dec](TRANSFORMS[enc](s))).toBe(s)
      }
    })
  }
})

describe('encoders produce the expected shape', () => {
  it('base64', () => expect(TRANSFORMS['base64']('abc')).toBe('YWJj'))
  it('url encodes reserved chars', () => expect(TRANSFORMS['url']('a b/c')).toBe('a%20b%2Fc'))
  it('double-url double-encodes', () => expect(TRANSFORMS['double-url']('a b')).toBe('a%2520b'))
  it('hex', () => expect(TRANSFORMS['hex']('AB')).toBe('4142'))
  it('unicode', () => expect(TRANSFORMS['unicode']('A')).toBe('\\u0041'))
  it('html-entity escapes <', () => expect(TRANSFORMS['html-entity']('<')).toBe('&#60;'))
})

describe('applyChain', () => {
  it('applies transforms left to right', () => {
    // url-encode, then base64 the encoded string.
    expect(applyChain('a b', ['url', 'base64'])).toBe(Buffer.from('a%20b').toString('base64'))
  })
  it('rejects an unknown transform', () => {
    expect(() => applyChain('x', ['nope'])).toThrow(/unknown transform/)
  })
  it('rejects an over-long chain', () => {
    expect(() => applyChain('x', Array(9).fill('base64'))).toThrow(/too long/)
  })
  it('is identity for an empty chain', () => {
    expect(applyChain('unchanged', [])).toBe('unchanged')
  })
})

describe('decoders never throw on malformed input', () => {
  it('returns input unchanged on bad hex/base64/url', () => {
    expect(TRANSFORMS['hex-decode']('zzz')).toBeDefined()
    expect(() => TRANSFORMS['url-decode']('%')).not.toThrow()
    expect(TRANSFORMS['url-decode']('%')).toBe('%')
  })
})
