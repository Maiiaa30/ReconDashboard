import { describe, expect, it } from 'vitest'
import { faviconHash, murmur3_32 } from './mmh3'

describe('murmur3_32', () => {
  it('matches canonical mmh3 vectors (signed 32-bit)', () => {
    expect(murmur3_32(Buffer.from(''))).toBe(0)
    expect(murmur3_32(Buffer.from('hello'))).toBe(613153351) // == python mmh3.hash("hello")
  })

  it('is deterministic and distinguishes inputs', () => {
    expect(murmur3_32(Buffer.from('abc'))).toBe(murmur3_32(Buffer.from('abc')))
    expect(murmur3_32(Buffer.from('abc'))).not.toBe(murmur3_32(Buffer.from('abd')))
  })

  it('honours the seed', () => {
    expect(murmur3_32(Buffer.from('x'), 0)).not.toBe(murmur3_32(Buffer.from('x'), 1))
  })
})

describe('faviconHash', () => {
  it('is stable for identical icon bytes (correlates assets across IPs)', () => {
    const icon = Buffer.from('\x00\x00\x01\x00fake-icon-bytes-here', 'binary')
    expect(faviconHash(icon)).toBe(faviconHash(icon))
    expect(faviconHash(icon)).not.toBe(faviconHash(Buffer.from('different-icon')))
  })

  it('hashes the newline-wrapped base64 (Shodan/mmh3 convention)', () => {
    const icon = Buffer.from('some-favicon-content')
    const b64 = icon.toString('base64')
    const wrapped = `${(b64.match(/.{1,76}/g) ?? []).join('\n')}\n`
    expect(faviconHash(icon)).toBe(murmur3_32(Buffer.from(wrapped, 'utf8')))
  })
})
