import { describe, it, expect } from 'vitest'
import { TtlCache } from './cache'

describe('TtlCache', () => {
  it('returns a cached value before the TTL and undefined after it', async () => {
    const c = new TtlCache<string, number>(15)
    c.set('a', 1)
    expect(c.get('a')).toBe(1)
    await new Promise((r) => setTimeout(r, 30))
    expect(c.get('a')).toBeUndefined()
  })

  it('distinguishes a cached null from a cache miss', () => {
    const c = new TtlCache<string, number | null>(60_000)
    c.set('x', null)
    expect(c.get('x')).toBeNull() // cached "nothing here"
    expect(c.get('y')).toBeUndefined() // never fetched
  })

  it('evicts the oldest entry when over the size cap', () => {
    const c = new TtlCache<number, number>(60_000, 2)
    c.set(1, 1)
    c.set(2, 2)
    c.set(3, 3) // evicts key 1
    expect(c.get(1)).toBeUndefined()
    expect(c.get(2)).toBe(2)
    expect(c.get(3)).toBe(3)
  })
})
