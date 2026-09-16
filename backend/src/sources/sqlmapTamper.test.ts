import { describe, expect, it } from 'vitest'
import { GENERIC_TAMPER, tamperForBrand } from './sqlmapTamper'

describe('tamperForBrand', () => {
  it('returns null when no brand is given', () => {
    expect(tamperForBrand(null)).toBeNull()
    expect(tamperForBrand(undefined)).toBeNull()
    expect(tamperForBrand('')).toBeNull()
  })

  it('maps a header-slug brand to its vendor chain', () => {
    expect(tamperForBrand('cloudflare')?.tamper).toContain('charencode')
    expect(tamperForBrand('akamai')?.tamper).toContain('charunicodeencode')
    expect(tamperForBrand('imperva')?.tamper).toContain('percentage')
  })

  it('maps a richer wafw00f label (brand + manufacturer) to the same chain', () => {
    expect(tamperForBrand('Cloudflare (Cloudflare Inc.)')?.reason).toMatch(/cloudflare/i)
    expect(tamperForBrand('Imperva SecureSphere (Imperva Inc.)')?.tamper).toContain('percentage')
    // Incapsula is Imperva's product name and gets the same heavy chain.
    expect(tamperForBrand('Incapsula (Imperva)')?.tamper).toContain('percentage')
  })

  it('sets a delay for rate-aggressive cloud WAFs and none for the rest', () => {
    expect(tamperForBrand('cloudflare')?.delay).toBe(1)
    expect(tamperForBrand('akamai')?.delay).toBe(1)
    expect(tamperForBrand('aws-waf')?.delay).toBe(0)
    expect(tamperForBrand('fastly')?.delay).toBe(0)
  })

  it('falls back to the generic chain for an unknown but present WAF', () => {
    expect(tamperForBrand('SomeVendorNeverSeen')).toEqual(GENERIC_TAMPER)
  })
})
