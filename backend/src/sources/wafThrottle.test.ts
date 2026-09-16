import { describe, expect, it } from 'vitest'
import { throttleForBrand } from './wafThrottle'

describe('throttleForBrand', () => {
  it('returns null when no WAF is known (full speed)', () => {
    expect(throttleForBrand(null)).toBeNull()
    expect(throttleForBrand(undefined)).toBeNull()
    expect(throttleForBrand('')).toBeNull()
  })

  it('gives aggressive rate engines the heaviest throttle', () => {
    for (const b of ['cloudflare', 'Akamai (Akamai Technologies)', 'Imperva SecureSphere', 'Incapsula']) {
      expect(throttleForBrand(b)?.rateLimit).toBe(5)
    }
  })

  it('gives lighter CDNs a moderate throttle', () => {
    for (const b of ['sucuri', 'aws-waf', 'fastly', 'ModSecurity', 'F5 BIG-IP']) {
      expect(throttleForBrand(b)?.rateLimit).toBe(10)
    }
  })

  it('gives an unknown-but-present WAF a light throttle', () => {
    const t = throttleForBrand('SomeUnknownWAF')
    expect(t?.rateLimit).toBe(15)
    expect(t?.ffufDelay).toMatch(/^\d/)
    expect(t?.dalfoxWorker).toBeGreaterThan(0)
  })
})
