import { describe, expect, it } from 'vitest'
import { parseWafw00f } from './wafFingerprint'

describe('parseWafw00f', () => {
  it('reads the current shape (firewall + manufacturer, detected)', () => {
    const out = JSON.stringify([{ url: 'https://x', detected: true, firewall: 'Cloudflare', manufacturer: 'Cloudflare Inc.' }])
    expect(parseWafw00f(out)).toEqual({
      detected: true, brand: 'Cloudflare', manufacturer: 'Cloudflare Inc.', version: null, source: 'wafw00f',
    })
  })

  it('reads the older shape (waf/vendor keys)', () => {
    const out = JSON.stringify([{ detected: true, waf: 'Imperva SecureSphere', vendor: 'Imperva Inc.' }])
    const fp = parseWafw00f(out)
    expect(fp?.brand).toBe('Imperva SecureSphere')
    expect(fp?.manufacturer).toBe('Imperva Inc.')
  })

  it('tolerates a banner printed before the JSON array', () => {
    const out = 'wafw00f : v2.2.0\nChecking https://x\n[{"detected": true, "firewall": "Akamai"}]\n'
    expect(parseWafw00f(out)?.brand).toBe('Akamai')
  })

  it('returns null for a generic/none result or empty output', () => {
    expect(parseWafw00f(JSON.stringify([{ detected: false, firewall: 'Generic' }]))).toBeNull()
    expect(parseWafw00f(JSON.stringify([]))).toBeNull()
    expect(parseWafw00f('no json here')).toBeNull()
    expect(parseWafw00f('')).toBeNull()
  })
})
