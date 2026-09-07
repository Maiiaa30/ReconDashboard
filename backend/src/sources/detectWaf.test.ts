import { describe, expect, it } from 'vitest'
import { detectWaf } from './httpProbe'

const h = (init: Record<string, string>) => new Headers(init)

describe('detectWaf', () => {
  it('identifies Cloudflare from cf-ray / server header', () => {
    expect(detectWaf(h({ 'cf-ray': 'abc-EWR', server: 'cloudflare' }))).toBe('cloudflare')
    expect(detectWaf(h({ server: 'cloudflare' }))).toBe('cloudflare')
    expect(detectWaf(h({ 'cf-mitigated': 'challenge' }))).toBe('cloudflare')
  })

  it('falls back to the challenge body when headers are stripped', () => {
    expect(detectWaf(h({}), '<title>Just a moment...</title>')).toBe('cloudflare')
    expect(detectWaf(h({}), 'nothing here')).toBeNull()
  })

  it('identifies other common edges', () => {
    expect(detectWaf(h({ server: 'AkamaiGHost' }))).toBe('akamai')
    expect(detectWaf(h({ 'x-sucuri-id': '12' }))).toBe('sucuri')
    expect(detectWaf(h({ 'x-iinfo': '1' }))).toBe('imperva')
  })

  it('returns null for a plain host', () => {
    expect(detectWaf(h({ server: 'nginx' }))).toBeNull()
  })
})
