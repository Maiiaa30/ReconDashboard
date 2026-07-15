import { describe, expect, it } from 'vitest'
import { detectTakeover, matchTakeoverFingerprint } from './takeover'

describe('detectTakeover', () => {
  it('flags a dangling CNAME to a known service', () => {
    expect(detectTakeover(['x.github.io'], 404)).toEqual({ service: 'github-pages', cname: 'x.github.io' })
    expect(detectTakeover(['app.herokuapp.com'], null)).toMatchObject({ service: 'heroku' })
  })
  it('does not flag a live 2xx host', () => {
    expect(detectTakeover(['x.github.io'], 200)).toBeNull()
  })
  it('does not flag a CNAME to no known service', () => {
    expect(detectTakeover(['x.example.com'], 404)).toBeNull()
  })
})

describe('matchTakeoverFingerprint', () => {
  it('confirms when the service unclaimed-page string is present', () => {
    expect(matchTakeoverFingerprint('github-pages', "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>")).toBe(true)
    expect(matchTakeoverFingerprint('aws-s3', '<Error><Code>NoSuchBucket</Code></Error>')).toBe(true)
    expect(matchTakeoverFingerprint('fastly', 'Fastly error: unknown domain: foo.com')).toBe(true)
  })
  it('does not confirm a normal page', () => {
    expect(matchTakeoverFingerprint('github-pages', '<html><body>Welcome to my site</body></html>')).toBe(false)
  })
  it('returns false for a service with no fingerprint', () => {
    expect(matchTakeoverFingerprint('aws-cloudfront', 'anything')).toBe(false)
  })
})
