import { describe, expect, it } from 'vitest'
import { isChallengePage } from './browserProbe'

describe('isChallengePage', () => {
  it('flags the Cloudflare interstitial by title', () => {
    expect(isChallengePage('<html><title>Just a moment...</title></html>', 'Just a moment...')).toBe(true)
    expect(isChallengePage('<html><title>Attention Required! | Cloudflare</title></html>', 'Attention Required! | Cloudflare')).toBe(true)
  })

  it('flags a small challenge body even without a telltale title', () => {
    expect(isChallengePage('<div id="challenge-platform">cf_chl_opt</div>', null)).toBe(true)
  })

  it('treats a real rendered app as cleared', () => {
    expect(isChallengePage('<html><title>Acme Dashboard</title><main>Welcome back</main></html>', 'Acme Dashboard')).toBe(false)
  })

  it('does not false-flag a large app bundle that mentions turnstile', () => {
    const big = '<html><title>Login</title>' + 'x'.repeat(13_000) + 'turnstile widget</html>'
    expect(isChallengePage(big, 'Login')).toBe(false)
  })
})
