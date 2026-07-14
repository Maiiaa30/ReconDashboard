import { describe, expect, it } from 'vitest'
import { authenticator } from 'otplib'
import { checkTotpStep } from './totp'

// Audit §3 #4: otplib.verify has no used-token memory, so a captured code replays
// for its whole ~30s step. checkTotpStep returns the code's absolute time-step so
// the caller can reject any step it has already accepted.
describe('checkTotpStep (TOTP replay guard)', () => {
  it('returns a stable step for a valid token, null for an invalid one', () => {
    const secret = authenticator.generateSecret()
    const token = authenticator.generate(secret)

    const step1 = checkTotpStep(token, secret)
    const step2 = checkTotpStep(token, secret)

    expect(typeof step1).toBe('number')
    // Same code within its window → same step. The consume guard rejects a token
    // whose step is <= the last accepted one, so this reuse is caught.
    expect(step2).toBe(step1)
    expect(checkTotpStep('000000', secret)).toBeNull()
    expect(checkTotpStep('not-a-code', secret)).toBeNull()
  })
})
