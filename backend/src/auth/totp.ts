import { authenticator } from 'otplib'

const ISSUER = 'ReconDashboard'

export function generateTotpSecret(): string {
  return authenticator.generateSecret()
}

// otpauth:// URL the operator scans / pastes into their authenticator app.
export function totpAuthUrl(username: string, secret: string): string {
  return authenticator.keyuri(username, ISSUER, secret)
}

export function verifyTotp(token: string, secret: string): boolean {
  try {
    return authenticator.verify({ token: token.trim(), secret })
  } catch {
    return false
  }
}

// Return the absolute TOTP time-step the token is valid for (current step plus
// otplib's matched window delta), or null if the token is invalid. Callers
// persist the highest accepted step and reject any token at or below it, so a
// captured code can't be replayed within its ~30s window (audit §3 #4).
export function checkTotpStep(token: string, secret: string): number | null {
  try {
    const delta = authenticator.checkDelta(token.trim(), secret)
    if (delta == null) return null
    const stepSeconds = authenticator.options.step ?? 30
    return Math.floor(Date.now() / 1000 / stepSeconds) + delta
  } catch {
    return null
  }
}
