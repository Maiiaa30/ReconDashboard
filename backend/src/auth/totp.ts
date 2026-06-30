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
