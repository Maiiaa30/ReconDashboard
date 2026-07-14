// CORS verdict — pure, so the severity logic is unit-testable without a network.
// The dangerous case is a server that REFLECTS an attacker-chosen Origin back in
// Access-Control-Allow-Origin: any site the victim visits can then read the
// response. It becomes critical-adjacent when Allow-Credentials is also true (the
// attacker origin can read the victim's authenticated responses).

export type CorsSeverity = 'low' | 'medium' | 'high'

export interface CorsVerdict {
  severity: CorsSeverity
  reflected: 'origin' | 'null' | 'wildcard'
  withCreds: boolean
}

// Decide whether a single Origin probe revealed a misconfiguration.
//   * `*`               → permissive but browsers refuse to send credentials with
//                         it, so it is low (often an intentional public API).
//   * EXACT reflection  → the server echoed the attacker origin verbatim. With
//                         Allow-Credentials:true this is high; otherwise medium
//                         (arbitrary origins can still read non-credentialed or
//                         IP/network-authenticated responses).
// The exact-match guard matters: a server that echoes a DIFFERENT allowed origin
// (not the one we sent) is not vulnerable, so `acao === sentOrigin` — never a
// substring test — is what gates a finding.
export function corsVerdict(sentOrigin: string, acao: string | null, acac: string | null): CorsVerdict | null {
  if (!acao) return null
  const withCreds = (acac ?? '').trim().toLowerCase() === 'true'
  if (acao.trim() === '*') return { severity: 'low', reflected: 'wildcard', withCreds }
  if (acao.trim() === sentOrigin) {
    return { severity: withCreds ? 'high' : 'medium', reflected: sentOrigin === 'null' ? 'null' : 'origin', withCreds }
  }
  return null
}
