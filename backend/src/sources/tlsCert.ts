import { X509Certificate } from 'node:crypto'
import { connect, type PeerCertificate } from 'node:tls'
import { assertPublicHost } from './guard'
import { normalizeHost } from '../util/validate'

// Passive-ish TLS certificate grab: connect to :443, read the leaf certificate,
// and harvest its Subject Alternative Names (often reveal sibling hostnames) plus
// a fingerprint (identical certs across IPs correlate assets). SSRF-guarded.

const TIMEOUT_MS = 9_000

export interface TlsCertInfo {
  host: string
  sans: string[] // hostnames from the SAN extension (DNS: entries)
  fingerprint256: string | null
  issuer: string | null
  validTo: string | null
  publicKeyPem: string | null // SPKI PEM of the leaf key (a JWT alg-confusion key source)
}

export async function grabTlsCert(host: string): Promise<TlsCertInfo | null> {
  await assertPublicHost(host) // refuse internal/Tailscale targets

  const cert = await new Promise<PeerCertificate | null>((resolve) => {
    let settled = false
    const finish = (v: PeerCertificate | null) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(v)
    }
    const socket = connect(
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS },
      () => finish(socket.getPeerCertificate(false)),
    )
    socket.on('timeout', () => finish(null))
    socket.on('error', () => finish(null))
  })

  if (!cert || Object.keys(cert).length === 0) return null

  // subjectaltname looks like: "DNS:example.com, DNS:*.example.com, IP:1.2.3.4"
  const sans = new Set<string>()
  for (const part of String(cert.subjectaltname ?? '').split(',')) {
    const m = part.trim().match(/^DNS:(.+)$/i)
    if (!m) continue
    const h = normalizeHost(m[1]) // strips leading *. and validates
    if (h) sans.add(h)
  }

  const issuer = cert.issuer ? [cert.issuer.O, cert.issuer.CN].filter(Boolean).join(' / ') || null : null

  // Extract the leaf's public key as SPKI PEM (from the DER `raw`). A JWT that a
  // server verifies with this key can be forged via RS256->HS256 confusion.
  let publicKeyPem: string | null = null
  try {
    if (cert.raw) publicKeyPem = new X509Certificate(cert.raw).publicKey.export({ type: 'spki', format: 'pem' }).toString()
  } catch {
    /* leave null — an exotic key type just means no cert-based confusion source */
  }

  return {
    host,
    sans: [...sans],
    fingerprint256: cert.fingerprint256 ?? null,
    issuer,
    validTo: cert.valid_to ?? null,
    publicKeyPem,
  }
}
