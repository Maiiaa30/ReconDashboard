import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { FastifyInstance } from 'fastify'

// Route-level tests for the two safety rails the audit (§5) flagged as untested:
// the default-deny auth guard and the scan-policy gate. Builds the REAL app
// (buildApp) against a throwaway SQLite DB and drives it with app.inject().

let app: FastifyInstance
let cookie = ''
let tmpDir = ''
// Loosely typed to avoid threading drizzle types through the test.
let db: any
let domains: any

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), 'recon-itest-'))
  // Set env BEFORE importing — config + db/index read it at module load.
  process.env.VITEST = 'true' // buildApp must not auto-listen/start workers
  process.env.DATABASE_PATH = join(tmpDir, 'app.db')
  process.env.SESSION_SECRET = 'x'.repeat(48)
  process.env.ADMIN_USERNAME = 'operator'
  process.env.ADMIN_PASSWORD = 'integration-test-pw'
  process.env.NODE_ENV = 'test' // isProd=false → session cookie not Secure over inject

  const mod = await import('./index')
  app = await mod.buildApp()
  await app.ready()
  db = (await import('./db/index')).db
  domains = (await import('./db/schema')).domains
})

afterAll(async () => {
  await app?.close()
  try {
    rmSync(tmpDir, { recursive: true, force: true })
  } catch {
    /* temp cleanup best-effort */
  }
})

const newDomain = (v: Record<string, unknown>): number =>
  Number(db.insert(domains).values(v).run().lastInsertRowid)

const nmap = (id: number, payload: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: `/api/domains/${id}/scan/nmap`, headers: { cookie }, payload })

describe('auth guard (default-deny)', () => {
  it('401s an unauthenticated request to a protected route', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/domains' })
    expect(res.statusCode).toBe(401)
  })

  it('allows the public health check without auth', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health' })
    expect(res.statusCode).toBe(200)
  })

  it('logs in with the right credentials and issues a session cookie', async () => {
    const bad = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { username: 'operator', password: 'nope' } })
    expect(bad.statusCode).toBe(401)

    const res = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { username: 'operator', password: 'integration-test-pw' } })
    expect(res.statusCode).toBe(200)
    const raw = res.headers['set-cookie']
    cookie = String(Array.isArray(raw) ? raw[0] : raw).split(';')[0]
    expect(cookie).toMatch(/^sid=/)

    // The same protected route now succeeds with the cookie.
    const ok = await app.inject({ method: 'GET', url: '/api/domains', headers: { cookie } })
    expect(ok.statusCode).toBe(200)
  })
})

describe('scan-policy gate', () => {
  it('refuses an active scan on a passive_only domain without confirm', async () => {
    const id = newDomain({ host: 'passive.example.com', mode: 'passive_only' })
    const res = await nmap(id, {})
    expect(res.statusCode).toBe(400)
    expect(res.json().code).toBe('confirm_required')
  })

  it('refuses a target that is not within the domain, even with confirm', async () => {
    const id = newDomain({ host: 'scope.example.com', mode: 'active_authorized' })
    const res = await nmap(id, { target: 'evil.com', confirm: true })
    expect(res.statusCode).toBe(400)
    expect(res.json().code).toBe('out_of_domain')
  })

  it('refuses a scan whose authorization window has expired', async () => {
    const id = newDomain({ host: 'expired.example.com', mode: 'active_authorized', authorizedUntil: new Date(Date.now() - 86_400_000) })
    const res = await nmap(id, { confirm: true })
    expect(res.statusCode).toBe(403)
    expect(res.json().code).toBe('window_expired')
  })

  it('allows an authorized, in-scope active scan (enqueues a job)', async () => {
    const id = newDomain({ host: 'ok.example.com', mode: 'active_authorized' })
    const res = await nmap(id, { confirm: true })
    expect(res.statusCode).toBe(202)
    expect(typeof res.json().jobId).toBe('number')
  })
})
