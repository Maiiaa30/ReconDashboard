import type { FastifyInstance, FastifyPluginAsync } from 'fastify'
import { eq } from 'drizzle-orm'
import { db } from '../db/index'
import { users } from '../db/schema'
import { getOperator, getOperatorById } from './seed'
import { hashPassword, verifyPassword } from './passwords'
import { checkTotpStep, totpAuthUrl } from './totp'

// Verify a TOTP token AND consume its time-step: reject a code whose step was
// already accepted, so a captured code can't be replayed within its ~30s window
// (audit §3 #4). `op` must be the current DB row (carries lastTotpStep).
function consumeTotp(op: { id: number; totpSecret: string; lastTotpStep: number | null }, token: string): boolean {
  const step = checkTotpStep(token, op.totpSecret)
  if (step == null) return false
  if (op.lastTotpStep != null && step <= op.lastTotpStep) return false // replay
  db.update(users).set({ lastTotpStep: step, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
  return true
}

interface LoginBody {
  username?: string
  password?: string
  token?: string
}

const loginSchema = {
  body: {
    type: 'object',
    required: ['username', 'password'],
    properties: {
      username: { type: 'string', minLength: 1, maxLength: 200 },
      password: { type: 'string', minLength: 1, maxLength: 1000 },
      token: { type: 'string', maxLength: 12 },
    },
  },
}

const tokenSchema = {
  body: {
    type: 'object',
    required: ['token'],
    properties: { token: { type: 'string', minLength: 6, maxLength: 12 } },
  },
}

export const authRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // --- Login (rate-limited; see registration in index.ts) -------------------
  app.post<{ Body: LoginBody }>(
    '/api/auth/login',
    {
      schema: loginSchema,
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '1 minute',
          // Run at preHandler (after body parse) and key on IP+username: behind a
          // single upstream (the tailnet proxy) every login would otherwise share
          // one IP bucket, and this also throttles a per-account brute force.
          hook: 'preHandler',
          keyGenerator: (req) =>
            `${req.ip}:${String((req.body as { username?: string } | undefined)?.username ?? '')
              .toLowerCase()
              .slice(0, 64)}`,
        },
      },
    },
    async (request, reply) => {
      const { username = '', password = '', token } = request.body

      const op = getOperator()
      // Generic failure message regardless of which check fails (no oracle).
      const fail = () => reply.code(401).send({ error: 'invalid credentials' })

      if (!op || op.username !== username) {
        // Still spend time verifying to reduce timing signal.
        await verifyPassword(
          '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG',
          password,
        )
        return fail()
      }

      const passwordOk = await verifyPassword(op.passwordHash, password)
      if (!passwordOk) return fail()

      if (op.totpEnabled) {
        if (!token || !consumeTotp(op, token)) return fail()
      }

      // Rotate the session id at the moment of authentication so a pre-login
      // session id (which an attacker could have fixed) can't be reused after
      // login. @fastify/session does not rotate on privilege change on its own.
      // Login is single-step here (password + optional TOTP in one request), so
      // this is the exact point the session becomes authenticated.
      await request.session.regenerate()
      request.session.userId = op.id
      request.session.username = op.username
      return reply.send({ user: { username: op.username } })
    },
  )

  // --- Logout ----------------------------------------------------------------
  app.post('/api/auth/logout', async (request, reply) => {
    await request.session.destroy()
    return reply.send({ ok: true })
  })

  // --- Current session -------------------------------------------------------
  app.get('/api/auth/me', async (request, reply) => {
    const op = getOperatorById(request.session.userId!)
    if (!op) return reply.code(401).send({ error: 'unauthorized' })
    return reply.send({
      user: { username: op.username, totpEnabled: op.totpEnabled, selectedDomainId: op.selectedDomainId },
    })
  })

  // Persist the operator's selected target so it follows the account across
  // browsers/devices (not just localStorage). null clears it.
  app.post<{ Body: { domainId: number | null } }>(
    '/api/auth/selected-domain',
    {
      schema: {
        body: {
          type: 'object',
          required: ['domainId'],
          properties: { domainId: { type: ['integer', 'null'] } },
        },
      },
    },
    async (request, reply) => {
      const op = getOperatorById(request.session.userId!)
      if (!op) return reply.code(401).send({ error: 'unauthorized' })
      const domainId = request.body.domainId
      db.update(users).set({ selectedDomainId: domainId, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      return reply.send({ ok: true, selectedDomainId: domainId })
    },
  )

  // --- TOTP enrollment (returns otpauth URL as text; QR is a later add) ------
  app.get('/api/auth/enroll', async (request, reply) => {
    const op = getOperatorById(request.session.userId!)
    if (!op) return reply.code(401).send({ error: 'unauthorized' })
    return reply.send({
      totpEnabled: op.totpEnabled,
      otpauthUrl: totpAuthUrl(op.username, op.totpSecret),
    })
  })

  app.post<{ Body: { token: string } }>(
    '/api/auth/totp/enable',
    { schema: tokenSchema },
    async (request, reply) => {
      const op = getOperatorById(request.session.userId!)
      if (!op) return reply.code(401).send({ error: 'unauthorized' })
      if (!consumeTotp(op, request.body.token)) {
        return reply.code(400).send({ error: 'invalid code' })
      }
      db.update(users).set({ totpEnabled: true, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      return reply.send({ totpEnabled: true })
    },
  )

  app.post<{ Body: { token: string } }>(
    '/api/auth/totp/disable',
    { schema: tokenSchema },
    async (request, reply) => {
      const op = getOperatorById(request.session.userId!)
      if (!op) return reply.code(401).send({ error: 'unauthorized' })
      // Require a valid current code to turn 2FA off.
      if (!consumeTotp(op, request.body.token)) {
        return reply.code(400).send({ error: 'invalid code' })
      }
      db.update(users).set({ totpEnabled: false, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      return reply.send({ totpEnabled: false })
    },
  )

  // --- Change password (no .env needed) -------------------------------------
  app.post<{ Body: { currentPassword: string; newPassword: string } }>(
    '/api/auth/password',
    {
      schema: {
        body: {
          type: 'object',
          required: ['currentPassword', 'newPassword'],
          properties: {
            currentPassword: { type: 'string', minLength: 1, maxLength: 1000 },
            newPassword: { type: 'string', minLength: 10, maxLength: 1000 },
          },
        },
      },
    },
    async (request, reply) => {
      const op = getOperatorById(request.session.userId!)
      if (!op) return reply.code(401).send({ error: 'unauthorized' })
      const ok = await verifyPassword(op.passwordHash, request.body.currentPassword)
      if (!ok) return reply.code(400).send({ error: 'current password is incorrect' })
      const passwordHash = await hashPassword(request.body.newPassword)
      db.update(users).set({ passwordHash, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      return reply.send({ ok: true })
    },
  )

  // --- Change username (requires current password) --------------------------
  app.post<{ Body: { password: string; newUsername: string } }>(
    '/api/auth/username',
    {
      schema: {
        body: {
          type: 'object',
          required: ['password', 'newUsername'],
          properties: {
            password: { type: 'string', minLength: 1, maxLength: 1000 },
            newUsername: { type: 'string', minLength: 1, maxLength: 200, pattern: '^[A-Za-z0-9._-]+$' },
          },
        },
      },
    },
    async (request, reply) => {
      const op = getOperatorById(request.session.userId!)
      if (!op) return reply.code(401).send({ error: 'unauthorized' })
      const ok = await verifyPassword(op.passwordHash, request.body.password)
      if (!ok) return reply.code(400).send({ error: 'password is incorrect' })
      const newUsername = request.body.newUsername.trim()
      try {
        db.update(users).set({ username: newUsername, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      } catch (err) {
        // username has a UNIQUE constraint; return a clean 409 instead of a 500.
        if (err instanceof Error && /UNIQUE/i.test(err.message)) {
          return reply.code(409).send({ error: 'username already taken' })
        }
        throw err
      }
      request.session.username = newUsername
      return reply.send({ ok: true, username: newUsername })
    },
  )
}
