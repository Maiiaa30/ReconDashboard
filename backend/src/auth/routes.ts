import type { FastifyInstance, FastifyPluginAsync } from 'fastify'
import { eq } from 'drizzle-orm'
import { db } from '../db/index'
import { users } from '../db/schema'
import { getOperator, getOperatorById } from './seed'
import { verifyPassword } from './passwords'
import { totpAuthUrl, verifyTotp } from './totp'

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
        rateLimit: { max: 5, timeWindow: '1 minute' },
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
        if (!token || !verifyTotp(token, op.totpSecret)) return fail()
      }

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
    return reply.send({ user: { username: op.username, totpEnabled: op.totpEnabled } })
  })

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
      if (!verifyTotp(request.body.token, op.totpSecret)) {
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
      if (!verifyTotp(request.body.token, op.totpSecret)) {
        return reply.code(400).send({ error: 'invalid code' })
      }
      db.update(users).set({ totpEnabled: false, updatedAt: new Date() }).where(eq(users.id, op.id)).run()
      return reply.send({ totpEnabled: false })
    },
  )
}
