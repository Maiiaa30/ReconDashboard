import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import fastifyCookie from '@fastify/cookie'
import fastifySession from '@fastify/session'
import fastifyRateLimit from '@fastify/rate-limit'
import { config } from './config'
import './db/index' // opens SQLite, ensures data dir/volume exists
import { runMigrations } from './db/migrate'
import { seedAdmin } from './auth/seed'
import { dedupeExistingFindings } from './findings/store'
import { authRoutes } from './auth/routes'
import { authGuard } from './auth/guard'
import { sqliteSessionStore, startSessionPruner } from './auth/sessionStore'
import { registerJobHandlers } from './jobs/register'
import { getScorer } from './scoring'
import { startWorker } from './jobs/worker'
import { startJobsPruner } from './jobs/queue'
import { startScheduler } from './jobs/scheduler'
import { domainRoutes } from './routes/domains'
import { jobRoutes } from './routes/jobs'
import { findingRoutes } from './routes/findings'
import { reconRoutes } from './routes/recon'
import { toolRoutes } from './routes/tools'
import { scanRoutes } from './routes/scans'
import { toolScanRoutes } from './routes/toolScan'
import { owaspRoutes } from './routes/owasp'
import { exportRoutes } from './routes/export'
import { screenshotRoutes } from './routes/screenshots'
import { noteRoutes } from './routes/notes'
import { drawingRoutes } from './routes/drawings'
import { backupRoutes } from './routes/backup'
import { auditRoutes } from './routes/audit'
import { homeRoutes } from './routes/home'
import { metaRoutes } from './routes/meta'
import { leakRoutes } from './routes/leaks'
import { replayRoutes } from './routes/replay'
import { captureRoutes } from './routes/capture'
import { payloadRoutes } from './routes/payloads'
import { matchReplaceRoutes } from './routes/matchReplace'

// Build and fully configure the app (migrations, seed, plugins, guard, routes)
// WITHOUT listening or starting background workers — so an integration test can
// import it and drive it with app.inject(). main() adds the background + listen.
export async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: !process.env.VITEST, // quiet during tests
    // Backups can be a few MB; allow a generous JSON/body limit.
    bodyLimit: 16 * 1024 * 1024,
  })

  // Consistent error envelope for THROWN errors + schema-validation failures.
  // Routes that call reply.send({ error }) explicitly are unaffected. 500s hide
  // internals in production; validation errors become a clean 400.
  app.setErrorHandler((err: FastifyError, req: FastifyRequest, reply: FastifyReply) => {
    if (err.validation) {
      return reply.code(400).send({ error: `invalid request: ${err.message}`, code: 'validation' })
    }
    const status = typeof err.statusCode === 'number' && err.statusCode >= 400 ? err.statusCode : 500
    if (status >= 500) {
      req.log.error({ err }, 'unhandled route error')
      return reply.code(status).send({ error: config.isProd ? 'internal server error' : err.message })
    }
    return reply.code(status).send({ error: err.message })
  })
  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({ error: 'not found' })
  })

  // Apply schema, then create the operator if this is a first run.
  runMigrations()
  await seedAdmin(app.log)

  // Instantiate the scorer now so a misconfigured AI_PROVIDER fails fast.
  getScorer()

  // One-time cleanup of duplicate findings from before write-time dedup existed.
  const removed = dedupeExistingFindings()
  if (removed > 0) app.log.info(`removed ${removed} duplicate finding(s)`)

  // Rate limiting — registered globally disabled; opted into per-route (login).
  await app.register(fastifyRateLimit, { global: false })

  // Sessions: signed httpOnly cookie + SQLite-backed server store.
  await app.register(fastifyCookie)
  await app.register(fastifySession, {
    secret: config.sessionSecret,
    cookieName: 'sid',
    store: sqliteSessionStore,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // strict: the app is reached only over Tailscale and has no legitimate
      // cross-site entry point, so the session cookie should never ride along on
      // a cross-site request — a cheap CSRF hardening with no UX cost here.
      sameSite: 'strict',
      secure: config.isProd,
      path: '/',
      maxAge: Math.floor(config.sessionMaxAgeMs / 1000),
    },
  })

  // Auth guard runs after the session plugin has loaded the session.
  app.addHook('onRequest', authGuard)

  // Public + auth routes.
  app.get('/api/health', async () => ({ status: 'ok' }))
  await app.register(authRoutes)

  // Feature routes (all behind the auth guard).
  await app.register(domainRoutes)
  await app.register(reconRoutes)
  await app.register(toolRoutes)
  await app.register(scanRoutes)
  await app.register(toolScanRoutes)
  await app.register(owaspRoutes)
  await app.register(exportRoutes)
  await app.register(screenshotRoutes)
  await app.register(jobRoutes)
  await app.register(findingRoutes)
  await app.register(noteRoutes)
  await app.register(drawingRoutes)
  await app.register(backupRoutes)
  await app.register(auditRoutes)
  await app.register(homeRoutes)
  await app.register(metaRoutes)
  await app.register(leakRoutes)
  await app.register(replayRoutes)
  await app.register(captureRoutes)
  await app.register(payloadRoutes)
  await app.register(matchReplaceRoutes)

  return app
}

// Background processing (worker, scheduler, pruners). Not started in tests, which
// only build the app to drive it with app.inject().
function startBackground(app: FastifyInstance): void {
  registerJobHandlers()
  startWorker(app.log)
  startScheduler(app.log)
  startSessionPruner()
  // Prune old terminal job rows so the table doesn't grow forever (audit §4).
  // audit_log is intentionally left unpruned — it is append-only legal cover; an
  // archive-then-prune policy is an open operator decision, not done here.
  startJobsPruner(config.jobsRetentionDays)
}

async function main(): Promise<void> {
  const app = await buildApp()
  startBackground(app)
  await app.listen({ port: config.port, host: config.host })
  app.log.info(`backend listening on ${config.host}:${config.port}`)
}

// Only auto-start when run as the entrypoint — importing buildApp (e.g. from a
// test) must not trigger listen() or the background workers.
if (!process.env.VITEST) {
  main().catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
