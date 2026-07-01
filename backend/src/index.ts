import Fastify from 'fastify'
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

async function main() {
  const app = Fastify({
    logger: true,
    // Backups can be a few MB; allow a generous JSON/body limit.
    bodyLimit: 16 * 1024 * 1024,
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

  // Background processing.
  registerJobHandlers()
  startWorker(app.log)
  startScheduler(app.log)
  startSessionPruner()

  await app.listen({ port: config.port, host: config.host })
  app.log.info(`backend listening on ${config.host}:${config.port}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
