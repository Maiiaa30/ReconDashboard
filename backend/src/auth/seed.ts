import { eq } from 'drizzle-orm'
import type { FastifyBaseLogger } from 'fastify'
import { config } from '../config'
import { db } from '../db/index'
import { users } from '../db/schema'
import { hashPassword } from './passwords'
import { generateTotpSecret, totpAuthUrl } from './totp'

// First-run setup: if there is no operator account, create one from .env.
// The single operator model means we never expose public signup.
export async function seedAdmin(log: FastifyBaseLogger): Promise<void> {
  const existing = db.select().from(users).limit(1).all()
  if (existing.length > 0) {
    return
  }

  const passwordHash = await hashPassword(config.admin.password)
  const totpSecret = generateTotpSecret()

  db.insert(users)
    .values({
      username: config.admin.username,
      passwordHash,
      totpSecret,
      totpEnabled: false,
    })
    .run()

  log.info(`Seeded operator account "${config.admin.username}".`)
  log.info(
    `TOTP is DISABLED by default. To enable 2FA later, scan/enter this in your authenticator, ` +
      `then enable it from the dashboard:`,
  )
  log.info(`  otpauth URL: ${totpAuthUrl(config.admin.username, totpSecret)}`)

  if (config.admin.isDefaultPassword) {
    log.warn(
      'ADMIN_PASSWORD is still the placeholder "change-me". Set a real password in .env and ' +
        'delete the SQLite DB (or change it via the DB) before any real use.',
    )
  }
}

// Helper for routes: load the single operator (there is only ever one).
export function getOperator() {
  const row = db.select().from(users).limit(1).all()[0]
  return row
}

export function getOperatorById(id: number) {
  return db.select().from(users).where(eq(users.id, id)).limit(1).all()[0]
}
