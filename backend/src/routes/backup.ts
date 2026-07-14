import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { createEncryptedBackup, stageRestore, verifyBackup } from '../backup/backup'
import { actorName, writeAudit } from '../audit/store'
import { getOperatorById } from '../auth/seed'
import { verifyPassword } from '../auth/passwords'
import { verifyTotp } from '../auth/totp'

// Phase 8: download an encrypted dump of the SQLite DB. The passphrase comes
// from BACKUP_PASSPHRASE (env) or, if unset, the request body — it is never
// stored. The response is the raw encrypted blob.
export const backupRoutes: FastifyPluginAsync = async (app) => {
  app.post<{ Body: { passphrase?: string } }>('/api/backup', async (request, reply) => {
    const passphrase = config.backupPassphrase || (request.body?.passphrase ?? '')
    if (!passphrase || passphrase.length < 12) {
      return reply
        .code(400)
        .send({ error: 'passphrase required (>=12 chars), via BACKUP_PASSPHRASE or request body' })
    }

    let blob: Buffer
    try {
      blob = await createEncryptedBackup(passphrase)
    } catch (err) {
      request.log.error({ err }, 'backup failed')
      return reply.code(500).send({ error: 'backup failed' })
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    reply
      .header('Content-Type', 'application/octet-stream')
      .header('Content-Disposition', `attachment; filename="recon-backup-${stamp}.rdb"`)
    return reply.send(blob)
  })

  // Whether a server-side passphrase is configured (so the UI can hide the field).
  app.get('/api/backup/status', async () => ({
    serverPassphraseConfigured: Boolean(config.backupPassphrase),
  }))

  // Accept the raw encrypted .rdb as an octet-stream body (scoped to this
  // plugin). The passphrase comes from the X-Backup-Passphrase header (kept out
  // of the URL, so it isn't logged) or the server-side BACKUP_PASSPHRASE.
  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer' }, (_req, body, done) =>
    done(null, body),
  )

  function readInput(request: {
    headers: Record<string, unknown>
    body: unknown
  }): { blob?: Buffer; passphrase: string; error?: string } {
    const passphrase = config.backupPassphrase || String(request.headers['x-backup-passphrase'] ?? '')
    if (!passphrase || passphrase.length < 12) {
      return { passphrase: '', error: 'passphrase required (>=12 chars) via X-Backup-Passphrase or BACKUP_PASSPHRASE' }
    }
    const blob = request.body
    if (!Buffer.isBuffer(blob) || blob.length < 48) {
      return { passphrase, error: 'send the encrypted .rdb as an application/octet-stream body' }
    }
    return { blob, passphrase }
  }

  // Confirm a backup is decryptable and a loadable SQLite DB (never touches the
  // live DB) — so the operator can trust a backup before ever needing it.
  app.post('/api/backup/verify', async (request, reply) => {
    const { blob, passphrase, error } = readInput(request)
    if (error) return reply.code(400).send({ error })
    const result = await verifyBackup(blob!, passphrase)
    return reply.code(result.ok ? 200 : 422).send(result)
  })

  // Re-authenticate the operator for a destructive action. Credentials come via
  // headers because the request body is the raw .rdb octet-stream. Returns an
  // error string to send, or null when re-auth passed.
  async function requireReauth(request: {
    session: { userId?: number }
    headers: Record<string, unknown>
  }): Promise<{ status: number; error: string } | null> {
    const op = getOperatorById(request.session.userId!)
    if (!op) return { status: 401, error: 'unauthorized' }
    const password = String(request.headers['x-reauth-password'] ?? '')
    if (!password || !(await verifyPassword(op.passwordHash, password))) {
      return { status: 403, error: 'restore requires re-entering your password (X-Reauth-Password)' }
    }
    if (op.totpEnabled) {
      const token = String(request.headers['x-reauth-token'] ?? '')
      if (!verifyTotp(token, op.totpSecret)) {
        return { status: 403, error: 'restore requires a valid 2FA code (X-Reauth-Token)' }
      }
    }
    return null
  }

  // Stage a verified backup to be swapped in on the next backend restart. This
  // replaces the entire database, so it re-authenticates the operator (password
  // + 2FA if enabled) and is rate-limited — a live session alone is not enough.
  app.post('/api/backup/restore', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (request, reply) => {
    const reauth = await requireReauth(request)
    if (reauth) return reply.code(reauth.status).send({ error: reauth.error })
    const { blob, passphrase, error } = readInput(request)
    if (error) return reply.code(400).send({ error })
    const result = await stageRestore(blob!, passphrase, config.databasePath)
    if (!result.ok) return reply.code(422).send(result)
    writeAudit({
      actor: actorName(request.session.userId),
      action: 'backup:restore-staged',
      detail: { bytes: result.bytes },
    })
    request.log.warn('database restore staged — restart the backend to apply')
    return reply.send({
      ...result,
      staged: true,
      restartRequired: true,
      message: 'Restore staged. Restart the backend to apply; the current DB is kept as a .pre-restore copy.',
    })
  })
}
