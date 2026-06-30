import type { FastifyPluginAsync } from 'fastify'
import { config } from '../config'
import { createEncryptedBackup } from '../backup/backup'

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
      return reply.code(500).send({ error: err instanceof Error ? err.message : 'backup failed' })
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
}
