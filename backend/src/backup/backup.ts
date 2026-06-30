import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { sqlite } from '../db/index'

// Phase 8: encrypted backup of the SQLite database, so a host suspension never
// loses data. We take a consistent snapshot via SQLite's online backup API,
// then encrypt it with AES-256-GCM using a scrypt-derived key.
//
// On-disk/download format (single binary blob):
//   magic "RDB1" (4) | salt (16) | iv (12) | authTag (16) | ciphertext
const MAGIC = Buffer.from('RDB1', 'utf8')

// scrypt cost: N=2^17 is well above the default (2^14) for a password-derived
// key. maxmem must be raised to allow it (128 * N * r bytes ≈ 128 MB headroom).
const SCRYPT_PARAMS = { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 } as const

export async function createEncryptedBackup(passphrase: string): Promise<Buffer> {
  if (!passphrase || passphrase.length < 12) {
    throw new Error('backup passphrase must be at least 12 characters')
  }

  const snapshotPath = join(tmpdir(), `recon-backup-${randomUUID()}.db`)
  try {
    // Consistent snapshot of the live DB (handles WAL correctly).
    await sqlite.backup(snapshotPath)
    const plain = await readFile(snapshotPath)

    const salt = randomBytes(16)
    const iv = randomBytes(12)
    const key = scryptSync(passphrase, salt, 32, SCRYPT_PARAMS)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()])
    const authTag = cipher.getAuthTag()

    return Buffer.concat([MAGIC, salt, iv, authTag, ciphertext])
  } finally {
    await rm(snapshotPath, { force: true }).catch(() => {})
  }
}

// Decryption helper (not exposed via API; documented for restores via a script).
export function decryptBackup(blob: Buffer, passphrase: string): Buffer {
  if (!blob.subarray(0, 4).equals(MAGIC)) throw new Error('not a recon-dashboard backup')
  const salt = blob.subarray(4, 20)
  const iv = blob.subarray(20, 32)
  const authTag = blob.subarray(32, 48)
  const ciphertext = blob.subarray(48)
  const key = scryptSync(passphrase, salt, 32, SCRYPT_PARAMS)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
