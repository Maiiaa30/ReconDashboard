import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { readFile, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import Database from 'better-sqlite3'
import { sqlite } from '../db/index'

// The first 16 bytes of every SQLite database file.
const SQLITE_HEADER = Buffer.from('SQLite format 3\0', 'latin1')

export function isSqliteBuffer(buf: Buffer): boolean {
  return buf.length >= 16 && buf.subarray(0, 16).equals(SQLITE_HEADER)
}

// Open a candidate DB file read-only and run a quick integrity check, so we only
// ever accept a backup we've confirmed actually loads.
function integrityOk(path: string): boolean {
  let dbc: Database.Database | null = null
  try {
    dbc = new Database(path, { readonly: true, fileMustExist: true })
    const row = dbc.pragma('quick_check', { simple: true })
    return row === 'ok'
  } catch {
    return false
  } finally {
    dbc?.close()
  }
}

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

// Decrypt an encrypted backup blob back to the raw SQLite bytes. Throws if the
// magic/format is wrong or the GCM auth tag fails (wrong passphrase / tampered).
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

export interface BackupCheck {
  ok: boolean
  error?: string
  bytes?: number
}

// Confirm a backup is decryptable AND a loadable SQLite database — so the
// operator can trust it before ever needing it. Decrypts to a temp file and runs
// an integrity check, then cleans up. Never touches the live DB.
export async function verifyBackup(blob: Buffer, passphrase: string): Promise<BackupCheck> {
  let plain: Buffer
  try {
    plain = decryptBackup(blob, passphrase)
  } catch {
    return { ok: false, error: 'decryption failed — wrong passphrase or corrupt/incomplete backup' }
  }
  if (!isSqliteBuffer(plain)) return { ok: false, error: 'decrypted data is not a SQLite database' }
  const tmp = join(tmpdir(), `recon-verify-${randomUUID()}.db`)
  try {
    await writeFile(tmp, plain)
    if (!integrityOk(tmp)) return { ok: false, error: 'SQLite integrity check failed on the decrypted backup' }
    return { ok: true, bytes: plain.length }
  } finally {
    await rm(tmp, { force: true }).catch(() => {})
  }
}

// Stage a verified backup for restore-on-next-boot. We do NOT hot-swap the live
// DB under an open handle; instead we write the verified bytes to
// "<dbPath>.restore" and db/index.ts atomically swaps it in on the next start
// (keeping the previous DB as a ".pre-restore-*" safety copy).
export async function stageRestore(blob: Buffer, passphrase: string, dbPath: string): Promise<BackupCheck> {
  const check = await verifyBackup(blob, passphrase)
  if (!check.ok) return check
  const plain = decryptBackup(blob, passphrase)
  const tmp = `${dbPath}.restore.tmp-${randomUUID()}`
  await writeFile(tmp, plain)
  await rename(tmp, `${dbPath}.restore`) // atomic on the same filesystem
  return check
}
