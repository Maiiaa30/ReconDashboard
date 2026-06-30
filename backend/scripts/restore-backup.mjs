#!/usr/bin/env node
// Decrypt a recon-dashboard encrypted backup (.rdb) back into a SQLite file.
//
// Usage:
//   node scripts/restore-backup.mjs <backup.rdb> <output.db>
//   (you will be prompted for the passphrase, or set BACKUP_PASSPHRASE)
//
// Format: magic "RDB1" (4) | salt (16) | iv (12) | authTag (16) | ciphertext
import { readFileSync, writeFileSync } from 'node:fs'
import { createDecipheriv, scryptSync } from 'node:crypto'
import { createInterface } from 'node:readline'

const [, , inPath, outPath] = process.argv
if (!inPath || !outPath) {
  console.error('Usage: node scripts/restore-backup.mjs <backup.rdb> <output.db>')
  process.exit(1)
}

function ask(question) {
  if (process.env.BACKUP_PASSPHRASE) return Promise.resolve(process.env.BACKUP_PASSPHRASE)
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a) }))
}

const blob = readFileSync(inPath)
const MAGIC = Buffer.from('RDB1', 'utf8')
if (!blob.subarray(0, 4).equals(MAGIC)) {
  console.error('Not a recon-dashboard backup (bad magic).')
  process.exit(1)
}

const passphrase = (await ask('Backup passphrase: ')).trim()
const salt = blob.subarray(4, 20)
const iv = blob.subarray(20, 32)
const authTag = blob.subarray(32, 48)
const ciphertext = blob.subarray(48)

try {
  // Must match createEncryptedBackup's scrypt params.
  const key = scryptSync(passphrase, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  writeFileSync(outPath, plain)
  console.log(`Restored ${plain.length} bytes -> ${outPath}`)
} catch {
  console.error('Decryption failed — wrong passphrase or corrupted backup.')
  process.exit(1)
}
