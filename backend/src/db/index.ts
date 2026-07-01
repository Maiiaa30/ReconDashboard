import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { closeSync, existsSync, mkdirSync, openSync, readSync, renameSync, rmSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as schema from './schema'

const dbPath = process.env.DATABASE_PATH ?? './data/app.db'

// Ensure the parent directory exists (locally ./data, in Docker the volume).
mkdirSync(dirname(resolve(dbPath)), { recursive: true })

// Restore-on-boot: if a verified backup was staged (backup/backup.ts writes
// "<dbPath>.restore"), swap it in now — before the DB is opened — keeping the
// previous DB as a ".pre-restore-*" safety copy. Doing it at boot avoids hot-
// swapping the file under an open handle.
applyStagedRestore(dbPath)

function looksLikeSqlite(path: string): boolean {
  try {
    const fd = openSync(path, 'r')
    try {
      const buf = Buffer.alloc(16)
      readSync(fd, buf, 0, 16, 0)
      return buf.equals(Buffer.from('SQLite format 3\0', 'latin1'))
    } finally {
      closeSync(fd)
    }
  } catch {
    return false
  }
}

function applyStagedRestore(path: string): void {
  const staged = `${path}.restore`
  if (!existsSync(staged)) return
  if (!looksLikeSqlite(staged)) {
    // Don't destroy the live DB for a bad staged file — drop it and carry on.
    rmSync(staged, { force: true })
    console.warn(`[restore] ignored ${staged}: not a valid SQLite file`)
    return
  }
  if (existsSync(path)) {
    renameSync(path, `${path}.pre-restore-${Date.now()}`)
  }
  // The staged snapshot is self-contained; drop any stale WAL/SHM of the old DB.
  rmSync(`${path}-wal`, { force: true })
  rmSync(`${path}-shm`, { force: true })
  renameSync(staged, path)
  console.warn(`[restore] restored database from staged backup (previous DB kept as ${path}.pre-restore-*)`)
}

const sqlite = new Database(dbPath)
// WAL + a busy_timeout so the worker write, the 2.5s job poll, the session
// store, backups and migrate don't throw spurious SQLITE_BUSY when they briefly
// overlap. synchronous=NORMAL is crash-safe under WAL and markedly faster for
// the row-by-row finding UPSERTs a big scan generates. cache/mmap help the
// scan-heavy read paths. All are plain PRAGMAs — no new deps.
sqlite.pragma('journal_mode = WAL')
sqlite.pragma('busy_timeout = 5000')
sqlite.pragma('synchronous = NORMAL')
sqlite.pragma('foreign_keys = ON')
sqlite.pragma('cache_size = -16000') // ~16 MB page cache
sqlite.pragma('mmap_size = 268435456') // 256 MB memory-mapped I/O

export const db = drizzle(sqlite, { schema })
export { sqlite }
