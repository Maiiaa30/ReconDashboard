import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as schema from './schema'

const dbPath = process.env.DATABASE_PATH ?? './data/app.db'

// Ensure the parent directory exists (locally ./data, in Docker the volume).
mkdirSync(dirname(resolve(dbPath)), { recursive: true })

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
