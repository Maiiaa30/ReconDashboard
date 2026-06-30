import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as schema from './schema'

const dbPath = process.env.DATABASE_PATH ?? './data/app.db'

// Ensure the parent directory exists (locally ./data, in Docker the volume).
mkdirSync(dirname(resolve(dbPath)), { recursive: true })

const sqlite = new Database(dbPath)
sqlite.pragma('journal_mode = WAL')
sqlite.pragma('foreign_keys = ON')

export const db = drizzle(sqlite, { schema })
export { sqlite }
