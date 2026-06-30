import type { SessionStore } from '@fastify/session'
import { sqlite } from '../db/index'

// A minimal SQLite-backed session store for @fastify/session.
// Sessions survive backend restarts (unlike the default in-memory store).
//
// @fastify/session expects a callback-style store: get/set/destroy.

// Statements are prepared lazily on first use. This module is imported before
// migrations run, so the `sessions` table may not exist yet at import time.
type Stmt = ReturnType<typeof sqlite.prepare>
let stmts: { upsert: Stmt; get: Stmt; del: Stmt; prune: Stmt } | null = null

function s() {
  if (!stmts) {
    stmts = {
      upsert: sqlite.prepare(
        `INSERT INTO sessions (sid, session, expires_at) VALUES (@sid, @session, @expiresAt)
         ON CONFLICT(sid) DO UPDATE SET session = @session, expires_at = @expiresAt`,
      ),
      get: sqlite.prepare(`SELECT session, expires_at as expiresAt FROM sessions WHERE sid = ?`),
      del: sqlite.prepare(`DELETE FROM sessions WHERE sid = ?`),
      prune: sqlite.prepare(`DELETE FROM sessions WHERE expires_at < ?`),
    }
  }
  return stmts
}

function expiresAtFromSession(session: { cookie?: { expires?: Date | string | null } }): number {
  const expires = session.cookie?.expires
  if (expires) return new Date(expires).getTime()
  // Fallback: 7 days out, so a session without an explicit expiry still prunes.
  return Date.now() + 7 * 24 * 60 * 60 * 1000
}

export const sqliteSessionStore: SessionStore = {
  set(sid, session, callback) {
    try {
      s().upsert.run({
        sid,
        session: JSON.stringify(session),
        expiresAt: expiresAtFromSession(session),
      })
      callback()
    } catch (err) {
      callback(err as Error)
    }
  },

  get(sid, callback) {
    try {
      const row = s().get.get(sid) as { session: string; expiresAt: number } | undefined
      if (!row) {
        callback(null, null)
        return
      }
      if (row.expiresAt < Date.now()) {
        s().del.run(sid)
        callback(null, null)
        return
      }
      callback(null, JSON.parse(row.session))
    } catch (err) {
      callback(err as Error)
    }
  },

  destroy(sid, callback) {
    try {
      s().del.run(sid)
      callback()
    } catch (err) {
      callback(err as Error)
    }
  },
}

// Remove expired rows periodically.
export function startSessionPruner(intervalMs = 60 * 60 * 1000): NodeJS.Timeout {
  const timer = setInterval(() => {
    try {
      s().prune.run(Date.now())
    } catch {
      // best-effort; ignore
    }
  }, intervalMs)
  timer.unref()
  return timer
}
