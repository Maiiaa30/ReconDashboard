import { describe, expect, it, vi, beforeEach } from 'vitest'

// Real in-memory jobs table so the reaper / cancel SQL runs for real. drizzle is
// used with the imported `jobs` table object, so no schema wiring is needed.
vi.mock('../db/index', async () => {
  const Database = (await import('better-sqlite3')).default
  const { drizzle } = await import('drizzle-orm/better-sqlite3')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE jobs (
      id integer PRIMARY KEY AUTOINCREMENT,
      type text NOT NULL,
      status text NOT NULL DEFAULT 'queued',
      params text,
      result text,
      error text,
      progress text,
      domain_id integer,
      attempts integer NOT NULL DEFAULT 0,
      cancel_requested integer NOT NULL DEFAULT 0,
      created_at integer NOT NULL DEFAULT 0,
      started_at integer,
      finished_at integer,
      updated_at integer NOT NULL DEFAULT 0
    );
  `)
  return { db: drizzle(sqlite), sqlite }
})

import { db } from '../db/index'
import { jobs } from '../db/schema'
import {
  JOB_TIMEOUT_MS,
  getJob,
  markCancelRequested,
  pruneTerminalJobs,
  reapTimedOutRunning,
  requeueStaleRunning,
} from './queue'

const PAST = () => new Date(Date.now() - JOB_TIMEOUT_MS - 10 * 60 * 1000) // well past deadline+grace
const insert = (v: Record<string, unknown>): number =>
  Number(db.insert(jobs).values({ createdAt: new Date(), updatedAt: new Date(), ...v } as any).run().lastInsertRowid)

// Audit §5: the worker kept cancel + wall-clock-timeout state in memory, so a job
// left 'running' after a crash was unkillable and its timeout never fired.
describe('job reaper + durable cancel (audit §5)', () => {
  beforeEach(() => {
    db.delete(jobs).run()
  })

  it('dead-letters a loud job stuck running past the deadline', () => {
    const id = insert({ type: 'nmap_scan', status: 'running', startedAt: PAST(), attempts: 1 })
    expect(reapTimedOutRunning().dead).toBe(1)
    expect(getJob(id)?.status).toBe('dead')
  })

  it('re-queues an orphaned passive job past the deadline', () => {
    const id = insert({ type: 'subdomain_discovery', status: 'running', startedAt: PAST(), attempts: 0 })
    expect(reapTimedOutRunning().requeued).toBe(1)
    expect(getJob(id)?.status).toBe('queued')
  })

  it('leaves a running job under the deadline alone (it is still executing)', () => {
    const id = insert({ type: 'nmap_scan', status: 'running', startedAt: new Date(), attempts: 1 })
    expect(reapTimedOutRunning()).toEqual({ requeued: 0, dead: 0, cancelled: 0 })
    expect(getJob(id)?.status).toBe('running')
  })

  it('honors a durable cancel on a stale running job (cancel, not re-run)', () => {
    const id = insert({ type: 'subdomain_discovery', status: 'running', startedAt: PAST(), attempts: 0, cancelRequested: true })
    const r = requeueStaleRunning()
    expect(r.cancelled).toBe(1)
    expect(r.requeued).toBe(0)
    expect(getJob(id)?.status).toBe('cancelled')
  })

  it('markCancelRequested marks a running job but is a no-op on a finished one', () => {
    const running = insert({ type: 'nmap_scan', status: 'running', startedAt: new Date() })
    const done = insert({ type: 'nmap_scan', status: 'done', startedAt: new Date(), finishedAt: new Date() })
    expect(markCancelRequested(running)).toBe(true)
    expect(getJob(running)?.cancelRequested).toBe(true)
    expect(markCancelRequested(done)).toBe(false)
  })
})

describe('pruneTerminalJobs retention (audit §4)', () => {
  beforeEach(() => {
    db.delete(jobs).run()
  })

  const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000) // 40 days ago
  const recent = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) // 1 day ago

  it('deletes only terminal jobs older than the window; keeps queued/running/recent', () => {
    const oldDone = insert({ type: 'osint_gather', status: 'done', updatedAt: old, finishedAt: old })
    const oldError = insert({ type: 'nmap_scan', status: 'error', updatedAt: old, finishedAt: old })
    const oldDead = insert({ type: 'nmap_scan', status: 'dead', updatedAt: old, finishedAt: old })
    const recentDone = insert({ type: 'osint_gather', status: 'done', updatedAt: recent, finishedAt: recent })
    const oldQueued = insert({ type: 'osint_gather', status: 'queued', updatedAt: old })
    const oldRunning = insert({ type: 'nmap_scan', status: 'running', startedAt: old, updatedAt: old })

    const removed = pruneTerminalJobs(30 * 24 * 60 * 60 * 1000)
    expect(removed).toBe(3) // the three old terminal jobs

    expect(getJob(oldDone)).toBeUndefined()
    expect(getJob(oldError)).toBeUndefined()
    expect(getJob(oldDead)).toBeUndefined()
    // Never pruned: recent terminal, and queued/running at any age.
    expect(getJob(recentDone)?.status).toBe('done')
    expect(getJob(oldQueued)?.status).toBe('queued')
    expect(getJob(oldRunning)?.status).toBe('running')
  })
})
