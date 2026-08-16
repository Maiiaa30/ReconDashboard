import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

let getLocalReadiness: typeof import('./meta').getLocalReadiness
let sqlite: typeof import('../db/index').sqlite
let testDir = ''

beforeAll(async () => {
  testDir = mkdtempSync(join(tmpdir(), 'recon-readiness-'))
  process.env.DATABASE_PATH = join(testDir, 'app.db')

  const migration = await import('../db/migrate')
  migration.runMigrations()
  sqlite = (await import('../db/index')).sqlite
  getLocalReadiness = (await import('./meta')).getLocalReadiness
})

afterAll(() => {
  sqlite.close()
  rmSync(testDir, { recursive: true, force: true })
})

describe('local readiness', () => {
  it('reports database, storage, worker, queue, capture and backup state', () => {
    const readiness = getLocalReadiness()

    expect(readiness.database.ok).toBe(true)
    expect(readiness.database.sizeBytes).toBeGreaterThan(0)
    expect(readiness.storage.freeBytes).toEqual(expect.any(Number))
    expect(readiness.worker.running).toBe(false)
    expect(readiness.queue).toMatchObject({
      queued: expect.any(Number),
      running: expect.any(Number),
      failed: expect.any(Number),
    })
    expect(readiness.capture).toHaveProperty('enabled')
    expect(readiness.backup).toHaveProperty('serverPassphraseConfigured')
  })
})
