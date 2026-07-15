import { describe, expect, it } from 'vitest'
import { diffSnapshot, type AssetSnapshot } from './changeWatch'

const snap = (over: Partial<AssetSnapshot> = {}): AssetSnapshot => ({ ports: [80, 443], tech: ['nginx'], up: true, ...over })

describe('diffSnapshot', () => {
  it('detects a NEW open port on a known IP', () => {
    const changes = diffSnapshot(snap(), snap({ ports: [80, 443, 8080] }))
    expect(changes).toContainEqual({ kind: 'new_port', port: 8080 })
    expect(changes.filter((c) => c.kind === 'new_port')).toHaveLength(1) // only the new one
  })

  it('detects new tech (case-insensitive, no dup on same tech)', () => {
    expect(diffSnapshot(snap(), snap({ tech: ['NGINX', 'php'] }))).toContainEqual({ kind: 'new_tech', tech: 'php' })
    expect(diffSnapshot(snap(), snap({ tech: ['nginx'] }))).toEqual([]) // unchanged
  })

  it('detects a host coming up and going dark', () => {
    expect(diffSnapshot(snap({ up: false, ports: [] }), snap({ up: true }))).toContainEqual({ kind: 'up' })
    expect(diffSnapshot(snap({ up: true }), snap({ up: false, ports: [] }))).toContainEqual({ kind: 'down' })
  })

  it('reports no change when nothing material moved', () => {
    expect(diffSnapshot(snap(), snap())).toEqual([])
  })

  it('does not flag a REMOVED port as a change (only additions/up/down)', () => {
    const changes = diffSnapshot(snap({ ports: [80, 443, 22] }), snap({ ports: [80, 443] }))
    expect(changes.filter((c) => c.kind === 'new_port')).toEqual([])
  })
})
