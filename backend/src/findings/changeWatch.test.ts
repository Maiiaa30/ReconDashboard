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

  it('detects page-title and certificate changes', () => {
    const changes = diffSnapshot(
      snap({ title: 'Old portal', certFp: 'AA' }),
      snap({ title: 'New portal', certFp: 'BB' }),
    )
    expect(changes).toContainEqual({ kind: 'title_changed', from: 'Old portal', to: 'New portal' })
    expect(changes).toContainEqual({ kind: 'cert_changed', from: 'AA', to: 'BB' })
  })

  it('detects HTTP, technology and visual baseline changes', () => {
    const changes = diffSnapshot(
      snap({ status: 200, server: 'nginx', redirect: '/old', contentHash: 'aaa', contentLength: 1000, screenshotHash: 'one' }),
      snap({ status: 302, server: 'caddy', redirect: '/login', contentHash: 'bbb', contentLength: 1200, screenshotHash: 'two' }),
    )
    expect(changes).toContainEqual({ kind: 'status_changed', from: 200, to: 302 })
    expect(changes).toContainEqual({ kind: 'server_changed', from: 'nginx', to: 'caddy' })
    expect(changes).toContainEqual({ kind: 'redirect_changed', from: '/old', to: '/login' })
    expect(changes).toContainEqual({ kind: 'content_changed', fromLength: 1000, toLength: 1200 })
    expect(changes).toContainEqual({ kind: 'screenshot_changed' })
  })

  it('ignores small content-length drift to reduce dynamic-page noise', () => {
    const changes = diffSnapshot(
      snap({ contentHash: 'aaa', contentLength: 1000 }),
      snap({ contentHash: 'bbb', contentLength: 1020 }),
    )
    expect(changes.find((change) => change.kind === 'content_changed')).toBeUndefined()
  })

  it('does not flag a REMOVED port as a change (only additions/up/down)', () => {
    const changes = diffSnapshot(snap({ ports: [80, 443, 22] }), snap({ ports: [80, 443] }))
    expect(changes.filter((c) => c.kind === 'new_port')).toEqual([])
  })
})
