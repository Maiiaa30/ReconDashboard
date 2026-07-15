import { describe, expect, it } from 'vitest'
import { extractSignals, parseSourceMapSources, sourceMapUrl } from './jsRecon'

describe('extractSignals', () => {
  it('extracts endpoints, params and secrets from a body', () => {
    const body = `fetch("/api/v1/users?role=admin"); const k="AKIAABCDEFGHIJKLMNOP";`
    const sig = extractSignals(body)
    expect(sig.endpoints).toContain('/api/v1/users?role=admin')
    expect(sig.params).toContain('role')
    expect(sig.secrets.some((s) => s.pattern === 'AWS access key id')).toBe(true)
  })
})

describe('sourceMapUrl', () => {
  it('resolves a relative sourceMappingURL against the bundle URL', () => {
    const body = 'console.log(1)\n//# sourceMappingURL=app.min.js.map'
    expect(sourceMapUrl(body, 'https://t.com/static/app.min.js')).toBe('https://t.com/static/app.min.js.map')
  })
  it('supports the legacy //@ form', () => {
    expect(sourceMapUrl('x\n//@ sourceMappingURL=b.map', 'https://t.com/a.js')).toBe('https://t.com/b.map')
  })
  it('ignores inline data: maps and returns null when absent', () => {
    expect(sourceMapUrl('x\n//# sourceMappingURL=data:application/json;base64,AAAA', 'https://t.com/a.js')).toBeNull()
    expect(sourceMapUrl('no map here', 'https://t.com/a.js')).toBeNull()
  })
})

describe('parseSourceMapSources', () => {
  it('returns the un-minified sourcesContent with names', () => {
    const map = JSON.stringify({
      version: 3,
      sources: ['src/api/client.ts', 'src/util.ts'],
      sourcesContent: ['export const BASE = "/api/internal";', ''],
    })
    const out = parseSourceMapSources(map)
    expect(out.length).toBe(1) // the empty source is skipped
    expect(out[0].name).toBe('src/api/client.ts')
    expect(out[0].content).toContain('/api/internal')
  })
  it('returns [] for non-map JSON', () => {
    expect(parseSourceMapSources('{"foo":1}')).toEqual([])
    expect(parseSourceMapSources('not json')).toEqual([])
  })
})

describe('source map recovers endpoints not in the minified bundle', () => {
  it('finds an internal endpoint present only in the original source', () => {
    const minified = 'var a=1;\n//# sourceMappingURL=app.js.map' // no /admin/secret here
    expect(extractSignals(minified).endpoints).not.toContain('/admin/secret-panel')
    const map = JSON.stringify({
      version: 3,
      sources: ['src/routes.ts'],
      sourcesContent: ['const routes = { "path": "/admin/secret-panel" }; fetch("/admin/secret-panel?token=x");'],
    })
    const [src] = parseSourceMapSources(map)
    const sig = extractSignals(src.content)
    expect(sig.endpoints).toContain('/admin/secret-panel?token=x')
    expect(sig.routes).toContain('/admin/secret-panel')
  })
})
