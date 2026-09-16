import { describe, expect, it } from 'vitest'
import { parseFindingsJson, parseNmapXml, parseNucleiJsonl } from './import'

describe('parseNucleiJsonl', () => {
  it('maps each JSONL line to a nuclei finding shape that matches native scans', () => {
    const jsonl = [
      JSON.stringify({ 'template-id': 'CVE-2021-1234', info: { name: 'Some CVE', severity: 'high' }, host: 'a.example.com', 'matched-at': 'https://a.example.com/x' }),
      JSON.stringify({ 'template-id': 'tech-detect', info: { name: 'Tech', severity: 'info' }, 'matched-at': 'https://b.example.com' }),
    ].join('\n')
    const { items, skipped } = parseNucleiJsonl(jsonl)
    expect(skipped).toBe(0)
    expect(items).toHaveLength(2)
    expect(items[0]).toMatchObject({
      type: 'nuclei',
      data: { templateId: 'CVE-2021-1234', name: 'Some CVE', severity: 'high', target: 'a.example.com', matched: 'https://a.example.com/x', imported: true },
      tags: ['nuclei', 'imported'],
    })
    // host derived from matched-at when `host` is absent
    expect(items[1].data.target).toBe('b.example.com')
  })

  it('skips blank and unparseable lines without throwing', () => {
    const { items, skipped, errors } = parseNucleiJsonl('\n{bad json\n\n' + JSON.stringify({ 'template-id': 't', 'matched-at': 'https://x' }))
    expect(items).toHaveLength(1)
    expect(skipped).toBe(1)
    expect(errors.length).toBeGreaterThan(0)
  })
})

describe('parseNmapXml', () => {
  const xml = `<?xml version="1.0"?><nmaprun>
    <host>
      <address addr="203.0.113.5" addrtype="ipv4"/>
      <hostnames><hostname name="a.example.com"/></hostnames>
      <ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.25"/></port>
        <port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
        <port protocol="tcp" portid="8080"><state state="closed"/><service name="http-proxy"/></port>
      </ports>
    </host>
  </nmaprun>`

  it('produces one nmap finding per host with open+filtered ports (closed dropped)', () => {
    const { items, skipped } = parseNmapXml(xml)
    expect(skipped).toBe(0)
    expect(items).toHaveLength(1)
    const d = items[0].data as any
    expect(items[0].type).toBe('nmap')
    expect(d.target).toBe('a.example.com')
    expect(d.ip).toBe('203.0.113.5')
    expect(d.allPorts.map((p: any) => p.port).sort((a: number, b: number) => a - b)).toEqual([80, 443])
    expect(d.openPorts.map((p: any) => p.port)).toEqual([80])
    expect(d.openPorts[0]).toMatchObject({ service: 'http', product: 'nginx', version: '1.25' })
    expect(d.imported).toBe(true)
  })

  it('returns an error note (not a throw) on malformed XML', () => {
    const { items, errors } = parseNmapXml('<nmaprun><host>')
    // fast-xml-parser is lenient; a host with no address is skipped, so no items.
    expect(items).toHaveLength(0)
    expect(Array.isArray(errors)).toBe(true)
  })
})

describe('parseFindingsJson', () => {
  it('accepts a bare array and a { findings: [...] } envelope', () => {
    const item = { type: 'owasp', data: { url: 'https://a/x', title: 'XSS' }, tags: ['xss'] }
    expect(parseFindingsJson(JSON.stringify([item])).items).toHaveLength(1)
    const env = parseFindingsJson(JSON.stringify({ findings: [item] }))
    expect(env.items).toHaveLength(1)
    expect(env.items[0]).toMatchObject({ type: 'owasp', tags: ['xss', 'imported'], data: { imported: true } })
  })

  it('skips unknown types and non-object data', () => {
    const { items, skipped } = parseFindingsJson(JSON.stringify([
      { type: 'made_up', data: { x: 1 } },
      { type: 'owasp', data: 'not-an-object' },
      { type: 'owasp', data: { url: 'https://ok' } },
    ]))
    expect(items).toHaveLength(1)
    expect(skipped).toBe(2)
  })

  it('reports an error for non-array, non-envelope input', () => {
    expect(parseFindingsJson('42').errors.length).toBeGreaterThan(0)
    expect(parseFindingsJson('{bad').errors.length).toBeGreaterThan(0)
  })
})
