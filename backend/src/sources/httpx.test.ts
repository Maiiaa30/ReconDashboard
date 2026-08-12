import { describe, expect, it } from 'vitest'
import { parseHttpxJsonl } from './httpx'

describe('parseHttpxJsonl', () => {
  it('normalizes enrichment and response fingerprints', () => {
    const rows = parseHttpxJsonl(JSON.stringify({
      input: 'Portal.Example.com', url: 'https://portal.example.com', status_code: 302,
      title: 'Sign in', webserver: 'nginx', tech: ['Nginx', 'React'], a: ['203.0.113.20'],
      cname: ['edge.example.net.'], location: '/login', content_length: 450,
      hash: { body_sha256: 'abc123' },
    }))
    expect(rows.get('portal.example.com')).toMatchObject({
      scheme: 'https', status: 302, server: 'nginx', loginHint: true,
      technologies: ['Nginx', 'React'], redirect: '/login', contentHash: 'abc123', contentLength: 450,
    })
  })
})
