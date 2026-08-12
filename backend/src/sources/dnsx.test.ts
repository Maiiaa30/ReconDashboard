import { describe, expect, it } from 'vitest'
import { parseDnsxJsonl } from './dnsx'

describe('parseDnsxJsonl', () => {
  it('merges DNS records for the same host and ignores noise', () => {
    const rows = parseDnsxJsonl([
      JSON.stringify({ host: 'App.Example.com', a: ['203.0.113.10'], cname: ['edge.example.net.'] }),
      'not-json',
      JSON.stringify({ input: 'app.example.com', aaaa: ['2001:db8::10'] }),
    ].join('\n'))
    expect(rows.get('app.example.com')).toEqual({
      host: 'app.example.com', a: ['203.0.113.10'], aaaa: ['2001:db8::10'], cname: ['edge.example.net'],
    })
  })
})
