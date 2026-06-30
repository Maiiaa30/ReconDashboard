import { describe, expect, it } from 'vitest'
import { toCsv } from './csv'

describe('toCsv — spreadsheet formula-injection neutralization', () => {
  it('prefixes a single quote on cells starting with a formula trigger', () => {
    expect(toCsv(['v'], [['=cmd']]).split('\r\n')[1]).toBe("'=cmd")
    expect(toCsv(['v'], [['+1']]).split('\r\n')[1]).toBe("'+1")
    expect(toCsv(['v'], [['-1']]).split('\r\n')[1]).toBe("'-1")
    expect(toCsv(['v'], [['@SUM']]).split('\r\n')[1]).toBe("'@SUM")
    // Leading tab is neutralized (prefixed) but not quoted (tab isn't a quote trigger).
    expect(toCsv(['v'], [['\tx']]).split('\r\n')[1]).toBe("'\tx")
    // Leading CR is neutralized AND quoted (CR is an RFC quote trigger).
    expect(toCsv(['v'], [['\rx']])).toBe("v\r\n\"'\rx\"")
  })
  it('does not touch safe leading characters', () => {
    const out = toCsv(['v'], [['example.com'], ['200 OK'], ['nginx']])
    expect(out.split('\r\n').slice(1)).toEqual(['example.com', '200 OK', 'nginx'])
  })
})

describe('toCsv — RFC-4180 quoting', () => {
  it('quotes fields containing comma, quote, CR, or LF and doubles quotes', () => {
    expect(toCsv(['a'], [['x,y']]).split('\r\n')[1]).toBe('"x,y"')
    expect(toCsv(['a'], [['he said "hi"']]).split('\r\n')[1]).toBe('"he said ""hi"""')
    expect(toCsv(['a'], [['line1\nline2']]).split('\r\n')[1]).toBe('"line1\nline2"')
  })
  it('renders null/undefined as empty cells', () => {
    expect(toCsv(['a', 'b'], [[null, undefined]]).split('\r\n')[1]).toBe(',')
  })
  it('joins rows with CRLF and keeps the header first', () => {
    const out = toCsv(['h1', 'h2'], [['a', 'b'], ['c', 'd']])
    expect(out).toBe('h1,h2\r\na,b\r\nc,d')
  })
})
