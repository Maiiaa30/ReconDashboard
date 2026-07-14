import { describe, expect, it } from 'vitest'
import { applyRules, orderRules, type MatchReplaceRule } from './matchReplace'

const rule = (over: Partial<MatchReplaceRule>): MatchReplaceRule => ({
  id: 1,
  domainId: null,
  name: 'r',
  enabled: true,
  part: 'url',
  match: '',
  replace: '',
  isRegex: false,
  ...over,
})

const req = { method: 'GET', url: 'https://t.com/a?x=1', headers: { Accept: '*/*' } as Record<string, string>, body: 'hello world' }

describe('applyRules — headers', () => {
  it('injects a new header', () => {
    const out = applyRules(req, [rule({ part: 'header', match: 'Authorization', replace: 'Bearer T' })])
    expect(out.headers).toMatchObject({ Authorization: 'Bearer T' })
  })
  it('overwrites an existing header case-insensitively, preserving its key', () => {
    const out = applyRules({ ...req, headers: { accept: 'text/html' } }, [rule({ part: 'header', match: 'Accept', replace: 'application/json' })])
    expect(out.headers).toEqual({ accept: 'application/json' })
  })
  it('deletes a header when replace is empty', () => {
    const out = applyRules({ ...req, headers: { Cookie: 'x=1' } }, [rule({ part: 'header', match: 'Cookie', replace: '' })])
    expect(out.headers).toEqual({})
  })
})

describe('applyRules — url/body', () => {
  it('literal replace in the url', () => {
    const out = applyRules(req, [rule({ part: 'url', match: 'x=1', replace: 'x=2' })])
    expect(out.url).toBe('https://t.com/a?x=2')
  })
  it('regex replace in the body with a backref', () => {
    const out = applyRules(req, [rule({ part: 'body', match: '(hello) (world)', replace: '$2 $1', isRegex: true })])
    expect(out.body).toBe('world hello')
  })
  it('skips a rule with an invalid regex instead of throwing', () => {
    const out = applyRules(req, [rule({ part: 'body', match: '(unclosed', replace: 'x', isRegex: true })])
    expect(out.body).toBe('hello world') // unchanged
  })
})

describe('applyRules — enabled + order', () => {
  it('ignores a disabled rule', () => {
    const out = applyRules(req, [rule({ part: 'url', match: 'x=1', replace: 'x=9', enabled: false })])
    expect(out.url).toBe('https://t.com/a?x=1')
  })
  it('does not mutate the input request', () => {
    const original = { ...req, headers: { ...req.headers } }
    applyRules(req, [rule({ part: 'header', match: 'X', replace: 'y' })])
    expect(req).toEqual(original)
  })
})

describe('orderRules', () => {
  it('puts global rules before domain rules, then by id', () => {
    const rules = [rule({ id: 3, domainId: 5 }), rule({ id: 2, domainId: null }), rule({ id: 1, domainId: 5 })]
    expect(orderRules(rules).map((r) => r.id)).toEqual([2, 1, 3])
  })
})
