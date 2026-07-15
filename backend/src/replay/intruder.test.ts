import { describe, it, expect, vi } from 'vitest'

// Mock the sender so runIntruder can be exercised without a network. The response
// is driven by the payload placed in ?q= by the template.
vi.mock('./send', () => ({
  sendRawRequest: vi.fn(async (req: { url: string }) => {
    const q = new URL(req.url).searchParams.get('q') ?? ''
    let body = 'ok normal body'
    let status = 200
    if (q === 'tokens') body = 'csrf=aaa x csrf=bbb y csrf=ccc'
    else if (q === 'boom') {
      body = 'internal error detail'
      status = 500
    }
    return { status, statusText: '', headers: [], body, bodyBytes: Buffer.byteLength(body), truncated: false, timeMs: 100, finalUrl: req.url, redirects: [] }
  }),
}))

import { applyPayload, applyPayloads, attackCount, expandAttack, expandPayloads, findInteresting, MAX_PAYLOADS, positionsInTemplate, runIntruder, type IntruderAttempt } from './intruder'

describe('expandPayloads', () => {
  it('expands a numeric range with zero-padding', () => {
    expect(expandPayloads({ mode: 'range', from: 8, to: 11, pad: 3 })).toEqual(['008', '009', '010', '011'])
  })
  it('splits a list, trimming blanks', () => {
    expect(expandPayloads({ mode: 'list', list: ' a \n\nb\n c ' })).toEqual(['a', 'b', 'c'])
  })
  it('rejects an empty list and a backwards range', () => {
    expect(() => expandPayloads({ mode: 'list', list: '   ' })).toThrow(/empty/)
    expect(() => expandPayloads({ mode: 'range', from: 5, to: 1 })).toThrow(/>=/)
  })
  it('rejects a range larger than the cap', () => {
    expect(() => expandPayloads({ mode: 'range', from: 0, to: MAX_PAYLOADS + 1 })).toThrow(/cap/)
  })
})

describe('positionsInTemplate', () => {
  it('finds numbered positions across url/headers/body', () => {
    const t = { method: 'POST', url: 'https://t.com/?a={{P1}}', headers: { X: '{{P2}}' }, body: '{{P3}}' }
    expect(positionsInTemplate(t)).toEqual([1, 2, 3])
  })
  it('treats legacy {{PAYLOAD}} as P1', () => {
    expect(positionsInTemplate({ method: 'GET', url: 'https://t.com/?a={{PAYLOAD}}' })).toEqual([1])
  })
  it('returns [] when unmarked', () => {
    expect(positionsInTemplate({ method: 'GET', url: 'https://t.com/' })).toEqual([])
  })
})

describe('applyPayloads', () => {
  it('substitutes each numbered position independently', () => {
    const out = applyPayloads(
      { method: 'POST', url: 'https://t.com/?u={{P1}}', headers: { 'X-Try': '{{P2}}', Static: 'keep' }, body: '{"p":"{{P1}}"}' },
      { 1: 'alice', 2: 'tok' },
    )
    expect(out.url).toBe('https://t.com/?u=alice')
    expect(out.headers).toEqual({ 'X-Try': 'tok', Static: 'keep' })
    expect(out.body).toBe('{"p":"alice"}')
  })
  it('applyPayload (single) fills every position with the one payload', () => {
    const out = applyPayload({ method: 'GET', url: 'https://t.com/?a={{PAYLOAD}}&b={{P1}}', body: undefined }, 'x')
    expect(out.url).toBe('https://t.com/?a=x&b=x')
  })
})

describe('attackCount', () => {
  const P = [1, 2]
  it('battering-ram = len(list)', () => expect(attackCount('battering-ram', P, [['a', 'b', 'c']])).toBe(3))
  it('sniper = positions × len(list)', () => expect(attackCount('sniper', P, [['a', 'b', 'c']])).toBe(6))
  it('pitchfork = min(list lengths)', () => expect(attackCount('pitchfork', P, [['a', 'b', 'c'], ['x', 'y']])).toBe(2))
  it('cluster-bomb = product', () => expect(attackCount('cluster-bomb', P, [['a', 'b', 'c'], ['x', 'y']])).toBe(6))
})

describe('expandAttack', () => {
  const P = [1, 2]
  it('battering-ram puts the same payload in every position', () => {
    expect(expandAttack('battering-ram', P, [['a', 'b']])).toEqual([{ 1: 'a', 2: 'a' }, { 1: 'b', 2: 'b' }])
  })
  it('sniper varies one position at a time, others empty', () => {
    expect(expandAttack('sniper', P, [['a', 'b']])).toEqual([
      { 1: 'a', 2: '' },
      { 1: 'b', 2: '' },
      { 1: '', 2: 'a' },
      { 1: '', 2: 'b' },
    ])
  })
  it('pitchfork pairs lists in lockstep', () => {
    expect(expandAttack('pitchfork', P, [['a', 'b'], ['x', 'y']])).toEqual([{ 1: 'a', 2: 'x' }, { 1: 'b', 2: 'y' }])
  })
  it('cluster-bomb is the Cartesian product', () => {
    expect(expandAttack('cluster-bomb', P, [['a', 'b'], ['x', 'y']])).toEqual([
      { 1: 'a', 2: 'x' },
      { 1: 'a', 2: 'y' },
      { 1: 'b', 2: 'x' },
      { 1: 'b', 2: 'y' },
    ])
  })
  it('rejects a product over the cap before materializing', () => {
    const big = Array.from({ length: 200 }, (_, i) => String(i))
    expect(() => expandAttack('cluster-bomb', P, [big, big])).toThrow(/exceeds/)
  })
})

describe('findInteresting (anomaly weighting)', () => {
  const row = (over: Partial<IntruderAttempt>): IntruderAttempt => ({ payload: 'p', status: 200, length: 1000, words: 100, timeMs: 100, ...over })
  const uniform = (n: number) => Array.from({ length: n }, () => row({}))

  it('does NOT flag a single slow response as interesting (network jitter)', () => {
    const rows = [...uniform(8), row({ payload: 'slow', timeMs: 400 })] // only time deviates
    const { interesting } = findInteresting(rows)
    expect(interesting.find((a) => a.payload === 'slow')).toBeUndefined()
  })

  it('flags a genuinely different status/length', () => {
    const rows = [...uniform(8), row({ payload: 'hit', status: 500, length: 20 })]
    const { interesting } = findInteresting(rows)
    expect(interesting.some((a) => a.payload === 'hit')).toBe(true)
  })

  it('always flags errors and grep-match hits', () => {
    const rows = [...uniform(5), row({ payload: 'err', error: 'boom' }), row({ payload: 'm', matched: true })]
    const flagged = findInteresting(rows).interesting.map((a) => a.payload)
    expect(flagged).toContain('err')
    expect(flagged).toContain('m')
  })
})

describe('runIntruder body excerpt + multi-extract', () => {
  const template = { method: 'GET', url: 'https://t.com/?q={{P1}}' }
  const run = () =>
    runIntruder(
      template,
      [{ 1: 'a' }, { 1: 'b' }, { 1: 'c' }, { 1: 'd' }, { 1: 'e' }, { 1: 'tokens' }, { 1: 'boom' }],
      { positions: [1], grep: { extract: 'csrf=([a-z0-9]+)' }, signal: new AbortController().signal },
    )

  it('captures every grep-extract match, not just the first', async () => {
    const res = await run()
    const tokens = res.attempts.find((a) => a.payload === 'tokens')!
    expect(tokens.extract).toBe('aaa')
    expect(tokens.extractAll).toEqual(['aaa', 'bbb', 'ccc'])
  })

  it('retains a body excerpt only on interesting rows', async () => {
    const res = await run()
    const boom = res.interesting.find((a) => a.payload === 'boom')! // status 500 → interesting
    expect(boom.bodyExcerpt).toContain('internal error')
    const normal = res.attempts.find((a) => a.payload === 'a')!
    expect(normal.bodyExcerpt).toBeUndefined() // stripped from non-interesting rows
  })
})
