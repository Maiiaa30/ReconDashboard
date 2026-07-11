import { describe, it, expect } from 'vitest'
import { applyPayload, expandPayloads, MAX_PAYLOADS, PAYLOAD_MARKER } from './intruder'

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

describe('applyPayload', () => {
  it('substitutes the marker in url, headers and body', () => {
    const out = applyPayload(
      {
        method: 'POST',
        url: `https://t.com/verify?code=${PAYLOAD_MARKER}`,
        headers: { 'X-Try': PAYLOAD_MARKER, Static: 'keep' },
        body: `{"code":"${PAYLOAD_MARKER}"}`,
      },
      '000123',
    )
    expect(out.url).toBe('https://t.com/verify?code=000123')
    expect(out.headers).toEqual({ 'X-Try': '000123', Static: 'keep' })
    expect(out.body).toBe('{"code":"000123"}')
  })

  it('leaves a template without the marker unchanged', () => {
    const tpl = { method: 'GET', url: 'https://t.com/a', body: undefined }
    expect(applyPayload(tpl, 'x')).toEqual(tpl)
  })
})
