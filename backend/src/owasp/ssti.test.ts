import { describe, expect, it } from 'vitest'
import { sstiConfirmed, SSTI_MARKER } from './ssti'

describe('sstiConfirmed', () => {
  it('confirms when the payload evaluated but the control did not', () => {
    expect(sstiConfirmed(`result is ${SSTI_MARKER}`, 'result is 1337*1191')).toBe(true)
  })

  it('does NOT confirm when the product is already on the page (control has it too)', () => {
    // A page that happens to contain 1592367 → control body has it → not SSTI.
    expect(sstiConfirmed(`price ${SSTI_MARKER}`, `price ${SSTI_MARKER}`)).toBe(false)
  })

  it('does NOT confirm when the payload was only reflected, not evaluated', () => {
    // Payload echoed verbatim; the product never appears.
    expect(sstiConfirmed('you searched for {{1337*1191}}', 'you searched for 1337*1191')).toBe(false)
  })

  it('does NOT confirm when neither body has the marker', () => {
    expect(sstiConfirmed('nothing here', 'nothing here')).toBe(false)
  })
})
