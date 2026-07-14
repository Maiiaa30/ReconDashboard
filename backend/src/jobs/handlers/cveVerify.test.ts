import { describe, expect, it } from 'vitest'
import { classifyCveVerify } from './cveVerify'

// The three-way outcome is the correctness-critical part of CVE verification: a
// missing template and a template that ran-but-didn't-match BOTH produce zero
// matches, and conflating either with "not vulnerable" would let a real CVE be
// dismissed. This locks the distinction down without needing nuclei installed.
describe('classifyCveVerify', () => {
  it('is confirmed whenever nuclei matched at least once', () => {
    expect(classifyCveVerify(1, '')).toBe('confirmed')
    expect(classifyCveVerify(3, 'Templates loaded for current scan: 1')).toBe('confirmed')
  })

  it('is no_template when nuclei loaded zero templates for the id', () => {
    expect(classifyCveVerify(0, '[INF] Templates loaded for current scan: 0')).toBe('no_template')
    expect(classifyCveVerify(0, '[WRN] No templates provided for scan')).toBe('no_template')
    expect(classifyCveVerify(0, 'could not find templates matching the given id')).toBe('no_template')
  })

  it('is not_reproduced when a template ran but nothing matched', () => {
    expect(classifyCveVerify(0, '[INF] Templates loaded for current scan: 1')).toBe('not_reproduced')
    expect(classifyCveVerify(0, '')).toBe('not_reproduced')
  })

  it('never treats a missing template as not_reproduced (would read as "safe")', () => {
    // A zero-template run must be no_template, not not_reproduced — the latter
    // implies "we checked and it's fine", which is exactly the wrong signal.
    expect(classifyCveVerify(0, 'Templates loaded for current scan: 0')).not.toBe('not_reproduced')
  })
})
