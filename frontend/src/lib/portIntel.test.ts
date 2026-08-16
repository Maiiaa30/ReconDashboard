import { describe, expect, it } from 'vitest'
import { classifyPort, isNotablePort, riskTone } from './portIntel'

describe('port intelligence', () => {
  it('classifies high-risk exposed services', () => {
    expect(classifyPort(6379)).toMatchObject({ label: 'Redis', category: 'database', risk: 'high' })
    expect(isNotablePort(6379)).toBe(true)
    expect(riskTone('high')).toBe('red')
  })

  it('does not promote ordinary web ports as notable', () => {
    expect(classifyPort(443)?.category).toBe('web')
    expect(isNotablePort(443)).toBe(false)
    expect(classifyPort(65535)).toBeNull()
  })
})
