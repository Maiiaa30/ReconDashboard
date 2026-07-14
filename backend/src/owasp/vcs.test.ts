import { describe, expect, it } from 'vitest'
import { gitTriadComplete } from './vcs'

describe('gitTriadComplete', () => {
  it('is true only when HEAD, config and index are all present', () => {
    expect(gitTriadComplete(['head', 'config', 'index'])).toBe(true)
    expect(gitTriadComplete(['index', 'config', 'head'])).toBe(true) // order-independent
  })

  it('is false for a partial exposure', () => {
    expect(gitTriadComplete(['head'])).toBe(false)
    expect(gitTriadComplete(['head', 'config'])).toBe(false)
    expect(gitTriadComplete([])).toBe(false)
  })

  it('ignores duplicates', () => {
    expect(gitTriadComplete(['head', 'head', 'config', 'index', 'index'])).toBe(true)
  })
})
