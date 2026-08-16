import { describe, expect, it } from 'vitest'
import { MODULES } from './navigation'
import { PAGE_KEYS } from './PageContent'

describe('page workspace registry', () => {
  it('renders every routable module exactly once', () => {
    const moduleKeys = MODULES.map((module) => module.key).sort()
    const pageKeys = [...PAGE_KEYS].sort()

    expect(new Set(pageKeys).size).toBe(pageKeys.length)
    expect(pageKeys).toEqual(moduleKeys)
  })
})
