import { describe, expect, it } from 'vitest'
import { buildAppRoute, parseAppRoute, routeDomain } from './appRoute'

describe('application routes', () => {
  it('round-trips global and engagement workspaces', () => {
    expect(parseAppRoute(buildAppRoute('home'))).toEqual({ page: 'home' })
    expect(parseAppRoute(buildAppRoute('findings', 42))).toEqual({ page: 'findings', domainId: 42 })
    expect(parseAppRoute(buildAppRoute('audit'))).toEqual({ page: 'audit' })
  })

  it('rejects unknown pages and invalid engagement ids', () => {
    expect(parseAppRoute('/unknown')).toBeNull()
    expect(parseAppRoute('/engagements/0/findings')).toBeNull()
    expect(parseAppRoute('/engagements/not-a-number/findings')).toBeNull()
  })

  it('carries the selected target only for target-scoped pages', () => {
    expect(routeDomain('command', undefined, 7)).toBe(7)
    expect(routeDomain('audit', undefined, 7)).toBeUndefined()
    expect(routeDomain('domains', 9, 7)).toBe(9)
  })
})
