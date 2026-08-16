import { describe, expect, it } from 'vitest'
import { MODULE_INDEX, NAV_SECTIONS, readExpandedSections, sectionForModule } from './navigation'

describe('progressive navigation', () => {
  it('keeps the core operator workflow permanently visible', () => {
    const workflow = NAV_SECTIONS.find((section) => section.primary)

    expect(workflow?.title).toBe('Workflow')
    expect(workflow?.items.map((item) => item.key)).toEqual([
      'home', 'command', 'actions', 'domains', 'assets', 'runs', 'findings', 'reports',
    ])
  })

  it('keeps every specialist module available to command search', () => {
    const keys = MODULE_INDEX.map((item) => item.key)

    expect(new Set(keys).size).toBe(keys.length)
    expect(keys).toContain('profiles')
    expect(keys).toContain('replay')
    expect(keys).toContain('settings')
  })

  it('restores only recognized collapsible sections', () => {
    expect([...readExpandedSections('["Testing","System","Unknown","Workflow"]')]).toEqual(['Testing', 'System'])
    expect(readExpandedSections('not-json').size).toBe(0)
  })

  it('finds the section containing a contextual destination', () => {
    expect(sectionForModule('profiles')?.title).toBe('Testing')
    expect(sectionForModule('changes')?.title).toBe('Workspace')
  })
})
