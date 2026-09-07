import axe from 'axe-core'
import { fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { Tabs } from './Tabs'

type K = 'a' | 'b' | 'c'
const ITEMS = [
  { key: 'a' as K, label: 'Alpha' },
  { key: 'b' as K, label: 'Beta' },
  { key: 'c' as K, label: 'Gamma' },
]

function Harness() {
  const [value, setValue] = useState<K>('a')
  return <Tabs label="Test tabs" items={ITEMS} value={value} onChange={setValue} />
}

describe('Tabs (WAI-ARIA tab pattern)', () => {
  it('exposes a labelled tablist with roving tabindex and aria-selected', () => {
    render(<Harness />)
    const list = screen.getByRole('tablist', { name: 'Test tabs' })
    expect(list).toBeInTheDocument()
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(3)
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveAttribute('tabindex', '0')
    expect(tabs[1]).toHaveAttribute('tabindex', '-1')
  })

  it('moves selection with Arrow keys and wraps, and Home/End jump to ends', () => {
    render(<Harness />)
    const tabs = () => screen.getAllByRole('tab')
    tabs()[0].focus()
    fireEvent.keyDown(tabs()[0], { key: 'ArrowRight' })
    expect(tabs()[1]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(tabs()[1], { key: 'ArrowLeft' })
    expect(tabs()[0]).toHaveAttribute('aria-selected', 'true')
    // wrap left from the first → last
    fireEvent.keyDown(tabs()[0], { key: 'ArrowLeft' })
    expect(tabs()[2]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(tabs()[2], { key: 'Home' })
    expect(tabs()[0]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(tabs()[0], { key: 'End' })
    expect(tabs()[2]).toHaveAttribute('aria-selected', 'true')
  })

  it('selects on click', () => {
    render(<Harness />)
    fireEvent.click(screen.getByRole('tab', { name: 'Beta' }))
    expect(screen.getByRole('tab', { name: 'Beta' })).toHaveAttribute('aria-selected', 'true')
  })

  it('has no axe violations', async () => {
    const { container } = render(<Harness />)
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
    expect(result.violations).toEqual([])
  })
})
