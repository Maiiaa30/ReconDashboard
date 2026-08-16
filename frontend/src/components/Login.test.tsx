import axe from 'axe-core'
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Login } from './Login'
import { ToastProvider } from './Toast'

function renderLogin() {
  return render(
    <ToastProvider>
      <Login onSuccess={vi.fn()} />
    </ToastProvider>,
  )
}

async function expectNoAccessibilityViolations(container: HTMLElement) {
  // jsdom has no layout/canvas engine, so contrast requires a real-browser
  // pass. Keep all structural, naming, landmark, and form rules enabled here.
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
  expect(result.violations).toEqual([])
}

describe('login accessibility', () => {
  it('has an accessible initial form', async () => {
    const { container } = renderLogin()
    await expectNoAccessibilityViolations(container)
  })

  it('keeps the optional two-factor flow accessible', async () => {
    const { container } = renderLogin()
    fireEvent.click(screen.getByRole('button', { name: 'I have a 2FA code' }))

    expect(screen.getByRole('textbox', { name: '2FA code' })).toBeInTheDocument()
    await expectNoAccessibilityViolations(container)
  })
})
