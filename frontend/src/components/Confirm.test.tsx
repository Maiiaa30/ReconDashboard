import axe from 'axe-core'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { ConfirmProvider, useConfirm } from './Confirm'

// A harness that opens the dialog and records its boolean result, so the
// promise-based API can be driven from a test.
function Harness() {
  const confirm = useConfirm()
  const [result, setResult] = useState('')
  return (
    <>
      <button onClick={async () => setResult(String(await confirm({ title: 'Delete it?', message: 'This cannot be undone.', tone: 'danger' })))}>open</button>
      <span data-testid="result">{result}</span>
    </>
  )
}

function open() {
  const utils = render(
    <ConfirmProvider>
      <Harness />
    </ConfirmProvider>,
  )
  // Focus the trigger first: real browsers focus a button on click (jsdom's
  // fireEvent.click does not), and the dialog restores focus to it on close.
  const trigger = screen.getByRole('button', { name: 'open' })
  trigger.focus()
  fireEvent.click(trigger)
  return utils
}

describe('Confirm dialog accessibility', () => {
  it('exposes a labelled, described modal and focuses the confirm button', () => {
    open()
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    // Title + message are wired as the accessible name/description.
    expect(dialog).toHaveAccessibleName('Delete it?')
    expect(dialog).toHaveAccessibleDescription('This cannot be undone.')
    expect(screen.getByRole('button', { name: 'Confirm' })).toHaveFocus()
  })

  it('has no axe violations', async () => {
    const { container } = open()
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
    expect(result.violations).toEqual([])
  })

  it('traps Tab within the dialog', () => {
    open()
    const confirmBtn = screen.getByRole('button', { name: 'Confirm' })
    const cancelBtn = screen.getByRole('button', { name: 'Cancel' })
    confirmBtn.focus()
    // Tab off the last control wraps to the first.
    fireEvent.keyDown(confirmBtn, { key: 'Tab' })
    expect(cancelBtn).toHaveFocus()
    // Shift+Tab off the first wraps to the last.
    fireEvent.keyDown(cancelBtn, { key: 'Tab', shiftKey: true })
    expect(confirmBtn).toHaveFocus()
  })

  it('Escape cancels (resolves false) and restores focus to the trigger', async () => {
    open()
    fireEvent.keyDown(document.body, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
    expect(screen.getByTestId('result')).toHaveTextContent('false')
    expect(screen.getByRole('button', { name: 'open' })).toHaveFocus()
  })

  it('confirming resolves true', async () => {
    open()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('true'))
  })
})
