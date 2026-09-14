import type { ReactNode } from 'react'
import { render } from '@testing-library/react'
import axe from 'axe-core'
import { expect } from 'vitest'
import { AppProvider } from '../state'
import { ToastProvider } from '../components/Toast'
import { ConfirmProvider } from '../components/Confirm'

// Render a workspace page the way the Shell does: inside the app-state, toast and
// confirm providers, and wrapped in a <main> landmark. Mirroring the real
// landmark matters for the axe sweep - otherwise the "region" (best-practice)
// rule would flag the page content as living outside any landmark, which is an
// artefact of rendering the page in isolation, not a real defect.
//
// The `../api` module MUST be mocked by the test file (vi.mock) before using
// this, because AppProvider loads domains + the saved selection on mount.
export function renderPage(ui: ReactNode) {
  return render(
    <ToastProvider>
      <ConfirmProvider>
        <AppProvider>
          <main>{ui}</main>
        </AppProvider>
      </ConfirmProvider>
    </ToastProvider>,
  )
}

// jsdom has no layout or canvas engine, so colour contrast can only be judged in a
// real browser; every other structural, naming, landmark and role rule stays on.
export async function expectNoAxeViolations(container: HTMLElement) {
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })
  expect(result.violations).toEqual([])
}
