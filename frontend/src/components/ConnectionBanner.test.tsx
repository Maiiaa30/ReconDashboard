import { afterEach, describe, expect, it } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { ConnectionBanner } from './ConnectionBanner'
import { markOffline, markOnline, resetConnection } from '../api/connection'

describe('ConnectionBanner', () => {
  afterEach(() => resetConnection())

  it('stays hidden while the backend is reachable', () => {
    render(<ConnectionBanner />)
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('appears when the connection drops and clears when it recovers', () => {
    render(<ConnectionBanner />)

    act(() => markOffline())
    expect(screen.getByRole('status')).toHaveTextContent(/connection lost/i)

    act(() => markOnline())
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('reacts to the browser offline event', () => {
    render(<ConnectionBanner />)
    act(() => window.dispatchEvent(new Event('offline')))
    expect(screen.getByRole('status')).toHaveTextContent(/unreachable/i)
  })
})
