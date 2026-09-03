import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type Me } from './api'
import { clearSessionExpired, subscribeConnection } from './api/connection'
import { Login } from './components/Login'
import { Shell } from './components/Shell'
import { ConnectionBanner } from './components/ConnectionBanner'
import { ToastProvider } from './components/Toast'
import { ConfirmProvider } from './components/Confirm'
import { AppProvider } from './state'

type AuthState =
  | { status: 'loading' }
  | { status: 'authed'; me: Me }
  | { status: 'anon' }

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ status: 'loading' })
  // Set when an authenticated session drops (a 401 from any background request),
  // so the login screen can explain why the operator was sent back.
  const [sessionExpired, setSessionExpired] = useState(false)

  // Mirror auth status so the connection subscriber can tell a genuine mid-
  // session expiry from the initial anonymous `api.me()` probe.
  const authRef = useRef<AuthState>(auth)
  useEffect(() => {
    authRef.current = auth
  }, [auth])

  const refresh = useCallback(async () => {
    try {
      const me = await api.me()
      setSessionExpired(false)
      setAuth({ status: 'authed', me })
    } catch {
      // A 401 (not signed in) or an unreachable backend both land on the login
      // screen; the connection banner covers the unreachable case separately.
      setAuth({ status: 'anon' })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // Any 401 from a background request expires an authenticated session: route
  // back to the login screen and say why. The initial anonymous probe also
  // trips this signal, so only react when we were actually authed.
  useEffect(
    () =>
      subscribeConnection((state) => {
        if (!state.sessionExpired) return
        clearSessionExpired()
        if (authRef.current.status === 'authed') {
          setSessionExpired(true)
          setAuth({ status: 'anon' })
        }
      }),
    [],
  )

  if (auth.status === 'loading') {
    return (
      <div className="min-h-full flex items-center justify-center bg-ink-950 text-zinc-400 text-sm">
        Loading…
      </div>
    )
  }

  return (
    <ToastProvider>
      <ConfirmProvider>
        <ConnectionBanner />
        {auth.status === 'anon' ? (
          <Login onSuccess={refresh} sessionExpired={sessionExpired} />
        ) : (
          <AppProvider>
            <Shell me={auth.me} onLogout={() => setAuth({ status: 'anon' })} />
          </AppProvider>
        )}
      </ConfirmProvider>
    </ToastProvider>
  )
}
