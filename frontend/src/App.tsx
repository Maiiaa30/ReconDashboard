import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Me } from './api'
import { Login } from './components/Login'
import { Shell } from './components/Shell'
import { ToastProvider } from './components/Toast'
import { ConfirmProvider } from './components/Confirm'
import { AppProvider } from './state'

type AuthState =
  | { status: 'loading' }
  | { status: 'authed'; me: Me }
  | { status: 'anon' }

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ status: 'loading' })

  const refresh = useCallback(async () => {
    try {
      const me = await api.me()
      setAuth({ status: 'authed', me })
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setAuth({ status: 'anon' })
      } else {
        // Backend unreachable etc. — treat as anon so the login screen shows.
        setAuth({ status: 'anon' })
      }
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

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
        {auth.status === 'anon' ? (
          <Login onSuccess={refresh} />
        ) : (
          <AppProvider>
            <Shell me={auth.me} onLogout={() => setAuth({ status: 'anon' })} />
          </AppProvider>
        )}
      </ConfirmProvider>
    </ToastProvider>
  )
}
