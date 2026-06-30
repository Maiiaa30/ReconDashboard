import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Me } from './api'
import { Login } from './components/Login'
import { Shell } from './components/Shell'
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
      <div className="min-h-full flex items-center justify-center bg-zinc-950 text-zinc-500 text-sm">
        Loading…
      </div>
    )
  }

  if (auth.status === 'anon') {
    return <Login onSuccess={refresh} />
  }

  return (
    <AppProvider>
      <Shell me={auth.me} onLogout={() => setAuth({ status: 'anon' })} />
    </AppProvider>
  )
}
