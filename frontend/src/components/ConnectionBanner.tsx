import { useEffect, useSyncExternalStore } from 'react'
import { WifiOff } from 'lucide-react'
import { getConnection, markOffline, subscribeConnection, type ConnectionState } from '../api/connection'

export function useConnection(): ConnectionState {
  const state = useSyncExternalStore(subscribeConnection, getConnection, getConnection)

  useEffect(() => {
    // The browser knows immediately when the NIC/Wi-Fi drops; reflect it at once
    // instead of waiting for the next poll to fail. A regained browser
    // connection is only optimistic (the backend/tailnet may still be down), so
    // recovery is left to the next successful request marking us online.
    const onOffline = () => markOffline()
    window.addEventListener('offline', onOffline)
    return () => window.removeEventListener('offline', onOffline)
  }, [])

  return state
}

// Fixed top strip shown whenever the backend is unreachable. Visible on both the
// login screen and the authenticated shell.
export function ConnectionBanner() {
  const { online } = useConnection()
  if (online) return null
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed inset-x-0 top-0 z-[100] flex items-center justify-center gap-2 bg-amber-500/95 px-4 py-1.5 text-center text-xs font-medium text-amber-950 shadow-md"
    >
      <WifiOff size={14} aria-hidden />
      <span>Connection lost - the backend is unreachable. Retrying automatically…</span>
    </div>
  )
}
