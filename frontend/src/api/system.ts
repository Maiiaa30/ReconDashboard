import { apiError, get, readResponseBody, type RequestOptions } from './http'

export interface Wordlist {
  path: string
  name: string
  sizeKb: number
  category?: 'payload' | 'content'
}

export interface MetaStatus {
  scorer: string
  aiProvider: string
  scheduler: { enabled: boolean; intervalMinutes: number }
  discordConfigured: boolean
  llm?: { enabled: boolean; model: string | null }
  leaks?: { enabled: boolean; provider: string | null }
  tools: {
    subfinder: boolean
    nmap: boolean
    nuclei: boolean
    ffuf: boolean
    chromium: boolean
    dig: boolean
    katana?: boolean
    naabu?: boolean
    dalfox?: boolean
    dnsx?: boolean
    httpx?: boolean
    sslscan?: boolean
    sqlmap?: boolean
    wpenum?: boolean
    bypass403?: boolean
    methods?: boolean
    datastores?: boolean
  }
  wordlists: Wordlist[]
  readiness: {
    checkedAt: number
    database: { ok: boolean; sizeBytes: number }
    storage: { freeBytes: number | null }
    worker: {
      running: boolean
      startedAt: number | null
      lastTickAt: number | null
      lanes: { passive: boolean; loud: boolean }
    }
    queue: { queued: number; running: number; failed: number; lastActivityAt: number | null }
    capture: { enabled: boolean; extensionSeenAt: number | null }
    backup: { serverPassphraseConfigured: boolean }
  }
}

export interface BackupCheckResult {
  ok: boolean
  error?: string
  bytes?: number
  staged?: boolean
  restartRequired?: boolean
  message?: string
}

async function uploadBackup(
  path: string,
  blob: Blob,
  passphrase?: string,
  reauth?: { password: string; token?: string },
): Promise<BackupCheckResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
  if (passphrase) headers['X-Backup-Passphrase'] = passphrase
  if (reauth?.password) headers['X-Reauth-Password'] = reauth.password
  if (reauth?.token) headers['X-Reauth-Token'] = reauth.token
  const response = await fetch(`/api${path}`, { method: 'POST', headers, body: blob })
  const body = await readResponseBody(response)
  // Verification uses 422 for a well-formed negative result, so callers can
  // render its structured explanation without treating it as a transport error.
  if (!response.ok && response.status !== 422) throw apiError(response, body)
  return body as BackupCheckResult
}

export const systemApi = {
  meta: (options?: RequestOptions) => get<MetaStatus>('/meta/status', options),
  backupStatus: () => get<{ serverPassphraseConfigured: boolean }>('/backup/status'),
  backupVerify: (blob: Blob, passphrase?: string) => uploadBackup('/backup/verify', blob, passphrase),
  backupRestore: (blob: Blob, passphrase: string | undefined, reauth: { password: string; token?: string }) =>
    uploadBackup('/backup/restore', blob, passphrase, reauth),
}
