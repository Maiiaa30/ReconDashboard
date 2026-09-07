import { apiError, get, readResponseBody, type RequestOptions } from './http'
import { metaStatusSchema } from './schemas'

// MetaStatus and Wordlist are defined by their zod schema (single source of
// truth) and re-exported so call sites import them unchanged.
export type { MetaStatus, Wordlist } from './schemas'

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
  meta: (options?: RequestOptions) => get('/meta/status', options, metaStatusSchema),
  backupStatus: () => get<{ serverPassphraseConfigured: boolean }>('/backup/status'),
  backupVerify: (blob: Blob, passphrase?: string) => uploadBackup('/backup/verify', blob, passphrase),
  backupRestore: (blob: Blob, passphrase: string | undefined, reauth: { password: string; token?: string }) =>
    uploadBackup('/backup/restore', blob, passphrase, reauth),
}
