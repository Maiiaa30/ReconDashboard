import { afterEach, describe, expect, it, vi } from 'vitest'
import { systemApi } from './system'

describe('system API client', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('sends backup verification as a protected binary upload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({ ok: false, error: 'invalid backup' }),
    } as Response)
    vi.stubGlobal('fetch', fetchMock)
    const blob = new Blob(['backup'])

    await expect(systemApi.backupVerify(blob, 'long-passphrase')).resolves.toEqual({ ok: false, error: 'invalid backup' })
    expect(fetchMock).toHaveBeenCalledWith('/api/backup/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Backup-Passphrase': 'long-passphrase',
      },
      body: blob,
    })
  })
})
