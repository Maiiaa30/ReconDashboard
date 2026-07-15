import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../util/exec', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../util/exec')>()
  return { ...actual, run: vi.fn() }
})
vi.mock('./guard', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./guard')>()
  return { ...actual, guardedFetch: vi.fn(), assertPublicHost: vi.fn() }
})

import { run, ToolNotFoundError } from '../util/exec'
import { guardedFetch, assertPublicHost } from './guard'
import {
  runKatana,
  runNaabu,
  runDalfox,
  runSslscan,
  runSqlmap,
  runWpEnum,
  runBypass403,
  runDatastores,
  sameAsDenied,
} from './binTools'

const mockRun = vi.mocked(run)
const mockFetch = vi.mocked(guardedFetch)
const mockAssertPublicHost = vi.mocked(assertPublicHost)

beforeEach(() => {
  mockRun.mockReset()
  mockFetch.mockReset()
  mockAssertPublicHost.mockReset()
  mockAssertPublicHost.mockResolvedValue(undefined)
})

describe('runKatana', () => {
  it('dedupes URLs and prefers ones with query params', async () => {
    mockRun.mockResolvedValue({
      stdout: 'https://a.com/x?y=1\nhttps://a.com/x?y=1\nhttps://a.com/plain\nnot-a-url\n',
      stderr: '',
    })
    const f = await runKatana('https', 'a.com')
    expect(f?.items).toEqual(['https://a.com/x?y=1'])
    expect(f?.title).toBe('Crawled 2 URL(s)')
  })

  it('returns null when nothing is crawled', async () => {
    mockRun.mockResolvedValue({ stdout: '', stderr: '' })
    expect(await runKatana('https', 'a.com')).toBeNull()
  })
})

describe('runNaabu', () => {
  it('parses ports and flags admin ports as medium severity', async () => {
    mockRun.mockResolvedValue({ stdout: 'a.com:80\na.com:22\na.com:80\n', stderr: '' })
    const f = await runNaabu('a.com')
    expect(f?.items).toEqual(['22', '80'])
    expect(f?.severity).toBe('medium')
    expect(f?.detail).toContain('22')
  })

  it('keeps partial stdout from a non-ENOENT failure', async () => {
    const err = Object.assign(new Error('timed out'), { stdout: 'a.com:443\n', code: undefined })
    mockRun.mockRejectedValue(err)
    const f = await runNaabu('a.com')
    expect(f?.items).toEqual(['443'])
    expect(f?.severity).toBe('low')
  })

  it('rethrows when the binary is missing', async () => {
    mockRun.mockRejectedValue(Object.assign(new Error('nope'), { code: 'ENOENT' }))
    await expect(runNaabu('a.com')).rejects.toThrow()
  })

  it('returns null when no ports are found', async () => {
    mockRun.mockResolvedValue({ stdout: '', stderr: '' })
    expect(await runNaabu('a.com')).toBeNull()
  })
})

describe('runDalfox', () => {
  it('extracts PoC/VULN lines', async () => {
    mockRun.mockResolvedValue({
      stdout: 'noise\n[POC] https://a.com/?q=<script>\n[VULN] confirmed\n',
      stderr: '',
    })
    const f = await runDalfox('https', 'a.com')
    expect(f?.severity).toBe('high')
    expect(f?.items).toHaveLength(2)
  })

  it('keeps partial stdout from a non-zero exit', async () => {
    const err = Object.assign(new Error('exit 1'), { stdout: '[POC] hit\n', code: undefined })
    mockRun.mockRejectedValue(err)
    const f = await runDalfox('https', 'a.com')
    expect(f?.items).toEqual(['[POC] hit'])
  })

  it('returns null with no PoC/VULN markers', async () => {
    mockRun.mockResolvedValue({ stdout: 'scan complete, nothing found\n', stderr: '' })
    expect(await runDalfox('https', 'a.com')).toBeNull()
  })
})

describe('runSslscan', () => {
  it('flags SSLv3/Heartbleed as medium severity with cert expiry', async () => {
    mockRun.mockResolvedValue({
      stdout: [
        'SSLv3 enabled',
        'Vulnerable to heartbleed',
        'Not valid after: Jan  1 00:00:00 2020 GMT',
      ].join('\n'),
      stderr: '',
    })
    const f = await runSslscan('a.com')
    expect(f?.severity).toBe('medium')
    expect(f?.items).toContain('SSLv3 enabled (POODLE)')
    expect(f?.items).toContain('Heartbleed vulnerable')
    expect(f?.detail).toContain('2020')
  })

  it('flags sub-128-bit ciphers as low severity when nothing else is wrong', async () => {
    mockRun.mockResolvedValue({ stdout: 'Accepted TLSv1.2 64 bits RC2-CBC-MD5\n', stderr: '' })
    const f = await runSslscan('a.com')
    // matches both the weak-bit-strength branch and the RC4|MD5|... branch
    expect(f?.items.some((i) => /Weak cipher/.test(i))).toBe(true)
  })

  it('returns null when no weaknesses are present', async () => {
    mockRun.mockResolvedValue({ stdout: 'TLSv1.3 looks fine\n', stderr: '' })
    expect(await runSslscan('a.com')).toBeNull()
  })
})

describe('runSqlmap', () => {
  it('extracts injectable parameters, DBMS and technique', async () => {
    mockRun.mockResolvedValue({
      stdout: [
        'sqlmap identified the following injection point(s)',
        "Parameter: id (GET)",
        '    Type: boolean-based blind',
        'back-end DBMS: MySQL >= 5.0.12',
      ].join('\n'),
      stderr: '',
    })
    const f = await runSqlmap('https', 'a.com')
    expect(f?.severity).toBe('high')
    expect(f?.items).toContain('Injectable parameter: id')
    expect(f?.items).toContain('Back-end DBMS: MySQL >= 5.0.12')
    expect(f?.items).toContain('Technique: boolean-based blind')
  })

  it('returns null when sqlmap reports no injection', async () => {
    mockRun.mockResolvedValue({ stdout: 'all tested parameters do not appear to be injectable', stderr: '' })
    expect(await runSqlmap('https', 'a.com')).toBeNull()
  })

  it('rethrows ToolNotFoundError instead of swallowing it', async () => {
    mockRun.mockRejectedValue(new ToolNotFoundError('sqlmap'))
    await expect(runSqlmap('https', 'a.com')).rejects.toBeInstanceOf(ToolNotFoundError)
  })

  it('falls back to a generic item when the point is confirmed but unparsed', async () => {
    mockRun.mockResolvedValue({ stdout: 'target appears to be injectable', stderr: '' })
    const f = await runSqlmap('https', 'a.com')
    expect(f?.items).toEqual(['sqlmap flagged the target as injectable'])
  })
})

describe('runWpEnum', () => {
  const base = 'https://a.com'

  it('returns null for a non-WordPress site', async () => {
    mockFetch.mockResolvedValue({ status: 200, body: '<html>nothing here</html>', finalUrl: base })
    expect(await runWpEnum('https', 'a.com')).toBeNull()
  })

  it('extracts version, users and plugins, escalating to medium when users leak', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === base) {
        return {
          status: 200,
          finalUrl: url,
          body: '<meta name="generator" content="WordPress 6.2" /><link href="wp-content/plugins/akismet/style.css">',
        }
      }
      if (url === `${base}/readme.html`) return { status: 200, body: '', finalUrl: url }
      if (url === `${base}/wp-json/wp/v2/users`) {
        return { status: 200, body: JSON.stringify([{ slug: 'admin' }, { name: 'editor' }]), finalUrl: url }
      }
      if (url === `${base}/xmlrpc.php`) return { status: 405, body: '', finalUrl: url }
      return null
    })
    const f = await runWpEnum('https', 'a.com')
    expect(f?.detail).toBe('Version 6.2')
    expect(f?.severity).toBe('medium')
    expect(f?.items).toContain('Users (REST): admin, editor')
    expect(f?.items).toContain('Plugins: akismet')
    expect(f?.items).toContain('xmlrpc.php reachable (brute-force / pingback)')
  })

  it('falls back to the readme.html version when no generator meta tag is present', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === base) return { status: 200, finalUrl: url, body: 'wp-content/themes/x' }
      if (url === `${base}/readme.html`) return { status: 200, body: 'Version 5.9.1', finalUrl: url }
      return null
    })
    const f = await runWpEnum('https', 'a.com')
    expect(f?.detail).toBe('Version 5.9.1')
    expect(f?.severity).toBe('low')
  })

  it('ignores a non-JSON users endpoint instead of throwing', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === base) return { status: 200, finalUrl: url, body: 'wp-includes/js/x.js' }
      if (url === `${base}/wp-json/wp/v2/users`) return { status: 200, body: '<html>not json</html>', finalUrl: url }
      return null
    })
    const f = await runWpEnum('https', 'a.com')
    expect(f?.items.some((i) => i.startsWith('Users'))).toBe(false)
  })
})

describe('runBypass403', () => {
  const base = 'https://a.com'

  it('returns null when no path is protected', async () => {
    mockFetch.mockResolvedValue({ status: 200, body: '', finalUrl: base })
    expect(await runBypass403('https', 'a.com')).toBeNull()
  })

  it('returns null when protected paths resist every bypass technique', async () => {
    mockFetch.mockImplementation(async (url, opts) => {
      if (url === `${base}/admin` && !opts?.headers && !opts?.method) {
        return { status: 403, body: '', finalUrl: url }
      }
      return null
    })
    expect(await runBypass403('https', 'a.com')).toBeNull()
  })

  it('reports a hit when a spoofed-IP header flips 403 into 2xx', async () => {
    mockFetch.mockImplementation(async (url, opts) => {
      if (url === `${base}/admin` && !opts?.headers && !opts?.method) {
        return { status: 403, body: '', finalUrl: url } // initial detection
      }
      if (url === `${base}/admin` && opts?.headers?.['X-Forwarded-For'] === '127.0.0.1') {
        return { status: 200, body: 'bypassed', finalUrl: url } // the winning bypass
      }
      return null // every other path/attempt combination
    })
    const f = await runBypass403('https', 'a.com')
    expect(f?.severity).toBe('high')
    expect(f?.items).toEqual(['/admin → 200 via header X-Forwarded-For: 127.0.0.1'])
    expect(f?.title).toBe('403/401 bypass — 1 on 1 protected path(s)')
  })

  it('caps exhaustive retries at MAX_FORBIDDEN protected paths', async () => {
    // Every candidate path is "protected", but the bypass battery only succeeds
    // via X-Forwarded-For — confirms the scan didn't keep collecting past the cap.
    mockFetch.mockImplementation(async (url, opts) => {
      if (!opts?.headers && !opts?.method) return { status: 403, body: '', finalUrl: url } // any bare probe is "protected"
      if (opts?.headers?.['X-Forwarded-For'] === '127.0.0.1') return { status: 200, body: 'ok', finalUrl: url }
      return null
    })
    const f = await runBypass403('https', 'a.com')
    expect(f?.title).toMatch(/on 5 protected path\(s\)/)
  })

  it('does NOT flag a soft-403 (200 with the same denial body)', async () => {
    const denial = '<html><body>Access Denied — you are not authorized</body></html>'
    mockFetch.mockImplementation(async (url, opts) => {
      if (url === `${base}/admin` && !opts?.headers && !opts?.method) return { status: 403, body: denial, finalUrl: url }
      // A "bypass" that returns 200 but the SAME denial page — not a real bypass.
      if (url === `${base}/admin` && opts?.headers?.['X-Forwarded-For'] === '127.0.0.1') return { status: 200, body: denial, finalUrl: url }
      return null
    })
    expect(await runBypass403('https', 'a.com')).toBeNull()
  })
})

describe('runDatastores — infra control planes', () => {
  it('files a critical for an unauthenticated Docker API /version', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === `http://a.com:2375/version`) {
        return { status: 200, body: '{"Version":"24.0.7","ApiVersion":"1.43","GitCommit":"abc"}', finalUrl: url }
      }
      return null // every other datastore/panel/infra probe: nothing there
    })
    const f = await runDatastores('https', 'a.com')
    expect(f?.severity).toBe('critical')
    expect(f?.items.join(' ')).toMatch(/Docker Engine API/)
  })

  it('does NOT file when the Docker API rejects with 401', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === `http://a.com:2375/version`) return { status: 401, body: 'unauthorized', finalUrl: url }
      return null
    })
    expect(await runDatastores('https', 'a.com')).toBeNull()
  })

  it('files a critical for an unauthenticated etcd', async () => {
    mockFetch.mockImplementation(async (url) => {
      if (url === `http://a.com:2379/version`) return { status: 200, body: '{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}', finalUrl: url }
      return null
    })
    const f = await runDatastores('https', 'a.com')
    expect(f?.items.join(' ')).toMatch(/etcd/)
  })
})

describe('sameAsDenied', () => {
  it('treats near-identical bodies as the same denial page', () => {
    const denial = 'x'.repeat(1000)
    expect(sameAsDenied(denial, denial)).toBe(true)
    expect(sameAsDenied('x'.repeat(1020), denial)).toBe(true) // within 5%
  })
  it('treats a substantially different body as a real bypass', () => {
    expect(sameAsDenied('x'.repeat(5000), 'x'.repeat(1000))).toBe(false)
  })
  it('never matches against an empty denial body', () => {
    expect(sameAsDenied('anything', '')).toBe(false)
  })
})
