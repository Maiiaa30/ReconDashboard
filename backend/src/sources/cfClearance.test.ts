import { createCipheriv, pbkdf2Sync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { describe, expect, it } from 'vitest'
import { decryptCookieValue, readClearanceCookies } from './cfClearance'

const KEY = pbkdf2Sync('peanuts', 'saltysalt', 1, 16, 'sha1')
const IV = Buffer.alloc(16, ' ')

// Encrypt like Linux headless Chromium (v10, no keyring): AES-128-CBC + 'v10' tag.
function encryptV10(plain: Buffer): Buffer {
  const c = createCipheriv('aes-128-cbc', KEY, IV)
  return Buffer.concat([Buffer.from('v10'), c.update(plain), c.final()])
}

describe('decryptCookieValue', () => {
  it('round-trips a v10 cookie', () => {
    expect(decryptCookieValue(encryptV10(Buffer.from('abcTOKEN123.xyz')))).toBe('abcTOKEN123.xyz')
  })

  it('strips the 32-byte domain-hash prefix (Chrome M124+)', () => {
    const hashPrefix = Buffer.alloc(32, 0x01) // binary, non-printable leading byte
    expect(decryptCookieValue(encryptV10(Buffer.concat([hashPrefix, Buffer.from('realvalue')])))).toBe('realvalue')
  })

  it('rejects a v11 (keyring) blob it cannot decrypt', () => {
    expect(decryptCookieValue(Buffer.concat([Buffer.from('v11'), Buffer.alloc(16)]))).toBeNull()
  })
})

describe('readClearanceCookies', () => {
  function makeDb(rows: { name: string; host: string; value: string }[]): string {
    const dir = mkdtempSync(join(tmpdir(), 'cf-cookies-'))
    const path = join(dir, 'Cookies')
    const db = new Database(path)
    db.exec('CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB)')
    const ins = db.prepare('INSERT INTO cookies (host_key, name, encrypted_value) VALUES (?, ?, ?)')
    for (const r of rows) ins.run(r.host, r.name, encryptV10(Buffer.from(r.value)))
    db.close()
    return path
  }

  it('builds a cookie header from cf_clearance (+__cf_bm) for the host', () => {
    const path = makeDb([
      { name: 'cf_clearance', host: '.example.com', value: 'CLR' },
      { name: '__cf_bm', host: '.example.com', value: 'BM' },
    ])
    expect(readClearanceCookies(path, 'app.example.com')).toBe('cf_clearance=CLR; __cf_bm=BM')
  })

  it('returns null when cf_clearance is absent', () => {
    const path = makeDb([{ name: '__cf_bm', host: '.example.com', value: 'BM' }])
    expect(readClearanceCookies(path, 'example.com')).toBeNull()
  })
})
