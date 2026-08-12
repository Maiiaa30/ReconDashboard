import { describe, expect, it } from 'vitest'
import { BUILTIN_PAYLOAD_SETS } from './builtins'

const set = (id: string) => BUILTIN_PAYLOAD_SETS.find((item) => item.id === id)

describe('offensive payload library', () => {
  it('includes the required deep payload categories', () => {
    for (const id of ['xxe', 'crlf', 'log4shell', 'mass-assignment', 'prototype-pollution']) {
      expect(set(id)?.payloads.length).toBeGreaterThan(0)
    }
  })

  it('includes Azure IMDS and its required header note', () => {
    const payloadSet = set('ssrf')
    const ssrf = [...(payloadSet?.payloads ?? []), ...(payloadSet?.notes ?? [])].join('\n')
    expect(ssrf).toContain('/metadata/instance')
    expect(ssrf).toMatch(/Metadata:\s*true/i)
  })
})
