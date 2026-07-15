import { describe, expect, it } from 'vitest'
import { scanDeserialization } from './deser'

const names = (s: string) => scanDeserialization(s).map((h) => h.name)

describe('scanDeserialization', () => {
  it('detects a base64 Java serialized blob (rO0AB…) in a cookie', () => {
    expect(names('session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA')).toContain('Java serialized object')
  })

  it('detects a PHP serialized object', () => {
    expect(names('data=O:4:"User":1:{s:4:"name";s:3:"bob";}')).toContain('PHP serialized object')
  })

  it('detects a .NET ViewState / BinaryFormatter blob', () => {
    expect(names('__VIEWSTATE=%2FwEPDwUK')).toContain('.NET ViewState / BinaryFormatter')
    expect(names('AAEAAAD/////AQAAAAAAAAAM')).toContain('.NET ViewState / BinaryFormatter')
  })

  it('detects a node-serialize payload', () => {
    expect(names('{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\')}"}')).toContain('Node node-serialize payload')
  })

  it('detects Python pickle opcodes', () => {
    expect(names('cposix\nsystem\n(dp0')).toContain('Python pickle')
  })

  it('produces no findings for ordinary data', () => {
    expect(scanDeserialization('user=alice&role=admin&page=2')).toEqual([])
    expect(scanDeserialization('{"id":123,"name":"widget"}')).toEqual([])
  })

  it('is safe on empty input', () => {
    expect(scanDeserialization('')).toEqual([])
  })
})
