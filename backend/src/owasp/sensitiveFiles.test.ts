import { describe, expect, it } from 'vitest'
import { SENSITIVE_FILES } from './activeChecks'

const sigOf = (path: string) => SENSITIVE_FILES.find((f) => f.path === path)!.signatures
const matches = (path: string, body: string) => sigOf(path).some((re) => re.test(body))

describe('SENSITIVE_FILES signatures', () => {
  it('.DS_Store matches the Bud1 magic but NOT arbitrary binary (FP fix)', () => {
    expect(matches('/.DS_Store', '\x00\x00\x00\x01Bud1\x00\x00\x00')).toBe(true)
    // Previously the `\x00\x00\x00` alternative flagged most binaries — no longer.
    expect(matches('/.DS_Store', '\x00\x00\x00\x00\x01\x02\x03random-binary')).toBe(false)
  })

  it('id_rsa matches a private-key PEM header', () => {
    expect(matches('/id_rsa', '-----BEGIN OPENSSH PRIVATE KEY-----\nabc')).toBe(true)
    expect(matches('/id_rsa', '<html>not a key</html>')).toBe(false)
  })

  it('terraform state matches a tfstate JSON', () => {
    expect(matches('/.terraform/terraform.tfstate', '{\n  "terraform_version": "1.5.0",\n  "serial": 3')).toBe(true)
  })

  it('.git reflog matches the reflog line format', () => {
    const line = `${'0'.repeat(40)} ${'a'.repeat(40)} Dev <d@x.io> 1700000000 +0000\tcommit`
    expect(matches('/.git/logs/HEAD', line)).toBe(true)
  })

  it('web.config matches IIS config XML', () => {
    expect(matches('/web.config', '<configuration>\n <connectionStrings>')).toBe(true)
  })

  it('appsettings.json matches a .NET config with a connection string', () => {
    expect(matches('/appsettings.json', '{ "ConnectionStrings": { "DefaultConnection": "..." } }')).toBe(true)
  })
})
