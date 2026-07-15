import { describe, expect, it } from 'vitest'
import { clusterBySignature } from './correlate'

describe('clusterBySignature', () => {
  it('clusters hosts sharing a cert fingerprint across DIFFERENT IPs', () => {
    const clusters = clusterBySignature([
      { host: 'a.t.com', ip: '1.1.1.1', certFp: 'AA:BB' },
      { host: 'b.t.com', ip: '2.2.2.2', certFp: 'AA:BB' }, // same cert, different IP
      { host: 'c.t.com', ip: '3.3.3.3', certFp: 'ZZ:ZZ' },
    ])
    const cert = clusters.find((c) => c.kind === 'cert' && c.signature === 'AA:BB')
    expect(cert).toBeTruthy()
    expect(cert!.hosts.sort()).toEqual(['a.t.com', 'b.t.com'])
    expect(cert!.ips.sort()).toEqual(['1.1.1.1', '2.2.2.2']) // cross-IP
  })

  it('clusters hosts sharing a favicon hash', () => {
    const clusters = clusterBySignature([
      { host: 'x.t.com', ip: '1.1.1.1', faviconHash: 116323821 },
      { host: 'y.t.com', ip: '9.9.9.9', faviconHash: 116323821 },
    ])
    const fav = clusters.find((c) => c.kind === 'favicon')
    expect(fav?.hosts.sort()).toEqual(['x.t.com', 'y.t.com'])
  })

  it('does NOT cluster a signature unique to one host', () => {
    const clusters = clusterBySignature([
      { host: 'only.t.com', certFp: 'UNIQUE', faviconHash: 42 },
      { host: 'other.t.com', certFp: 'DIFFERENT' },
    ])
    expect(clusters).toEqual([])
  })

  it('ignores null/absent signatures', () => {
    const clusters = clusterBySignature([
      { host: 'a.t.com', certFp: null, faviconHash: null },
      { host: 'b.t.com' },
    ])
    expect(clusters).toEqual([])
  })

  it('sorts larger clusters first', () => {
    const clusters = clusterBySignature([
      { host: 'a', faviconHash: 1 },
      { host: 'b', faviconHash: 1 },
      { host: 'c', faviconHash: 1 },
      { host: 'd', certFp: 'x' },
      { host: 'e', certFp: 'x' },
    ])
    expect(clusters[0].hosts.length).toBe(3)
  })
})
