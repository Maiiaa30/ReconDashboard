// MurmurHash3 x86 32-bit — the algorithm Shodan / favicon-hash use to correlate
// assets by their favicon (identical icons hash identically across different IPs,
// so they survive CDN fronting). Matches Python's mmh3.hash (signed 32-bit).

export function murmur3_32(data: Buffer, seed = 0): number {
  const c1 = 0xcc9e2d51
  const c2 = 0x1b873593
  let h1 = seed | 0
  const len = data.length
  const nblocks = len >> 2

  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readUInt32LE(i * 4)
    k1 = Math.imul(k1, c1)
    k1 = (k1 << 15) | (k1 >>> 17)
    k1 = Math.imul(k1, c2)
    h1 ^= k1
    h1 = (h1 << 13) | (h1 >>> 19)
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0
  }

  let k1 = 0
  const tail = nblocks * 4
  switch (len & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16
    // falls through
    case 2:
      k1 ^= data[tail + 1] << 8
    // falls through
    case 1:
      k1 ^= data[tail]
      k1 = Math.imul(k1, c1)
      k1 = (k1 << 15) | (k1 >>> 17)
      k1 = Math.imul(k1, c2)
      h1 ^= k1
  }

  h1 ^= len
  h1 ^= h1 >>> 16
  h1 = Math.imul(h1, 0x85ebca6b)
  h1 ^= h1 >>> 13
  h1 = Math.imul(h1, 0xc2b2ae35)
  h1 ^= h1 >>> 16
  return h1 | 0 // signed 32-bit, like mmh3.hash
}

// Shodan-style favicon hash: mmh3.hash(base64.encodebytes(bytes)). Python's
// encodebytes wraps base64 at 76 chars per line with a trailing newline — the
// hash is over that exact byte layout, so we reproduce it.
export function faviconHash(iconBytes: Buffer): number {
  const b64 = iconBytes.toString('base64')
  const wrapped = `${(b64.match(/.{1,76}/g) ?? []).join('\n')}\n`
  return murmur3_32(Buffer.from(wrapped, 'utf8'))
}
