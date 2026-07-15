// Insecure-deserialization marker scan — pure, zero target traffic. Serialized
// object blobs in cookies / params / captured requests are a strong insecure-
// deserialization (gadget-chain / RCE) signal. This looks for each runtime's
// distinctive serialization header in data the tool already holds. High-confidence
// markers only (this is needs-review, but false positives waste operator time).

export interface DeserHit {
  name: string
  sample: string
}

const MARKERS: { name: string; re: RegExp }[] = [
  // Java serialization: raw header 0xAC 0xED, or its base64 form "rO0AB".
  { name: 'Java serialized object', re: /rO0AB[A-Za-z0-9+/]{4,}|\xac\xed\x00\x05/ },
  // PHP serialize(): O:<len>:"<class>":<n>:{ …
  { name: 'PHP serialized object', re: /O:\d+:"[A-Za-z0-9_\\]{1,80}":\d+:\{/ },
  // .NET: ViewState field or a base64 BinaryFormatter header (AAEAAAD////).
  { name: '.NET ViewState / BinaryFormatter', re: /__VIEWSTATE|AAEAAAD\/{4}/ },
  // node-serialize IIFE marker (CVE-2017-5941 territory).
  { name: 'Node node-serialize payload', re: /_\$\$ND_FUNC\$\$_/ },
  // Python pickle opcodes / global references.
  { name: 'Python pickle', re: /c__builtin__\n|c__main__\n|\(dp\d|\(lp\d/ },
  // Ruby Marshal base64 header ("BAg" = \x04\x08) followed by a type char.
  { name: 'Ruby Marshal', re: /\x04\x08[\x30-\x7a]|BAg[A-Za-z]{2}/ },
]

export function scanDeserialization(text: string): DeserHit[] {
  if (!text) return []
  const out: DeserHit[] = []
  for (const m of MARKERS) {
    const hit = m.re.exec(text)
    if (hit) out.push({ name: m.name, sample: hit[0].slice(0, 60) })
  }
  return out
}
