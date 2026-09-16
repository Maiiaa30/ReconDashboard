// Maps a detected WAF brand to a sqlmap `--tamper` chain that tends to slip that
// vendor's signature engine, plus a suggested request delay for rate-based rules.
//
// These are STARTING POINTS, not guarantees — tamper effectiveness is empirical
// and WAF rules change. The chains use only stock sqlmap tamper scripts (shipped
// with the binary), so no custom scripts are needed. Order within a chain does
// not matter: sqlmap sorts tampers by their declared priority at runtime.
//
// Brands are matched by keyword against whatever label we have — either our
// header-based `detectWaf` slug (cloudflare/akamai/imperva/…) or a richer
// wafw00f identification ("Cloudflare (Cloudflare Inc.)"), so both feed the same
// table via a lowercase substring match.

export interface TamperPreset {
  // Comma-separated stock sqlmap tamper scripts.
  tamper: string
  // Seconds between requests. Cloud WAFs with aggressive rate rules get a small
  // delay; most get 0 (the operator can still override in the UI).
  delay: number
  // Human label for the UI, so the operator sees why this chain was chosen.
  reason: string
}

// A brand-neutral chain that is broadly useful when the vendor is unknown.
export const GENERIC_TAMPER: TamperPreset = {
  tamper: 'between,randomcase,space2comment',
  delay: 0,
  reason: 'generic evasion (WAF vendor unknown)',
}

// Keyword → preset. First keyword that appears in the brand label wins, so keep
// more specific vendors before generic ones.
const PRESETS: Array<{ keyword: string; preset: TamperPreset }> = [
  {
    keyword: 'cloudflare',
    preset: { tamper: 'space2comment,charencode,randomcase', delay: 1, reason: 'Cloudflare tamper chain' },
  },
  {
    keyword: 'akamai',
    preset: { tamper: 'space2comment,randomcase,charunicodeencode', delay: 1, reason: 'Akamai tamper chain' },
  },
  {
    // Imperva/Incapsula is among the harder engines — a heavier chain.
    keyword: 'imperva',
    preset: { tamper: 'between,percentage,randomcase,space2comment', delay: 1, reason: 'Imperva/Incapsula tamper chain' },
  },
  {
    keyword: 'incapsula',
    preset: { tamper: 'between,percentage,randomcase,space2comment', delay: 1, reason: 'Imperva/Incapsula tamper chain' },
  },
  {
    keyword: 'sucuri',
    preset: { tamper: 'space2comment,randomcase', delay: 1, reason: 'Sucuri tamper chain' },
  },
  {
    keyword: 'aws',
    preset: { tamper: 'between,charencode,randomcase', delay: 0, reason: 'AWS WAF tamper chain' },
  },
  {
    keyword: 'fastly',
    preset: { tamper: 'between,randomcase,space2comment', delay: 0, reason: 'Fastly tamper chain' },
  },
  {
    // Self-hosted ModSecurity / OWASP CRS.
    keyword: 'modsecurity',
    preset: { tamper: 'modsecurityversioned,space2comment,randomcase', delay: 0, reason: 'ModSecurity/CRS tamper chain' },
  },
  {
    keyword: 'mod_security',
    preset: { tamper: 'modsecurityversioned,space2comment,randomcase', delay: 0, reason: 'ModSecurity/CRS tamper chain' },
  },
  {
    keyword: 'f5',
    preset: { tamper: 'between,randomcase,space2comment', delay: 0, reason: 'F5 BIG-IP ASM tamper chain' },
  },
  {
    keyword: 'big-ip',
    preset: { tamper: 'between,randomcase,space2comment', delay: 0, reason: 'F5 BIG-IP ASM tamper chain' },
  },
]

// A heavier, vendor-agnostic chain for the escalation retry when the first
// (lighter) chain was still being blocked. Superset of the per-vendor chains,
// stacking encoding + comment + case + keyword-morphing tampers.
export const HEAVY_TAMPER = 'space2comment,charencode,charunicodeencode,randomcase,between,percentage,randomcomments,equaltolike'

/**
 * The escalated tamper chain to retry with after the initial chain was blocked.
 * Vendor-agnostic today (the heavy superset); the brand is accepted so a future
 * per-vendor escalation can key off it without changing callers.
 */
export function escalatedTamper(_brand?: string | null): string {
  return HEAVY_TAMPER
}

/**
 * Pick a tamper preset for a detected WAF brand. Returns the generic chain when
 * the brand is unknown but a WAF is present, or `null` when no brand is given
 * (caller decides whether to still run the generic chain).
 */
export function tamperForBrand(brand: string | null | undefined): TamperPreset | null {
  if (!brand) return null
  const label = brand.toLowerCase()
  for (const { keyword, preset } of PRESETS) {
    if (label.includes(keyword)) return preset
  }
  return GENERIC_TAMPER
}
