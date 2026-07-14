// Version-control exposure helpers, kept pure so the escalation rule is testable.

export type GitPart = 'head' | 'config' | 'index'

// A single exposed .git file is a strong signal; all three of HEAD, config and
// index together prove the repository is fully DUMPABLE — an attacker can
// reconstruct source, history and any committed secrets. That combination is
// what warrants critical (vs the individual highs).
export function gitTriadComplete(parts: GitPart[]): boolean {
  const set = new Set(parts)
  return set.has('head') && set.has('config') && set.has('index')
}
