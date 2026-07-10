// Tiny in-memory TTL cache for idempotent external lookups (e.g. InternetDB per
// IP) so repeated scans don't re-hit a free API for data that barely changes.
// Process-lifetime, size-bounded (oldest entry evicted first). Not persisted —
// a restart simply re-warms it.
export class TtlCache<K, V> {
  private store = new Map<K, { value: V; expires: number }>()

  constructor(
    private ttlMs: number,
    private max = 5_000,
  ) {}

  get(key: K): V | undefined {
    const hit = this.store.get(key)
    if (!hit) return undefined
    if (Date.now() > hit.expires) {
      this.store.delete(key)
      return undefined
    }
    return hit.value
  }

  set(key: K, value: V): void {
    if (this.store.size >= this.max && !this.store.has(key)) {
      const oldest = this.store.keys().next().value
      if (oldest !== undefined) this.store.delete(oldest)
    }
    this.store.set(key, { value, expires: Date.now() + this.ttlMs })
  }
}
