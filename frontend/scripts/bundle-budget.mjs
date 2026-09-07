// Fail the build if the eager first-load JS (the entry chunk + everything it
// statically imports) exceeds the budget. Lazy route/diagram chunks are excluded
// by design - they only load on demand. Reads Vite's build manifest so the set is
// exact, not guessed by filename.
import { readFileSync, existsSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { join } from 'node:path'

const DIST = 'dist'
// Budget for the entry first-load, gzipped. Raise deliberately when a genuinely
// needed dependency lands in the shell - not to paper over an accidental import.
const BUDGET_KB = 150

const manifestPath = existsSync(join(DIST, '.vite/manifest.json'))
  ? join(DIST, '.vite/manifest.json')
  : join(DIST, 'manifest.json')
if (!existsSync(manifestPath)) {
  console.error(`bundle-budget: no manifest at ${manifestPath} - run "npm run build" first (build.manifest must be true).`)
  process.exit(1)
}
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

const entry = Object.values(manifest).find((c) => c.isEntry)
if (!entry) {
  console.error('bundle-budget: no entry chunk in manifest.')
  process.exit(1)
}

// Walk the static import graph from the entry (imports = eager; dynamicImports are
// lazy and intentionally skipped).
const seen = new Set()
const files = new Set()
;(function walk(key) {
  if (seen.has(key)) return
  seen.add(key)
  const chunk = manifest[key]
  if (!chunk) return
  files.add(chunk.file)
  for (const css of chunk.css ?? []) files.add(css)
  for (const dep of chunk.imports ?? []) walk(dep)
})(Object.keys(manifest).find((k) => manifest[k] === entry))

let total = 0
const rows = []
for (const f of files) {
  const buf = readFileSync(join(DIST, f))
  const gz = gzipSync(buf).length
  total += gz
  rows.push([f, gz])
}
rows.sort((a, b) => b[1] - a[1])

const kb = (n) => (n / 1024).toFixed(1) + ' kB'
console.log('First-load (entry + static imports), gzipped:')
for (const [f, gz] of rows) console.log(`  ${kb(gz).padStart(10)}  ${f}`)
console.log(`  ${'-'.repeat(10)}`)
console.log(`  ${kb(total).padStart(10)}  total   (budget ${BUDGET_KB} kB)`)

if (total > BUDGET_KB * 1024) {
  console.error(`\nbundle-budget: FAIL - first-load ${kb(total)} exceeds the ${BUDGET_KB} kB budget.`)
  process.exit(1)
}
console.log('\nbundle-budget: OK')
