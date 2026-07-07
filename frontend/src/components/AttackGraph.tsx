import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import type { AttackPath } from '../api'

// force-graph pulls in a canvas renderer; only load it when a graph is shown.
const ForceGraph2D = lazy(() => import('react-force-graph-2d'))

type NodeKind = 'domain' | 'ip' | 'host'

interface GraphNode {
  id: string
  kind: NodeKind
  label: string
  sub?: string
  color: string
  val: number
  path?: AttackPath
}

interface GraphLink {
  source: string
  target: string
  kind: 'ip' | 'host'
  color: string
}

// Risk color follows the same red/amber/zinc scale used by <Badge> elsewhere.
function riskColor(p: AttackPath): string {
  if (p.kev) return '#f87171' // red-400
  if (p.worstCvss != null && p.worstCvss >= 9) return '#f87171'
  if (p.worstCvss != null && p.worstCvss >= 7) return '#fbbf24' // amber-400
  if (p.cveCount > 0 || (p.score ?? 0) >= 60) return '#fbbf24'
  return '#818cf8' // accent-400 (indigo) — no known CVEs
}

function buildGraph(paths: AttackPath[], rootLabel: string): { nodes: GraphNode[]; links: GraphLink[] } {
  const nodes: GraphNode[] = [{ id: '__root__', kind: 'domain', label: rootLabel, color: '#c7caff', val: 10 }]
  const links: GraphLink[] = []
  const seenHosts = new Set<string>()

  for (const p of paths) {
    const ipId = `ip:${p.ip}`
    const color = riskColor(p)
    nodes.push({
      id: ipId,
      kind: 'ip',
      label: p.ip,
      sub: [p.asn ? `AS${p.asn}` : null, p.ports.length ? `:${p.ports.slice(0, 6).join(',')}` : null]
        .filter(Boolean)
        .join(' · '),
      color,
      // Bigger only for genuinely risky nodes, capped so they never dominate.
      val: 3 + Math.min(5, p.cveCount * 0.6),
      path: p,
    })
    links.push({ source: '__root__', target: ipId, kind: 'ip', color: color + '55' })

    for (const h of p.hosts) {
      const hostId = `host:${h}`
      if (!seenHosts.has(hostId)) {
        seenHosts.add(hostId)
        nodes.push({ id: hostId, kind: 'host', label: h, color: '#71717a', val: 1 })
      }
      links.push({ source: ipId, target: hostId, kind: 'host', color: '#3f3f4644' })
    }
  }

  return { nodes, links }
}

function nodeRadius(node: GraphNode): number {
  if (node.kind === 'domain') return 7
  if (node.kind === 'host') return 2.5
  // Grow with CVE count, but cap so a 33-CVE host doesn't become a giant blob.
  return Math.min(8, 3.5 + (node.path?.cveCount ?? 0) * 0.35)
}

export function AttackGraph({ paths, host }: { paths: AttackPath[]; host: string }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const fgRef = useRef<any>(null)
  const didFitRef = useRef(false)
  const [selected, setSelected] = useState<AttackPath | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [hoverId, setHoverId] = useState<string | null>(null)
  const [width, setWidth] = useState(0)

  function clearSelection() {
    setSelected(null)
    setSelectedId(null)
  }

  // Content signature: rebuild the graph (and re-run the sim) ONLY when the
  // correlation data actually changes, not on every 8s findings poll — the
  // parent hands us a fresh array each time even when nothing changed.
  const sig = useMemo(
    () => paths.map((p) => `${p.ip}|${p.hosts.join(',')}|${p.cveCount}|${p.worstCvss}|${p.kev}|${p.ports.join(',')}`).join(';'),
    [paths],
  )
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const { nodes, links, neighbors } = useMemo(() => {
    const g = buildGraph(paths, host)
    // Adjacency (built from string endpoints, before the sim swaps them for
    // node objects) — powers the "focus" dimming when a node is selected.
    const neighbors = new Map<string, Set<string>>()
    for (const l of g.links) {
      if (!neighbors.has(l.source)) neighbors.set(l.source, new Set())
      if (!neighbors.has(l.target)) neighbors.set(l.target, new Set())
      neighbors.get(l.source)!.add(l.target)
      neighbors.get(l.target)!.add(l.source)
    }
    return { ...g, neighbors }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig, host])
  // Stable object identity so ForceGraph2D doesn't reheat on unrelated re-renders.
  const graphData = useMemo(() => ({ nodes, links }), [nodes, links])

  // Is this node in focus? (no selection = everything in focus)
  const inFocus = (id: string) => !selectedId || id === selectedId || !!neighbors.get(selectedId)?.has(id)
  const idOf = (end: any) => (typeof end === 'object' ? end.id : end)

  // Track container width so the canvas fills the card (and reflows on resize).
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    setWidth(el.clientWidth)
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Layout: enough repulsion to avoid overlap, but compact enough that the
  // graph fills the frame instead of drifting into empty corners. Trunk links
  // (root→IP) medium length, leaf links (IP→host) short so hosts hug their IP.
  const configForces = (fg: any) => {
    fg.d3Force('charge')?.strength(-95).distanceMax(260)
    fg.d3Force('link')?.distance((l: any) => (l.kind === 'host' ? 16 : 52))
  }
  // Callback ref: the graph is lazy-loaded behind <Suspense>, so a plain effect
  // can fire before the instance exists. Configuring forces here guarantees they
  // apply the moment the instance attaches.
  const setFgRef = (inst: any) => {
    fgRef.current = inst || null
    if (inst) configForces(inst)
  }
  // On data change, re-tune + reheat + allow a fresh auto-fit.
  useEffect(() => {
    const fg = fgRef.current
    if (!fg) return
    configForces(fg)
    didFitRef.current = false
    fg.d3ReheatSimulation?.()
  }, [sig])

  return (
    <div className="relative overflow-hidden rounded-xl border border-hair bg-ink-950/60">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-hair/60 px-3 py-2 text-[11px] text-zinc-500">
        <Legend color="#c7caff" label="target" />
        <Legend color="#f87171" label="KEV / CVSS ≥ 9" />
        <Legend color="#fbbf24" label="CVSS ≥ 7 or elevated" />
        <Legend color="#818cf8" label="no known CVEs" />
        <Legend color="#71717a" label="host" />
        <span className="ml-auto text-zinc-600">drag · scroll to zoom · hover / click a node</span>
      </div>

      <div ref={containerRef} className="h-[460px] w-full cursor-grab">
        <Suspense fallback={<div className="flex h-full items-center justify-center text-sm text-zinc-500">Loading graph…</div>}>
          <ForceGraph2D
            ref={setFgRef as any}
            graphData={graphData}
            width={width || undefined}
            height={460}
            backgroundColor="rgba(0,0,0,0)"
            nodeId="id"
            nodeRelSize={4}
            nodeLabel={(n: any) => (n.kind === 'domain' ? n.label : `${n.label}${n.sub ? ` — ${n.sub}` : ''}`)}
            linkColor={(l: any) => {
              if (!selectedId) return l.color
              const on = idOf(l.source) === selectedId || idOf(l.target) === selectedId
              return on ? '#c7caffcc' : '#ffffff0d' // highlight the selected node's edges, fade the rest
            }}
            linkWidth={(l: any) => {
              const base = l.kind === 'ip' ? 1 : 0.5
              if (!selectedId) return base
              const on = idOf(l.source) === selectedId || idOf(l.target) === selectedId
              return on ? 2 : base
            }}
            linkDirectionalParticles={(l: any) => {
              const on = !selectedId || idOf(l.source) === selectedId || idOf(l.target) === selectedId
              return on && l.color?.startsWith('#f87171') ? 2 : 0
            }}
            linkDirectionalParticleWidth={2}
            linkDirectionalParticleColor={() => '#f8717188'}
            warmupTicks={80}
            cooldownTicks={120}
            onEngineStop={() => {
              // Frame the whole graph once it settles (but never fight the user
              // after they've panned/zoomed).
              if (!didFitRef.current) {
                didFitRef.current = true
                fgRef.current?.zoomToFit(500, 30)
              }
            }}
            onNodeClick={(n: any) => {
              setSelected(n.path ?? null)
              setSelectedId(n.id)
            }}
            onBackgroundClick={clearSelection}
            onNodeHover={(n: any) => {
              setHoverId(n?.id ?? null)
              if (containerRef.current) containerRef.current.style.cursor = n ? 'pointer' : 'grab'
            }}
            nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
              const r = nodeRadius(node)
              const isHover = node.id === hoverId
              const isSelected = node.id === selectedId
              const focused = inFocus(node.id)

              // Out-of-focus nodes (when something is selected) fade back.
              ctx.globalAlpha = focused ? 1 : 0.14

              // Selected node gets a glow so it reads as "the active one".
              if (isSelected) {
                ctx.shadowColor = '#818cf8'
                ctx.shadowBlur = 16
              }
              ctx.beginPath()
              ctx.arc(node.x, node.y, isSelected ? r + 1 : r, 0, 2 * Math.PI, false)
              ctx.fillStyle = node.color
              ctx.fill()
              ctx.shadowBlur = 0

              // Rings: selected = bright accent (distinct), hover = white,
              // KEV/critical IP = red — in that priority order.
              if (isSelected) {
                ctx.lineWidth = 2.2 / globalScale
                ctx.strokeStyle = '#c7caff'
                ctx.stroke()
              } else if (isHover) {
                ctx.lineWidth = 1.5 / globalScale
                ctx.strokeStyle = '#ffffff'
                ctx.stroke()
              } else if (node.kind === 'ip' && node.path?.kev) {
                ctx.lineWidth = 1.5 / globalScale
                ctx.strokeStyle = '#fca5a5'
                ctx.stroke()
              }

              // Labels:
              //  • target always (the anchor),
              //  • selected node + its neighbours, and the hovered node,
              //  • IP + host nodes once you've zoomed in enough to read them —
              //    hosts (the grey leaf nodes) now get names too, drawn smaller
              //    and dimmer so a dense cluster stays legible.
              const isHost = node.kind === 'host'
              const nearSelection = selectedId != null && focused
              const showLabel =
                node.kind === 'domain' ||
                isSelected ||
                isHover ||
                nearSelection ||
                (node.kind === 'ip' && globalScale >= 1.1) ||
                (isHost && globalScale >= 1.1)
              if (!showLabel) {
                ctx.globalAlpha = 1
                return
              }

              // Constant on-screen size; hosts a touch smaller than IPs.
              const fontSize = (isHost && !isHover && !isSelected ? 10 : 12) / globalScale
              ctx.font = `${node.kind === 'domain' || isSelected ? 600 : 400} ${fontSize}px ui-sans-serif, system-ui`
              ctx.textAlign = 'center'
              ctx.textBaseline = 'top'
              const label = node.label
              const pad = 3 / globalScale
              const tw = ctx.measureText(label).width
              const ty = node.y + r + pad
              // Pill behind the text so it stays legible over links/nodes.
              ctx.fillStyle = isHost && !isHover && !isSelected ? 'rgba(13,15,21,0.66)' : 'rgba(13,15,21,0.82)'
              ctx.beginPath()
              const bx = node.x - tw / 2 - pad
              const bw = tw + pad * 2
              const bh = fontSize + pad
              const br = 2 / globalScale
              roundRect(ctx, bx, ty - pad / 2, bw, bh, br)
              ctx.fill()
              ctx.fillStyle = isSelected
                ? '#e0e2ff'
                : isHover
                  ? '#f4f4f5'
                  : isHost
                    ? 'rgba(161,161,170,0.92)' // zinc-400, matches the grey nodes
                    : 'rgba(212,212,216,0.92)'
              ctx.fillText(label, node.x, ty)
              ctx.globalAlpha = 1
            }}
            nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
              const r = nodeRadius(node) + 3
              ctx.fillStyle = color
              ctx.beginPath()
              ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false)
              ctx.fill()
            }}
          />
        </Suspense>
      </div>

      {selected && (
        <div className="absolute bottom-3 right-3 max-w-xs rounded-lg border border-hair bg-ink-900/95 p-3 text-xs shadow-pop">
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="font-mono text-zinc-100">{selected.ip}</span>
            <button onClick={clearSelection} className="text-zinc-500 hover:text-zinc-300">
              ✕
            </button>
          </div>
          {selected.asnName && <div className="text-zinc-500">AS{selected.asn} — {selected.asnName}</div>}
          {selected.hosts.length > 0 && (
            <div className="mt-1 break-all font-mono text-[11px] text-zinc-300">{selected.hosts.join(', ')}</div>
          )}
          {selected.ports.length > 0 && (
            <div className="mt-1 text-zinc-400">ports: {selected.ports.join(', ')}</div>
          )}
          {selected.cveCount > 0 && (
            <div className="mt-1 text-amber-400">
              {selected.cveCount} CVE{selected.cveCount > 1 ? 's' : ''}
              {selected.worstCvss != null && ` · worst CVSS ${selected.worstCvss}`}
              {selected.kev && ' · KEV'}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Small rounded-rect helper (not all canvas impls have ctx.roundRect yet).
function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, w / 2, h / 2)
  ctx.moveTo(x + rr, y)
  ctx.arcTo(x + w, y, x + w, y + h, rr)
  ctx.arcTo(x + w, y + h, x, y + h, rr)
  ctx.arcTo(x, y + h, x, y, rr)
  ctx.arcTo(x, y, x + w, y, rr)
  ctx.closePath()
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  )
}
