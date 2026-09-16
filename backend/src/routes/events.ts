import type { FastifyPluginAsync } from 'fastify'
import { subscribe, type AppEvent } from '../events/bus'

// Server-Sent Events stream of coarse change signals (jobs/findings/runs). The
// client opens one EventSource and refreshes the relevant view on each event,
// which lets pages drop to a slower poll while still updating instantly. Runs
// behind the same session auth guard as every other /api route.
//
// The payload is intentionally tiny — `{ kind, domainId? }` — never the changed
// data, so a dropped connection or missed event degrades to the poll, never to
// stale data shown as fresh.
export const eventRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/events', (request, reply) => {
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      // Disable proxy buffering so events aren't held back (nginx et al.).
      'X-Accel-Buffering': 'no',
    })
    // An initial comment opens the stream for the browser's EventSource.
    reply.raw.write(': connected\n\n')

    const send = (ev: AppEvent) => {
      // A write after the socket is gone would throw; guard it.
      if (reply.raw.writableEnded) return
      try {
        reply.raw.write(`data: ${JSON.stringify(ev)}\n\n`)
      } catch {
        /* client vanished mid-write; the close handler cleans up */
      }
    }
    const unsubscribe = subscribe(send)

    // Heartbeat keeps intermediaries from timing out an idle stream.
    const heartbeat = setInterval(() => {
      if (reply.raw.writableEnded) return
      try {
        reply.raw.write(': hb\n\n')
      } catch {
        /* ignore */
      }
    }, 25_000)

    const cleanup = () => {
      clearInterval(heartbeat)
      unsubscribe()
    }
    request.raw.on('close', cleanup)
    request.raw.on('error', cleanup)

    // Tell Fastify we've taken over the raw socket; it must not try to send a body.
    reply.hijack()
  })
}
