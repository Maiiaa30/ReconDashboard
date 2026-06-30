import '@fastify/session'

declare module 'fastify' {
  interface Session {
    userId?: number
    username?: string
  }
}
