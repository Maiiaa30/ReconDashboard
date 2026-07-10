import { describe, it, expect } from 'vitest'
import { parseSpec } from './apiSurface'

describe('parseSpec', () => {
  it('parses an OpenAPI 3 document: endpoints, servers, auth schemes', () => {
    const doc = {
      openapi: '3.0.1',
      info: { title: 'Orders API', version: '2.4.0' },
      servers: [{ url: 'https://api.example.com/v2' }],
      components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
      paths: {
        '/orders': { get: {}, post: {} },
        '/orders/{id}': { get: {}, delete: {} },
      },
    }
    const spec = parseSpec('https://x/openapi.json', JSON.stringify(doc))
    expect(spec).not.toBeNull()
    expect(spec!.format).toBe('openapi')
    expect(spec!.title).toBe('Orders API')
    expect(spec!.apiVersion).toBe('2.4.0')
    expect(spec!.operationCount).toBe(4)
    expect(spec!.endpoints).toContainEqual({ method: 'DELETE', path: '/orders/{id}' })
    expect(spec!.servers).toEqual(['https://api.example.com/v2'])
    expect(spec!.authSchemes).toEqual(['bearerAuth:http'])
  })

  it('parses a Swagger 2 document (host/basePath/securityDefinitions)', () => {
    const doc = {
      swagger: '2.0',
      info: { title: 'Legacy', version: '1.0' },
      host: 'legacy.example.com',
      basePath: '/api',
      schemes: ['https'],
      securityDefinitions: { apiKey: { type: 'apiKey', name: 'X-Key', in: 'header' } },
      paths: { '/ping': { get: {} } },
    }
    const spec = parseSpec('https://x/swagger.json', JSON.stringify(doc))
    expect(spec!.format).toBe('swagger')
    expect(spec!.servers).toEqual(['https://legacy.example.com/api'])
    expect(spec!.authSchemes).toEqual(['apiKey:apiKey'])
    expect(spec!.operationCount).toBe(1)
  })

  it('rejects non-spec JSON and invalid input', () => {
    expect(parseSpec('u', JSON.stringify({ hello: 'world' }))).toBeNull()
    expect(parseSpec('u', 'not json')).toBeNull()
  })
})
