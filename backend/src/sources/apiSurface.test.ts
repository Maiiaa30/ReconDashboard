import { describe, it, expect } from 'vitest'
import { parseSpec, apiPathsFromCorpus } from './apiSurface'

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

describe('apiPathsFromCorpus', () => {
  it('keeps only this host’s API-looking paths and extracts query params', () => {
    const urls = [
      'https://target.com/api/v1/users?id=5',
      'https://target.com/about', // not API-ish
      'https://target.com/logo.png', // asset
      'https://api.other.com/api/secret', // different host
      'https://target.com/blog?utm_source=x', // marketing query → excluded
      'https://target.com/graphql',
      'not-a-url',
    ]
    const { endpoints, params } = apiPathsFromCorpus('target.com', urls)
    expect(endpoints).toContain('/api/v1/users?id=5')
    expect(endpoints).toContain('/graphql')
    expect(endpoints).not.toContain('/about')
    expect(endpoints).not.toContain('/logo.png')
    expect(endpoints).not.toContain('/api/secret') // belongs to a different host
    expect(endpoints.some((e) => e.startsWith('/blog'))).toBe(false)
    expect(params).toContain('id')
  })

  it('is case-insensitive on the host and dedups', () => {
    const { endpoints } = apiPathsFromCorpus('Target.com', [
      'https://TARGET.com/api/a',
      'https://target.com/api/a',
    ])
    expect(endpoints).toEqual(['/api/a'])
  })
})
