// Shared shapes for the API-surface findings (spec / GraphQL / JS recon).

export interface SpecParam {
  name: string
  in: string
  required: boolean
}
export interface SpecBodyField {
  name: string
  type: string
  required: boolean
}
export interface SpecEndpoint {
  method: string
  path: string
  summary?: string | null
  params?: SpecParam[]
  body?: { contentType: string; fields: SpecBodyField[] } | null
}
export interface SpecData {
  kind: 'openapi'
  host: string
  specUrl: string
  format: 'openapi' | 'swagger'
  version: string | null
  title: string | null
  apiVersion: string | null
  servers: string[]
  authSchemes: string[]
  operationCount: number
  endpoints: SpecEndpoint[]
}
export interface GqlOperation {
  kind: 'query' | 'mutation'
  name: string
  args: { name: string; type: string }[]
}
export interface GqlData {
  kind: 'graphql'
  host: string
  endpoint: string
  introspectionEnabled: boolean
  queryType: string | null
  typeCount: number
  operations?: GqlOperation[]
}

export interface JsData {
  kind: 'js'
  host: string
  filesScanned: number
  endpoints: string[]
  params: string[]
  secrets: { pattern: string; sample: string; file: string }[]
  fromCorpus?: number // how many endpoints came from passive URLs (wayback/crawl), not JS
  frameworks?: string[] // SPA stack detected client-side (React/Next/Vue/…)
  routes?: string[] // client-side route paths
  env?: { key: string; value: string | null }[] // baked-in public env config
}
