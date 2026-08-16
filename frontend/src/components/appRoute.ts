import { DOMAIN_SCOPED, MODULES, type ModuleKey } from './navigation'

export interface AppRoute {
  page: ModuleKey
  domainId?: number
}

const MODULE_KEYS = new Set<string>(MODULES.map((module) => module.key))

function isModuleKey(value: string): value is ModuleKey {
  return MODULE_KEYS.has(value)
}

export function parseAppRoute(pathname: string): AppRoute | null {
  const segments = pathname.split('/').filter(Boolean).map(decodeURIComponent)
  if (segments.length === 0) return { page: 'home' }

  if (segments.length === 1 && isModuleKey(segments[0])) {
    return { page: segments[0] }
  }

  if (segments.length === 3 && segments[0] === 'engagements' && isModuleKey(segments[2])) {
    const domainId = Number(segments[1])
    if (Number.isSafeInteger(domainId) && domainId > 0) return { page: segments[2], domainId }
  }

  return null
}

export function buildAppRoute(page: ModuleKey, domainId?: number | null): string {
  if (page === 'home') return '/'
  if (domainId != null) return `/engagements/${domainId}/${page}`
  return `/${page}`
}

export function routeDomain(page: ModuleKey, requestedId: number | undefined, selectedId: number | null): number | undefined {
  if (requestedId != null) return requestedId
  return DOMAIN_SCOPED.includes(page) ? selectedId ?? undefined : undefined
}
