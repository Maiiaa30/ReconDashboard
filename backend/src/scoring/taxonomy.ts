// Shared tag taxonomy helpers so findings get consistent, useful tags.

// Common port -> service label.
const PORT_SERVICE: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
  111: 'rpc', 135: 'msrpc', 139: 'netbios', 143: 'imap', 161: 'snmp', 389: 'ldap',
  443: 'https', 445: 'smb', 465: 'smtps', 587: 'smtp', 636: 'ldaps', 873: 'rsync',
  993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 2049: 'nfs', 2375: 'docker',
  2376: 'docker-tls', 3000: 'http-alt', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres',
  5601: 'kibana', 5672: 'amqp', 5900: 'vnc', 5984: 'couchdb', 6379: 'redis', 8000: 'http-alt',
  8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt', 9000: 'http-alt', 9200: 'elasticsearch',
  9300: 'elasticsearch', 11211: 'memcached', 15672: 'rabbitmq', 27017: 'mongodb',
}

// Ports that expose admin surfaces / data stores — higher interest.
const ADMIN_PORTS = new Set([
  21, 22, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984,
  6379, 9200, 9300, 11211, 15672, 27017,
])

export function portTags(port: number): string[] {
  const svc = PORT_SERVICE[port]
  const tags = [svc ? `svc:${svc}` : `port:${port}`]
  if (ADMIN_PORTS.has(port)) tags.push('admin-port')
  return tags
}

export function isAdminPort(port: number): boolean {
  return ADMIN_PORTS.has(port)
}

// Normalize a Server header / CPE product into a short tech tag.
const TECH_PATTERNS: { re: RegExp; tag: string }[] = [
  { re: /nginx/i, tag: 'nginx' },
  { re: /apache/i, tag: 'apache' },
  { re: /iis|microsoft-httpapi/i, tag: 'iis' },
  { re: /cloudflare/i, tag: 'cloudflare' },
  { re: /cloudfront/i, tag: 'cloudfront' },
  { re: /openresty/i, tag: 'openresty' },
  { re: /litespeed/i, tag: 'litespeed' },
  { re: /caddy/i, tag: 'caddy' },
  { re: /tomcat|coyote/i, tag: 'tomcat' },
  { re: /express/i, tag: 'express' },
  { re: /werkzeug|flask/i, tag: 'flask' },
  { re: /gunicorn/i, tag: 'gunicorn' },
  { re: /jetty/i, tag: 'jetty' },
  { re: /wordpress|wp-/i, tag: 'wordpress' },
  { re: /drupal/i, tag: 'drupal' },
  { re: /joomla/i, tag: 'joomla' },
  { re: /jboss|wildfly/i, tag: 'jboss' },
  { re: /php/i, tag: 'php' },
]

export function techTag(raw: string | null | undefined): string | null {
  if (!raw) return null
  for (const { re, tag } of TECH_PATTERNS) if (re.test(raw)) return `tech:${tag}`
  // Fall back to the first token of the Server header.
  const token = raw.split(/[\/\s]/)[0]?.toLowerCase().replace(/[^a-z0-9.-]/g, '')
  return token ? `tech:${token}` : null
}

// Tech from a CPE string like "cpe:/a:nginx:nginx:1.18.0".
export function techFromCpe(cpe: string): string | null {
  const parts = cpe.split(':')
  const product = parts[3] || parts[2]
  return product ? `tech:${product.toLowerCase()}` : null
}

// HTTP status -> tags.
export function statusTags(status: number | null | undefined): string[] {
  if (status == null) return ['no-response']
  const tags = ['live', `http:${status}`]
  if (status >= 200 && status < 300) tags.push('http-2xx')
  else if (status >= 300 && status < 400) tags.push('redirect')
  else if (status === 401 || status === 403) tags.push('auth-gated')
  else if (status >= 400 && status < 500) tags.push('http-4xx')
  else if (status >= 500) tags.push('http-5xx')
  return tags
}
