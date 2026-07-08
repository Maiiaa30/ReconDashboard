// Port intelligence: classify a TCP port into a category + risk + a plain-English
// "what is probably running here" note, so genuinely interesting exposure (an
// unauthenticated camera stream, a building-automation controller, a naked
// database, remote-desktop, an admin panel) jumps out instead of being one more
// blue number. This is a heuristic on the port NUMBER — nmap service detection,
// when present, is still the ground truth.

export type PortCategory =
  | 'camera'
  | 'ics'
  | 'iot'
  | 'database'
  | 'remote'
  | 'admin'
  | 'file'
  | 'mail'
  | 'infra'
  | 'voip'
  | 'web'

export type PortRisk = 'high' | 'medium' | 'low'

export interface PortInfo {
  label: string
  category: PortCategory
  risk: PortRisk
  note: string
}

export const CATEGORY_META: Record<PortCategory, { label: string; icon: string }> = {
  camera: { label: 'Camera / DVR', icon: '📹' },
  ics: { label: 'ICS / building', icon: '🏭' },
  iot: { label: 'IoT', icon: '📡' },
  database: { label: 'Database', icon: '🗄️' },
  remote: { label: 'Remote access', icon: '🖥️' },
  admin: { label: 'Admin panel', icon: '⚙️' },
  file: { label: 'File / share', icon: '📁' },
  mail: { label: 'Mail', icon: '✉️' },
  infra: { label: 'Infra', icon: '🧩' },
  voip: { label: 'VoIP', icon: '📞' },
  web: { label: 'Web', icon: '🌐' },
}

const PORTS: Record<number, PortInfo> = {
  // --- Cameras / DVR / NVR ---------------------------------------------------
  554: { label: 'RTSP', category: 'camera', risk: 'high', note: 'Live video stream (IP cameras / DVR). Frequently unauthenticated — try VLC / a camera scanner.' },
  8554: { label: 'RTSP (alt)', category: 'camera', risk: 'high', note: 'Alternate RTSP video-stream port.' },
  37777: { label: 'Dahua DVR', category: 'camera', risk: 'high', note: 'Dahua camera/DVR control port — known default-cred and CVE history.' },
  37778: { label: 'Dahua (UDP)', category: 'camera', risk: 'high', note: 'Dahua camera/DVR aux port.' },
  34567: { label: 'Xiongmai DVR', category: 'camera', risk: 'high', note: '“Sofia” DVR/NVR port (Xiongmai OEM) — mass default-cred / Mirai target.' },
  8899: { label: 'DVR web', category: 'camera', risk: 'medium', note: 'Common cheap-DVR web/control port.' },
  3702: { label: 'ONVIF discovery', category: 'camera', risk: 'medium', note: 'WS-Discovery — often reveals ONVIF cameras on the network.' },

  // --- ICS / SCADA / building automation (door access, HVAC, gates) ----------
  502: { label: 'Modbus', category: 'ics', risk: 'high', note: 'Industrial Modbus/TCP — no auth by design. Exposed = serious.' },
  102: { label: 'S7comm', category: 'ics', risk: 'high', note: 'Siemens S7 PLC protocol.' },
  44818: { label: 'EtherNet/IP', category: 'ics', risk: 'high', note: 'Allen-Bradley / Rockwell CIP.' },
  20000: { label: 'DNP3', category: 'ics', risk: 'high', note: 'DNP3 (utilities/SCADA).' },
  47808: { label: 'BACnet', category: 'ics', risk: 'high', note: 'Building automation — HVAC, lighting, door/access controllers (this is often the “gym door” type device).' },
  2404: { label: 'IEC-104', category: 'ics', risk: 'high', note: 'IEC 60870-5-104 (power/utilities).' },
  1911: { label: 'Niagara Fox', category: 'ics', risk: 'medium', note: 'Tridium Niagara building-automation framework.' },
  4911: { label: 'Niagara Fox/TLS', category: 'ics', risk: 'medium', note: 'Tridium Niagara over TLS.' },
  9600: { label: 'OMRON FINS', category: 'ics', risk: 'medium', note: 'OMRON PLC protocol.' },

  // --- IoT -------------------------------------------------------------------
  1883: { label: 'MQTT', category: 'iot', risk: 'medium', note: 'IoT message broker — often no auth, can leak/inject device telemetry.' },
  8883: { label: 'MQTT/TLS', category: 'iot', risk: 'medium', note: 'IoT MQTT over TLS.' },
  5683: { label: 'CoAP', category: 'iot', risk: 'medium', note: 'Constrained IoT protocol.' },

  // --- Databases (exposed DBs are almost always a finding) -------------------
  3306: { label: 'MySQL', category: 'database', risk: 'high', note: 'MySQL/MariaDB exposed to the internet.' },
  5432: { label: 'PostgreSQL', category: 'database', risk: 'high', note: 'PostgreSQL exposed.' },
  27017: { label: 'MongoDB', category: 'database', risk: 'high', note: 'MongoDB — historically shipped with no auth.' },
  6379: { label: 'Redis', category: 'database', risk: 'high', note: 'Redis — no auth by default; RCE-capable if writable.' },
  9200: { label: 'Elasticsearch', category: 'database', risk: 'high', note: 'Elasticsearch REST — often open, dumps all indices.' },
  9300: { label: 'Elasticsearch (transport)', category: 'database', risk: 'high', note: 'Elasticsearch node-to-node transport.' },
  5984: { label: 'CouchDB', category: 'database', risk: 'high', note: 'CouchDB REST.' },
  11211: { label: 'Memcached', category: 'database', risk: 'high', note: 'Memcached — no auth; DRDoS amplifier.' },
  1433: { label: 'MSSQL', category: 'database', risk: 'high', note: 'Microsoft SQL Server.' },
  1521: { label: 'Oracle DB', category: 'database', risk: 'high', note: 'Oracle TNS listener.' },
  9042: { label: 'Cassandra', category: 'database', risk: 'medium', note: 'Cassandra CQL.' },
  8086: { label: 'InfluxDB', category: 'database', risk: 'medium', note: 'InfluxDB HTTP API.' },
  5601: { label: 'Kibana', category: 'database', risk: 'medium', note: 'Kibana — front-end to Elasticsearch data.' },

  // --- Remote access ---------------------------------------------------------
  22: { label: 'SSH', category: 'remote', risk: 'low', note: 'SSH — expected, but note version + auth methods.' },
  23: { label: 'Telnet', category: 'remote', risk: 'high', note: 'Telnet — cleartext credentials. Should never be exposed.' },
  3389: { label: 'RDP', category: 'remote', risk: 'high', note: 'Windows Remote Desktop — brute-force / BlueKeep target.' },
  5900: { label: 'VNC', category: 'remote', risk: 'high', note: 'VNC — often no/weak auth, full desktop.' },
  5901: { label: 'VNC :1', category: 'remote', risk: 'high', note: 'VNC display :1.' },
  5985: { label: 'WinRM', category: 'remote', risk: 'medium', note: 'Windows Remote Management (HTTP).' },
  5986: { label: 'WinRM/TLS', category: 'remote', risk: 'medium', note: 'Windows Remote Management (HTTPS).' },
  512: { label: 'rexec', category: 'remote', risk: 'high', note: 'BSD r-service — cleartext, obsolete.' },
  513: { label: 'rlogin', category: 'remote', risk: 'high', note: 'BSD r-service — cleartext, obsolete.' },
  514: { label: 'rsh/syslog', category: 'remote', risk: 'high', note: 'BSD r-service — cleartext, obsolete.' },

  // --- Admin panels / management ---------------------------------------------
  10000: { label: 'Webmin', category: 'admin', risk: 'medium', note: 'Webmin server admin panel.' },
  2082: { label: 'cPanel', category: 'admin', risk: 'medium', note: 'cPanel (HTTP).' },
  2083: { label: 'cPanel/TLS', category: 'admin', risk: 'medium', note: 'cPanel (HTTPS).' },
  2086: { label: 'WHM', category: 'admin', risk: 'medium', note: 'WHM host management (HTTP).' },
  2087: { label: 'WHM/TLS', category: 'admin', risk: 'medium', note: 'WHM host management (HTTPS).' },
  8006: { label: 'Proxmox', category: 'admin', risk: 'medium', note: 'Proxmox VE web UI.' },
  9090: { label: 'Cockpit', category: 'admin', risk: 'medium', note: 'Cockpit / Prometheus / Openfire admin.' },
  7001: { label: 'WebLogic', category: 'admin', risk: 'medium', note: 'Oracle WebLogic — deserialization CVE history.' },
  8161: { label: 'ActiveMQ', category: 'admin', risk: 'medium', note: 'ActiveMQ web console.' },
  15672: { label: 'RabbitMQ mgmt', category: 'admin', risk: 'medium', note: 'RabbitMQ management UI.' },
  9000: { label: 'Portainer/PHP-FPM', category: 'admin', risk: 'medium', note: 'Portainer, SonarQube, PHP-FPM, or Xdebug — worth a look.' },

  // --- File / shares ---------------------------------------------------------
  21: { label: 'FTP', category: 'file', risk: 'medium', note: 'FTP — cleartext; check anonymous access.' },
  445: { label: 'SMB', category: 'file', risk: 'high', note: 'SMB/CIFS — EternalBlue-class; check shares.' },
  139: { label: 'NetBIOS', category: 'file', risk: 'medium', note: 'NetBIOS session (legacy SMB).' },
  2049: { label: 'NFS', category: 'file', risk: 'high', note: 'NFS — check for world-readable/writable exports.' },
  873: { label: 'rsync', category: 'file', risk: 'medium', note: 'rsync daemon — often lists modules anonymously.' },
  69: { label: 'TFTP', category: 'file', risk: 'medium', note: 'TFTP — no auth; config/firmware leaks.' },

  // --- Mail ------------------------------------------------------------------
  25: { label: 'SMTP', category: 'mail', risk: 'low', note: 'SMTP — check open relay / user enum.' },
  110: { label: 'POP3', category: 'mail', risk: 'low', note: 'POP3.' },
  143: { label: 'IMAP', category: 'mail', risk: 'low', note: 'IMAP.' },
  465: { label: 'SMTPS', category: 'mail', risk: 'low', note: 'SMTP over TLS.' },
  587: { label: 'Submission', category: 'mail', risk: 'low', note: 'Mail submission.' },
  993: { label: 'IMAPS', category: 'mail', risk: 'low', note: 'IMAP over TLS.' },
  995: { label: 'POP3S', category: 'mail', risk: 'low', note: 'POP3 over TLS.' },

  // --- Infra -----------------------------------------------------------------
  53: { label: 'DNS', category: 'infra', risk: 'low', note: 'DNS — check zone transfer / recursion.' },
  161: { label: 'SNMP', category: 'infra', risk: 'medium', note: 'SNMP — default community strings leak device data.' },
  389: { label: 'LDAP', category: 'infra', risk: 'medium', note: 'LDAP — may allow anonymous bind.' },
  636: { label: 'LDAPS', category: 'infra', risk: 'low', note: 'LDAP over TLS.' },
  3128: { label: 'Squid proxy', category: 'infra', risk: 'medium', note: 'Proxy — check for open relay / SSRF pivot.' },

  // --- VoIP ------------------------------------------------------------------
  5060: { label: 'SIP', category: 'voip', risk: 'medium', note: 'SIP — VoIP; extension enum / toll fraud.' },
  5061: { label: 'SIP/TLS', category: 'voip', risk: 'low', note: 'SIP over TLS.' },

  // --- Web (common, expected) ------------------------------------------------
  80: { label: 'HTTP', category: 'web', risk: 'low', note: 'Web server.' },
  443: { label: 'HTTPS', category: 'web', risk: 'low', note: 'Web server (TLS).' },
  8080: { label: 'HTTP (alt)', category: 'web', risk: 'low', note: 'Alt web / proxy / app server.' },
  8443: { label: 'HTTPS (alt)', category: 'web', risk: 'low', note: 'Alt web (TLS).' },
  8000: { label: 'HTTP (alt)', category: 'web', risk: 'low', note: 'Alt web / dev server.' },
  8888: { label: 'HTTP (alt)', category: 'web', risk: 'low', note: 'Alt web / Jupyter / dev server.' },
}

// VNC 5902–5906 all map to the same meaning.
for (let d = 2; d <= 6; d++) {
  PORTS[5900 + d] = { label: `VNC :${d}`, category: 'remote', risk: 'high', note: `VNC display :${d}.` }
}

export function classifyPort(port: number): PortInfo | null {
  return PORTS[port] ?? null
}

// "Notable" = worth surfacing: a known non-web service at medium+ risk, or any
// high-risk port. Plain web ports (80/443) are not notable.
export function isNotablePort(port: number): boolean {
  const info = classifyPort(port)
  if (!info) return false
  if (info.category === 'web') return false
  return info.risk === 'high' || info.risk === 'medium'
}

// Tailwind-ish tone for the port badge, driven by risk.
export function riskTone(risk: PortRisk): 'red' | 'amber' | 'zinc' {
  return risk === 'high' ? 'red' : risk === 'medium' ? 'amber' : 'zinc'
}
