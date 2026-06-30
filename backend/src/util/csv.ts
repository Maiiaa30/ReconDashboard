// Minimal, correct CSV serialization (RFC-4180-ish): quote fields containing
// comma, quote, CR or LF; double embedded quotes.
function cell(value: unknown): string {
  let s = value == null ? '' : String(value)
  // Neutralize spreadsheet formula injection: recon data (page titles, server
  // headers, URLs) is attacker-influenced, so a leading =,+,-,@ (or tab/CR)
  // could execute as a formula in Excel/Sheets. Prefix with a single quote.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  const lines = [headers.map(cell).join(',')]
  for (const row of rows) lines.push(row.map(cell).join(','))
  return lines.join('\r\n')
}
