// Server-Side Template Injection detection — pure confirmation logic so the
// false-positive guard is unit-testable. The trick to killing reflection FPs is a
// LITERAL-CONTROL DIFFERENTIAL: send an arithmetic expression the template engine
// would EVALUATE, and separately send the SAME expression as a plain literal that
// no engine evaluates. Only when the distinctive product appears for the evaluated
// payload but NOT for the literal control has the server actually executed it.

// A distinctive 7-digit product (1337 * 1191) — vanishingly unlikely to appear in
// a page by chance, unlike 7*7 = 49.
export const SSTI_MARKER = '1592367'

// The same arithmetic, sent as a plain literal (no template braces). If the page
// already contains the product, the control body will too, and we bail.
export const SSTI_CONTROL = '1337*1191'

// One benign arithmetic payload per major template syntax.
export const SSTI_PAYLOADS: readonly string[] = [
  '{{1337*1191}}', // Jinja2 / Twig / Nunjucks
  '${1337*1191}', // JSP EL / Thymeleaf / JS template literal / Freemarker
  '#{1337*1191}', // Ruby ERB-ish / Spring EL
  '<%= 1337*1191 %>', // ERB / EJS
  '*{1337*1191}', // Thymeleaf selection
  '{1337*1191}', // Angular-ish / bare
]

// Confirmed iff the evaluated payload produced the product AND the literal control
// did not (so the number wasn't already on the page — that's the FP killer).
export function sstiConfirmed(payloadBody: string, controlBody: string): boolean {
  return payloadBody.includes(SSTI_MARKER) && !controlBody.includes(SSTI_MARKER)
}
