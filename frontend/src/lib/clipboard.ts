// Copy text to the clipboard, resilient to non-secure contexts.
//
// The dashboard is often served over plain HTTP on a non-localhost address
// (e.g. http://100.86.63.107:5173 over Tailscale). In such a "non-secure
// context" the browser leaves `navigator.clipboard` undefined, so calling
// `navigator.clipboard.writeText(...)` throws a synchronous TypeError before
// any .then()/.catch() runs — copy buttons silently do nothing. We therefore
// only touch the async Clipboard API when it actually exists and the page is a
// secure context, and otherwise fall back to the legacy execCommand approach.
// Never throws; returns whether the copy succeeded.
export async function copyText(text: string): Promise<boolean> {
  if (window.isSecureContext && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Fall through to the legacy path below.
    }
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.top = '-9999px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
