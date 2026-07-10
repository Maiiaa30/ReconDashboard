import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

// A crash in one page should degrade to an inline message, not white-screen the
// whole app. Wrap each page in this; keying it by the active page resets it on
// navigation so a broken page doesn't stay broken after you move away.
interface Props {
  children: ReactNode
}
interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface it in the console for debugging too.
    console.error('Page crashed:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-5">
          <div className="mb-2 flex items-center gap-2 text-red-200">
            <AlertTriangle size={18} className="text-red-400" />
            <h2 className="text-sm font-semibold">This page hit an error</h2>
          </div>
          <p className="text-sm text-red-200/80">
            The rest of the app is fine — switch to another page, or reload. If this keeps happening after a clean rebuild,
            copy the message below.
          </p>
          <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-red-900/40 bg-ink-950/60 p-2.5 text-xs text-red-300">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="mt-3 rounded-lg border border-hair px-3 py-1.5 text-sm text-zinc-200 transition hover:bg-ink-800 hover:border-hair-strong"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
