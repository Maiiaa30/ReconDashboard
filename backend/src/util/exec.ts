import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

// SECURITY: subprocesses are ONLY ever invoked via execFile with an explicit
// argument array. We never build a shell command string and never pass
// shell:true, so user-influenced values cannot be interpreted by a shell.
// Every host/domain argument must already have passed validate.ts.

export class ToolNotFoundError extends Error {
  constructor(public tool: string) {
    super(`tool not found: ${tool}`)
  }
}

export interface RunResult {
  stdout: string
  stderr: string
}

interface RunOptions {
  timeoutMs?: number
  maxBuffer?: number
}

export async function run(
  file: string,
  args: string[],
  opts: RunOptions = {},
): Promise<RunResult> {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout: opts.timeoutMs ?? 120_000,
      maxBuffer: opts.maxBuffer ?? 32 * 1024 * 1024,
      windowsHide: true,
      // No `shell` option — arguments are passed directly to the binary.
    })
    return { stdout: stdout.toString(), stderr: stderr.toString() }
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string }
    if (e.code === 'ENOENT') {
      throw new ToolNotFoundError(file)
    }
    // execFile throws on non-zero exit; some tools (nmap, ffuf) exit non-zero
    // with useful output. Re-throw with output attached for the caller.
    const wrapped = new Error(`${file} failed: ${e.message}`) as Error & RunResult
    wrapped.stdout = e.stdout?.toString() ?? ''
    wrapped.stderr = e.stderr?.toString() ?? ''
    throw wrapped
  }
}

/** True if a binary is resolvable on PATH. */
export async function toolExists(file: string): Promise<boolean> {
  try {
    // `--version` is supported by all four recon tools; ignore exit code.
    await execFileAsync(file, ['--version'], { timeout: 10_000, windowsHide: true })
    return true
  } catch (err) {
    const e = err as NodeJS.ErrnoException
    if (e.code === 'ENOENT') return false
    // Non-zero exit but the binary exists.
    return true
  }
}
