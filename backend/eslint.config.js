import tseslint from 'typescript-eslint'

// Intentionally MINIMAL. This config exists for ONE job: structurally prevent the
// SSRF-guard bypass (AUDIT-2026-07 §3 #1) from ever recurring by banning raw
// fetch() in the target-facing recon code. It deliberately does NOT enable the
// recommended ruleset — that would flood the build with pre-existing `as any`
// findings and turn a security guardrail into a reformat chore.
export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'drizzle/**', '*.config.js'],
  },
  // Parse every source file as TypeScript, but apply no rules by default. The
  // plugin is registered (so existing inline eslint-disable directives for
  // @typescript-eslint rules resolve) without any of its rules being enabled.
  {
    files: ['src/**/*.ts'],
    plugins: { '@typescript-eslint': tseslint.plugin },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { sourceType: 'module', ecmaVersion: 'latest' },
    },
  },
  // The guardrail: no raw fetch() in code that talks to (attacker-controlled)
  // target hosts. Everything here must go through guardedFetch/guardedFetchRaw,
  // which re-runs the SSRF check on every redirect hop.
  {
    files: ['src/sources/**/*.ts', 'src/owasp/**/*.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.name='fetch']",
          message:
            'Do not call fetch() directly here — use guardedFetch / guardedFetchRaw from sources/guard.ts, which SSRF-guards every redirect hop.',
        },
      ],
    },
  },
  // Reviewed exceptions to the ban:
  //  - guard.ts / httpProbe.ts ARE the guarded clients (they call fetch behind
  //    the per-hop assertPublicHost check).
  //  - buckets.ts / leaks.ts hit FIXED cloud-provider / breach-provider endpoints
  //    with strictly-sanitized names — not target-controlled hosts, so the SSRF
  //    guard does not apply.
  //  - *.test.ts stub/inspect fetch.
  {
    files: [
      'src/sources/guard.ts',
      'src/sources/httpProbe.ts',
      'src/sources/buckets.ts',
      'src/sources/leaks.ts',
      'src/**/*.test.ts',
    ],
    rules: {
      'no-restricted-syntax': 'off',
    },
  },
)
