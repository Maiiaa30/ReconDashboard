import { defineConfig } from 'vitest/config'

// Tests must not depend on a local .env (CI has none). config.ts requires
// SESSION_SECRET (and reads the admin creds) at import, and several modules pull
// config in transitively, so provide safe dummy values here. The integration
// test (app.integration.test.ts) overrides these — plus DATABASE_PATH — in its
// own beforeAll before it builds the app.
export default defineConfig({
  test: {
    env: {
      SESSION_SECRET: 'test-session-secret-that-is-at-least-32-characters-long',
      ADMIN_USERNAME: 'operator',
      ADMIN_PASSWORD: 'test-password',
    },
  },
})
