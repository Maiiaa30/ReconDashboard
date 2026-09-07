import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In Docker dev, set VITE_API_PROXY=http://backend:3001 so the dev server
// proxies API calls to the backend container. Locally it defaults to localhost.
const apiProxy = process.env.VITE_API_PROXY ?? 'http://localhost:3001'

export default defineConfig({
  plugins: [react()],
  // @excalidraw/excalidraw references process.env at runtime.
  define: {
    'process.env.IS_PREACT': JSON.stringify('false'),
  },
  build: {
    // Emit a manifest so the bundle-budget script can measure the real first-load
    // set (entry chunk + its static imports) rather than guessing by filename.
    manifest: true,
    rollupOptions: {
      output: {
        // Pull the rarely-changing React runtime into its own long-cached chunk so
        // it isn't re-downloaded on every app change and drops out of the entry.
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-dom/client'],
        },
      },
    },
  },
  server: {
    host: true,
    port: Number(process.env.PORT) || 5173,
    proxy: {
      '/api': {
        target: apiProxy,
        changeOrigin: true,
      },
    },
  },
})
