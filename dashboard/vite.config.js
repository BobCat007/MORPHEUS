import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const writeToken = env.MORPHEUS_API_WRITE_TOKEN || process.env.MORPHEUS_API_WRITE_TOKEN

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
          ws: true,
          configure(proxy) {
            proxy.on('proxyReq', (proxyReq, req) => {
              const isIncidentUpdate =
                req.method === 'PATCH' &&
                /^\/api\/v1\/incidents\/[^/]+\/status(?:\?|$)/.test(req.url || '')

              if (isIncidentUpdate && writeToken) {
                proxyReq.setHeader('X-Morpheus-Write-Token', writeToken)
              }
            })
          },
        },
      },
    },
  }
})
