import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    // Proxy API calls so /api/* → http://api:8000/*
    // This avoids CORS issues during development inside Docker
    proxy: {
      '/api': {
        target: 'http://api:8000',
        changeOrigin: true,
        ws: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
