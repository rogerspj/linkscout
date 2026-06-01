import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite is the build tool and dev server for the frontend.
// It handles JSX transformation, hot module reloading, and the dev server.
// The default dev server port is 5173 — the FastAPI CORS config whitelists this.
export default defineConfig({
  plugins: [react()],
})
