import fs from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Same local certificate as the backend (made by `npm run cert:new` in
// backend/), so the app is served over HTTPS with TLS 1.3 only. If the
// certificate hasn't been made yet, falls back to plain HTTP -- in that case
// also point VITE_API_BASE_URL and the backend's FRONTEND_ORIGIN at http.
const certDir = new URL('../backend/certs/', import.meta.url);
const certFile = new URL('localhost-cert.pem', certDir);
const keyFile = new URL('localhost-key.pem', certDir);
const https =
  fs.existsSync(certFile) && fs.existsSync(keyFile)
    ? { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile), minVersion: 'TLSv1.3' }
    : undefined;

export default defineConfig({
  plugins: [react()],
  // strictPort: the backend's CORS policy only allows this exact origin
  // (FRONTEND_ORIGIN in backend/.env). Silently falling back to 5174 when
  // 5173 is busy would load the page but fail every API call, so fail
  // loudly instead.
  server: { port: 5173, strictPort: true, https },
});
