import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // strictPort: the backend's CORS policy only allows this exact origin
  // (FRONTEND_ORIGIN in backend/.env). Silently falling back to 5174 when
  // 5173 is busy would load the page but fail every API call, so fail
  // loudly instead.
  server: { port: 5173, strictPort: true },
});
