import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { qualityReportPlugin } from './dev/qualityPlugin.mjs';

export default defineConfig({
  // qualityReportPlugin: local test reports and runner, dev server only (TASKS P1-5)
  plugins: [react(), qualityReportPlugin()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
