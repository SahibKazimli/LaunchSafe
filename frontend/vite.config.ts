import { defineConfig } from 'vite';
import { resolve } from 'path';

/** Dev API: run `uvicorn main:app --reload` from `backend/` on port 8000. */
const API_ORIGIN = 'http://localhost:8000';

function proxyToApi() {
  return { target: API_ORIGIN, changeOrigin: true };
}

export default defineConfig({
  root: '.',
  server: {
    port: 5173,
    proxy: {
      '/start-scan': proxyToApi(),
      '/scan-status': proxyToApi(),
      '/api': proxyToApi(),
      '/start-fix': proxyToApi(),
      '/fix-status': proxyToApi(),
      '/fix-patches': proxyToApi(),
      '/debug': proxyToApi(),
    },
  },
  plugins: [{
    name: 'page-routes',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const url = req.url || '';
        if (/^\/scan\/[^/]+/.test(url)) req.url = '/scan.html';
        else if (/^\/report\/[^/]+/.test(url)) req.url = '/report.html';
        else if (/^\/fix\/[^/]+/.test(url)) req.url = '/fix.html';
        next();
      });
    },
  }],
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        scan: resolve(__dirname, 'scan.html'),
        report: resolve(__dirname, 'report.html'),
        fix: resolve(__dirname, 'fix.html'),
      },
    },
  },
});
