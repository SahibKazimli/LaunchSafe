import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: '.',
  server: {
    port: 5173,
    proxy: {
      '/start-scan': 'http://localhost:8000',
      '/scan-status': 'http://localhost:8000',
      '/api': 'http://localhost:8000',
      '/start-fix': 'http://localhost:8000',
      '/fix-status': 'http://localhost:8000',
      '/fix-patches': 'http://localhost:8000',
      '/debug': 'http://localhost:8000',
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
