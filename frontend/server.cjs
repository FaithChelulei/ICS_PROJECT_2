// Serves the built website (dist/) when it is hosted, e.g. on Azure App
// Service:  node server.cjs  (no packages needed). Not used on a laptop,
// where `npm run dev` serves the site.
//
// Every response carries security headers: a Content-Security-Policy that
// only lets the page talk to its own backend (API_ORIGIN) and load the
// Google fonts it uses, no framing (clickjacking), no MIME sniffing, and
// HSTS so browsers only ever come back over HTTPS. Any path that is not a
// file gets index.html, so the React routes (/caregiver, /auditor, ...)
// work when opened or refreshed directly.
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, 'dist');
const PORT = process.env.PORT || 8080;
const API_ORIGIN = process.env.API_ORIGIN || '';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon',
  '.json': 'application/json', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8',
};

const CSP = [
  "default-src 'self'",
  `connect-src 'self' ${API_ORIGIN}`.trim(),
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const HEADERS = {
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

http.createServer((req, res) => {
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { urlPath = '/'; }
  let file = path.normalize(path.join(ROOT, urlPath));
  if (!file.startsWith(ROOT)) file = path.join(ROOT, 'index.html');
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) file = path.join(ROOT, 'index.html');
    const ext = path.extname(file);
    // Built assets have content hashes in their names: cache them; never cache index.html.
    const cache = file.includes(`${path.sep}assets${path.sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache';
    res.writeHead(200, { ...HEADERS, 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': cache });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}).listen(PORT, () => console.log(`Website on port ${PORT}`));
