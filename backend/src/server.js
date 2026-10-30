require('dotenv').config();
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const app = require('./app');

const PORT = process.env.PORT || 4000;

// Data in transit: HTTPS with TLS 1.3 only (older protocol versions are
// refused at the handshake). Turned on by TLS_CERT_FILE + TLS_KEY_FILE in
// .env -- see `npm run cert:new`. If they're set but the files are missing
// the server refuses to start rather than quietly falling back to HTTP.
const certFile = process.env.TLS_CERT_FILE;
const keyFile = process.env.TLS_KEY_FILE;

let server;
let scheme;
if (certFile && keyFile) {
  const resolve = (p) => path.resolve(__dirname, '..', p);
  try {
    server = https.createServer(
      { cert: fs.readFileSync(resolve(certFile)), key: fs.readFileSync(resolve(keyFile)), minVersion: 'TLSv1.3' },
      app
    );
  } catch (err) {
    console.error(`TLS is configured but the certificate could not be loaded (${err.message}). Run \`npm run cert:new\` in backend/, or remove TLS_CERT_FILE/TLS_KEY_FILE from .env to run over plain HTTP.`);
    process.exit(1);
  }
  scheme = 'https';
} else {
  console.warn('WARNING: TLS_CERT_FILE/TLS_KEY_FILE not set -- serving over plain HTTP. Data in transit is NOT encrypted.');
  server = http.createServer(app);
  scheme = 'http';
}

server.listen(PORT, () => {
  console.log(`Backend listening on ${scheme}://localhost:${PORT}`);
});
