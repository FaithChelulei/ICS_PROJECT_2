// npm run cert:new -- makes the local TLS certificate the backend (and the
// Vite dev server) serve HTTPS with. Writes backend/certs/localhost-cert.pem
// and localhost-key.pem; certs/ is gitignored, the key never leaves this
// machine.
//
// The certificate is only valid for localhost / 127.0.0.1 and is marked
// CA:FALSE, so trusting it (npm run cert:trust) lets the browser accept
// THIS server without letting the cert vouch for any other site.
//
// Needs OpenSSL. On Windows it ships with Git for Windows, which is checked
// as a fallback when `openssl` isn't on PATH.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CERT_DIR = path.join(__dirname, '..', 'certs');
const KEY = path.join(CERT_DIR, 'localhost-key.pem');
const CERT = path.join(CERT_DIR, 'localhost-cert.pem');

function findOpenssl() {
  const candidates = [
    'openssl',
    'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
  ];
  for (const bin of candidates) {
    try {
      execFileSync(bin, ['version'], { stdio: 'ignore' });
      return bin;
    } catch { /* try the next one */ }
  }
  throw new Error('OpenSSL not found. Install Git for Windows (it includes OpenSSL) or add openssl to PATH.');
}

if (fs.existsSync(CERT) && !process.argv.includes('--force')) {
  console.log(`Certificate already exists: ${CERT}\nRe-run with --force to replace it (then run cert:trust again).`);
  process.exit(0);
}

fs.mkdirSync(CERT_DIR, { recursive: true });
execFileSync(findOpenssl(), [
  'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
  '-days', '825', // the longest validity browsers accept for a server cert
  '-subj', '/CN=localhost',
  '-keyout', KEY,
  '-out', CERT,
  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  '-addext', 'basicConstraints=critical,CA:FALSE',
  '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
  '-addext', 'extendedKeyUsage=serverAuth',
], { stdio: ['ignore', 'ignore', 'inherit'] });

console.log(`Created ${CERT}\n        ${KEY}\nNext: npm run cert:trust (once), then restart the backend and frontend.`);
