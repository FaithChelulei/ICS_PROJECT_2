// npm run key:new
// Generates a fresh 256-bit key and writes it straight into backend/.env
// as the next ENCRYPTION_KEY_<n>, and makes it the active key. The key is
// never printed, so it doesn't end up in terminal history or screenshots.
// After running: restart the backend, then re-encrypt existing data
// (Admin > Encryption Keys > Re-encrypt, or npm run key:reencrypt).
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');
if (!fs.existsSync(envPath)) {
  console.error('backend/.env not found -- copy .env.example to .env first.');
  process.exit(1);
}

const original = fs.readFileSync(envPath, 'utf8');
const lines = original.split(/\r?\n/);

let highest = 0;
for (const line of lines) {
  if (/^ENCRYPTION_KEY=/.test(line)) highest = Math.max(highest, 1);
  const m = /^ENCRYPTION_KEY_(\d+)=/.exec(line);
  if (m) highest = Math.max(highest, Number(m[1]));
}
const nextId = highest + 1;
if (nextId > 255) {
  console.error('Key ids go up to 255 -- retire old keys from .env first.');
  process.exit(1);
}

const newKey = crypto.randomBytes(32).toString('base64');
const newVar = nextId === 1 ? 'ENCRYPTION_KEY' : `ENCRYPTION_KEY_${nextId}`;

const kept = lines.filter((l) => !/^ENCRYPTION_ACTIVE_KEY_ID=/.test(l));
while (kept.length && kept[kept.length - 1] === '') kept.pop();
kept.push('', `# Added by npm run key:new on ${new Date().toISOString()}`, `${newVar}=${newKey}`, `ENCRYPTION_ACTIVE_KEY_ID=${nextId}`, '');

fs.writeFileSync(envPath, kept.join('\n'));
console.log(`Added encryption key #${nextId} to backend/.env and made it the active key.`);
console.log('Next: restart the backend, then re-encrypt existing data:');
console.log('  Admin > Encryption Keys > "Re-encrypt to active key"   (or: npm run key:reencrypt)');
console.log('Once the status shows 0 values on an old key, you can delete that key from .env.');
