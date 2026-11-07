// npm run key:new
// Generates a fresh 256-bit key and writes it straight into backend/.env
// as the next key id, and makes it the active key. The key is never
// printed, so it doesn't end up in terminal history or screenshots.
//   - With Azure Key Vault configured (KEY_VAULT_URL + KEY_VAULT_KEY_NAME),
//     only the WRAPPED key is written (ENCRYPTION_KEY_<n>_WRAPPED); the
//     plain key exists in memory just long enough to be wrapped.
//   - Without it, the plain key is written (ENCRYPTION_KEY_<n>), for local
//     development.
// After running: restart the backend, then re-encrypt existing data
// (Admin > Encryption Keys > Re-encrypt, or npm run key:reencrypt).
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { wrapKey, vaultConfigured } = require('../src/utils/keyVault');

const envPath = path.join(__dirname, '..', '.env');

(async () => {
  if (!fs.existsSync(envPath)) throw new Error('backend/.env not found -- copy .env.example to .env first.');
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);

  let highest = 0;
  for (const line of lines) {
    if (/^ENCRYPTION_KEY=/.test(line)) highest = Math.max(highest, 1);
    const m = /^ENCRYPTION_KEY_(\d+)(?:_WRAPPED)?=/.exec(line);
    if (m) highest = Math.max(highest, Number(m[1]));
  }
  const nextId = highest + 1;
  if (nextId > 255) throw new Error('Key ids go up to 255 -- retire old keys from .env first.');

  const raw = crypto.randomBytes(32);
  const useVault = vaultConfigured();
  const line = useVault
    ? `ENCRYPTION_KEY_${nextId}_WRAPPED=${await wrapKey(raw)}`
    : `${nextId === 1 ? 'ENCRYPTION_KEY' : `ENCRYPTION_KEY_${nextId}`}=${raw.toString('base64')}`;

  const kept = lines.filter((l) => !/^ENCRYPTION_ACTIVE_KEY_ID=/.test(l));
  while (kept.length && kept[kept.length - 1] === '') kept.pop();
  kept.push('', `# Added by npm run key:new on ${new Date().toISOString()}`, line, `ENCRYPTION_ACTIVE_KEY_ID=${nextId}`, '');
  fs.writeFileSync(envPath, kept.join('\n'));

  console.log(`Added encryption key #${nextId} to backend/.env${useVault ? ', wrapped by Azure Key Vault,' : ''} and made it the active key.`);
  console.log('Next: restart the backend, then re-encrypt existing data:');
  console.log('  Admin > Encryption Keys > "Re-encrypt to active key"   (or: npm run key:reencrypt)');
  console.log('Once the status shows 0 values on an old key, you can delete that key from .env.');
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
