// npm run key:wrap   -- moves every PLAIN encryption key in backend/.env
//                       under Azure Key Vault protection: wraps it with the
//                       vault's master key, proves the vault can unwrap it
//                       again, then replaces the plain line with
//                       ENCRYPTION_KEY_<n>_WRAPPED. Keys are never printed.
// npm run key:check  -- asks the vault to unwrap the stored keys, to prove
//                       this machine / identity can start the backend.
//
// Needs KEY_VAULT_URL and KEY_VAULT_KEY_NAME in backend/.env and an Azure
// identity with "Key Vault Crypto User" on the vault (e.g. `az login`).
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { wrapKey, unlockKeys, vaultConfigured } = require('../src/utils/keyVault');

const envPath = path.join(__dirname, '..', '.env');

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a.trim()); }));
}

async function wrapAll() {
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  const plain = lines
    .map((line, i) => ({ i, m: /^(ENCRYPTION_KEY(?:_(\d+))?)=(.+)$/.exec(line) }))
    .filter((x) => x.m)
    .map(({ i, m }) => ({ i, name: m[1], id: m[2] ? Number(m[2]) : 1, value: m[3].trim() }));
  if (plain.length === 0) {
    console.log('No plain encryption keys in backend/.env -- nothing to wrap.');
    return;
  }

  console.log(`Found ${plain.length} plain key(s): ${plain.map((p) => `#${p.id}`).join(', ')}.`);
  console.log('After wrapping, the plain key is DELETED from .env. If the vault or its master key were ever');
  console.log('deleted, the wrapped key could not be opened -- so keep an offline backup of the plain key');
  console.log('(e.g. in a password manager) BEFORE continuing.');
  if ((await ask('Type YES once the plain key is backed up somewhere safe: ')) !== 'YES') {
    console.log('Cancelled -- nothing changed.');
    return;
  }

  for (const p of plain) {
    const raw = Buffer.from(p.value, 'base64');
    if (raw.length !== 32) throw new Error(`${p.name} is not a 32-byte base64 key -- nothing changed`);
    lines[p.i] = `ENCRYPTION_KEY_${p.id}_WRAPPED=${await wrapKey(raw)}`; // round-trip checked inside
    console.log(`  key #${p.id}: wrapped and verified`);
  }
  fs.writeFileSync(envPath, lines.join('\n'));
  console.log('Done: .env now holds only wrapped keys. Restart the backend; it will unlock them via Key Vault.');
}

(async () => {
  if (!vaultConfigured()) throw new Error('Set KEY_VAULT_URL and KEY_VAULT_KEY_NAME in backend/.env first.');
  if (process.argv[2] === 'wrap') {
    await wrapAll();
  } else {
    const n = await unlockKeys();
    console.log(n ? `Key Vault unwrapped ${n} key(s) for this identity -- the backend can start.` : 'No wrapped keys in .env yet (run npm run key:wrap).');
  }
})().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
