// npm run key:status      -- which keys exist, which is active, how many
//                            encrypted values use each one
// npm run key:reencrypt   -- move every value onto the active key
// npm run key:verify      -- decrypt every value to prove all keys needed are present
// Same logic the Admin > Encryption Keys page uses. Prints ids and
// fingerprints only, never key material.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const db = require('../src/config/db');
const { getStatus, reencryptAll, verifyAll } = require('../src/services/keyRotation');

function printStatus(s) {
  console.log(`Active key: #${s.activeKeyId}`);
  for (const k of s.keys) {
    console.log(`  key #${k.id}  fp ${k.fingerprint}  ${k.active ? '(active)' : '        '}  ${k.encryptedValues} value(s)`);
  }
  for (const k of s.missingKeys) {
    console.log(`  key #${k.id}  NOT CONFIGURED  ${k.encryptedValues} value(s) unreadable until it is restored`);
  }
  console.log(`${s.totalValues} encrypted value(s); ${s.needsReencryption} not yet on the active key.`);
}

(async () => {
  const cmd = process.argv[2];
  if (cmd === 'reencrypt') {
    const r = await reencryptAll();
    console.log(`Re-encrypted ${r.updatedValues} value(s) in ${r.updatedRows} row(s) to key #${r.activeKeyId}.`);
  }
  if (cmd === 'verify' || cmd === 'reencrypt') {
    const v = await verifyAll();
    console.log(`Verified: ${v.ok} value(s) decrypt correctly, ${v.failures.length} failure(s).`);
    for (const f of v.failures) console.log(`  FAIL ${f.table}.${f.column} id=${f.id}: ${f.error}`);
    if (v.failures.length) process.exitCode = 1;
  }
  printStatus(await getStatus());
  await db.pool.end();
})().catch(async (err) => {
  console.error('Failed:', err.message);
  try { await db.pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
