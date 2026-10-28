// Unit tests for key-versioned AES-256-GCM (no database, no server).
// Run: node --test test/encryption.test.js
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const K1 = crypto.randomBytes(32).toString('base64');
const K2 = crypto.randomBytes(32).toString('base64');

function setKeys(env) {
  for (const name of Object.keys(process.env)) {
    if (/^ENCRYPTION_(KEY|KEY_\d+|ACTIVE_KEY_ID)$/.test(name)) delete process.env[name];
  }
  Object.assign(process.env, env);
}

const { encryptField, decryptField, keyIdOf } = require('../src/utils/encryption');

// The pre-versioning format: iv || ciphertext || tag, with key #1.
function legacyEncrypt(text, b64key) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(b64key, 'base64'), iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}

test('round-trips with a single key', () => {
  setKeys({ ENCRYPTION_KEY: K1 });
  const enc = encryptField('Amara Osei');
  assert.strictEqual(keyIdOf(enc), 1);
  assert.strictEqual(decryptField(enc), 'Amara Osei');
});

test('values written before versioning still decrypt', () => {
  setKeys({ ENCRYPTION_KEY: K1, ENCRYPTION_KEY_2: K2 });
  const legacy = legacyEncrypt('2021-03-14', K1);
  assert.strictEqual(decryptField(legacy), '2021-03-14');
  assert.strictEqual(keyIdOf(legacy), 1);
});

test('new values use the highest key unless ENCRYPTION_ACTIVE_KEY_ID says otherwise', () => {
  setKeys({ ENCRYPTION_KEY: K1, ENCRYPTION_KEY_2: K2 });
  assert.strictEqual(keyIdOf(encryptField('x')), 2);
  setKeys({ ENCRYPTION_KEY: K1, ENCRYPTION_KEY_2: K2, ENCRYPTION_ACTIVE_KEY_ID: '1' });
  assert.strictEqual(keyIdOf(encryptField('x')), 1);
});

test('old values stay readable after a new key is added, and new-key values after the old one is retired', () => {
  setKeys({ ENCRYPTION_KEY: K1 });
  const old = encryptField('before rotation');
  setKeys({ ENCRYPTION_KEY: K1, ENCRYPTION_KEY_2: K2 });
  const fresh = encryptField('after rotation');
  assert.strictEqual(decryptField(old), 'before rotation');
  setKeys({ ENCRYPTION_KEY_2: K2 }); // key #1 retired
  assert.strictEqual(decryptField(fresh), 'after rotation');
  assert.throws(() => decryptField(old), /key #1|not configured/);
});

test('tampering is detected', () => {
  setKeys({ ENCRYPTION_KEY: K1 });
  const enc = encryptField('Developmental milestone');
  enc[enc.length - 20] ^= 0xff;
  assert.throws(() => decryptField(enc));
});

test('each encryption uses a fresh IV', () => {
  setKeys({ ENCRYPTION_KEY: K1 });
  assert.notDeepStrictEqual(encryptField('same'), encryptField('same'));
});

test('a misconfigured active key id is refused', () => {
  setKeys({ ENCRYPTION_KEY: K1, ENCRYPTION_ACTIVE_KEY_ID: '7' });
  assert.throws(() => encryptField('x'), /ENCRYPTION_ACTIVE_KEY_ID/);
});
