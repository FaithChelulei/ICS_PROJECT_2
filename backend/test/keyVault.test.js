// Unit tests for envelope encryption (utils/keyVault.js) -- `npm test`.
// Azure Key Vault is replaced by a stand-in with the same wrapKey /
// unwrapKey interface, backed by a local RSA-OAEP-256 key pair, so the
// logic is proven without an Azure account.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const keyVault = require('../src/utils/keyVault');
const { encryptField, decryptField } = require('../src/utils/encryption');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const oaep = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
let refuse = false;
const standInVault = async () => ({
  wrapKey: async (alg, key) => ({ result: crypto.publicEncrypt({ key: publicKey, ...oaep }, key) }),
  unwrapKey: async (alg, wrapped) => {
    if (refuse) throw new Error('Forbidden: caller lacks Key Vault Crypto User');
    return { result: crypto.privateDecrypt({ key: privateKey, ...oaep }, wrapped) };
  },
});

const ENV_NAMES = ['KEY_VAULT_URL', 'KEY_VAULT_KEY_NAME', 'ENCRYPTION_KEY', 'ENCRYPTION_KEY_7', 'ENCRYPTION_KEY_7_WRAPPED', 'ENCRYPTION_ACTIVE_KEY_ID'];
function freshEnv(values) {
  for (const n of ENV_NAMES) delete process.env[n];
  Object.assign(process.env, values);
  refuse = false;
  keyVault._setClientFactoryForTests(standInVault);
}
const vault = { KEY_VAULT_URL: 'https://stand-in.vault.azure.net', KEY_VAULT_KEY_NAME: 'childguard-kek' };

test('wrapping returns something other than the key, and the vault can open it again', async () => {
  freshEnv(vault);
  const raw = crypto.randomBytes(32);
  const wrapped = Buffer.from(await keyVault.wrapKey(raw), 'base64');
  assert.ok(!wrapped.includes(raw), 'the wrapped value must not contain the plain key');
  const opened = Buffer.from((await (await standInVault()).unwrapKey('RSA-OAEP-256', wrapped)).result);
  assert.ok(opened.equals(raw));
});

test('a wrapped key unlocked at start-up encrypts and decrypts like a plain one', async () => {
  const raw = crypto.randomBytes(32);
  freshEnv(vault);
  const wrapped = await keyVault.wrapKey(raw);
  // Data written earlier with the PLAIN key...
  freshEnv({ ENCRYPTION_KEY_7: raw.toString('base64'), ENCRYPTION_ACTIVE_KEY_ID: '7' });
  const before = encryptField('Amani Otieno');
  // ...still reads after switching to the WRAPPED key.
  freshEnv({ ...vault, ENCRYPTION_KEY_7_WRAPPED: wrapped, ENCRYPTION_ACTIVE_KEY_ID: '7' });
  assert.strictEqual(await keyVault.unlockKeys(), 1);
  assert.strictEqual(decryptField(before), 'Amani Otieno');
  assert.strictEqual(decryptField(encryptField('2021-03-03')), '2021-03-03');
});

test('a wrapped key that was never unlocked refuses to be used', () => {
  freshEnv({ ...vault, ENCRYPTION_KEY_7_WRAPPED: 'AAAA', ENCRYPTION_ACTIVE_KEY_ID: '7' });
  assert.throws(() => encryptField('x'), /has not been unlocked/);
});

test('wrapped keys without the vault settings stop start-up', async () => {
  freshEnv({ ENCRYPTION_KEY_7_WRAPPED: 'AAAA' });
  await assert.rejects(keyVault.unlockKeys(), /KEY_VAULT_URL/);
});

test('if the vault refuses this identity, start-up stops (fail closed)', async () => {
  freshEnv(vault);
  const wrapped = await keyVault.wrapKey(crypto.randomBytes(32));
  freshEnv({ ...vault, ENCRYPTION_KEY_7_WRAPPED: wrapped });
  refuse = true;
  await assert.rejects(keyVault.unlockKeys(), /refused to unwrap ENCRYPTION_KEY_7_WRAPPED/);
});

test('the same key id configured both plain and wrapped is rejected', async () => {
  const raw = crypto.randomBytes(32);
  freshEnv(vault);
  const wrapped = await keyVault.wrapKey(raw);
  freshEnv({ ...vault, ENCRYPTION_KEY_7_WRAPPED: wrapped, ENCRYPTION_KEY_7: raw.toString('base64') });
  await keyVault.unlockKeys();
  assert.throws(() => encryptField('x'), /both plain .* and wrapped/);
});
