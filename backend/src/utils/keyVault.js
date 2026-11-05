// Envelope encryption with Azure Key Vault.
//
// The data-encryption keys (the AES-256 keys in encryption.js) are never
// stored in plain form. Each one is stored WRAPPED -- encrypted by a master
// key (the "key-encryption key") that lives inside Azure Key Vault and never
// leaves it:
//
//   ENCRYPTION_KEY_<n>_WRAPPED=<base64>   in .env / the host's settings
//
// At start-up the backend asks the vault to unwrap them (RSA-OAEP-256); the
// plain keys then exist only in this process's memory. A copy of .env, a
// backup, or the server's disk on its own is therefore useless: without
// the vault -- and an identity the vault trusts -- the wrapped keys can't
// be opened. Every unwrap is recorded in the vault's own logs.
//
// Turned on by KEY_VAULT_URL + KEY_VAULT_KEY_NAME. Without them, plain
// ENCRYPTION_KEY_<n> values in .env still work (local development).
//
// Who may unwrap: DefaultAzureCredential -- your `az login` session on this
// laptop, the app's managed identity once hosted on Azure. Grant it the
// "Key Vault Crypto User" role on the vault.
const ALGORITHM = 'RSA-OAEP-256';

// Plain keys unwrapped at start-up, by key id. Never written anywhere.
const unlocked = new Map();
let clientFactory = null;

function vaultConfigured() {
  return Boolean(process.env.KEY_VAULT_URL && process.env.KEY_VAULT_KEY_NAME);
}

// The vault's crypto client for the master key. Tests inject a stand-in.
async function cryptoClient() {
  if (clientFactory) return clientFactory();
  const { DefaultAzureCredential } = require('@azure/identity');
  const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
  const credential = new DefaultAzureCredential();
  const key = await new KeyClient(process.env.KEY_VAULT_URL, credential).getKey(process.env.KEY_VAULT_KEY_NAME);
  return new CryptographyClient(key, credential);
}

function wrappedKeyEntries(env = process.env) {
  const out = [];
  for (const [name, value] of Object.entries(env)) {
    const m = /^ENCRYPTION_KEY_(\d+)_WRAPPED$/.exec(name);
    if (m && value) out.push({ id: Number(m[1]), name, wrapped: Buffer.from(value, 'base64') });
  }
  return out;
}

// Call once at start-up (server, CLI tools) before anything encrypts or
// decrypts. Fails loudly -- refusing to start beats running without keys.
async function unlockKeys() {
  const entries = wrappedKeyEntries();
  if (entries.length === 0) return 0;
  if (!vaultConfigured()) {
    throw new Error('Wrapped encryption keys are configured but KEY_VAULT_URL / KEY_VAULT_KEY_NAME are not set.');
  }
  const client = await cryptoClient();
  for (const { id, name, wrapped } of entries) {
    let result;
    try {
      result = await client.unwrapKey(ALGORITHM, wrapped);
    } catch (err) {
      throw new Error(`Key Vault refused to unwrap ${name}: ${err.message}`);
    }
    const key = Buffer.from(result.result);
    if (key.length !== 32) throw new Error(`${name} unwrapped to ${key.length} bytes, expected 32`);
    unlocked.set(id, key);
  }
  return entries.length;
}

// Wraps a plain 32-byte key with the vault's master key (key:wrap, key:new).
async function wrapKey(rawKey) {
  const client = await cryptoClient();
  const { result } = await client.wrapKey(ALGORITHM, rawKey);
  // Prove the vault can open it again before anyone deletes the plain key.
  const back = Buffer.from((await client.unwrapKey(ALGORITHM, Buffer.from(result))).result);
  if (!back.equals(rawKey)) throw new Error('Key Vault round-trip check failed -- nothing was changed');
  return Buffer.from(result).toString('base64');
}

function unlockedKeys() {
  return unlocked;
}

// Tests only: use a stand-in vault, and forget unlocked keys.
function _setClientFactoryForTests(factory) {
  clientFactory = factory;
  unlocked.clear();
}

module.exports = { unlockKeys, wrapKey, unlockedKeys, vaultConfigured, wrappedKeyEntries, _setClientFactoryForTests };
