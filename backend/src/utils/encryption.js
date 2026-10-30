// AES-256-GCM encryption for every child record field stored at rest
// (proposal 3.6.3: "AES-256 encryption for all child records in the
// PostgreSQL database"). GCM gives us both confidentiality and a built-in
// tamper check (the auth tag) — a modified ciphertext fails to decrypt
// instead of silently returning garbage.
//
// Each field gets its OWN random IV, bundled into the same buffer as the
// ciphertext, so no IV is ever reused across fields.
//
// KEY VERSIONING (proposal 3.6.3: key storage and rotation). Several keys
// can be configured at once, each with a numeric id:
//   ENCRYPTION_KEY       -> key #1 (the original variable name)
//   ENCRYPTION_KEY_2     -> key #2, ENCRYPTION_KEY_3 -> key #3, ...
//   ENCRYPTION_ACTIVE_KEY_ID (optional) -> which key NEW data uses;
//                           defaults to the highest id configured.
// Every new value is written as:
//   "CGK" (3-byte marker) | key id (1 byte) | IV (12) | ciphertext | tag (16)
// so it always says which key decrypts it. Values written before
// versioning existed have no marker and were encrypted with key #1; they
// still decrypt. Rotating = add a new key, make it active, then re-encrypt
// existing rows (see services/keyRotation.js) so the old key can be retired.
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV, the GCM standard size
const TAG_LENGTH = 16;
const MARKER = Buffer.from('CGK', 'ascii');
const HEADER_LENGTH = MARKER.length + 1;
const LEGACY_KEY_ID = 1;

function decodeKey(name, value) {
  const key = Buffer.from(value || '', 'base64');
  if (key.length !== 32) {
    throw new Error(
      `${name} must decode to exactly 32 bytes. Generate a new key with: npm run key:new`
    );
  }
  return key;
}

// Read fresh from process.env each call (cheap), so tests and the rotation
// script see the current configuration.
function loadKeys() {
  const keys = new Map();
  if (process.env.ENCRYPTION_KEY) {
    keys.set(LEGACY_KEY_ID, decodeKey('ENCRYPTION_KEY', process.env.ENCRYPTION_KEY));
  }
  for (const [name, value] of Object.entries(process.env)) {
    const m = /^ENCRYPTION_KEY_(\d+)$/.exec(name);
    if (!m) continue;
    const id = Number(m[1]);
    if (id < 1 || id > 255) throw new Error(`${name}: key ids must be 1-255`);
    keys.set(id, decodeKey(name, value));
  }
  if (keys.size === 0) {
    throw new Error('No encryption key configured. Set ENCRYPTION_KEY in backend/.env (generate one with: npm run key:new).');
  }
  return keys;
}

function activeKeyId(keys = loadKeys()) {
  const configured = process.env.ENCRYPTION_ACTIVE_KEY_ID;
  const id = configured ? Number(configured) : Math.max(...keys.keys());
  if (!keys.has(id)) {
    throw new Error(`ENCRYPTION_ACTIVE_KEY_ID=${configured} but no key with that id is configured`);
  }
  return id;
}

function gcmDecrypt(key, iv, ciphertext, authTag) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// Which key a stored value was encrypted with: its marker byte, or
// LEGACY_KEY_ID for pre-versioning values.
function keyIdOf(bundle) {
  if (bundle.length > HEADER_LENGTH + IV_LENGTH + TAG_LENGTH && bundle.subarray(0, MARKER.length).equals(MARKER)) {
    return bundle[MARKER.length];
  }
  return LEGACY_KEY_ID;
}

// Encrypts one plaintext string with the active key (or an explicit key
// id, used by tests). Returns one Buffer ready for a BYTEA column.
function encryptField(plaintext, { keyId } = {}) {
  const keys = loadKeys();
  const id = keyId || activeKeyId(keys);
  const key = keys.get(id);
  if (!key) throw new Error(`No encryption key with id ${id} is configured`);

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([MARKER, Buffer.from([id]), iv, ciphertext, authTag]);
}

// Reverses encryptField, for both versioned and legacy values. Throws if
// the value was tampered with or its key is no longer configured — that's
// GCM's auth tag doing its job, not a bug.
function decryptField(bundle) {
  const keys = loadKeys();
  const hasMarker =
    bundle.length > HEADER_LENGTH + IV_LENGTH + TAG_LENGTH &&
    bundle.subarray(0, MARKER.length).equals(MARKER);

  if (hasMarker) {
    const id = bundle[MARKER.length];
    const key = keys.get(id);
    if (key) {
      const body = bundle.subarray(HEADER_LENGTH);
      try {
        return gcmDecrypt(
          key,
          body.subarray(0, IV_LENGTH),
          body.subarray(IV_LENGTH, body.length - TAG_LENGTH),
          body.subarray(body.length - TAG_LENGTH)
        );
      } catch {
        // Either tampered, or a legacy value whose random IV happened to
        // start with "CGK" (~1 in 16 million) -- try it as legacy below.
      }
    }
  }

  const legacyKey = keys.get(LEGACY_KEY_ID);
  try {
    if (!legacyKey) throw new Error('no legacy key');
    return gcmDecrypt(
      legacyKey,
      bundle.subarray(0, IV_LENGTH),
      bundle.subarray(IV_LENGTH, bundle.length - TAG_LENGTH),
      bundle.subarray(bundle.length - TAG_LENGTH)
    );
  } catch {
    if (hasMarker && !keys.has(bundle[MARKER.length])) {
      throw new Error(`Value was encrypted with key #${bundle[MARKER.length]}, which is not configured`);
    }
    throw new Error('Decryption failed: the value was modified or its key is not configured');
  }
}

module.exports = { encryptField, decryptField, keyIdOf, loadKeys, activeKeyId, LEGACY_KEY_ID };
