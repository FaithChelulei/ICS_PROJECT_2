// AES-256-GCM encryption for every child record field stored at rest
// (proposal 3.6.3: "AES-256 encryption for all child records in the
// PostgreSQL database"). GCM gives us both confidentiality and a built-in
// tamper check (the auth tag) — a modified ciphertext fails to decrypt
// instead of silently returning garbage.
//
// IMPORTANT: each field gets its OWN random IV, bundled into the same
// buffer as the ciphertext (iv || ciphertext || authTag). Reusing one IV
// across multiple encrypted fields under the same key (the original design
// — one shared enc_iv column per row) breaks AES-GCM's security guarantees
// if that IV is ever reused, so each *_enc column is now fully
// self-contained and there is no separate enc_iv column.
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // 96-bit IV, the GCM standard size
const TAG_LENGTH = 16;

function getKey() {
  const key = Buffer.from(process.env.ENCRYPTION_KEY || '', 'base64');
  if (key.length !== 32) {
    throw new Error(
      'ENCRYPTION_KEY must decode to exactly 32 bytes. Generate one with: ' +
      `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
    );
  }
  return key;
}

// Encrypts one plaintext string. Returns a single Buffer: IV + ciphertext
// + auth tag, ready to store directly in one BYTEA column.
function encryptField(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, ciphertext, authTag]);
}

// Reverses encryptField. Throws if the ciphertext was tampered with or the
// wrong key is used — that's GCM's auth tag doing its job, not a bug.
function decryptField(bundle) {
  const key = getKey();
  const iv = bundle.subarray(0, IV_LENGTH);
  const authTag = bundle.subarray(bundle.length - TAG_LENGTH);
  const ciphertext = bundle.subarray(IV_LENGTH, bundle.length - TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

module.exports = { encryptField, decryptField };
