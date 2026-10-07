// AES-256-GCM encryption for every child record field stored at rest
// (proposal 3.6.3: "AES-256 encryption for all child records in the
// PostgreSQL database"). GCM gives us both confidentiality and a built-in
// tamper check (the auth tag) — a modified ciphertext fails to decrypt
// instead of silently returning garbage.
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

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

// Encrypts one plaintext string. Returns the pieces the schema stores:
// ciphertext + IV, each as a Buffer (BYTEA columns). The GCM auth tag is
// appended to the ciphertext so one BYTEA column is enough to hold both.
function encryptField(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12); // 96-bit IV, the GCM standard size
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: Buffer.concat([ciphertext, authTag]), // stored in *_enc
    iv,                                                // stored in enc_iv
  };
}

// Reverses encryptField. Throws if the ciphertext was tampered with or the
// wrong key/IV is used — that's GCM's auth tag doing its job, not a bug.
function decryptField(ciphertextWithTag, iv) {
  const key = getKey();
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

module.exports = { encryptField, decryptField };
