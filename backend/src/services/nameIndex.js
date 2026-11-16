// Blind index of children's names (db/012_educator_asks_by_name.sql).
//
// Names are stored encrypted with AES-256-GCM and a fresh random IV, so the
// same name never looks the same twice and the database cannot search it.
// To let an educator's request find "Amani Wanjiru" WITHOUT decrypting every
// child, each child also stores a keyed fingerprint of the normalised name:
//
//     name_index = HMAC-SHA256(indexKey, normalise(fullName))
//
// The index key is derived (HKDF) from a data-encryption key, so it is as
// well protected as the data itself (unlocked from Azure Key Vault at
// start-up), and nobody holding only the database can test guesses. The key
// id is stored beside the fingerprint; a lookup tries every configured key,
// and start-up re-indexes rows made under a key that is no longer active.
const crypto = require('crypto');
const db = require('../config/db');
const { loadKeys, activeKeyId, decryptField } = require('../utils/encryption');

// "  amani  WANJIRU " and "Wanjiru Amani" are the same child's name: case,
// spacing, punctuation and the order of the names are ignored.
function normaliseName(name) {
  return String(name || '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\s]/gu, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .sort()
    .join(' ');
}

const keyCache = new Map();
function indexKey(keyId) {
  const dataKey = loadKeys().get(keyId);
  if (!dataKey) throw new Error(`No encryption key #${keyId} for the name index`);
  const cacheKey = `${keyId}:${dataKey.toString('base64')}`;
  if (!keyCache.has(cacheKey)) {
    keyCache.set(cacheKey, Buffer.from(crypto.hkdfSync('sha256', dataKey, 'childguard', 'child-name-index-v1', 32)));
  }
  return keyCache.get(cacheKey);
}

function fingerprint(name, keyId) {
  return crypto.createHmac('sha256', indexKey(keyId)).update(normaliseName(name), 'utf8').digest('hex');
}

// For storing: the fingerprint under the key new data uses.
function nameIndexFor(name) {
  const keyId = activeKeyId();
  return { nameIndex: fingerprint(name, keyId), keyId };
}

// For looking up: one fingerprint per configured key.
function lookupPairs(name) {
  return [...loadKeys().keys()].map((keyId) => ({ keyId, nameIndex: fingerprint(name, keyId) }));
}

// Fills in missing fingerprints (profiles made before 012) and redoes those
// made under a key that is no longer the active one. Skips anonymised
// profiles: their identity is gone and must not be findable.
async function backfillNameIndex() {
  const active = activeKeyId();
  return db.runAsSystem(async () => {
    const { rows } = await db.query(
      `SELECT ci.child_profile_id, ci.full_name_enc
       FROM child_identifiers ci JOIN child_profiles cp ON cp.id = ci.child_profile_id
       WHERE cp.identity_anonymised_at IS NULL
         AND (ci.name_index IS NULL OR ci.name_index_key_id IS DISTINCT FROM $1)`, [active]);
    for (const r of rows) {
      const { nameIndex, keyId } = nameIndexFor(decryptField(r.full_name_enc));
      await db.query('UPDATE child_identifiers SET name_index = $1, name_index_key_id = $2 WHERE child_profile_id = $3',
        [nameIndex, keyId, r.child_profile_id]);
    }
    return rows.length;
  });
}

module.exports = { normaliseName, nameIndexFor, lookupPairs, backfillNameIndex };
