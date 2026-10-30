// Encryption key status + re-encryption, shared by the SysAdmin API
// (Admin > Encryption Keys) and the CLI (npm run key:status / key:reencrypt).
//
// These are the only operations that need EVERY child row, so each one runs
// as the explicit 'System' identity (db.runAsSystem) -- row-level security
// otherwise shows a SysAdmin no child data at all. Values are only ever
// decrypted here to re-encrypt or verify them; nothing is returned.
const crypto = require('crypto');
const db = require('../config/db');
const { encryptField, decryptField, keyIdOf, loadKeys, activeKeyId } = require('../utils/encryption');

// Every encrypted column in the schema. Add here if a new *_enc column is
// ever introduced, or rotation will silently skip it.
const ENCRYPTED_COLUMNS = {
  child_identifiers: ['full_name_enc', 'date_of_birth_enc', 'family_background_enc'],
  developmental_records: ['milestone_enc', 'health_indicator_enc', 'assessment_score_enc', 'progress_notes_enc'],
};

// Short, non-reversible identifier so people can tell keys apart without
// ever seeing key material.
function fingerprint(key) {
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);
}

function getStatus() {
  return db.runAsSystem(getStatusAsSystem);
}

async function getStatusAsSystem() {
  const keys = loadKeys();
  const active = activeKeyId(keys);
  const counts = {};

  for (const [table, cols] of Object.entries(ENCRYPTED_COLUMNS)) {
    const { rows } = await db.query(`SELECT ${cols.join(', ')} FROM ${table}`);
    for (const row of rows) {
      for (const col of cols) {
        if (!row[col]) continue;
        const id = keyIdOf(row[col]);
        counts[id] = (counts[id] || 0) + 1;
      }
    }
  }

  const keyList = [...keys.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([id, key]) => ({
      id,
      fingerprint: fingerprint(key),
      active: id === active,
      encryptedValues: counts[id] || 0,
    }));

  // Values pointing at a key id that isn't configured any more -- these
  // can't be read until that key is restored.
  const missing = Object.keys(counts)
    .map(Number)
    .filter((id) => !keys.has(id))
    .map((id) => ({ id, encryptedValues: counts[id] }));

  const totalValues = Object.values(counts).reduce((a, b) => a + b, 0);
  const needsReencryption = totalValues - (counts[active] || 0);

  return { activeKeyId: active, keys: keyList, missingKeys: missing, totalValues, needsReencryption };
}

// Re-encrypts every value not already on the active key, all-or-nothing:
// one transaction, rows locked while they're rewritten, rolled back
// entirely if any single value fails to decrypt (so a half-rotated
// database can't happen). Each value is decrypted and re-checked before
// the row is written.
function reencryptAll() {
  return db.runAsSystem(reencryptAllAsSystem);
}

async function reencryptAllAsSystem() {
  const keys = loadKeys();
  const active = activeKeyId(keys);
  let updatedValues = 0;
  let updatedRows = 0;

  await db.transaction(async (client) => {
    for (const [table, cols] of Object.entries(ENCRYPTED_COLUMNS)) {
      const { rows } = await client.query(`SELECT id, ${cols.join(', ')} FROM ${table} FOR UPDATE`);
      for (const row of rows) {
        const sets = [];
        const values = [];
        for (const col of cols) {
          const current = row[col];
          if (!current || keyIdOf(current) === active) continue;
          const plaintext = decryptField(current);
          const rewritten = encryptField(plaintext, { keyId: active });
          if (decryptField(rewritten) !== plaintext) {
            throw new Error(`Round-trip check failed for ${table}.${col} id=${row.id}`);
          }
          values.push(rewritten);
          sets.push(`${col} = $${values.length}`);
        }
        if (sets.length === 0) continue;
        values.push(row.id);
        await client.query(`UPDATE ${table} SET ${sets.join(', ')} WHERE id = $${values.length}`, values);
        updatedValues += sets.length;
        updatedRows += 1;
      }
    }
  });

  return { activeKeyId: active, updatedRows, updatedValues };
}

// Decrypts every stored value (results discarded) -- proves the configured
// keys can still read all child data, e.g. before retiring an old key.
function verifyAll() {
  return db.runAsSystem(verifyAllAsSystem);
}

async function verifyAllAsSystem() {
  let ok = 0;
  const failures = [];
  for (const [table, cols] of Object.entries(ENCRYPTED_COLUMNS)) {
    const { rows } = await db.query(`SELECT id, ${cols.join(', ')} FROM ${table}`);
    for (const row of rows) {
      for (const col of cols) {
        if (!row[col]) continue;
        try {
          decryptField(row[col]);
          ok += 1;
        } catch (err) {
          failures.push({ table, column: col, id: row.id, error: err.message });
        }
      }
    }
  }
  return { ok, failures };
}

module.exports = { getStatus, reencryptAll, verifyAll, ENCRYPTED_COLUMNS, fingerprint };
