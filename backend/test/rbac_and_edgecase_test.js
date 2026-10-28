// End-to-end API checks against the RUNNING backend + ML service.
// Run from backend/:   npm run test:api   (backend on :4000, ML on :5001)
//
// Non-destructive: it never deletes or edits your real accounts or data.
// It uses three dedicated test accounts (created on first run, reused
// after) with MFA off and a fresh random password each run, and LOCKS them
// again at the end so they can't be signed into between runs. Their
// activity (one deliberately flagged session, one test child) stays in the
// audit trail under the "childguard.test" names -- the audit log is
// append-only by design, so nothing is cleaned up from it.
// Email: at most one risk-alert email, to a +test address of the SMTP inbox.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');
const { signRiskResponseToken } = require('../src/utils/riskResponseToken');

const BASE = 'http://127.0.0.1:4000';
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const testEmail = (tag) => `${inbox[0]}+childguard-test-${tag}@${inbox[1]}`;

const ACCOUNTS = {
  cg: { tag: 'caregiver', role: 'Caregiver', username: 'test.caregiver', name: 'Test Caregiver' },
  au: { tag: 'auditor', role: 'SecurityAuditor', username: 'test.auditor', name: 'Test Auditor' },
  ad: { tag: 'admin', role: 'SysAdmin', username: 'test.admin', name: 'Test Admin' },
};

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} - ${name}${detail ? ' :: ' + detail : ''}`);
}

async function ensureTestAccount(a) {
  const email = testEmail(a.tag);
  const hash = await bcrypt.hash(PASS, 10);
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [a.role]);
  const { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (rows[0]) {
    await db.query(
      `UPDATE users SET password_hash = $1, is_locked = FALSE, locked_reason = NULL,
              must_change_password = FALSE, mfa_required = FALSE WHERE id = $2`,
      [hash, rows[0].id]
    );
    return { ...a, email, id: rows[0].id };
  }
  const { rows: ins } = await db.query(
    `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password)
     VALUES ($1, $2, $3, $4, $5, FALSE, FALSE) RETURNING id`,
    [email, a.name, a.username, hash, roleRows[0].id]
  );
  return { ...a, email, id: ins[0].id };
}

async function lockTestAccounts() {
  await db.query(
    "UPDATE users SET is_locked = TRUE, locked_reason = 'automated test account (locked between runs)' WHERE email LIKE $1",
    [`${inbox[0]}+childguard-test-%@${inbox[1]}`]
  );
}

async function api(path, { method = 'GET', token, device, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (device) headers['X-Device-Name'] = device;
  const res = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html or empty */ }
  return { status: res.status, json, text };
}

async function login(identifier, device) {
  const r = await api('/auth/login', { method: 'POST', device, body: { identifier, password: PASS } });
  if (!r.json || !r.json.token) throw new Error(`login failed for ${identifier}: ${r.status} ${r.text}`);
  return r.json;
}

async function expectStatus(label, path, opts, expected) {
  const r = await api(path, opts);
  record(label, r.status === expected, `got ${r.status}, expected ${expected}`);
  return r;
}

async function main() {
  const health = await api('/health').catch(() => null);
  if (!health || health.status !== 200) throw new Error('Backend is not running on :4000 -- start it with npm run dev first.');
  const ml = await fetch('http://127.0.0.1:5001/health').catch(() => null);
  if (!ml || !ml.ok) throw new Error('ML service is not running on :5001 -- start ml/service/app.py first.');

  console.log('Preparing dedicated test accounts (your real accounts are not touched)...');
  const cgAcct = await ensureTestAccount(ACCOUNTS.cg);
  const auAcct = await ensureTestAccount(ACCOUNTS.au);
  const adAcct = await ensureTestAccount(ACCOUNTS.ad);

  console.log('\n=== Authentication ===');
  const wrong = await api('/auth/login', { method: 'POST', body: { identifier: cgAcct.email, password: 'wrong-password' } });
  record('Wrong password is rejected (401)', wrong.status === 401, `got ${wrong.status}`);

  const deviceA = 'test-device-A';
  const cg = await login(ACCOUNTS.cg.username, deviceA); // by USERNAME
  record('Login with username works', Boolean(cg.token));
  record('Login response carries fullName', cg.fullName === ACCOUNTS.cg.name, `fullName=${cg.fullName}`);
  const au = await login(auAcct.email); // by EMAIL
  record('Login with email works', Boolean(au.token));
  const ad = await login(adAcct.email);

  const me = await api('/auth/me', { token: cg.token, device: deviceA });
  record('/auth/me returns fullName', me.json && me.json.fullName === ACCOUNTS.cg.name, JSON.stringify(me.json));

  console.log('\n=== RBAC: each role against every other role\'s routes ===');
  await expectStatus('Caregiver -> auditor flagged sessions (403)', '/auditor/flagged-sessions', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> audit log (403)', '/auditor/audit-log', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> admin registration requests (403)', '/admin/registration-requests', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> admin locked users (403)', '/admin/users/locked', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> encryption status (403)', '/admin/encryption/status', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Auditor -> children (403)', '/children', { token: au.token }, 403);
  await expectStatus('Auditor -> create child (403)', '/children', { method: 'POST', token: au.token, body: { fullName: 'x', dateOfBirth: '2020-01-01' } }, 403);
  await expectStatus('Auditor -> admin registration requests (403)', '/admin/registration-requests', { token: au.token }, 403);
  await expectStatus('Auditor -> encryption re-encrypt (403)', '/admin/encryption/reencrypt', { method: 'POST', token: au.token }, 403);
  await expectStatus('Admin -> children (403)', '/children', { token: ad.token }, 403);
  await expectStatus('Admin -> auditor flagged sessions (403)', '/auditor/flagged-sessions', { token: ad.token }, 403);
  await expectStatus('Auditor -> own flagged sessions (200)', '/auditor/flagged-sessions?status=all', { token: au.token }, 200);
  await expectStatus('Auditor -> own audit log (200)', '/auditor/audit-log?limit=5', { token: au.token }, 200);
  await expectStatus('Admin -> own registration requests (200)', '/admin/registration-requests', { token: ad.token }, 200);
  await expectStatus('Admin -> own locked users (200)', '/admin/users/locked', { token: ad.token }, 200);
  await expectStatus('No token at all (401)', '/children', {}, 401);

  console.log('\n=== Caregiver: child profile, validation, consent ===');
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  await expectStatus('Future date of birth is rejected (400)', '/children',
    { method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'Future Child', dateOfBirth: tomorrow } }, 400);
  const created = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA,
    body: { fullName: 'Test Child', dateOfBirth: '2020-06-15', familyBackground: 'Automated test record' },
  });
  record('Caregiver creates child profile (201)', created.status === 201, `status=${created.status}`);
  record('Normal first action on a known device is NOT flagged', created.json && !created.json.riskNotice,
    created.json && created.json.riskNotice ? 'flagged' : 'not flagged');
  const childId = created.json && created.json.childProfileId;
  const list = await api('/children', { token: cg.token, device: deviceA });
  const mine = list.json && list.json.children.find((c) => c.childProfileId === childId);
  record('Child decrypts correctly in the list', mine && mine.fullName === 'Test Child' && mine.dateOfBirth === '2020-06-15');
  await expectStatus('Consent history is readable (200)', `/children/${childId}/consent`, { token: cg.token, device: deviceA }, 200);

  console.log('\n=== ML risk engine: same caregiver signs in from a NEW device ===');
  const deviceB = `test-device-B-${crypto.randomBytes(3).toString('hex')}`;
  const cg2 = await login(cgAcct.email, deviceB);
  const view = await api(`/children/${childId}/records`, { token: cg2.token, device: deviceB });
  record('Viewing records still succeeds (200)', view.status === 200, `status=${view.status}`);
  const flagged = Boolean(view.json && view.json.riskNotice);
  record('Action from an unrecognised device IS flagged', flagged, flagged ? 'riskNotice returned' : 'not flagged');

  let riskScoreId = null;
  if (flagged) {
    const after = await api('/children', { token: cg2.token, device: deviceB });
    record('Flagged session is revoked (next call 401)', after.status === 401, `status=${after.status}`);
    record('401 explains it was a risk sign-out', after.json && after.json.code === 'SESSION_REVOKED_RISK', after.json && after.json.code);
    const firstSession = await api('/children', { token: cg.token, device: deviceA });
    record('The other (device A) session is unaffected', firstSession.status === 200, `status=${firstSession.status}`);

    const { rows } = await db.query(
      `SELECT rs.id, rs.combined_score, rs.role_threshold FROM risk_scores rs
       JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE ar.user_id = $1 AND rs.is_flagged ORDER BY rs.created_at DESC LIMIT 1`,
      [cgAcct.id]
    );
    riskScoreId = rows[0].id;
    console.log(`     risk score ${Number(rows[0].combined_score).toFixed(3)} vs threshold ${rows[0].role_threshold}`);

    console.log('\n=== Security Auditor reviews it ===');
    const queue = await api('/auditor/flagged-sessions?status=pending', { token: au.token });
    record('Flagged session appears in the auditor queue', queue.json && queue.json.flaggedSessions.some((s) => s.risk_score_id === riskScoreId));
    await expectStatus('Auditor sets status=reviewing', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'reviewing' } }, 200);
    await expectStatus('Auditor rejects an invalid status (400)', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'bogus' } }, 400);
    await expectStatus('Auditor sets status=confirmed', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'confirmed' } }, 200);

    console.log('\n=== Owner\'s "This was me" link ===');
    const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
    const c1 = await api(`/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    record('Confirm link accepted', c1.status === 200 && c1.text.includes('Thanks for confirming'), `status=${c1.status}`);
    const c2 = await api(`/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    record('Second click is a harmless no-op', c2.text.includes('already responded'));
    const d1 = await api(`/risk-response/${riskScoreId}/deny?token=${signRiskResponseToken(riskScoreId, 'deny')}`);
    record('Deny after confirm is also a no-op (no lock)', d1.text.includes('already responded'));
    const bad = await api(`/risk-response/${riskScoreId}/confirm?token=forged`);
    record('Forged link token is refused', bad.status >= 400, `status=${bad.status}`);
  }

  console.log('\n=== SysAdmin: encryption keys + account actions ===');
  const enc = await api('/admin/encryption/status', { token: ad.token });
  record('Encryption status loads (200)', enc.status === 200, enc.json ? `active key #${enc.json.activeKeyId}` : '');
  record('Encryption status never exposes key material', enc.json && !JSON.stringify(enc.json).match(/[A-Za-z0-9+/]{43}=/));
  const re = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token });
  record('Re-encrypt runs (200) and leaves nothing behind', re.status === 200 && re.json.status.needsReencryption === 0,
    re.json ? `updated ${re.json.updatedValues} value(s)` : `status=${re.status}`);
  const relist = await api('/children', { token: cg.token, device: deviceA });
  const still = relist.json && relist.json.children.find((c) => c.childProfileId === childId);
  record('Child data still decrypts after re-encryption', still && still.fullName === 'Test Child');
  await expectStatus('Caregiver cannot unlock accounts (403)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: cg.token, device: deviceA }, 403);
  await expectStatus('Unlocking a not-locked account (409)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: ad.token }, 409);
  await expectStatus('Unlocking a nonexistent user (404)', '/admin/users/999999/unlock', { method: 'POST', token: ad.token }, 404);
  await expectStatus('Approving a nonexistent request (404)', '/admin/registration-requests/999999/approve', { method: 'POST', token: ad.token }, 404);

  console.log('\n=== SUMMARY ===');
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} passed.`);
  failed.forEach((f) => console.log(`  FAILED: ${f.name} :: ${f.detail || ''}`));
  return failed.length;
}

main()
  .then(async (failures) => {
    await lockTestAccounts();
    await db.pool.end();
    process.exit(failures ? 1 : 0);
  })
  .catch(async (err) => {
    console.error(err);
    try { await lockTestAccounts(); await db.pool.end(); } catch { /* ignore */ }
    process.exit(1);
  });
