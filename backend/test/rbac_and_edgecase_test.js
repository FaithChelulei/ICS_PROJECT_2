// Broader correctness pass: RBAC matrix across all 3 roles, the auditor
// review action, the "This was me" confirm path (untested so far -- we'd
// only exercised deny), and unlock's edge cases. Logs in each role ONCE
// via real MFA email, then reuses that token for every check below, to
// keep this run's email volume low (3 login emails total + 1 real risk
// alert for the confirm-path test -- not a flood).
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');
const { signRiskResponseToken } = require('../src/utils/riskResponseToken');

const BASE = 'http://127.0.0.1:4000';
const PASS = 'DevTest123!';
const results = [];

function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} - ${name}${detail ? ' :: ' + detail : ''}`);
}

async function loginAs(email) {
  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: PASS }),
  });
  const loginBody = await loginRes.json();
  if (!loginBody.userId) throw new Error(`login failed for ${email}: ${JSON.stringify(loginBody)}`);

  // Overwrite the just-created code with a known one so we don't have to
  // read the real inbox for this -- the real email still went out above.
  const code = '123456';
  const codeHash = await bcrypt.hash(code, 10);
  await db.query(
    `UPDATE mfa_codes SET code_hash = $1 WHERE id = (
       SELECT id FROM mfa_codes WHERE user_id = $2 ORDER BY created_at DESC LIMIT 1
     )`,
    [codeHash, loginBody.userId]
  );

  const verifyRes = await fetch(`${BASE}/auth/verify-mfa`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Device-Name': 'FAITH-TEST-PC' },
    body: JSON.stringify({ userId: loginBody.userId, code }),
  });
  const verifyBody = await verifyRes.json();
  if (!verifyBody.token) throw new Error(`verify-mfa failed for ${email}: ${JSON.stringify(verifyBody)}`);
  return { token: verifyBody.token, userId: loginBody.userId };
}

function authHeaders(token) {
  return { Authorization: `Bearer ${token}`, 'X-Device-Name': 'FAITH-TEST-PC', 'Content-Type': 'application/json' };
}

async function main() {
  console.log('Cleaning test data for a clean run...');
  await db.query('DELETE FROM risk_scores');
  await db.query('DELETE FROM access_requests');
  await db.query('DELETE FROM sessions');
  await db.query('DELETE FROM mfa_codes');
  await db.query('DELETE FROM developmental_records');
  await db.query('DELETE FROM child_identifiers');
  await db.query('DELETE FROM child_profiles');
  await db.query("UPDATE users SET is_locked = FALSE, locked_reason = NULL WHERE email LIKE 'faith.chelulei+%'");

  console.log('\n=== Logging in all 3 roles once (reused for every check below) ===');
  const cg = await loginAs('faith.chelulei+caregiver@strathmore.edu');
  const au = await loginAs('faith.chelulei+auditor@strathmore.edu');
  const ad = await loginAs('faith.chelulei+admin@strathmore.edu');
  console.log('All 3 logged in.');

  async function expectStatus(label, url, opts, expected) {
    const res = await fetch(url, opts);
    const ok = res.status === expected;
    record(label, ok, `got ${res.status}, expected ${expected}`);
    return res;
  }

  console.log('\n=== RBAC matrix: each role against every OTHER role\'s routes ===');

  // Caregiver blocked from auditor + admin routes
  await expectStatus('Caregiver -> GET /auditor/flagged-sessions', `${BASE}/auditor/flagged-sessions`,
    { headers: authHeaders(cg.token) }, 403);
  await expectStatus('Caregiver -> POST /auditor/flagged-sessions/999/review', `${BASE}/auditor/flagged-sessions/999/review`,
    { method: 'POST', headers: authHeaders(cg.token), body: JSON.stringify({ status: 'reviewing' }) }, 403);
  await expectStatus('Caregiver -> GET /admin/registration-requests', `${BASE}/admin/registration-requests`,
    { headers: authHeaders(cg.token) }, 403);
  await expectStatus('Caregiver -> GET /admin/users/locked', `${BASE}/admin/users/locked`,
    { headers: authHeaders(cg.token) }, 403);

  // SecurityAuditor blocked from children + admin routes
  await expectStatus('SecurityAuditor -> GET /children', `${BASE}/children`,
    { headers: authHeaders(au.token) }, 403);
  await expectStatus('SecurityAuditor -> POST /children', `${BASE}/children`,
    { method: 'POST', headers: authHeaders(au.token), body: JSON.stringify({ fullName: 'x', dateOfBirth: '2020-01-01' }) }, 403);
  await expectStatus('SecurityAuditor -> GET /admin/registration-requests', `${BASE}/admin/registration-requests`,
    { headers: authHeaders(au.token) }, 403);
  await expectStatus('SecurityAuditor -> GET /admin/users/locked', `${BASE}/admin/users/locked`,
    { headers: authHeaders(au.token) }, 403);

  // SysAdmin blocked from children + auditor routes
  await expectStatus('SysAdmin -> GET /children', `${BASE}/children`,
    { headers: authHeaders(ad.token) }, 403);
  await expectStatus('SysAdmin -> GET /auditor/flagged-sessions', `${BASE}/auditor/flagged-sessions`,
    { headers: authHeaders(ad.token) }, 403);

  // Positive controls -- each role CAN use its own routes
  await expectStatus('SecurityAuditor -> GET /auditor/flagged-sessions (own route)', `${BASE}/auditor/flagged-sessions?status=all`,
    { headers: authHeaders(au.token) }, 200);
  await expectStatus('SysAdmin -> GET /admin/users/locked (own route)', `${BASE}/admin/users/locked`,
    { headers: authHeaders(ad.token) }, 200);

  console.log('\n=== Caregiver creates a child profile (cold -- likely to flag) ===');
  const createRes = await fetch(`${BASE}/children`, {
    method: 'POST', headers: authHeaders(cg.token),
    body: JSON.stringify({ fullName: 'Test Child', dateOfBirth: '2019-05-10' }),
  });
  const createBody = await createRes.json();
  record('Caregiver creates child profile', createRes.status === 201, `status=${createRes.status}`);
  const flagged = Boolean(createBody.riskNotice);
  console.log(flagged ? 'Flagged, as expected for a cold action -- continuing with the confirm-path test.'
                       : 'Not flagged this run (borderline score landed under threshold) -- skipping confirm-path test below.');

  let riskScoreId = null;
  if (flagged) {
    const { rows } = await db.query(
      `SELECT rs.id FROM risk_scores rs
       JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE ar.user_id = $1 ORDER BY rs.created_at DESC LIMIT 1`,
      [cg.userId]
    );
    riskScoreId = rows[0].id;

    console.log('\n=== Security Auditor reviews it ===');
    await expectStatus('Auditor sets status=reviewing', `${BASE}/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', headers: authHeaders(au.token), body: JSON.stringify({ status: 'reviewing' }) }, 200);
    await expectStatus('Auditor rejects invalid status value', `${BASE}/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', headers: authHeaders(au.token), body: JSON.stringify({ status: 'bogus' }) }, 400);
    await expectStatus('Auditor sets status=confirmed', `${BASE}/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', headers: authHeaders(au.token), body: JSON.stringify({ status: 'confirmed' }) }, 200);
  }

  if (riskScoreId) {
    console.log('\n=== "This was me" confirm path (untested until now -- we had only exercised deny) ===');
    const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
    const confirmRes = await fetch(`${BASE}/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    const confirmText = await confirmRes.text();
    record('Confirm link accepted', confirmRes.status === 200 && confirmText.includes('Thanks for confirming'),
      confirmText.replace(/<[^>]+>/g, '').trim().slice(0, 80));

    const { rows: afterConfirm } = await db.query(
      'SELECT owner_response, (SELECT is_locked FROM users WHERE id = $1) AS locked FROM risk_scores WHERE id = $2',
      [cg.userId, riskScoreId]
    );
    record('owner_response = confirmed_benign', afterConfirm[0].owner_response === 'confirmed_benign', afterConfirm[0].owner_response);
    record('account NOT locked after confirming', afterConfirm[0].locked === false, `is_locked=${afterConfirm[0].locked}`);

    console.log('\n=== Idempotency: clicking confirm again, and clicking deny on an already-resolved alert ===');
    const confirmAgainRes = await fetch(`${BASE}/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    const confirmAgainText = await confirmAgainRes.text();
    record('Second confirm click is a no-op, not a crash', confirmAgainText.includes('already responded'),
      confirmAgainText.replace(/<[^>]+>/g, '').trim().slice(0, 80));

    const denyToken = signRiskResponseToken(riskScoreId, 'deny');
    const denyAfterConfirmRes = await fetch(`${BASE}/risk-response/${riskScoreId}/deny?token=${denyToken}`);
    const denyAfterConfirmText = await denyAfterConfirmRes.text();
    record('Deny after already-confirmed is also a no-op', denyAfterConfirmText.includes('already responded'),
      denyAfterConfirmText.replace(/<[^>]+>/g, '').trim().slice(0, 80));
  }

  console.log('\n=== Unlock endpoint edge cases (no real lock cycle needed -- that full loop was already proven) ===');
  await expectStatus('Caregiver cannot call unlock on anyone (403)', `${BASE}/admin/users/${cg.userId}/unlock`,
    { method: 'POST', headers: authHeaders(cg.token) }, 403);
  await expectStatus('SysAdmin unlocking a NOT-locked account -> 409', `${BASE}/admin/users/${cg.userId}/unlock`,
    { method: 'POST', headers: authHeaders(ad.token) }, 409);
  await expectStatus('SysAdmin unlocking a nonexistent user -> 404', `${BASE}/admin/users/999999/unlock`,
    { method: 'POST', headers: authHeaders(ad.token) }, 404);

  console.log('\n=== SUMMARY ===');
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} passed.`);
  if (failed.length) {
    console.log('FAILURES:');
    failed.forEach((f) => console.log(`  - ${f.name}: ${f.detail}`));
  }

  await db.pool.end();
}

main().catch((err) => { console.error(err); process.exit(1); });
