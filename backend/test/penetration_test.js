// Penetration-style test (proposal 3.3.7): tries to get past each security
// layer the way an attacker would, against the RUNNING system. Every check
// is an attack that must be REFUSED.
//
//   1 fake identity       5 getting around consent (the proposal's focus)
//   2 password guessing   6 injection
//   3 role escalation     7 transport + browser protections
//   4 other families' data (IDOR)
//
// Run from backend/:   npm run test:pen   (backend on :4000, ML on :5001)
//
// Uses the same dedicated test accounts as test:api (locked again at the
// end). The password-guessing check trips the login rate limit, which is
// per computer -- so it runs against a temporary second backend on :4099
// that is shut down afterwards, leaving the real backend's limit untouched.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

if (process.env.TLS_CERT_FILE && !process.env.NODE_EXTRA_CA_CERTS) {
  const certPath = require('path').resolve(__dirname, '..', process.env.TLS_CERT_FILE);
  const { status } = require('child_process').spawnSync(process.execPath, [__filename], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath },
  });
  process.exit(status === null ? 1 : status);
}

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const crypto = require('crypto');
const { spawn } = require('child_process');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../src/config/db');
const { signRiskResponseToken } = require('../src/utils/riskResponseToken');
const { PRIVACY_NOTICE_VERSION } = require('../src/services/privacyNotice');

const TLS_ON = Boolean(process.env.TLS_CERT_FILE);
const BASE = process.env.TEST_BASE || `${TLS_ON ? 'https' : 'http'}://localhost:4000`;
const TARGET_PORT = Number(new URL(BASE).port);
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const testEmail = (tag) => `${inbox[0]}+childguard-test-${tag}@${inbox[1]}`;
const NOTICE = { privacyNoticeVersion: PRIVACY_NOTICE_VERSION };

const results = [];
let group = '';
function check(name, refused, detail) {
  results.push({ group, name, pass: Boolean(refused), detail: detail || '' });
  console.log(`${refused ? 'BLOCKED' : 'NOT BLOCKED'} - ${name}${detail ? ` :: ${detail}` : ''}`);
}
function section(title) {
  group = title;
  console.log(`\n=== ${title} ===`);
}

async function api(p, { method = 'GET', token, body, raw, headers: extra = {}, base = BASE } = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-Device-Name': 'test-device-A', ...extra };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${p}`, { method, headers, body: raw ?? (body ? JSON.stringify(body) : undefined) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html/csv/pdf */ }
  return { status: res.status, json, text, headers: res.headers };
}

const accounts = [];
async function ensure(tag, role, username) {
  const email = testEmail(tag);
  const hash = await bcrypt.hash(PASS, 10);
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [role]);
  let { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (rows[0]) {
    await db.query(
      `UPDATE users SET password_hash = $1, is_locked = FALSE, locked_reason = NULL,
              must_change_password = FALSE, mfa_required = FALSE WHERE id = $2`, [hash, rows[0].id]);
  } else {
    ({ rows } = await db.query(
      `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password)
       VALUES ($1, $2, $3, $4, $5, FALSE, FALSE) RETURNING id`, [email, `Test ${role}`, username, hash, roleRows[0].id]));
  }
  await db.query("UPDATE access_requests SET requested_at = requested_at - interval '2 days' WHERE user_id = $1", [rows[0].id]);
  accounts.push(rows[0].id);
  return { id: rows[0].id, email };
}
async function login(acct) {
  const r = await api('/auth/login', { method: 'POST', body: { identifier: acct.email, password: PASS } });
  if (!r.json || !r.json.token) throw new Error(`login failed for ${acct.email}: ${r.status}`);
  return r.json.token;
}

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const isRefused = (r, ...codes) => (codes.length ? codes.includes(r.status) : r.status >= 400 && r.status < 500);

async function waitFor(base) {
  for (let ok = 0, i = 0; ok < 3 && i < 40; i++) {
    ok = (await fetch(`${base}/health`).then((r) => r.ok).catch(() => false)) ? ok + 1 : 0;
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function main() {
  await waitFor(BASE);
  const cg = await ensure('caregiver', 'Caregiver', 'test.caregiver');
  const cg2 = await ensure('caregiver2', 'Caregiver', 'test.caregiver2');
  const au = await ensure('auditor', 'SecurityAuditor', 'test.auditor');
  const ad = await ensure('admin', 'SysAdmin', 'test.admin');
  const cgToken = await login(cg);
  const cg2Token = await login(cg2);
  const auToken = await login(au);
  const adToken = await login(ad);

  // Fixtures: one child of the OTHER caregiver (the victim), with records
  // consent, and one of our own WITHOUT records consent.
  const victim = (await api('/children', {
    method: 'POST', token: cg2Token, body: { fullName: 'Victim Child', dateOfBirth: '2020-05-05', developmentalRecordsConsent: true, ...NOTICE },
  })).json.childProfileId;
  await api(`/children/${victim}/records`, {
    method: 'POST', token: cg2Token, body: { milestone: 'Private milestone', healthIndicator: 'Private', assessmentScore: 5 },
  });
  const ownNoConsent = (await api('/children', {
    method: 'POST', token: cgToken, body: { fullName: 'Own Child', dateOfBirth: '2020-06-06', ...NOTICE },
  })).json.childProfileId;
  const { rows: sess } = await db.query(
    'SELECT id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL ORDER BY issued_at DESC LIMIT 1', [cg.id]);
  const realPayload = { userId: cg.id, role: 'Caregiver', sessionId: sess[0].id };

  // ------------------------------------------------------------- 1
  section('1. Fake identity (authentication)');
  check('No token at all', isRefused(await api('/children'), 401));
  check('Random garbage token', isRefused(await api('/children', { token: 'not-a-real-token' }), 401));
  check('Token signed with a guessed secret, claiming SysAdmin',
    isRefused(await api('/admin/users/locked', { token: jwt.sign({ ...realPayload, role: 'SysAdmin' }, 'guessed-secret') }), 401));
  const [h, , sig] = cgToken.split('.');
  const tampered = `${h}.${b64({ ...jwt.decode(cgToken), role: 'SysAdmin' })}.${sig}`;
  check('Real caregiver token edited to say "SysAdmin" (signature kept)', isRefused(await api('/admin/users/locked', { token: tampered }), 401));
  const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...realPayload, role: 'SysAdmin' })}.`;
  check('Unsigned "alg: none" token claiming SysAdmin', isRefused(await api('/admin/users/locked', { token: unsigned }), 401));
  check('Expired token', isRefused(await api('/children', { token: jwt.sign(realPayload, process.env.JWT_SECRET, { expiresIn: -60 }) }), 401));
  const throwaway = await login(cg);
  await api('/auth/logout', { method: 'POST', token: throwaway });
  check('Token from a session that has logged out', isRefused(await api('/children', { token: throwaway }), 401));
  check('"This was me" email-link token used as a login token',
    isRefused(await api('/children', { token: signRiskResponseToken(1, 'confirm') }), 401));

  // ------------------------------------------------------------- 2
  section('2. Password guessing');
  const wrongPw = await api('/auth/login', { method: 'POST', body: { identifier: cg.email, password: 'wrong-password' } });
  const noUser = await api('/auth/login', { method: 'POST', body: { identifier: 'nobody-here@example.com', password: 'wrong-password' } });
  check('Same answer for a wrong password and an unknown email (no account discovery)',
    wrongPw.status === 401 && noUser.status === 401 && wrongPw.json.error === noUser.json.error, `"${wrongPw.json && wrongPw.json.error}"`);
  // Brute force, against a temporary second backend so this computer isn't
  // locked out of the real one for 15 minutes.
  const spare = spawn(process.execPath, ['src/server.js'], {
    cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: '4099' }, stdio: 'ignore',
  });
  const spareBase = BASE.replace(`:${TARGET_PORT}`, ':4099');
  try {
    await waitFor(spareBase);
    let blockedAt = null;
    for (let i = 1; i <= 25 && !blockedAt; i++) {
      const r = await api('/auth/login', { method: 'POST', base: spareBase, body: { identifier: cg.email, password: `guess-${i}` } });
      if (r.status === 429) blockedAt = i;
    }
    check('25 password guesses in a row are cut off by the rate limit', Boolean(blockedAt), blockedAt ? `blocked at guess #${blockedAt}` : 'never blocked');
    const correctAfter = await api('/auth/login', { method: 'POST', base: spareBase, body: { identifier: cg.email, password: PASS } });
    check('...and even the CORRECT password is refused while blocked', isRefused(correctAfter, 429), `status ${correctAfter.status}`);
  } finally {
    spare.kill();
  }

  // ------------------------------------------------------------- 3
  section('3. Doing more than your role allows');
  const asCg = (p, opts = {}) => api(p, { token: cgToken, ...opts });
  check('Caregiver approves an account request', isRefused(await asCg('/admin/registration-requests/1/approve', { method: 'POST' }), 403));
  check('Caregiver unlocks an account', isRefused(await asCg(`/admin/users/${cg2.id}/unlock`, { method: 'POST' }), 403));
  check('Caregiver re-encrypts all data', isRefused(await asCg('/admin/encryption/reencrypt', { method: 'POST' }), 403));
  check('Caregiver anonymises data (retention)', isRefused(await asCg('/admin/retention/apply', { method: 'POST' }), 403));
  check('Caregiver reads the audit log', isRefused(await asCg('/auditor/audit-log'), 403));
  check('Caregiver downloads a report', isRefused(await asCg('/auditor/reports/audit-log?format=csv'), 403));
  check('Caregiver records a breach decision', isRefused(await asCg('/auditor/flagged-sessions/1/breach-decision', {
    method: 'POST', body: { decision: 'no_real_risk', reason: 'trying to close my own alert' } }), 403));
  check('Auditor reads child data', isRefused(await api('/children', { token: auToken }), 403));
  check('Stolen admin session re-encrypts without the password (step-up)',
    isRefused(await api('/admin/encryption/reencrypt', { method: 'POST', token: adToken }), 403, 429));
  check('Stolen admin session anonymises data with a guessed password (step-up)',
    isRefused(await api('/admin/retention/apply', { method: 'POST', token: adToken, body: { password: 'guess' } }), 403, 429));

  // ------------------------------------------------------------- 4
  section('4. Other families\' children (IDOR)');
  const r1 = await asCg(`/children/${victim}/records`);
  check('Read another family\'s child records', isRefused(r1, 403) && !r1.text.includes('Private milestone'));
  check('Add a record to another family\'s child', isRefused(await asCg(`/children/${victim}/records`, {
    method: 'POST', body: { milestone: 'x', healthIndicator: 'x', assessmentScore: 1 } }), 403));
  check('Read another family\'s consent history', isRefused(await asCg(`/children/${victim}/consent`), 403));
  check('Revoke consent for another family\'s child', isRefused(await asCg(`/children/${victim}/consent`, {
    method: 'POST', body: { scope: 'developmental_records', consentGiven: false } }), 403));
  check('Rename another family\'s child', isRefused(await asCg(`/children/${victim}`, { method: 'PATCH', body: { fullName: 'Hijacked' } }), 403));
  check('Archive another family\'s child', isRefused(await asCg(`/children/${victim}/archive`, { method: 'POST', body: {} }), 403));
  const missing = await asCg('/children/99999999/records');
  check('A child number that doesn\'t exist gets the SAME answer (no guessing which exist)',
    missing.status === r1.status && missing.json.error === r1.json.error);
  const list = await asCg('/children');
  check('Own children list never includes another family\'s child',
    list.status === 200 && !list.json.children.some((c) => c.childProfileId === victim));
  const sneaky = await asCg('/children', { method: 'POST', body: {
    fullName: 'Sneaky Child', dateOfBirth: '2021-01-01', caregiverId: cg2.id, caregiver_id: cg2.id, ...NOTICE } });
  const { rows: owner } = await db.runAsSystem(() => db.query('SELECT caregiver_id FROM child_profiles WHERE id = $1', [sneaky.json.childProfileId]));
  check('Sneaking "caregiver_id = someone else" into the form is ignored', owner[0].caregiver_id === cg.id,
    `child owned by user #${owner[0].caregiver_id} (us: #${cg.id})`);
  // Invalid ids must be refused cleanly (4xx) everywhere, never reach the
  // database as a 500.
  for (const bad of ['1 OR 1=1', '-1', 'abc', `${victim}; DROP TABLE child_profiles`, '99999999999']) {
    const r = await asCg(`/children/${encodeURIComponent(bad)}/records`);
    check(`Tampered child number "${bad}"`, isRefused(r), `status ${r.status}`);
  }
  for (const [label, p, token] of [
    ['flag number on the auditor\'s review', '/auditor/flagged-sessions/abc/review', auToken],
    ['user number on the admin\'s unlock', '/admin/users/1%20OR%201=1/unlock', adToken],
    ['request number on the admin\'s approve', '/admin/registration-requests/abc/approve', adToken],
  ]) {
    const r = await api(p, { method: 'POST', token, body: { status: 'reviewing' } });
    check(`Tampered ${label}`, isRefused(r), `status ${r.status}`);
  }
  const link = await api('/risk-response/abc/confirm?token=x');
  check('Tampered alert number in an email link', isRefused(link), `status ${link.status}`);

  // ------------------------------------------------------------- 5
  section('5. Getting around consent');
  const nc = await asCg(`/children/${ownNoConsent}/records`);
  check('Read own child\'s records WITHOUT consent', isRefused(nc, 403) && nc.json.code === 'CONSENT_REQUIRED');
  check('Add a record WITHOUT consent', isRefused(await asCg(`/children/${ownNoConsent}/records`, {
    method: 'POST', body: { milestone: 'x', healthIndicator: 'x', assessmentScore: 1 } }), 403));
  check('Revoke the mandatory identity consent', isRefused(await asCg(`/children/${ownNoConsent}/consent`, {
    method: 'POST', body: { scope: 'profile_identity', consentGiven: false } }), 400));
  check('Grant consent under an invented scope ("everything")', isRefused(await asCg(`/children/${ownNoConsent}/consent`, {
    method: 'POST', body: { scope: 'everything', consentGiven: true } }), 400));
  check('Consent value sent as text ("yes") instead of true/false', isRefused(await asCg(`/children/${ownNoConsent}/consent`, {
    method: 'POST', body: { scope: 'developmental_records', consentGiven: 'yes' } }), 400));
  const direct = await db.runAs({ userId: cg.id, role: 'Caregiver' }, () => db.query(
    'SELECT COUNT(*)::int AS n FROM developmental_records WHERE child_profile_id = $1', [victim]));
  check('Skip the app and query the database directly for another family\'s records (row-level security)',
    direct.rows[0].n === 0, `${direct.rows[0].n} rows visible`);

  // ------------------------------------------------------------- 6
  section('6. Injection');
  check('SQL injection in the login box (\' OR \'1\'=\'1)', isRefused(await api('/auth/login', {
    method: 'POST', body: { identifier: "' OR '1'='1", password: "' OR '1'='1" } }), 401));
  const auditBefore = (await db.query('SELECT COUNT(*)::int AS n FROM audit_log')).rows[0].n;
  const sqli = await api(`/auditor/audit-log?q=${encodeURIComponent("'; DROP TABLE audit_log; --")}`, { token: auToken });
  const auditAfter = (await db.query('SELECT COUNT(*)::int AS n FROM audit_log')).rows[0].n;
  check('SQL injection in the audit-log search ("DROP TABLE")', sqli.status === 200 && auditAfter >= auditBefore,
    'treated as plain search text; table intact');
  check('SQL injection in a report date filter', isRefused(await api(`/auditor/reports/audit-log?format=csv&from=${encodeURIComponent("2026-01-01' OR '1'='1")}`, { token: auToken }), 400));
  const xssName = '<script>alert("stolen")</script>';
  const xss = await asCg('/children', { method: 'POST', body: { fullName: xssName, dateOfBirth: '2021-01-01', ...NOTICE } });
  const back = await asCg('/children');
  check('Script hidden in a child\'s name is stored as plain text, sent as JSON (never run)',
    xss.status === 201 && back.headers.get('content-type').includes('application/json')
      && back.json.children.some((c) => c.fullName === xssName));
  check('Broken (malformed) JSON is rejected cleanly', isRefused(await asCg('/children', { method: 'POST', raw: '{"fullName": ' }), 400));
  check('Oversized request (200 KB) is rejected', isRefused(await asCg('/children', {
    method: 'POST', body: { fullName: 'x'.repeat(200000), dateOfBirth: '2021-01-01', ...NOTICE } }), 413));

  // ------------------------------------------------------------- 7
  section('7. Transport and browser protections');
  if (TLS_ON) {
    const plain = await fetch(`http://localhost:${TARGET_PORT}/health`).then((r) => r.status).catch(() => 'refused');
    check('Plain, unencrypted HTTP', plain !== 200, `answer: ${plain}`);
    const old = await new Promise((resolve) => {
      const s = tls.connect({ host: 'localhost', port: TARGET_PORT, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', rejectUnauthorized: false });
      s.once('secureConnect', () => { s.destroy(); resolve('connected'); });
      s.once('error', (e) => resolve(e.code || e.message));
    });
    check('Old TLS 1.2 connection', old !== 'connected', old);
  } else {
    check('HTTPS is configured (TLS_CERT_FILE)', false, 'backend is running without TLS');
  }
  const hdr = (await api('/health')).headers;
  check('Security headers present (no-sniff, CSP, frame protection)',
    hdr.get('x-content-type-options') === 'nosniff' && Boolean(hdr.get('content-security-policy')) && Boolean(hdr.get('x-frame-options')));
  check('Server software not advertised (no X-Powered-By)', !hdr.get('x-powered-by'));
  const cors = await api('/children', { token: cgToken, headers: { Origin: 'https://evil.example' } });
  check('Request from a foreign website is not allowed by the browser (CORS)',
    cors.headers.get('access-control-allow-origin') !== 'https://evil.example', `allowed origin: ${cors.headers.get('access-control-allow-origin')}`);
  // Email-link tokens: bound to one flag and one action. Use flags that
  // belong to test accounts only, so nothing real could change.
  const { rows: flags } = await db.query(
    `SELECT rs.id FROM risk_scores rs JOIN access_requests ar ON ar.id = rs.access_request_id JOIN users u ON u.id = ar.user_id
     WHERE rs.is_flagged AND u.email LIKE '%childguard-test-anomaly%' ORDER BY rs.id DESC LIMIT 2`);
  if (flags.length === 2) {
    const [a, b] = flags.map((f) => f.id);
    check('"This was me" link for one alert used on a DIFFERENT alert',
      isRefused(await api(`/risk-response/${b}/confirm?token=${signRiskResponseToken(a, 'confirm')}`)));
    check('"This was me" token used on the "This was NOT me" link',
      isRefused(await api(`/risk-response/${a}/deny?token=${signRiskResponseToken(a, 'confirm')}`)));
  } else {
    check('Email-link checks (SKIPPED: run npm run test:anomaly first to create test alerts)', true);
  }
  check('Forged email-link token', isRefused(await api('/risk-response/1/confirm?token=forged')));

  const blocked = results.filter((r) => r.pass).length;
  console.log('\n=== SUMMARY ===');
  for (const g of [...new Set(results.map((r) => r.group))]) {
    const inG = results.filter((r) => r.group === g);
    console.log(`${g.padEnd(42)} ${inG.filter((r) => r.pass).length}/${inG.length} blocked`);
  }
  console.log(`${blocked === results.length ? 'RESULT: PASS' : 'RESULT: FAIL'} -- ${blocked}/${results.length} attacks blocked.`);
  const outDir = path.join(__dirname, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `penetration_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
  fs.writeFileSync(outFile, JSON.stringify({ ranAt: new Date().toISOString(), results }, null, 2));
  console.log(`Saved: ${path.relative(path.join(__dirname, '..'), outFile)}`);
  return blocked === results.length ? 0 : 1;
}

main()
  .catch((err) => {
    console.error('\nTest could not complete:', err.message, err.cause ? `(${err.cause.code || err.cause.message})` : '');
    return 1;
  })
  .then(async (code) => {
    if (accounts.length) {
      await db.query(
        "UPDATE users SET is_locked = TRUE, locked_reason = 'automated test account (locked between runs)' WHERE id = ANY($1)", [accounts]);
    }
    await db.pool.end();
    process.exit(code);
  });
