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

// The backend serves HTTPS with a local self-signed certificate. Node reads
// NODE_EXTRA_CA_CERTS only at start-up, so re-launch this script once with
// it pointing at that certificate (works whether or not cert:trust was run).
if (process.env.TLS_CERT_FILE && !process.env.NODE_EXTRA_CA_CERTS) {
  const certPath = require('path').resolve(__dirname, '..', process.env.TLS_CERT_FILE);
  const { status } = require('child_process').spawnSync(process.execPath, [__filename], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath },
  });
  process.exit(status === null ? 1 : status);
}

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');
const { signRiskResponseToken } = require('../src/utils/riskResponseToken');
const { PRIVACY_NOTICE_VERSION } = require('../src/services/privacyNotice');

const BASE = process.env.TEST_BASE || `${process.env.TLS_CERT_FILE ? 'https' : 'http'}://localhost:4000`;
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const testEmail = (tag) => `${inbox[0]}+childguard-test-${tag}@${inbox[1]}`;

const ACCOUNTS = {
  cg: { tag: 'caregiver', role: 'Caregiver', username: 'test.caregiver', name: 'Test Caregiver' },
  // Separate caregiver for the archive/retention checks, so their extra
  // data actions don't push the main test caregiver's risk score over the
  // threshold mid-run (which would correctly revoke its session).
  cg2: { tag: 'caregiver2', role: 'Caregiver', username: 'test.caregiver2', name: 'Test Caregiver Two' },
  au: { tag: 'auditor', role: 'SecurityAuditor', username: 'test.auditor', name: 'Test Auditor' },
  ad: { tag: 'admin', role: 'SysAdmin', username: 'test.admin', name: 'Test Admin' },
  // A second admin and a second auditor: two-person approval and "nobody
  // reviews their own week" need a different person of the same role.
  ad2: { tag: 'admin2', role: 'SysAdmin', username: 'test.admin2', name: 'Test Admin Two' },
  au2: { tag: 'auditor2', role: 'SecurityAuditor', username: 'test.auditor2', name: 'Test Auditor Two' },
  // Has no children and exists only to have its role changed and put back.
  rc: { tag: 'rolechange', role: 'Caregiver', username: 'test.rolechange', name: 'Test Role Change' },
  // Signs in with an emailed code (the others skip it so the suite can run unattended).
  mf: { tag: 'mfa', role: 'Caregiver', username: 'test.mfa', name: 'Test Sign-in Code' },
  // Educator access: a caregiver who shares a child, and two teachers.
  sh: { tag: 'sharing', role: 'Caregiver', username: 'test.sharing', name: 'Test Sharing Caregiver' },
  ed: { tag: 'educator', role: 'Educator', username: 'test.educator', name: 'Test Educator' },
  ed2: { tag: 'educator2', role: 'Educator', username: 'test.educator2', name: 'Test Educator Two' },
  // The "Take action" case flow (pause until verified, then access removed).
  ce: { tag: 'caseeducator', role: 'Educator', username: 'test.case.educator', name: 'Test Case Educator' },
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

// The risk features are day- and hour-based (files/events today, devices
// used today), so a second run on the same day would start with the first
// run's activity -- including its deliberate new-device login -- and the
// "normal first action is NOT flagged" check would correctly fail. Ageing
// the TEST accounts' earlier activity by two days makes every run start
// like a fresh working day while keeping device A in their history (so
// it's still "known"). Never touches real accounts or the audit log.
async function ageTestActivity(ids) {
  await db.query(
    "UPDATE access_requests SET requested_at = requested_at - interval '2 days' WHERE user_id = ANY($1)",
    [ids]
  );
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
  return { status: res.status, json, text, limit: res.headers.get('ratelimit-policy') };
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
  if (!health || health.status !== 200) throw new Error(`Backend is not answering at ${BASE} -- start it with npm start first.`);
  const mlBase = (process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001').replace(/\/+$/, '');
  const ml = await fetch(`${mlBase}/health`).catch(() => null);
  if (!ml || !ml.ok) throw new Error(`ML service is not answering at ${mlBase} -- start ml/service/app.py first.`);

  console.log('Preparing dedicated test accounts (your real accounts are not touched)...');
  const cgAcct = await ensureTestAccount(ACCOUNTS.cg);
  const auAcct = await ensureTestAccount(ACCOUNTS.au);
  const adAcct = await ensureTestAccount(ACCOUNTS.ad);
  const cg2Acct = await ensureTestAccount(ACCOUNTS.cg2);
  await ageTestActivity([cgAcct.id, auAcct.id, adAcct.id, cg2Acct.id]);

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
  const ad2Acct = await ensureTestAccount(ACCOUNTS.ad2);
  await ageTestActivity([ad2Acct.id]);
  const ad2 = await login(ad2Acct.email);
  // Two-person approval: test.admin asks, test.admin2 approves. Returns the id.
  async function approved(action) {
    const asked = await api('/admin/approvals', { method: 'POST', token: ad.token, body: { action, reason: 'Automated test run of two-person approval', password: PASS } });
    if (asked.status !== 201) return null;
    const ok = await api(`/admin/approvals/${asked.json.id}/approve`, { method: 'POST', token: ad2.token, body: { reason: 'Second admin approves for the test', password: PASS } });
    return ok.status === 200 ? asked.json.id : null;
  }

  console.log('\n=== Sign-in code (MFA) ===');
  const mfAcct = await ensureTestAccount(ACCOUNTS.mf);
  await db.query('UPDATE users SET mfa_required = TRUE WHERE id = $1', [mfAcct.id]);
  try {
    const signIn = () => api('/auth/login', { method: 'POST', body: { identifier: mfAcct.email, password: PASS } });
    const verifyCode = (challengeId, code) => api('/auth/verify-mfa', { method: 'POST', body: { challengeId, code } });
    // The emailed code is random and stored hashed; give the live one a known value.
    const setKnownCode = async () => db.query('UPDATE mfa_codes SET code_hash = $1 WHERE user_id = $2 AND consumed = FALSE',
      [await bcrypt.hash('123456', 10), mfAcct.id]);
    const first = await signIn();
    record('Step one returns a signed challenge, not the user id',
      first.json && first.json.mfaRequired === true && typeof first.json.challengeId === 'string' && !('userId' in first.json));
    await setKnownCode();
    record('Sending a user id instead of the challenge is refused (400)',
      (await api('/auth/verify-mfa', { method: 'POST', body: { userId: mfAcct.id, code: '123456' } })).status === 400);
    record('A forged challenge is refused (401)', (await verifyCode(`${first.json.challengeId.slice(0, -4)}AAAA`, '123456')).status === 401);
    const wrongCode = await verifyCode(first.json.challengeId, '000000');
    record('A wrong code is refused and says how many tries are left', wrongCode.status === 401 && /4 tries left/.test(wrongCode.json.error),
      wrongCode.json && wrongCode.json.error);
    const right = await verifyCode(first.json.challengeId, '123456');
    record('The right code signs in (200)', right.status === 200 && Boolean(right.json.token), `status=${right.status}`);
    record('A used code cannot be used again (401)', (await verifyCode(first.json.challengeId, '123456')).status === 401);
    const older = await signIn();
    const newer = await signIn();
    await setKnownCode();
    record('Signing in again cancels the older code', (await verifyCode(older.json.challengeId, '123456')).status === 401);
    let fifth = null;
    for (let i = 0; i < 5; i += 1) fifth = await verifyCode(newer.json.challengeId, '000000');
    record('After 5 wrong codes the code is cancelled', fifth.status === 401 && fifth.json.code === 'MFA_CODE_CANCELLED', fifth.json && fifth.json.error);
    record('...and then even the right code is refused', (await verifyCode(newer.json.challengeId, '123456')).status === 401);
  } finally {
    await db.query('UPDATE users SET mfa_required = FALSE WHERE id = $1', [mfAcct.id]);
  }

  const me = await api('/auth/me', { token: cg.token, device: deviceA });
  record('/auth/me returns fullName', me.json && me.json.fullName === ACCOUNTS.cg.name, JSON.stringify(me.json));

  console.log('\n=== Bad page parameters get a clear 400, never a 500 ===');
  await expectStatus('Unknown flagged-session status (400)', '/auditor/flagged-sessions?status=bogus', { token: au.token }, 400);
  await expectStatus('A parameter given twice (400)', '/auditor/flagged-sessions?status=pending&status=all', { token: au.token }, 400);
  await expectStatus('A nested parameter (400)', '/auditor/audit-log?q[x]=1', { token: au.token }, 400);
  await expectStatus('Audit log "from" that is not a date (400)', '/auditor/audit-log?from=yesterday', { token: au.token }, 400);
  await expectStatus('Audit log negative limit (400)', '/auditor/audit-log?limit=-5', { token: au.token }, 400);
  await expectStatus('Unknown registration-request status (400)', '/admin/registration-requests?status=bogus', { token: ad.token }, 400);
  await expectStatus('A valid date still works (200)', '/auditor/audit-log?from=2026-01-01&limit=5', { token: au.token }, 200);

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
  const NOTICE = { privacyNoticeVersion: PRIVACY_NOTICE_VERSION };
  const noNotice = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'No Notice Child', dateOfBirth: '2020-01-01' },
  });
  record('Child registration without accepting the privacy notice is refused (400, s.29)',
    noNotice.status === 400 && noNotice.json && noNotice.json.code === 'PRIVACY_NOTICE_REQUIRED', `status=${noNotice.status}`);
  const oldNotice = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'Old Notice Child', dateOfBirth: '2020-01-01', privacyNoticeVersion: '2000-01' },
  });
  record('An outdated privacy notice version is refused (400)', oldNotice.status === 400, `status=${oldNotice.status}`);
  const regNoNotice = await api('/auth/register', {
    method: 'POST', body: { fullName: 'No Notice Person', email: testEmail('nonotice'), requestedRole: 'Caregiver' },
  });
  record('Account request without accepting the privacy notice is refused (400, s.29)',
    regNoNotice.status === 400 && regNoNotice.json && regNoNotice.json.code === 'PRIVACY_NOTICE_REQUIRED', `status=${regNoNotice.status}`);
  await expectStatus('Future date of birth is rejected (400)', '/children',
    { method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'Future Child', dateOfBirth: tomorrow, ...NOTICE } }, 400);
  const created = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA,
    body: { fullName: 'Test Child', dateOfBirth: '2020-06-15', familyBackground: 'Automated test record', ...NOTICE },
  });
  record('Caregiver creates child profile (201)', created.status === 201, `status=${created.status}`);
  record('Normal first action on a known device is NOT flagged', created.json && !created.json.riskNotice,
    created.json && created.json.riskNotice ? 'flagged' : 'not flagged');
  const childId = created.json && created.json.childProfileId;
  const list = await api('/children', { token: cg.token, device: deviceA });
  const mine = list.json && list.json.children.find((c) => c.childProfileId === childId);
  record('Child decrypts correctly in the list', mine && mine.fullName === 'Test Child' && mine.dateOfBirth === '2020-06-15');
  await expectStatus('Consent history is readable (200)', `/children/${childId}/consent`, { token: cg.token, device: deviceA }, 200);
  await expectStatus('Non-boolean records consent at registration is rejected (400)', '/children',
    { method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'x', dateOfBirth: '2020-01-01', developmentalRecordsConsent: 'yes', ...NOTICE } }, 400);

  console.log('\n=== Consent enforcement on every records request ===');
  const recordBody = { milestone: 'Walks unaided', healthIndicator: 'Healthy', assessmentScore: 8 };
  const setRecordsConsent = (consentGiven) => api(`/children/${childId}/consent`, {
    method: 'POST', token: cg.token, device: deviceA, body: { scope: 'developmental_records', consentGiven },
  });
  const noConsent = await api(`/children/${childId}/records`, { token: cg.token, device: deviceA });
  record('Records blocked by default -- consent is opt-in (403 CONSENT_REQUIRED)',
    noConsent.status === 403 && noConsent.json && noConsent.json.code === 'CONSENT_REQUIRED', `status=${noConsent.status}`);
  await setRecordsConsent(true);
  await expectStatus('Records readable once consent is granted (200)', `/children/${childId}/records`, { token: cg.token, device: deviceA }, 200);
  await setRecordsConsent(false);
  const revokedView = await api(`/children/${childId}/records`, { token: cg.token, device: deviceA });
  record('Viewing records blocked after consent is revoked (403 CONSENT_REQUIRED)',
    revokedView.status === 403 && revokedView.json && revokedView.json.code === 'CONSENT_REQUIRED', `status=${revokedView.status}`);
  const revokedSubmit = await api(`/children/${childId}/records`, { method: 'POST', token: cg.token, device: deviceA, body: recordBody });
  record('Submitting a record blocked after consent is revoked (403 CONSENT_REQUIRED)',
    revokedSubmit.status === 403 && revokedSubmit.json && revokedSubmit.json.code === 'CONSENT_REQUIRED', `status=${revokedSubmit.status}`);
  const { rows: denials } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'access_denied_no_consent' AND detail LIKE $2",
    [cgAcct.id, `child_profile_id=${childId},%`]
  );
  record('Every consent refusal is written to the audit log', denials[0].n === 3, `${denials[0].n} entries, expected 3`);
  await setRecordsConsent(true); // the risk-engine checks below view this child's records

  console.log('\n=== Correcting a child\'s details (KDPA s.26(d)) ===');
  const patch = (body, token = cg.token) => api(`/children/${childId}`, { method: 'PATCH', token, device: deviceA, body });
  record('Correction with no fields is rejected (400)', (await patch({})).status === 400);
  record('Correction to an empty name is rejected (400)', (await patch({ fullName: '   ' })).status === 400);
  record('Correction to a future date of birth is rejected (400)', (await patch({ dateOfBirth: tomorrow })).status === 400);
  record('Security Auditor cannot correct a child (403)', (await patch({ fullName: 'x' }, au.token)).status === 403);
  const corrected = await patch({ fullName: 'Test Child Corrected' });
  record('Caregiver corrects their child\'s name (200)',
    corrected.status === 200 && JSON.stringify(corrected.json.updatedFields) === '["fullName"]', `status=${corrected.status}`);
  const afterFix = await api('/children', { token: cg.token, device: deviceA });
  record('Corrected name is stored and decrypts',
    afterFix.json && afterFix.json.children.some((c) => c.childProfileId === childId && c.fullName === 'Test Child Corrected'));
  const { rows: fixLog } = await db.query(
    "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'correct_child_details' ORDER BY id DESC LIMIT 1", [cgAcct.id]);
  record('Audit log names the corrected field but never the child\'s name',
    fixLog[0] && fixLog[0].detail === `child_profile_id=${childId}, fields=fullName` && !fixLog[0].detail.includes('Test Child'),
    fixLog[0] && fixLog[0].detail);
  await patch({ fullName: 'Test Child' }); // later checks look for the original name

  console.log('\n=== Downloadable reports (Security Auditor) ===');
  await expectStatus('Caregiver cannot download reports (403)', '/auditor/reports/audit-log?format=csv', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Admin cannot download reports (403)', '/auditor/reports/audit-log?format=csv', { token: ad.token }, 403);
  await expectStatus('Unknown report (404)', '/auditor/reports/everything', { token: au.token }, 404);
  await expectStatus('Unknown format (400)', '/auditor/reports/audit-log?format=xlsx', { token: au.token }, 400);
  await expectStatus('Malformed date (400)', '/auditor/reports/audit-log?from=30-10-2026', { token: au.token }, 400);
  await expectStatus('"from" after "to" (400)', '/auditor/reports/audit-log?from=2026-10-30&to=2026-10-01', { token: au.token }, 400);
  const { rows: exportsBefore } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'export_report'", [auAcct.id]);
  const todayIso = new Date().toISOString().slice(0, 10);
  const auditCsv = await api(`/auditor/reports/audit-log?format=csv&from=${todayIso}`, { token: au.token });
  // (.text() strips the UTF-8 BOM while decoding; the BOM itself is covered by reportFormats.test.js)
  record('Audit log CSV downloads (200, header row)', auditCsv.status === 200 && auditCsv.text.startsWith('Time,User,Role,Action'),
    `status=${auditCsv.status}`);
  const pdf = await api(`/auditor/reports/flagged-sessions?format=pdf`, { token: au.token });
  record('Flagged sessions PDF downloads (200, real PDF)', pdf.status === 200 && pdf.text.startsWith('%PDF-'), `status=${pdf.status}`);
  const consentCsv = await api(`/auditor/reports/consent-activity?format=csv&from=${todayIso}`, { token: au.token });
  record('Consent report includes this run\'s refusals',
    consentCsv.status === 200 && consentCsv.text.includes(`,${childId},Access refused,Developmental records,view_developmental_records`),
    `status=${consentCsv.status}`);
  const { rows: exportsAfter } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'export_report'", [auAcct.id]);
  record('Every download is written to the audit log', exportsAfter[0].n - exportsBefore[0].n === 3,
    `${exportsAfter[0].n - exportsBefore[0].n} new entries, expected 3`);

  console.log('\n=== Row-level security (enforced by PostgreSQL, not the app) ===');
  const asUser = (id, role, sql, params) => db.runAs({ userId: id, role }, () => db.query(sql, params));
  const count = async (id, role, sql, params) => (await asUser(id, role, sql, params)).rows[0].n;
  const { rows: rlsOn } = await db.query(
    "SELECT bool_and(relrowsecurity) AS on FROM pg_class WHERE relname IN ('child_profiles','child_identifiers','developmental_records','consent_records')");
  record('RLS is enabled on all four child-data tables', rlsOn[0].on === true,
    rlsOn[0].on ? '' : 'run node db/migrate.js as postgres');
  if (rlsOn[0].on) {
    const { rows: others } = await db.runAsSystem(() => db.query(
      'SELECT id FROM child_profiles WHERE caregiver_id <> $1 ORDER BY id LIMIT 1', [cgAcct.id]));
    const otherChild = others[0] && others[0].id;
    const { rows: own } = await db.runAsSystem(() => db.query(
      'SELECT COUNT(*)::int AS n FROM child_profiles WHERE caregiver_id = $1', [cgAcct.id]));

    record('Caregiver query with NO filter returns only their own children',
      await count(cgAcct.id, 'Caregiver', 'SELECT COUNT(*)::int AS n FROM child_profiles') === own[0].n, `own=${own[0].n}`);
    record('Caregiver cannot read another family\'s child identity',
      await count(cgAcct.id, 'Caregiver', 'SELECT COUNT(*)::int AS n FROM child_identifiers WHERE child_profile_id = $1', [otherChild]) === 0,
      `other child #${otherChild}`);
    let blocked = false;
    try {
      await asUser(cgAcct.id, 'Caregiver',
        "INSERT INTO developmental_records (child_profile_id, milestone_enc, health_indicator_enc, assessment_score_enc, created_by) VALUES ($1, 'x', 'x', 'x', $2)",
        [otherChild, cgAcct.id]);
    } catch (err) {
      blocked = /row-level security/.test(err.message);
    }
    record('Caregiver cannot write a record against another family\'s child', blocked);
    const deleted = await asUser(cgAcct.id, 'Caregiver', 'DELETE FROM child_profiles WHERE id = $1', [childId]);
    record('Caregiver cannot delete even their own child profile (no delete policy)', deleted.rowCount === 0, `deleted ${deleted.rowCount}`);
    record('No identity at all sees zero child rows (deny by default)',
      (await db.query('SELECT COUNT(*)::int AS n FROM child_identifiers')).rows[0].n === 0);
    record('Security Auditor sees no child identities',
      await count(auAcct.id, 'SecurityAuditor', 'SELECT COUNT(*)::int AS n FROM child_identifiers') === 0);
    record('Security Auditor can read consent history (Consent report)',
      await count(auAcct.id, 'SecurityAuditor', 'SELECT COUNT(*)::int AS n FROM consent_records') > 0);
    record('SysAdmin sees no child identities',
      await count(adAcct.id, 'SysAdmin', 'SELECT COUNT(*)::int AS n FROM child_identifiers') === 0);
    record('Explicit System identity (key rotation) sees every child',
      (await db.runAsSystem(() => db.query('SELECT COUNT(*)::int AS n FROM child_identifiers'))).rows[0].n > 0);
  }

  console.log('\n=== Archive / restrict a child profile (KDPA s.40(3)) ===');
  // The same device the penetration and performance suites use for this
  // account. A different one would (correctly) look like a new device and
  // be flagged whenever another suite ran first on the same day.
  const deviceC = 'test-device-A';
  const care2 = await login(ACCOUNTS.cg2.username, deviceC);
  const as2 = (path, opts = {}) => api(path, { token: care2.token, device: deviceC, ...opts });
  const kid = await as2('/children', {
    method: 'POST', body: { fullName: 'Archive Test Child', dateOfBirth: '2021-02-02', developmentalRecordsConsent: true, ...NOTICE },
  });
  const kidId = kid.json && kid.json.childProfileId;
  record('Second test caregiver registers a child (201)', kid.status === 201, `status=${kid.status}`);
  await expectStatus('Another caregiver cannot archive this child (403)', `/children/${kidId}/archive`,
    { method: 'POST', token: cg.token, device: deviceA, body: {} }, 403);
  // An id, not a time: a refusal logged a moment earlier can share the
  // same millisecond once the two clocks are rounded.
  const { rows: [{ last: probeAfterId }] } = await db.query('SELECT COALESCE(MAX(id), 0) AS last FROM audit_log');
  const probe = await api(`/children/${kidId}/records`, { token: cg.token, device: deviceA });
  record('Another caregiver cannot view this child’s records (403)', probe.status === 403 && probe.json && probe.json.code === 'NOT_YOUR_CHILD', `status=${probe.status}`);
  await expectStatus('Another caregiver cannot read this child’s consent (403)', `/children/${kidId}/consent`, { token: cg.token, device: deviceA }, 403);
  const missing = await api('/children/999999/records', { token: cg.token, device: deviceA });
  record('A profile number that does not exist gets the same answer (no hint it is missing)',
    missing.status === 403 && missing.json && missing.json.error === probe.json.error);
  const { rows: probeLog } = await db.query(
    "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'access_denied_not_owner' AND id > $2 ORDER BY id", [cgAcct.id, probeAfterId]);
  record('Each attempt on another family’s child is in the audit log',
    probeLog.length === 3 && probeLog[0].detail === `child_profile_id=${kidId}, attempted=view_developmental_records`
      && probeLog[1].detail === `child_profile_id=${kidId}, attempted=view_consent`,
    probeLog.map((r) => r.detail).join(' | '));
  const archivedRes = await as2(`/children/${kidId}/archive`, { method: 'POST', body: { reason: 'Left the programme' } });
  record('Owner archives the profile (200)', archivedRes.status === 200 && Boolean(archivedRes.json.archivedAt), `status=${archivedRes.status}`);
  const frozen = async (label, path, opts) => {
    const r = await as2(path, opts);
    record(label, r.status === 409 && r.json && r.json.code === 'PROFILE_ARCHIVED', `status=${r.status}`);
  };
  await frozen('Archived: records cannot be viewed (409)', `/children/${kidId}/records`);
  await frozen('Archived: records cannot be added (409)', `/children/${kidId}/records`, { method: 'POST', body: recordBody });
  await frozen('Archived: details cannot be corrected (409)', `/children/${kidId}`, { method: 'PATCH', body: { fullName: 'x' } });
  await frozen('Archived: consent cannot change (409)', `/children/${kidId}/consent`,
    { method: 'POST', body: { scope: 'developmental_records', consentGiven: false } });
  await expectStatus('Archiving twice is refused (409)', `/children/${kidId}/archive`, { method: 'POST', token: care2.token, device: deviceC, body: {} }, 409);
  let dbFrozen = false;
  try {
    await db.runAs({ userId: cg2Acct.id, role: 'Caregiver' }, () => db.query(
      "INSERT INTO developmental_records (child_profile_id, milestone_enc, health_indicator_enc, assessment_score_enc, created_by) VALUES ($1, 'x', 'x', 'x', $2)",
      [kidId, cg2Acct.id]));
  } catch (err) {
    dbFrozen = /row-level security/.test(err.message);
  }
  record('Database itself refuses new records for an archived child (RLS)', dbFrozen);
  const listed = await as2('/children');
  record('Archived child is still listed, marked archived (nothing deleted)',
    listed.json && listed.json.children.some((c) => c.childProfileId === kidId && c.archivedAt && c.fullName === 'Archive Test Child'));
  const { rows: archLog } = await db.query(
    "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'archive_child_profile' ORDER BY id DESC LIMIT 1", [cg2Acct.id]);
  record('Audit log records the archive but not the free-text reason',
    archLog[0] && archLog[0].detail === `child_profile_id=${kidId}, reason given`, archLog[0] && archLog[0].detail);
  const restored = await as2(`/children/${kidId}/restore`, { method: 'POST' });
  record('Owner restores the profile (200)', restored.status === 200, `status=${restored.status}`);
  await expectStatus('Restored: records viewable again (200)', `/children/${kidId}/records`, { token: care2.token, device: deviceC }, 200);

  console.log('\n=== Retention: anonymising archived profiles (KDPA s.39) ===');
  await expectStatus('Caregiver cannot see retention status (403)', '/admin/retention/status', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Auditor cannot apply retention (403)', '/admin/retention/apply', { method: 'POST', token: au.token }, 403);
  await as2(`/children/${kidId}/archive`, { method: 'POST', body: {} });
  // Simulate the retention period having passed -- for THIS test child only.
  await db.runAsSystem(() => db.query(
    "UPDATE child_profiles SET archived_at = now() - interval '400 days' WHERE id = $1", [kidId]));
  const retStatus = await api('/admin/retention/status', { token: ad.token });
  record('SysAdmin sees retention status (200)', retStatus.status === 200 && retStatus.json.due >= 1, retStatus.json && `due=${retStatus.json.due}`);
  // Never anonymise real data from a test run: only proceed if every
  // profile due right now belongs to a test account.
  const { rows: dueOwners } = await db.runAsSystem(() => db.query(
    `SELECT COUNT(*) FILTER (WHERE caregiver_id <> ALL($1))::int AS other FROM child_profiles
     WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL
       AND archived_at < now() - make_interval(days => $2)`,
    [[cgAcct.id, cg2Acct.id], Number(process.env.RETENTION_DAYS) || 365]));
  if (dueOwners[0].other > 0) {
    record('Retention apply (SKIPPED: real profiles are due -- not anonymising them from a test run)', true);
  } else {
    const applied = await api('/admin/retention/apply', { method: 'POST', token: ad.token, body: { password: PASS, approvalId: await approved('apply_retention') } });
    record('SysAdmin applies retention (200) and this child is anonymised',
      applied.status === 200 && applied.json.childProfileIds.includes(kidId), applied.json && `anonymised=${applied.json.anonymised}`);
    const afterRet = await as2('/children');
    const anon = afterRet.json && afterRet.json.children.find((c) => c.childProfileId === kidId);
    record('Identity replaced with a placeholder; profile kept',
      anon && anon.fullName === 'Anonymised child' && anon.familyBackground === null && Boolean(anon.anonymisedAt), anon && anon.fullName);
    const { rows: stillThere } = await db.runAsSystem(() => db.query(
      'SELECT (SELECT COUNT(*) FROM consent_records WHERE child_profile_id = $1)::int AS consents', [kidId]));
    record('Consent history kept for the audit trail', stillThere[0].consents > 0, `${stillThere[0].consents} consent rows`);
    await expectStatus('Anonymised profile cannot be restored (409)', `/children/${kidId}/restore`,
      { method: 'POST', token: care2.token, device: deviceC }, 409);
  }

  console.log('\n=== ML risk engine: same caregiver signs in from a NEW device ===');
  const deviceB = `test-device-B-${crypto.randomBytes(3).toString('hex')}`;
  const cg2 = await login(cgAcct.email, deviceB);
  const view = await api(`/children/${childId}/records`, { token: cg2.token, device: deviceB });
  const flagged = view.status === 401 && Boolean(view.json) && view.json.code === 'SESSION_REVOKED_RISK';
  record('Action from an unrecognised device IS flagged', flagged, `status=${view.status}`);
  record('The flagged read discloses nothing (no records sent)', flagged && !('records' in view.json));
  const { rows: refusedLog } = await db.query(
    `SELECT al.access_request_id, rs.is_flagged FROM audit_log al
     LEFT JOIN risk_scores rs ON rs.access_request_id = al.access_request_id
     WHERE al.user_id = $1 AND al.action = 'view_developmental_records_refused' ORDER BY al.id DESC LIMIT 1`, [cgAcct.id]);
  record('The refused read is in the audit log, linked to its flagged score',
    refusedLog[0] && refusedLog[0].access_request_id && refusedLog[0].is_flagged === true);
  const { rows: linked } = await db.query(
    `SELECT rs.combined_score FROM audit_log al JOIN risk_scores rs ON rs.access_request_id = al.access_request_id
     WHERE al.user_id = $1 AND al.action = 'view_developmental_records' ORDER BY al.id DESC LIMIT 1`, [cgAcct.id]);
  record('A normal records read in the audit log shows its risk score (not "Unscored")', linked.length === 1,
    linked[0] ? `score ${linked[0].combined_score}` : 'no linked score');

  let riskScoreId = null;
  if (flagged) {
    const after = await api('/children', { token: cg2.token, device: deviceB });
    record('Flagged session is revoked (next call 401)', after.status === 401, `status=${after.status}`);
    record('401 explains it was a risk sign-out', after.json && after.json.code === 'SESSION_REVOKED_RISK', after.json && after.json.code);
    // Device A is the owner's usual device: in real use it was used on
    // earlier days (here the whole test runs on one fresh day). Its pages
    // must keep working while the thief's device B is shut out.
    await ageTestActivity([cgAcct.id]);
    const firstSession = await api('/children', { token: cg.token, device: deviceA });
    const { isKnownDevice } = require('../src/services/featureComputation');
    const [knownA, knownB] = await db.runAs({ userId: cgAcct.id, role: 'Caregiver' },
      () => Promise.all([isKnownDevice(cgAcct.id, deviceA), isKnownDevice(cgAcct.id, deviceB)]));
    record('The usual device is trusted; a device that was flagged never becomes trusted the next day', knownA === true && knownB === false,
      `deviceA=${knownA} deviceB=${knownB}`);
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
    const { rows: [evidenceCols] } = await db.query(
      "SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name = 'risk_scores' AND column_name IN ('features', 'drivers', 'model_version')");
    if (evidenceCols.n === 3) {
      const { rows: [ev] } = await db.query('SELECT features, drivers, model_version FROM risk_scores WHERE id = $1', [riskScoreId]);
      record('The score is stored with the 7 feature values and the model version',
        ev.features && Object.keys(ev.features).length === 7 && /^Caregiver-[0-9a-f]{12}$/.test(ev.model_version || ''), ev.model_version);
      const item = queue.json.flaggedSessions.find((s) => s.risk_score_id === riskScoreId);
      record('The auditor sees what raised the score: the unrecognised device',
        item && item.likely_reason === 'Unknown device' && item.main_factors.length > 0 && /device/i.test(item.main_factors[0].text),
        item && item.main_factors.map((f) => `${f.text} +${f.raisedBy}`).join('; '));
    } else {
      console.log('SKIP - evidence checks: run node db/migrate.js (008_score_evidence.sql) on this database first');
    }
    await expectStatus('Auditor sets status=reviewing', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'reviewing' } }, 200);
    await expectStatus('Auditor rejects an invalid status (400)', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'bogus' } }, 400);
    await expectStatus('Auditor sets status=confirmed', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'confirmed' } }, 200);

    console.log('\n=== Owner\'s "This was me" link ===');
    const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
    const denyToken = signRiskResponseToken(riskScoreId, 'deny');
    const ownerResponse = async () => (await db.query('SELECT owner_response FROM risk_scores WHERE id = $1', [riskScoreId])).rows[0].owner_response;
    // A mail scanner opens both links: that must change nothing.
    const openedConfirm = await api(`/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    const openedDeny = await api(`/risk-response/${riskScoreId}/deny?token=${denyToken}`);
    record('Opening the email links only shows a page with a button',
      openedConfirm.status === 200 && openedConfirm.text.includes('method="post"') && openedDeny.status === 200 && openedDeny.text.includes('method="post"'));
    record('Opening the links changes nothing (a mail scanner cannot act)', (await ownerResponse()) === 'pending');
    const c1 = await api(`/risk-response/${riskScoreId}/confirm`, { method: 'POST', body: { token: confirmToken } });
    record('Pressing "Yes, this was me" is accepted', c1.status === 200 && c1.text.includes('Thanks for confirming'), `status=${c1.status}`);
    record('The owner’s answer is recorded', (await ownerResponse()) === 'confirmed_benign');
    const c2 = await api(`/risk-response/${riskScoreId}/confirm`, { method: 'POST', body: { token: confirmToken } });
    record('Second press is a harmless no-op', c2.text.includes('already responded'));
    const d1 = await api(`/risk-response/${riskScoreId}/deny`, { method: 'POST', body: { token: denyToken } });
    record('Deny after confirm is also a no-op (no lock)', d1.text.includes('already responded'));
    const bad = await api(`/risk-response/${riskScoreId}/confirm`, { method: 'POST', body: { token: 'forged' } });
    record('Forged link token is refused', bad.status >= 400, `status=${bad.status}`);

    console.log('\n=== Breach decision on a suspected breach (KDPA s.43) ===');
    const decide = (body, token = au.token) => api(`/auditor/flagged-sessions/${riskScoreId}/breach-decision`, { method: 'POST', token, body });
    const valid = { decision: 'no_real_risk', reason: 'Automated test: owner confirmed, known test device' };
    record('Not a breach candidate while confirmed and owner said "this was me" (409)', (await decide(valid)).status === 409);
    await api(`/auditor/flagged-sessions/${riskScoreId}/review`, { method: 'POST', token: au.token, body: { status: 'escalated' } });
    record('Unknown decision is rejected (400)', (await decide({ ...valid, decision: 'ignored' })).status === 400);
    record('A decision without reasoning is rejected (400)', (await decide({ ...valid, reason: 'ok' })).status === 400);
    record('Caregiver cannot record a breach decision (403)', (await decide(valid, cg.token)).status === 403);
    const decided = await decide(valid);
    record('Auditor records the decision on an escalated session (200, within 72 h)',
      decided.status === 200 && decided.json.withinWindow === true, decided.json && `${decided.json.hoursAfterFlag} h after flag`);
    record('The decision cannot be changed afterwards (409)', (await decide({ ...valid, decision: 'reported_to_admin' })).status === 409);
    const { rows: brLog } = await db.query(
      "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'breach_decision_recorded' ORDER BY id DESC LIMIT 1", [auAcct.id]);
    record('Breach decision is in the audit log with its timing',
      brLog[0] && brLog[0].detail.startsWith(`risk_score_id=${riskScoreId}, decision=no_real_risk`) && brLog[0].detail.includes('within_72h=true'),
      brLog[0] && brLog[0].detail);
  }

  console.log('\n=== SysAdmin: encryption keys + account actions ===');
  const enc = await api('/admin/encryption/status', { token: ad.token });
  record('Encryption status loads (200)', enc.status === 200, enc.json ? `active key #${enc.json.activeKeyId}` : '');
  record('Encryption status never exposes key material', enc.json && !JSON.stringify(enc.json).match(/[A-Za-z0-9+/]{43}=/));
  // 429 also counts as refused: repeat runs inside 15 minutes hit the
  // step-up failure limit, which is that protection working.
  const noPw = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token });
  record('Re-encrypt without the password is refused (step-up)', [403, 429].includes(noPw.status), `status=${noPw.status}`);
  const wrongPw = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token, body: { password: 'not-the-password' } });
  record('Re-encrypt with a wrong password is refused, session stays signed in',
    [403, 429].includes(wrongPw.status) && (await api('/auth/me', { token: ad.token })).status === 200, `status=${wrongPw.status}`);
  const { rows: stepLog } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'step_up_failed'", [adAcct.id]);
  record('Failed step-up attempts are in the audit log', stepLog[0].n > 0, `${stepLog[0].n} entries`);
  const unapproved = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token, body: { password: PASS } });
  record("Re-encrypt without a second admin's approval is refused (409)", unapproved.status === 409 && unapproved.json.code === 'APPROVAL_REQUIRED', `status=${unapproved.status}`);
  const re = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token, body: { password: PASS, approvalId: await approved('reencrypt_data') } });
  record('Re-encrypt runs (200) and leaves nothing behind', re.status === 200 && re.json.status.needsReencryption === 0,
    re.json ? `updated ${re.json.updatedValues} value(s)` : `status=${re.status}`);
  const relist = await api('/children', { token: cg.token, device: deviceA });
  const still = relist.json && relist.json.children.find((c) => c.childProfileId === childId);
  record('Child data still decrypts after re-encryption', still && still.fullName === 'Test Child');
  await expectStatus('Caregiver cannot unlock accounts (403)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: cg.token, device: deviceA }, 403);
  await expectStatus('Unlocking a not-locked account (409)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: ad.token }, 409);
  await expectStatus('Unlocking a nonexistent user (404)', '/admin/users/999999/unlock', { method: 'POST', token: ad.token }, 404);
  await expectStatus('Approving a nonexistent request (404)', '/admin/registration-requests/999999/approve', { method: 'POST', token: ad.token }, 404);

  console.log('\n=== Home page summaries ===');
  const adminHome = await api('/admin/overview', { token: ad.token });
  record('SysAdmin overview loads with its figures', adminHome.status === 200 && Number.isInteger(adminHome.json.pendingRequests)
    && Number.isInteger(adminHome.json.lockedAccounts) && Array.isArray(adminHome.json.activeUsers) && Number.isInteger(adminHome.json.retentionDue),
    `status=${adminHome.status}`);
  const auditHome = await api('/auditor/overview', { token: au.token });
  record('Auditor overview loads with 14 days of flags', auditHome.status === 200 && auditHome.json.flagsPerDay.length === 14,
    `status=${auditHome.status}, reasons=${auditHome.json && auditHome.json.reasons.length}`);
  await expectStatus('Caregiver cannot read the admin overview (403)', '/admin/overview', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver cannot read the auditor overview (403)', '/auditor/overview', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Auditor cannot read the admin overview (403)', '/admin/overview', { token: au.token }, 403);
  const homeText = JSON.stringify(adminHome.json) + JSON.stringify(auditHome.json);
  record('Overviews contain no child names', !homeText.includes('Test Child') && !homeText.includes('Anonymised child'));
  const cards = await api('/children', { token: cg.token, device: deviceA });
  const card = cards.json && cards.json.children.find((c) => c.childProfileId === childId);
  record('Child cards carry record count and consent status', card && Number.isInteger(card.recordCount) && card.recordsConsent === true);
  const meNow = await api('/auth/me', { token: cg.token, device: deviceA });
  record('/auth/me reports the previous sign-in', meNow.status === 200 && meNow.json.lastSignInAt !== undefined);

  console.log('\n=== Risk thresholds (FR-21) ===');
  const WHY = 'Automated test of this control';
  const setLimit = (role, threshold, password = PASS, token = au.token, reason = WHY) => api(`/auditor/risk-thresholds/${role}`, {
    method: 'POST', token, body: { threshold, reason, password },
  });
  const clearLimits = () => db.query("DELETE FROM risk_threshold_settings WHERE reason = $1", [WHY]);
  const clearSettings = () => db.query("DELETE FROM system_settings WHERE reason = $1", [WHY]);
  await clearLimits();
  await clearSettings();
  try {
    const limits = await api('/auditor/risk-thresholds', { token: au.token });
    const cgLimit = limits.json && limits.json.thresholds.find((t) => t.role === 'Caregiver');
    const ownLimit = limits.json && limits.json.thresholds.find((t) => t.role === 'SecurityAuditor');
    record('Auditor sees the limits for all four roles', limits.status === 200 && limits.json.thresholds.length === 4);
    record('Auditor\'s own role is marked not editable', ownLimit && ownLimit.editable === false && cgLimit.editable === true);
    await expectStatus('Caregiver cannot read risk limits (403)', '/auditor/risk-thresholds', { token: cg.token, device: deviceA }, 403);
    await expectStatus('Admin cannot read risk limits (403)', '/auditor/risk-thresholds', { token: ad.token }, 403);
    record('Admin cannot change a risk limit (403)', (await setLimit('Caregiver', 0.42, PASS, ad.token)).status === 403);
    const noPass = await api('/auditor/risk-thresholds/Caregiver', { method: 'POST', token: au.token, body: { threshold: 0.42, reason: WHY } });
    record('Changing a limit without the password is refused (403)', noPass.status === 403 && noPass.json.code === 'STEP_UP_REQUIRED');
    record('Changing a limit with a wrong password is refused (403)', (await setLimit('Caregiver', 0.42, 'not-the-password')).status === 403);
    const ownChange = await setLimit('SecurityAuditor', 0.7);
    record('Auditor cannot change their own role\'s limit (403)', ownChange.status === 403 && ownChange.json.code === 'OWN_ROLE_THRESHOLD');
    record('A limit above the allowed range is refused (400)', (await setLimit('Caregiver', 0.99)).status === 400);
    record('A limit below the allowed range is refused (400)', (await setLimit('Caregiver', 0.01)).status === 400);
    record('A limit that is not a number is refused (400)', (await setLimit('Caregiver', '0.42')).status === 400);
    record('A change with no real reason is refused (400)', (await setLimit('Caregiver', 0.42, PASS, au.token, 'short')).status === 400);
    record('An unknown role is refused (404)', (await setLimit('Nobody', 0.42)).status === 404);
    record('Same limit as now is refused (409)', (await setLimit('Caregiver', cgLimit.threshold)).status === 409);

    let dbRefused = false;
    try {
      await db.query('INSERT INTO risk_threshold_settings (role_name, threshold, reason, updated_by) VALUES ($1, 0.99, $2, $3)', ['Caregiver', WHY, auAcct.id]);
    } catch (err) {
      dbRefused = err.constraint === 'risk_threshold_within_limits';
    }
    record('The database itself refuses a limit outside the range', dbRefused);

    const since = new Date();
    const changed = await setLimit('Caregiver', 0.42);
    record('Auditor changes the Caregiver limit (200)', changed.status === 200, `status=${changed.status}`);
    const scored = await api(`/children/${childId}/records`, { token: cg.token, device: deviceA });
    const { rows: applied } = await db.query(
      `SELECT rs.role_threshold FROM risk_scores rs JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE ar.user_id = $1 ORDER BY rs.id DESC LIMIT 1`, [cgAcct.id]);
    // Either answer is correct here: a normal read (200), or -- when this
    // caregiver's activity so far crosses the new limit, as on a fresh
    // database -- a read refused before any record is sent (401). What is
    // checked is that the limit used was the new one.
    const answered = scored.status === 200 || (scored.status === 401 && scored.json && scored.json.code === 'SESSION_REVOKED_RISK');
    record('The very next action is scored against the new limit', answered && Number(applied[0].role_threshold) === 0.42,
      `status=${scored.status}, threshold=${applied[0] && applied[0].role_threshold}`);
    const { rows: limitLog } = await db.query(
      "SELECT detail FROM audit_log WHERE action = 'risk_threshold_changed' AND user_id = $1 AND created_at >= $2", [auAcct.id, since]);
    record('The change is in the audit log with its reason', limitLog.length === 1 && limitLog[0].detail.includes('to=0.42') && limitLog[0].detail.includes(WHY));
    const { rows: tried } = await db.query(
      "SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'step_up_failed' AND user_id = $1 AND detail LIKE '%risk-thresholds%'", [auAcct.id]);
    record('The wrong password attempt is in the audit log', tried[0].n >= 1);
  } finally {
    await clearLimits();
  }

  console.log('\n=== Users, roles and settings (FR-25) ===');
  const setRole = (id, role, password = PASS, token = ad.token, reason = WHY) => api(`/admin/users/${id}/role`, {
    method: 'POST', token, body: { role, reason, password },
  });
  const rcUser = await ensureTestAccount(ACCOUNTS.rc);
  const rcAcct = rcUser.id;
  await db.query("UPDATE users SET role_id = (SELECT id FROM roles WHERE name = 'Caregiver') WHERE id = $1", [rcAcct]);
  await ageTestActivity([rcAcct]);
  const rc = await login(rcUser.email);
  const people = await api('/admin/users', { token: ad.token });
  const listedUser = people.json && people.json.users.find((u) => u.id === cgAcct.id);
  record('Admin sees the user list with child counts', people.status === 200 && listedUser && listedUser.children >= 1);
  record('The user list contains no child names', !JSON.stringify(people.json).includes('Test Child'));
  // rc is a caregiver signed in just now; cg's session was ended on purpose earlier.
  await expectStatus('Caregiver cannot list users (403)', '/admin/users', { token: rc.token }, 403);
  await expectStatus('Auditor cannot list users (403)', '/admin/users', { token: au.token }, 403);
  record('Auditor cannot change a role (403)', (await setRole(rcAcct, 'SysAdmin', PASS, au.token)).status === 403);
  record('Caregiver cannot make themselves an admin (403)', (await api(`/admin/users/${rcAcct}/role`, {
    method: 'POST', token: rc.token, body: { role: 'SysAdmin', reason: WHY, password: PASS },
  })).status === 403);
  const roleNoPass = await api(`/admin/users/${rcAcct}/role`, { method: 'POST', token: ad.token, body: { role: 'SysAdmin', reason: WHY } });
  record('Changing a role without the password is refused (403)', roleNoPass.status === 403 && roleNoPass.json.code === 'STEP_UP_REQUIRED');
  const selfRole = await setRole(adAcct.id, 'Caregiver');
  record('Admin cannot change their own role (403)', selfRole.status === 403 && selfRole.json.code === 'OWN_ROLE_CHANGE');
  record('An unknown role is refused (400)', (await setRole(rcAcct, 'SuperUser')).status === 400);
  record('A role change with no real reason is refused (400)', (await setRole(rcAcct, 'SysAdmin', PASS, ad.token, 'short')).status === 400);
  record('Changing a nonexistent user is refused (404)', (await setRole(999999, 'SysAdmin')).status === 404);
  record('Setting the role a user already has is refused (409)', (await setRole(rcAcct, 'Caregiver')).status === 409);
  const hasChildren = await setRole(cgAcct.id, 'SecurityAuditor');
  record('A caregiver with children linked cannot be moved (409)', hasChildren.status === 409 && hasChildren.json.code === 'CAREGIVER_HAS_CHILDREN');
  const moved = await setRole(rcAcct, 'SecurityAuditor');
  record('Admin changes a user\'s role (200)', moved.status === 200, `status=${moved.status}`);
  const oldSession = await api('/auth/me', { token: rc.token });
  record('The user\'s open session ends at once (401)', oldSession.status === 401, `status=${oldSession.status}`);
  const rcAgain = await login(rcUser.email);
  record('The next sign-in carries the new role', rcAgain.role === 'SecurityAuditor', `role=${rcAgain.role}`);
  record('The new role gives the new access (200)', (await api('/auditor/audit-log?limit=1', { token: rcAgain.token })).status === 200);
  const { rows: roleLog } = await db.query(
    "SELECT detail FROM audit_log WHERE action = 'user_role_changed' AND user_id = $1 ORDER BY id DESC LIMIT 1", [adAcct.id]);
  record('The role change is in the audit log with its reason', roleLog[0] && roleLog[0].detail.includes('to=SecurityAuditor') && roleLog[0].detail.includes(WHY));
  record('Admin puts the role back (200)', (await setRole(rcAcct, 'Caregiver')).status === 200);
  const rcBack = await login(rcUser.email);
  record('After it is put back, sign-in is a caregiver again', rcBack.role === 'Caregiver', `role=${rcBack.role}`);

  const setSetting = (key, value, password = PASS, token = ad.token) => api(`/admin/settings/${key}`, {
    method: 'POST', token, body: { value, reason: WHY, password },
  });
  try {
    const settings = await api('/admin/settings', { token: ad.token });
    record('Admin sees the three settings', settings.status === 200 && settings.json.settings.length === 3);
    const settingsText = JSON.stringify(settings.json);
    record('Settings show no keys or passwords', !/ENCRYPTION|JWT|SMTP|DATABASE|password/i.test(settingsText));
    await expectStatus('Caregiver cannot read settings (403)', '/admin/settings', { token: rcBack.token }, 403);
    await expectStatus('Auditor cannot read settings (403)', '/admin/settings', { token: au.token }, 403);
    record('Changing a setting with a wrong password is refused (403)', (await setSetting('retention_days', 400, 'not-the-password')).status === 403);
    record('A retention period below the minimum is refused (400)', (await setSetting('retention_days', 1)).status === 400);
    record('A value that is not a whole number is refused (400)', (await setSetting('retention_days', 40.5)).status === 400);
    record('An unknown setting is refused (404)', (await setSetting('jwt_secret', 1)).status === 404);
    record('Admin changes the retention period (200)', (await setSetting('retention_days', 400)).status === 200);
    const retentionNow = await api('/admin/retention/status', { token: ad.token });
    record('Data Retention uses the new period at once', retentionNow.json && retentionNow.json.retentionDays === 400, `days=${retentionNow.json && retentionNow.json.retentionDays}`);
    record('Admin changes the report download limit (200)', (await setSetting('report_exports_per_hour', 40)).status === 200);
    const report = await api('/auditor/reports/flagged-sessions?format=csv', { token: au.token });
    record('The download limit uses the new value at once', report.status === 200 && /q=40/.test(report.limit || ''), `limit=${report.limit}`);
    const { rows: settingLog } = await db.query(
      "SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'system_setting_changed' AND user_id = $1 AND created_at > now() - interval '5 minutes'", [adAcct.id]);
    record('Setting changes are in the audit log', settingLog[0].n >= 2);
  } finally {
    await clearSettings();
  }

  console.log('\n=== Two-person approval (re-encryption, anonymising) ===');
  {
    const adA = await login(adAcct.email);
    const adB = await login(ad2Acct.email);
    const ask = (token, body) => api('/admin/approvals', { method: 'POST', token, body });
    const decide = (id, verb, token, body) => api(`/admin/approvals/${id}/${verb}`, { method: 'POST', token, body });
    const run = (approvalId, token = adA.token) => api('/admin/encryption/reencrypt', { method: 'POST', token, body: { password: PASS, approvalId } });
    const auNow = await login(auAcct.email);
    record('An auditor cannot ask for an approval (403)', (await ask(auNow.token, { action: 'reencrypt_data', reason: 'Not my role to ask', password: PASS })).status === 403);
    record('Asking without the password is refused (step-up)', [403, 429].includes((await ask(adA.token, { action: 'reencrypt_data', reason: 'Missing the password here' })).status));
    record('Asking with no real reason is refused (400)', (await ask(adA.token, { action: 'reencrypt_data', reason: 'short', password: PASS })).status === 400);
    record('An unknown action is refused (400)', (await ask(adA.token, { action: 'drop_database', reason: 'Trying an action that does not exist', password: PASS })).status === 400);
    const asked = await ask(adA.token, { action: 'reencrypt_data', reason: 'Key rotation after a staff change', password: PASS });
    record('A System Administrator asks for approval (201)', asked.status === 201 && asked.json.status === 'pending', `status=${asked.status}`);
    const id = asked.json && asked.json.id;
    const own = await decide(id, 'approve', adA.token, { reason: 'Approving my own request', password: PASS });
    record('The person who asked cannot approve it (403)', own.status === 403 && own.json.code === 'OWN_REQUEST', `status=${own.status}`);
    let dbRefused = false;
    try {
      await db.query("UPDATE pending_approvals SET decided_by = requested_by, status = 'approved', decided_at = now() WHERE id = $1", [id]);
    } catch { dbRefused = true; }
    record('The database also refuses one person deciding their own request', dbRefused);
    record('A pending request cannot be used (409)', (await run(id)).status === 409);
    const okd = await decide(id, 'approve', adB.token, { reason: 'Checked with the requester in person', password: PASS });
    record('A second System Administrator approves (200)', okd.status === 200, `status=${okd.status}`);
    record('An approval for re-encryption cannot anonymise (409)',
      (await api('/admin/retention/apply', { method: 'POST', token: adA.token, body: { password: PASS, approvalId: id } })).status === 409);
    const first = await run(id);
    record('The approved re-encryption runs once (200)', first.status === 200, `status=${first.status}`);
    record('The same approval cannot be used twice (409)', (await run(id)).status === 409);
    const asked2 = await ask(adA.token, { action: 'reencrypt_data', reason: 'Second request, to be rejected', password: PASS });
    await decide(asked2.json.id, 'reject', adB.token, { reason: 'Not needed this week', password: PASS });
    record('A rejected request cannot be used (409)', (await run(asked2.json.id)).status === 409);
    record('A decided request cannot be decided again (409)', (await decide(asked2.json.id, 'approve', adB.token, { reason: 'Changing my mind later', password: PASS })).status === 409);
    const asked3 = await ask(adA.token, { action: 'reencrypt_data', reason: 'Third request, left to expire', password: PASS });
    await decide(asked3.json.id, 'approve', adB.token, { reason: 'Approved, then left unused', password: PASS });
    await db.query("UPDATE pending_approvals SET decided_at = now() - interval '25 hours' WHERE id = $1", [asked3.json.id]);
    record('An approval older than 24 hours cannot be used (409)', (await run(asked3.json.id)).status === 409);
    const list = await api('/admin/approvals', { token: adB.token });
    record('Admins see the approval history', list.status === 200 && list.json.approvals.some((a) => a.id === id && a.status === 'used'));
    const { rows: apLog } = await db.query(
      "SELECT array_agg(DISTINCT action) AS a FROM audit_log WHERE action LIKE 'approval_%' AND detail LIKE $1", [`approval_id=${id},%`]);
    record('Asking and approving are in the audit log', Boolean(apLog[0].a && apLog[0].a.includes('approval_requested') && apLog[0].a.includes('approval_approved')), String(apLog[0].a));
  }

  console.log('\n=== Weekly review (layer 2: People to review) ===');
  {
    const au2Acct = await ensureTestAccount(ACCOUNTS.au2);
    await ageTestActivity([au2Acct.id]);
    const auW = await login(auAcct.email);
    const au2 = await login(au2Acct.email);
    const adW = await login(ad2Acct.email);
    const cgW = await login(ACCOUNTS.cg.username, deviceA);
    await expectStatus('A caregiver cannot see the weekly review (403)', '/auditor/weekly-review', { token: cgW.token, device: deviceA }, 403);
    await expectStatus("An admin cannot use the auditors' weekly review (403)", '/auditor/weekly-review', { token: adW.token }, 403);
    await expectStatus("An auditor cannot use the admins' page (403)", '/admin/weekly-review', { token: auW.token }, 403);
    const refreshed = await api('/auditor/weekly-review/refresh', { method: 'POST', token: au2.token });
    record('An auditor re-scores the week (200)', refreshed.status === 200 && refreshed.json.lastRefresh.ok === true && refreshed.json.lastRefresh.people >= 1,
      refreshed.json ? JSON.stringify(refreshed.json.lastRefresh) : `status=${refreshed.status}`);
    const list = await api('/auditor/weekly-review', { token: au2.token });
    record('The weekly list loads with people in it (200)', list.status === 200 && list.json.people.length >= 1, list.json && `${list.json.people.length} people`);
    record('An auditor never sees their own week', Boolean(list.json) && !list.json.people.some((p) => p.user_id === au2Acct.id));
    record('Every row has a score, the line (1.00) and both parts',
      Boolean(list.json) && list.json.people.every((p) => Number(p.score_limit) === 1 && p.parts && 'learned' in p.parts && 'change' in p.parts));
    await expectStatus('A bad week is refused (400)', '/auditor/weekly-review?week=last-tuesday', { token: au2.token }, 400);
    await expectStatus('An unknown role filter is refused (400)', '/auditor/weekly-review?role=Superuser', { token: au2.token }, 400);
    const cgOnly = await api('/auditor/weekly-review?role=Caregiver', { token: au2.token });
    record('The role filter works', cgOnly.status === 200 && cgOnly.json.people.every((p) => p.role === 'Caregiver'));
    const meNow = await api('/auth/me', { token: cgW.token, device: deviceA });
    record('Scoring the week signs nobody out', meNow.status === 200);
    const auRow = list.json && list.json.people.find((p) => p.user_id === auAcct.id);
    if (!auRow) {
      record("The test auditor's week is listed for a second auditor", false, 'no row');
    } else {
      const ownOpen = await api(`/auditor/weekly-review/${auRow.id}`, { token: auW.token });
      record('Nobody can open their own week (403)', ownOpen.status === 403 && ownOpen.json.code === 'OWN_WEEK', `status=${ownOpen.status}`);
      const ownDecide = await api(`/auditor/weekly-review/${auRow.id}/decision`, { method: 'POST', token: auW.token, body: { status: 'no_concern', note: 'Reviewing my own week' } });
      record('Nobody can decide on their own week (403)', ownDecide.status === 403);
      let dbRefused = false;
      try { await db.query('UPDATE weekly_reviews SET reviewed_by = user_id WHERE id = $1', [auRow.id]); } catch { dbRefused = true; }
      record("The database also refuses a review of one's own week", dbRefused);
      const detail = await api(`/auditor/weekly-review/${auRow.id}`, { token: au2.token });
      record('Another auditor opens the week with its day-by-day activity (200)', detail.status === 200 && Array.isArray(detail.json.days) && detail.json.days.length >= 1);
      record('A decision needs a note (400)', (await api(`/auditor/weekly-review/${auRow.id}/decision`, { method: 'POST', token: au2.token, body: { status: 'escalated', note: 'short' } })).status === 400);
      record('An unknown decision is refused (400)', (await api(`/auditor/weekly-review/${auRow.id}/decision`, { method: 'POST', token: au2.token, body: { status: 'deleted', note: 'Trying an unknown status' } })).status === 400);
      const dec = await api(`/auditor/weekly-review/${auRow.id}/decision`, { method: 'POST', token: au2.token, body: { status: 'escalated', note: 'Escalated by the automated test' } });
      record('Another auditor records a decision (200)', dec.status === 200, `status=${dec.status}`);
      const again = await api('/auditor/weekly-review/refresh', { method: 'POST', token: au2.token });
      const kept = await api('/auditor/weekly-review', { token: au2.token });
      record('Re-scoring keeps the decision', [200, 429].includes(again.status) && kept.json.people.find((p) => p.id === auRow.id).status === 'escalated');
      const { rows: wlog } = await db.query("SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'weekly_review_decision' AND detail LIKE $1", [`weekly_review_id=${auRow.id},%`]);
      record('The decision is in the audit log', wlog[0].n >= 1);
      const adminList = await api('/admin/weekly-review', { token: adW.token });
      record("Admins see the Security Auditors' weeks only", adminList.status === 200 && adminList.json.people.length >= 1 && adminList.json.people.every((p) => p.role === 'SecurityAuditor'));
      const adminDecide = await api(`/admin/weekly-review/${auRow.id}/decision`, { method: 'POST', token: adW.token, body: { status: 'no_concern', note: 'Admin checked the auditor week' } });
      record("An admin can decide on an auditor's week (200)", adminDecide.status === 200);
      const cgRow = list.json.people.find((p) => p.role === 'Caregiver');
      if (cgRow) record("An admin cannot open a caregiver's week (404)", (await api(`/admin/weekly-review/${cgRow.id}`, { token: adW.token })).status === 404);
    }
    const ov = await api('/auditor/overview', { token: au2.token });
    record('The home page reports risk scoring as online', ov.status === 200 && Boolean(ov.json.scoring) && ov.json.scoring.online === true);
  }

  // Fresh sessions for the section below (earlier sections end some on purpose).
  await ageTestActivity([cgAcct.id]);
  const cgS = await login(ACCOUNTS.cg.username, deviceA);
  const auE0 = await login(auAcct.email);
  console.log('\n=== Educator: caregiver-approved, read-only access to a child (SOFIA 3.1) ===');
  {
    const shAcct = await ensureTestAccount(ACCOUNTS.sh);
    const edAcct = await ensureTestAccount(ACCOUNTS.ed);
    const ed2Acct = await ensureTestAccount(ACCOUNTS.ed2);
    await db.query("UPDATE users SET ecd_centre = 'Test ECD Centre' WHERE id = ANY($1)", [[edAcct.id, ed2Acct.id]]);
    await ageTestActivity([shAcct.id, edAcct.id, ed2Acct.id]);
    // Close anything an earlier, interrupted run left open.
    await db.query("UPDATE educator_access SET status = CASE WHEN status = 'granted' THEN 'revoked' ELSE 'refused' END, ended_at = now(), decided_by = $2 WHERE educator_id = ANY($1) AND status IN ('pending', 'granted')", [[edAcct.id, ed2Acct.id], shAcct.id]);
    const devS = 'test-device-sharing';
    const devE = 'test-device-educator';
    const devE2 = 'test-device-educator2';
    const sh = await login(ACCOUNTS.sh.username, devS);
    const ed = await login(ACCOUNTS.ed.username, devE);
    const ed2 = await login(ACCOUNTS.ed2.username, devE2);
    const asEd = (path, opts = {}) => api(path, { token: ed.token, device: devE, ...opts });
    const asSh = (path, opts = {}) => api(path, { token: sh.token, device: devS, ...opts });

    await expectStatus('Educator -> caregiver children list (403)', '/children', { token: ed.token, device: devE }, 403);
    await expectStatus('Educator -> audit log (403)', '/auditor/audit-log', { token: ed.token, device: devE }, 403);
    await expectStatus('Educator -> admin users (403)', '/admin/users', { token: ed.token, device: devE }, 403);
    await expectStatus('Caregiver -> educator pages (403)', '/educator/children', { token: sh.token, device: devS }, 403);
    await expectStatus('Auditor -> educator pages (403)', '/educator/children', { token: auE0.token }, 403);

    // Names unique to this run (letters only: the name index ignores digits).
    const word = () => Array.from({ length: 7 }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]).join('');
    const KID = `Shared ${word()} Child`;
    const SIB = `Sibling ${word()} Child`;
    const BABY = `Baby ${word()} Child`;
    const OLD = `Older ${word()} Child`;
    const addKid = async (fullName, dateOfBirth, extra = {}) => {
      const r = await asSh('/children', { method: 'POST', body: { fullName, dateOfBirth, developmentalRecordsConsent: true, ...extra, ...NOTICE } });
      return r.json && r.json.childProfileId;
    };
    // Birth dates relative to today, so the ages hold whenever this runs.
    const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
    const KID_DOB = daysAgo(4 * 365 + 20);         // 4 years old
    const SIB_DOB = daysAgo(7 * 365 - 40);         // 6, turning 7 in about 6 weeks
    const kidId = await addKid(KID, KID_DOB, { familyBackground: 'Private family note' });
    const sibId = await addKid(SIB, SIB_DOB);
    await addKid(BABY, daysAgo(400));               // 1 year old
    await addKid(OLD, daysAgo(8 * 365));            // 8 years old
    await asSh(`/children/${kidId}/records`, { method: 'POST', body: { milestone: 'Counts to ten', healthIndicator: 'Healthy', assessmentScore: 7, progressNotes: 'Shared note' } });
    const { rows: idx } = await db.runAsSystem(() => db.query('SELECT name_index, name_index_key_id FROM child_identifiers WHERE child_profile_id = $1', [kidId]));
    record('A new child gets a blind index of the name (64 hex characters, no name)', Boolean(idx[0]) && /^[0-9a-f]{64}$/.test(idx[0].name_index) && idx[0].name_index_key_id > 0);

    const before = await asEd(`/educator/children/${kidId}/records`);
    record('Educator with no permission is refused (403 NO_ACCESS_GRANT)', before.status === 403 && before.json.code === 'NO_ACCESS_GRANT', `status=${before.status}`);
    const missing = await asEd('/educator/children/2147483000/records');
    record('...with the same answer for a child that does not exist', missing.status === 403 && missing.json.error === before.json.error);

    const ask = (childName, reason = 'Class educator, PP1 Blue', who = ed, dev = devE) =>
      api('/educator/access-requests', { method: 'POST', token: who.token, device: dev, body: { childName, reason } });
    const pendingFor = async () => (await asSh('/children/access')).json.requests.filter((r) => r.status === 'pending' && r.educatorName === ACCOUNTS.ed.name);
    record('A single word is not a full name (400)', (await ask('Amani')).status === 400);
    record('A request with no real reason is refused (400)', (await ask(KID, 'pls')).status === 400);
    await expectStatus('A caregiver cannot ask for access as an educator (403)', '/educator/access-requests',
      { method: 'POST', token: cgS.token, device: deviceA, body: { childName: KID, reason: 'Class educator, PP1 Blue' } }, 403);

    const nobody = await ask(`Nobody ${word()} Here`);
    const asked = await ask(KID.toLowerCase().split(' ').reverse().join('  '));
    record('Educator asks by the child’s name (201), case and name order ignored', asked.status === 201, `status=${asked.status}`);
    record('The reply is the same whether or not a child matched: no way to find out who is registered',
      nobody.status === 201 && nobody.json.message === asked.json.message && Object.keys(nobody.json).sort().join() === Object.keys(asked.json).sort().join());
    record('The reply tells the educator nothing about the child', !JSON.stringify(asked.json).includes(KID) && !('childProfileId' in asked.json));
    let waiting = await pendingFor();
    record('The request reaches that child’s parent only, naming the child', waiting.length === 1 && waiting[0].childProfileId === kidId && waiting[0].childName === KID
      && waiting[0].ecdCentre === 'Test ECD Centre' && waiting[0].reason === 'Class educator, PP1 Blue');
    await ask(KID);
    record('Asking again for the same child adds no second request', (await pendingFor()).length === 1);
    await ask(BABY);
    await ask(OLD);
    record('Children under 3 or aged 7+ are never matched (ECD age only)', (await pendingFor()).length === 1);
    const { rows: unmatched } = await db.query('SELECT COUNT(*)::int AS n FROM educator_access WHERE ask_id = $1', [nobody.json.id]);
    record('A name that matches nobody reaches nobody', unmatched[0].n === 0);
    const { rows: trailName } = await db.query("SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND detail LIKE $2", [edAcct.id, `%${KID.split(' ')[1]}%`]);
    record('The audit log records profile numbers, not the name typed', trailName[0].n === 0);

    const pendingList = await asEd('/educator/children');
    record('The educator’s list shows what they typed, and no child yet', pendingList.status === 200 && pendingList.json.children.length === 0
      && pendingList.json.asks.some((a) => a.id === asked.json.id) && !JSON.stringify(pendingList.json).includes('waiting') && !JSON.stringify(pendingList.json).includes('pending'));
    record('Still refused while the parent has not decided (403)', (await asEd(`/educator/children/${kidId}/records`)).status === 403);

    const decide = (who, id, body) => api(`/children/access/${id}/decision`, { method: 'POST', token: who.token, device: who === sh ? devS : deviceA, body });
    const reqId = waiting[0].id;
    record('Another caregiver cannot decide the request (404)', (await decide(cgS, reqId, { decision: 'grant' })).status === 404);
    record('The educator cannot approve their own request (403)', (await asEd(`/children/access/${reqId}/decision`, { method: 'POST', body: { decision: 'grant' } })).status === 403);
    record('An open-ended or odd period is refused (400)', (await decide(sh, reqId, { decision: 'grant', days: 9999 })).status === 400);
    record('A decision that is neither grant nor refuse is refused (400)', (await decide(sh, reqId, { decision: 'maybe' })).status === 400);
    const granted = await decide(sh, reqId, { decision: 'grant', days: 30 });
    record('Caregiver grants access for 30 days (200)', granted.status === 200 && granted.json.status === 'granted' && Boolean(granted.json.expiresAt), `status=${granted.status}`);
    record('A request cannot be decided twice (409)', (await decide(sh, reqId, { decision: 'refuse' })).status === 409);
    const long = await ask(SIB, 'Class educator, PP2 Green');
    const sibReq = (await pendingFor()).find((r) => r.childProfileId === sibId);
    const sibGrant = sibReq && await decide(sh, sibReq.id, { decision: 'grant', days: 90 });
    const sd = new Date(SIB_DOB);
    const seventh = new Date(Date.UTC(sd.getUTCFullYear() + 7, sd.getUTCMonth(), sd.getUTCDate()));
    record('Access never runs past the 7th birthday, whatever period is chosen', long.status === 201 && Boolean(sibGrant) && sibGrant.status === 200
      && new Date(sibGrant.json.expiresAt).getTime() === seventh.getTime(), sibGrant && sibGrant.json && sibGrant.json.expiresAt);
    if (sibGrant && sibGrant.status === 200) await asSh(`/children/access/${sibReq.id}/revoke`, { method: 'POST' });

    const mine = await asEd('/educator/children');
    const shared = mine.json && mine.json.children.find((c) => c.childProfileId === kidId);
    const statusOf = (list, id) => (list.json.asks.find((a) => a.id === id) || {}).status;
    record('The educator’s request shows Approved once granted; an unmatched one stays Requested',
      statusOf(mine, asked.json.id) === 'approved' && statusOf(mine, nobody.json.id) === 'requested');
    record('Educator now sees the child: name and age only', Boolean(shared) && shared.fullName === KID && /year/.test(shared.age));
    record('...and nothing about the parent’s other children', !JSON.stringify(mine.json.children).includes(SIB) && !JSON.stringify(mine.json.children).includes(BABY)
      && (await asEd(`/educator/children/${sibId}/records`)).status === 403);
    const view = await asEd(`/educator/children/${kidId}/records`);
    record('Educator reads the shared child’s records (200)', view.status === 200 && view.json.records.length === 1 && view.json.records[0].milestone === 'Counts to ten', `status=${view.status}`);
    const sent = JSON.stringify([mine.json, view.json]);
    record('No birth date, family background or parent contact reaches the educator',
      !sent.includes(KID_DOB) && !sent.includes('Private family note') && !sent.includes(shAcct.email) && !sent.includes('dateOfBirth') && !sent.includes('familyBackground'));
    const { rows: scored } = await db.query(
      `SELECT rs.model_version FROM risk_scores rs JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE ar.user_id = $1 AND ar.action_type = 'view_shared_child_records' ORDER BY rs.id DESC LIMIT 1`, [edAcct.id]);
    record('The read was risk-scored under the Educator label', Boolean(scored[0]) && String(scored[0].model_version).startsWith('Educator-as-Caregiver-'), scored[0] && scored[0].model_version);
    record('Educator cannot add a record: read-only (403)', (await asEd(`/children/${kidId}/records`, { method: 'POST', body: { milestone: 'x', healthIndicator: 'x', assessmentScore: 1 } })).status === 403);
    record('Educator cannot change the child’s consent (403)', (await asEd(`/children/${kidId}/consent`, { method: 'POST', body: { scope: 'developmental_records', consentGiven: true } })).status === 403);
    record('A different educator is refused the same child (403)', (await api(`/educator/children/${kidId}/records`, { token: ed2.token, device: devE2 })).status === 403);

    const asRole = (id, sql, params) => db.runAs({ userId: id, role: 'Educator' }, () => db.query(sql, params));
    record('Database: the educator can read exactly the one shared child',
      (await asRole(edAcct.id, 'SELECT COUNT(*)::int AS n FROM child_identifiers')).rows[0].n === 1
      && (await asRole(edAcct.id, 'SELECT COUNT(*)::int AS n FROM developmental_records WHERE child_profile_id = $1', [kidId])).rows[0].n === 1);
    record('Database: another educator reads no child at all',
      (await asRole(ed2Acct.id, 'SELECT COUNT(*)::int AS n FROM child_identifiers')).rows[0].n === 0);
    record('Database: the educator cannot change or delete a record',
      (await asRole(edAcct.id, 'UPDATE developmental_records SET created_at = created_at WHERE child_profile_id = $1', [kidId])).rowCount === 0
      && (await asRole(edAcct.id, 'DELETE FROM developmental_records WHERE child_profile_id = $1', [kidId])).rowCount === 0);
    const selfApprove = await db.query('UPDATE educator_access SET decided_by = educator_id WHERE id = $1', [reqId])
      .then(() => 'allowed', (e) => e.constraint || e.message);
    record('Database: an educator approving their own request is refused by a CHECK', selfApprove === 'not_self_decided', selfApprove);

    const inbox2 = await asSh('/children/access');
    record('Caregiver sees that the educator opened the records, and when',
      inbox2.json && inbox2.json.views.some((v) => v.viewer === ACCOUNTS.ed.name && v.childName === KID && v.viewerRole === 'Educator' && v.stopped === false));

    const consent = (given) => asSh(`/children/${kidId}/consent`, { method: 'POST', body: { scope: 'developmental_records', consentGiven: given } });
    await consent(false);
    const noConsentEd = await asEd(`/educator/children/${kidId}/records`);
    record('Records consent withdrawn: the educator is refused too (403 CONSENT_REQUIRED)', noConsentEd.status === 403 && noConsentEd.json.code === 'CONSENT_REQUIRED', `status=${noConsentEd.status}`);
    await consent(true);

    record('Another caregiver cannot revoke it (404)', (await api(`/children/access/${reqId}/revoke`, { method: 'POST', token: cgS.token, device: deviceA })).status === 404);
    const revoked = await asSh(`/children/access/${reqId}/revoke`, { method: 'POST' });
    record('Caregiver revokes the access (200)', revoked.status === 200 && revoked.json.status === 'revoked', `status=${revoked.status}`);
    const afterRevoke = await asEd(`/educator/children/${kidId}/records`);
    record('The educator is refused on the very next request (403)', afterRevoke.status === 403 && afterRevoke.json.code === 'NO_ACCESS_GRANT', `status=${afterRevoke.status}`);
    record('Database: the revoked educator reads no child', (await asRole(edAcct.id, 'SELECT COUNT(*)::int AS n FROM child_identifiers')).rows[0].n === 0);
    const afterList = await asEd('/educator/children');
    record('The educator’s list no longer names the child', afterList.json.children.length === 0 && !JSON.stringify(afterList.json.children).includes(KID));
    record('Revoking twice is refused (409)', (await asSh(`/children/access/${reqId}/revoke`, { method: 'POST' })).status === 409);

    await ask(KID, 'Asking again for the new term');
    const again = (await pendingFor()).find((r) => r.childProfileId === kidId);
    await decide(sh, again.id, { decision: 'grant', days: 30 });
    await db.query("UPDATE educator_access SET expires_at = now() - interval '1 minute' WHERE id = $1", [again.id]);
    const expired = await asEd(`/educator/children/${kidId}/records`);
    record('Access ends by itself when its period runs out (403)', expired.status === 403 && (await asEd('/educator/children')).json.children.length === 0, `status=${expired.status}`);

    await ask(KID, 'Second educator asking for access', ed2, devE2);
    const fromEd2 = (await asSh('/children/access')).json.requests.find((r) => r.status === 'pending' && r.educatorName === ACCOUNTS.ed2.name && r.childProfileId === kidId);
    const refused = fromEd2 && await decide(sh, fromEd2.id, { decision: 'refuse' });
    record('Caregiver refuses a request; that educator stays locked out', Boolean(refused) && refused.status === 200 && refused.json.status === 'refused'
      && (await api(`/educator/children/${kidId}/records`, { token: ed2.token, device: devE2 })).status === 403);
    const ed2List = await api('/educator/children', { token: ed2.token, device: devE2 });
    record('A refusal looks the same to the educator as a name that matched nobody (Requested)',
      ed2List.json.asks.length > 0 && ed2List.json.asks.every((a) => a.status === 'requested'));
    record('After access is taken back or runs out, the educator’s request shows Access ended',
      statusOf(await asEd('/educator/children'), asked.json.id) === 'ended');

    // An archived child is not findable.
    await ask(SIB, 'Class educator, PP2 Green');
    const sibPending = (await pendingFor()).find((r) => r.childProfileId === sibId);
    if (sibPending) await decide(sh, sibPending.id, { decision: 'refuse' });
    await asSh(`/children/${sibId}/archive`, { method: 'POST', body: { reason: 'Test: archived child' } });
    await ask(SIB, 'Class educator, PP2 Green');
    record('An archived child is never matched', !(await pendingFor()).some((r) => r.childProfileId === sibId));

    const wanted = ['child_access_requested', 'child_access_granted', 'child_access_refused', 'child_access_revoked', 'access_denied_no_grant', 'view_shared_child_records'];
    const { rows: trail } = await db.query(
      `SELECT action, COUNT(*)::int AS n FROM audit_log WHERE user_id = ANY($1) AND created_at > now() - interval '10 minutes'
       AND action = ANY($2) GROUP BY action`, [[shAcct.id, edAcct.id, ed2Acct.id], wanted]);
    record('Every request, decision, read and refusal is in the audit log', trail.length === wanted.length, trail.map((t) => `${t.action}=${t.n}`).join(', '));
    const { rows: leak } = await db.query(
      'SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = ANY($1) AND detail LIKE $2', [[shAcct.id, edAcct.id, ed2Acct.id], `%${KID}%`]);
    record('The audit log holds profile numbers, never the child’s name', leak[0].n === 0);

    const limitsE = await api('/auditor/risk-thresholds', { token: auE0.token });
    const edLimit = limitsE.json && limitsE.json.thresholds.find((t) => t.role === 'Educator');
    record('Educators have their own risk limit on the auditor’s page', Boolean(edLimit) && edLimit.defaultThreshold === 0.4 && edLimit.min === 0.4 && edLimit.max === 0.6 && edLimit.editable === true);

    // Verifying a new educator with their ECD centre.
    const probeEmail = testEmail(`probe-educator-${word()}`);
    const regBody = (extra) => ({ method: 'POST', body: { fullName: 'Probe Educator', email: probeEmail, requestedRole: 'Educator', reason: 'automated test', ...NOTICE, ...extra } });
    record('An educator request without the ECD centre is refused (400)', (await api('/auth/register', regBody({ centrePhone: '0712 345 678' }))).status === 400);
    record('An educator request without the centre phone is refused (400)', (await api('/auth/register', regBody({ ecdCentre: 'Probe ECD Centre' }))).status === 400);
    const regEd = await api('/auth/register', regBody({ ecdCentre: 'Probe ECD Centre', centrePhone: '0712 345 678' }));
    record('An educator can request an account with the centre and its phone (201)', regEd.status === 201, `status=${regEd.status}`);
    const adE = await login(adAcct.email);
    const listed = await api('/admin/registration-requests', { token: adE.token });
    const row = listed.json && listed.json.requests.find((r) => r.id === regEd.json.requestId);
    record('The admin sees the centre and its phone number', Boolean(row) && row.ecd_centre === 'Probe ECD Centre' && row.centre_phone === '0712 345 678');
    const noNote = await api(`/admin/registration-requests/${regEd.json.requestId}/approve`, { method: 'POST', token: adE.token, body: { verificationNote: 'ok' } });
    record('An educator cannot be approved without a verification note (400)', noNote.status === 400 && noNote.json.code === 'VERIFICATION_NOTE_REQUIRED', `status=${noNote.status}`);
    const approved = await api(`/admin/registration-requests/${regEd.json.requestId}/approve`, { method: 'POST', token: adE.token,
      body: { verificationNote: 'Called the centre; the head confirmed this educator teaches PP1' } });
    const { rows: made } = await db.query('SELECT id, ecd_centre, verification_note, verified_by FROM users WHERE email = $1', [probeEmail]);
    record('Approved with the note: the account keeps the centre, the note and who verified it', approved.status === 200 && Boolean(made[0])
      && made[0].ecd_centre === 'Probe ECD Centre' && /head confirmed/.test(made[0].verification_note) && made[0].verified_by === adAcct.id, `status=${approved.status}`);
    if (made[0]) await db.query('DELETE FROM users WHERE id = $1', [made[0].id]).catch(() => {});
    await db.query('DELETE FROM registration_requests WHERE email = $1', [probeEmail]);
  }

  console.log('\n=== Download my data (DPIA G6) and monitoring retention (DPIA G1) ===');
  {
    // A fresh working day for the test caregiver: this run has already done
    // many reads, and one more data action would (correctly) cross the limit.
    await ageTestActivity([cgAcct.id]);
    const cgE = await login(ACCOUNTS.cg.username, deviceA);
    const auE = await login(auAcct.email);
    const exp = await api('/children/export?format=json', { token: cgE.token, device: deviceA });
    record('A caregiver downloads their data (200)', exp.status === 200 && Array.isArray(exp.json.children) && exp.json.account.email === cgAcct.email, `status=${exp.status}`);
    record('The file holds their children, consent history and activity',
      Boolean(exp.json) && exp.json.children.some((c) => c.fullName === 'Test Child' && Array.isArray(c.consentHistory) && c.consentHistory.length > 0)
      && exp.json.yourActivity.length > 0);
    const { rows: ownIds } = await db.runAsSystem(() => db.query('SELECT id FROM child_profiles WHERE caregiver_id = $1', [cgAcct.id]));
    const own = new Set(ownIds.map((r) => r.id));
    record("The file holds exactly this caregiver's children, no other family's",
      Boolean(exp.json) && exp.json.children.length === own.size && exp.json.children.every((c) => own.has(c.childProfileId)));
    record('Records are left out where records consent is withdrawn',
      Boolean(exp.json) && exp.json.children.every((c) => Array.isArray(c.developmentalRecords) || typeof c.developmentalRecords === 'string'));
    await ageTestActivity([cgAcct.id]);
    const pdf = await api('/children/export', { token: cgE.token, device: deviceA });
    record('By default the download is a readable PDF document', pdf.status === 200 && pdf.text.startsWith('%PDF-'), `status=${pdf.status}`);
    await expectStatus('An auditor cannot download a caregiver export (403)', '/children/export', { token: auE.token }, 403);
    const { rows: expLog } = await db.query("SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'export_own_data'", [cgAcct.id]);
    record('The download is in the audit log', expLog[0].n >= 1);

    const adM = await login(ad2Acct.email);
    const st = await api('/admin/retention/status', { token: adM.token });
    record('Data Retention shows the monitoring period', st.status === 200 && st.json.monitoring && Number.isInteger(st.json.monitoring.days), st.json && JSON.stringify(st.json.monitoring && st.json.monitoring.due));
    const { rows: old } = await db.query(
      `INSERT INTO access_requests (user_id, action_type, pc_name, ip_address, requested_at)
       VALUES ($1, 'view_own_child_records', 'old-test-device', '10.0.0.9', now() - interval '800 days') RETURNING id`, [cgAcct.id]);
    await db.query(
      `INSERT INTO risk_scores (access_request_id, isoforest_score, autoencoder_score, combined_score, role_threshold, is_flagged, features, drivers, created_at)
       VALUES ($1, 0.1, 0.1, 0.1, 0.4, FALSE, '{"is_own_pc":1}', '[]', now() - interval '800 days')`, [old[0].id]);
    record('Clearing without the password is refused (step-up)', [403, 429].includes((await api('/admin/retention/monitoring/clear', { method: 'POST', token: adM.token })).status));
    await expectStatus('A caregiver cannot clear monitoring data (403)', '/admin/retention/monitoring/clear', { method: 'POST', token: cgE.token, device: deviceA }, 403);
    const cl = await api('/admin/retention/monitoring/clear', { method: 'POST', token: adM.token, body: { password: PASS } });
    record('Admin clears old monitoring details (200)', cl.status === 200 && cl.json.cleared.actions >= 1 && cl.json.cleared.scores >= 1, cl.json && JSON.stringify(cl.json.cleared));
    const { rows: after } = await db.query(
      `SELECT ar.pc_name, ar.ip_address, rs.features FROM access_requests ar JOIN risk_scores rs ON rs.access_request_id = ar.id WHERE ar.id = $1`, [old[0].id]);
    record('Device, address and evidence are cleared; the action and score are kept',
      after[0] && after[0].pc_name === null && after[0].ip_address === null && after[0].features === null);
    const { rows: recent } = await db.query(
      "SELECT COUNT(*)::int AS n FROM access_requests WHERE user_id = $1 AND requested_at > now() - interval '1 day' AND pc_name IS NOT NULL", [cgAcct.id]);
    record('Recent monitoring details are untouched', recent[0].n > 0);
    const { rows: clLog } = await db.query("SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'monitoring_data_cleared' AND user_id = $1", [ad2Acct.id]);
    record('Clearing is in the audit log', clLog[0].n >= 1);
    const tooShort = await api('/admin/settings/monitoring_retention_days', { method: 'POST', token: adM.token, body: { value: 30, reason: 'Trying a period that is too short', password: PASS } });
    record('A monitoring period below 90 days is refused (400)', tooShort.status === 400, `status=${tooShort.status}`);
  }

  console.log('\n=== "Take action": report, pause until verified, explain, decide (db/013) ===');
  {
    const ceAcct = await ensureTestAccount(ACCOUNTS.ce);
    const shAcct2 = await ensureTestAccount(ACCOUNTS.sh);
    await db.query("UPDATE users SET ecd_centre = 'Test ECD Centre' WHERE id = $1", [ceAcct.id]);
    await db.query("UPDATE account_cases SET status = 'verified', decided_by = $2, decided_at = now(), decision_note = 'closed by an earlier test run' WHERE user_id = $1 AND status IN ('reported', 'paused', 'explained')", [ceAcct.id, adAcct.id]);
    await ageTestActivity([ceAcct.id]);
    const devCE = 'test-device-case-educator';
    // A child shared with this educator, so removing access can be checked.
    const { rows: kid } = await db.runAsSystem(() => db.query(
      'SELECT id FROM child_profiles WHERE caregiver_id = $1 AND archived_at IS NULL ORDER BY id LIMIT 1', [shAcct2.id]));
    if (kid[0]) {
      await db.query("UPDATE educator_access SET status = 'revoked', ended_at = now(), decided_by = $3 WHERE educator_id = $1 AND child_profile_id = $2 AND status IN ('pending', 'granted')", [ceAcct.id, kid[0].id, shAcct2.id]);
      await db.query(
        `INSERT INTO educator_access (child_profile_id, caregiver_id, educator_id, reason, status, decided_at, decided_by, expires_at)
         VALUES ($1, $2, $3, 'Test: shared for the case check', 'granted', now(), $2, now() + interval '7 days')`, [kid[0].id, shAcct2.id, ceAcct.id]);
    }
    let ce = await login(ACCOUNTS.ce.username, devCE);
    await api('/educator/children', { token: ce.token, device: devCE });
    const auC = await login(auAcct.email);
    const adC = await login(adAcct.email);
    await api('/auditor/weekly-review/refresh', { method: 'POST', token: auC.token });
    const week = await api('/auditor/weekly-review', { token: auC.token });
    const row = week.json && week.json.people.find((p) => p.user_id === ceAcct.id);
    record('The educator appears on People to Review (everyone active is listed)', Boolean(row), `status=${week.status}`);
    if (row) {
      const report = await api(`/auditor/weekly-review/${row.id}/decision`, { method: 'POST', token: auC.token,
        body: { status: 'escalated', note: 'Test: reading far more than usual this week' } });
      record('Take action opens a case for the admin (200)', report.status === 200 && Boolean(report.json.caseId) && report.json.adminsTold === true, `status=${report.status}`);
      const caseId = report.json && report.json.caseId;
      await expectStatus('An auditor cannot see or act on cases (403)', '/admin/cases', { token: auC.token }, 403);
      const cases = await api('/admin/cases', { token: adC.token });
      const c = cases.json && cases.json.cases.find((x) => x.id === caseId);
      record('The admin sees the case with the auditor’s reason', Boolean(c) && c.status === 'reported' && /far more than usual/.test(c.reportNote));
      const noPass = await api(`/admin/cases/${caseId}/pause`, { method: 'POST', token: adC.token, body: { note: 'Pausing while we check' } });
      record('Pausing without the password is refused (step-up)', noPass.status === 403 && noPass.json.code === 'STEP_UP_REQUIRED');
      const paused = await api(`/admin/cases/${caseId}/pause`, { method: 'POST', token: adC.token, body: { note: 'Pausing while we check', password: PASS } });
      record('The admin pauses the account until verified (200)', paused.status === 200 && paused.json.status === 'paused', `status=${paused.status}`);
      const kicked = await api('/educator/children', { token: ce.token, device: devCE });
      record('The person’s open session ends at once (401 ACCOUNT_PAUSED)', kicked.status === 401 && kicked.json.code === 'ACCOUNT_PAUSED', `status=${kicked.status}`);
      ce = await login(ACCOUNTS.ce.username, devCE);
      record('The person can still sign in, and is told the account is paused', ce.paused === true);
      const blocked = await api('/educator/children', { token: ce.token, device: devCE });
      record('Every data request from a paused account is refused (403 ACCOUNT_PAUSED)', blocked.status === 403 && blocked.json.code === 'ACCOUNT_PAUSED', `status=${blocked.status}`);
      if (kid[0]) {
        const rec = await api(`/educator/children/${kid[0].id}/records`, { token: ce.token, device: devCE });
        record('...including a child’s records it was granted', rec.status === 403 && rec.json.code === 'ACCOUNT_PAUSED');
      }
      const mine = await api('/auth/paused-case', { token: ce.token, device: devCE });
      record('The paused person sees the pause, with no child data', mine.status === 200 && mine.json.paused === true && !JSON.stringify(mine.json).includes('Test Child'));
      record('A too-short explanation is refused (400)', (await api('/auth/paused-case/explanation', { method: 'POST', token: ce.token, device: devCE, body: { explanation: 'busy' } })).status === 400);
      const ex = await api('/auth/paused-case/explanation', { method: 'POST', token: ce.token, device: devCE,
        body: { explanation: 'End-of-term progress reports for my PP1 class' } });
      record('The person sends an explanation (200)', ex.status === 200 && ex.json.status === 'explained');
      const ownTry = await api(`/admin/cases/${caseId}/decision`, { method: 'POST', token: ce.token, device: devCE,
        body: { decision: 'verified', note: 'I verify myself', password: PASS } });
      record('The person cannot decide their own case (403)', ownTry.status === 403);
      const seen = (await api('/admin/cases', { token: adC.token })).json.cases.find((x) => x.id === caseId);
      record('The admin sees the explanation beside the auditor’s reason', seen && seen.status === 'explained' && /PP1/.test(seen.explanation));
      const ok = await api(`/admin/cases/${caseId}/decision`, { method: 'POST', token: adC.token,
        body: { decision: 'verified', note: 'Called the centre: report week confirmed', password: PASS } });
      record('The admin verifies it (200)', ok.status === 200 && ok.json.status === 'verified');
      const back = await api('/educator/children', { token: ce.token, device: devCE });
      record('Access is restored at once, with the person’s own password', back.status === 200, `status=${back.status}`);
      const detail = await api(`/auditor/weekly-review/${row.id}`, { token: auC.token });
      record('The auditor sees the outcome on People to Review', detail.json && detail.json.case && detail.json.case.status === 'verified'
        && /PP1/.test(detail.json.case.explanation || ''));
      record('A closed case cannot be decided again (409)', (await api(`/admin/cases/${caseId}/decision`, { method: 'POST', token: adC.token,
        body: { decision: 'removed', note: 'Changing my mind later', password: PASS } })).status === 409);

      // Second time: not verified, access removed.
      const again = await api(`/auditor/weekly-review/${row.id}/decision`, { method: 'POST', token: auC.token,
        body: { status: 'escalated', note: 'Test: still far above usual after the check' } });
      const case2 = again.json && again.json.caseId;
      const removed = await api(`/admin/cases/${case2}/decision`, { method: 'POST', token: adC.token,
        body: { decision: 'removed', note: 'Centre says this person no longer teaches there', password: PASS } });
      record('The admin removes access (200)', removed.status === 200 && removed.json.status === 'removed', `status=${removed.status}`);
      const { rows: lockedRow } = await db.query('SELECT is_locked FROM users WHERE id = $1', [ceAcct.id]);
      record('Removing access locks the account', lockedRow[0] && lockedRow[0].is_locked === true);
      if (kid[0]) {
        const { rows: grants } = await db.query(
          "SELECT COUNT(*)::int AS n FROM educator_access WHERE educator_id = $1 AND status = 'granted'", [ceAcct.id]);
        record('...and ends every child access the educator had', grants[0].n === 0 && removed.json.endedGrants >= 1);
        const parentView = await api('/children/access', { token: (await login(ACCOUNTS.sh.username, 'test-device-sharing')).token, device: 'test-device-sharing' });
        record('The parent sees that access was taken back', parentView.json && parentView.json.requests.some((r) => r.educatorName === ACCOUNTS.ce.name && r.status === 'revoked'));
      }
      const selfDecided = await db.query('UPDATE account_cases SET decided_by = user_id WHERE id = $1', [caseId])
        .then(() => 'allowed', (e) => e.constraint || e.message);
      record('Database: nobody can decide their own case (CHECK)', selfDecided === 'case_not_own', selfDecided);
      const { rows: trail } = await db.query(
        "SELECT action FROM audit_log WHERE action LIKE 'account_%' AND (detail LIKE $1 OR detail LIKE $2 OR detail = $3 OR detail = $4)",
        [`case_id=${caseId},%`, `case_id=${case2},%`, `case_id=${caseId}`, `case_id=${case2}`]);
      const acts = new Set(trail.map((t) => t.action));
      record('Every step is in the audit log', ['account_case_reported', 'account_paused', 'account_case_explained', 'account_case_verified', 'account_access_removed'].every((a) => acts.has(a)),
        [...acts].join(', '));
    }
  }

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
    // A request that was unexpectedly refused (for example a session the
    // risk engine ended) makes later checks read missing data. Report what
    // passed so far and why it stopped, instead of only a stack trace.
    const failed = results.filter((r) => !r.ok);
    console.error(`
STOPPED after ${results.length} checks (${failed.length} failed so far): ${err.message}`);
    failed.forEach((f) => console.error(`  FAILED: ${f.name} :: ${f.detail || ''}`));
    try { await lockTestAccounts(); await db.pool.end(); } catch { /* ignore */ }
    process.exit(1);
  });
